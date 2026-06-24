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
//! `Principal::row_visibility` 的 `Service` / `Anonymous` 分支返回 `Err(runctx::MissingCtx)`，
//! 强制调用方 deny；字段私有，外部无法绕过 funnel 伪造特权主体。

#![forbid(unsafe_code)]

use base64::Engine;
use vocab::PrincipalKind;
use vocab::tenant::{
    CrossTenantCapability, CrossTenantVisibility, RowVisibility, ScopedTenant, TenantId,
};

use primitives::authplan::{AuthPlan, AuthRequirement, RouteAuthOptOut, resolve_requirement};

// verify→mint bridge 经 `DynPdp` 调验签：`verify` 是 `Pdp` trait 方法，须 trait 在 scope（`as _`
// 只引入方法、不污染 `Pdp` 名——bridge 全程用 `diport::DynPdp` / `diport::RawCredential` 全限定）。
use diport::Pdp as _;

// reason: 确保 authplan 符号被引用，防止 cargo-udeps 误报未使用依赖（ADR-004 C8）。
#[allow(dead_code)]
const _: fn(AuthPlan, Option<RouteAuthOptOut>) -> AuthRequirement = resolve_requirement;

// kind claim 字符串常量（同义字面量 ≥3 次，抽 const）。
const KIND_USER: &str = "user";
const KIND_DEVICE: &str = "device";
const KIND_ADMIN: &str = "admin";
const KIND_SUPER_ADMIN: &str = "superAdmin";

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
/// 信任边界：只做**结构**校验，签名/exp 与身份 claims 由上游 verifier（`diport::Pdp`）负责。
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
    /// scoped 主体缺 tenant / tenant 非 canonical UUID → 一律 `TokenInvalid`（fail-closed）。
    fn derive_from_claims(
        subject: &str,
        tenant: Option<&str>,
        kind: Option<&str>,
    ) -> Result<Self, AuthnError> {
        // 空 subject fail-closed（F2）：verifier 产物即便绕过旧 decode_claims 的非空检查，也不得 mint
        // 空主体 Principal。此为 Principal 派生单一漏斗，覆盖 from_verified_jwt + bridge 两路。
        if subject.is_empty() {
            return Err(AuthnError::TokenInvalid);
        }
        // 单点决策 kind + 是否需 tenant，避免二级 match-on-PrincipalKind 的不可达 `_` 臂
        // （新增 PrincipalKind 时须在此加 KIND_* 串臂并定其 tenant 要求，无静默兜底）。
        let (kind, needs_tenant) = match kind {
            Some(KIND_USER) => (PrincipalKind::User, true),
            Some(KIND_DEVICE) => (PrincipalKind::Device, true),
            Some(KIND_ADMIN) => (PrincipalKind::Admin, true),
            // 跨租户超管：无 tenant（忽略任何 tenant claim）。
            Some(KIND_SUPER_ADMIN) => (PrincipalKind::SuperAdmin, false),
            // service/anonymous 不经 jwt funnel；未知/缺失 kind → TokenInvalid。
            _ => return Err(AuthnError::TokenInvalid),
        };
        let tenant = if needs_tenant {
            let raw = tenant.ok_or(AuthnError::TokenInvalid)?;
            Some(TenantId::parse(raw).map_err(|_| AuthnError::TokenInvalid)?)
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
    /// fail-closed：空 subject → `TokenInvalid`（F2，与 [`Self::derive_from_claims`] 同款非空不变式）。
    /// 信任原点 = verifier：subject 取自验签产物 [`diport::VerifiedClaims::subject`]，service token 的
    /// kind / tenant claim 不参与（service 主体恒跨租户）。
    fn service_from_subject(subject: &str) -> Result<Self, AuthnError> {
        if subject.is_empty() {
            return Err(AuthnError::TokenInvalid);
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
    /// 结构化解码 / claims 映射失败（坏 base64url / 坏 JSON / 缺 sub / 未知 kind / 坏 tenant），
    /// 或 verifier 报 [`diport::PdpError::InvalidSignature`]（签名 / MAC 校验失败）/
    /// [`diport::PdpError::Untrusted`]（签发者 / key / audience 不受信）。verify 层只做认证（非授权），
    /// 故凭据不可信 / 无效一律 401 invalid_token（RFC 6750 §3.1），403 留给 authz 层「已认证但无权」。
    #[error("token is invalid")]
    TokenInvalid,
    /// 令牌过期（verifier 报 [`diport::PdpError::Expired`]，经 verify→mint bridge 的 `From<PdpError>` 产生）。
    #[error("token is expired")]
    TokenExpired,
    /// 会话不存在。**本 crate 当前不可达**——由 W session store（`diport` 仓储 port）产生。
    #[error("session not found")]
    SessionNotFound,
    /// 主体已认证但无权（403 insufficient permission）。**本 crate 当前不可达**——由后续 authz / ABAC 层
    /// 产生；verify→mint bridge **不**产此态（凭据不可信 / 无效归 [`AuthnError::TokenInvalid`]，RFC 6750 §3.1）。
    #[error("principal not permitted")]
    Forbidden,
}

/// 验签 port 错误 → 认证错误映射（verify→mint bridge 经 `?` 使用，#1158）。fail-closed：所有 `PdpError`
/// 变体均映射到**拒绝**态，绝不静默成功；`PdpError` 是 `#[non_exhaustive]`，未来变体默认落 `TokenInvalid`。
impl From<diport::PdpError> for AuthnError {
    fn from(e: diport::PdpError) -> Self {
        match e {
            diport::PdpError::InvalidSignature => AuthnError::TokenInvalid,
            diport::PdpError::Expired => AuthnError::TokenExpired,
            // verify 层纯认证：Untrusted（iss / key / aud 不受信 / 未知 alg / kid 无匹配）= 凭据无效 →
            // 401 invalid_token（RFC 6750 §3.1），非 403 Forbidden（后者留给 authz 层「已认证但无权」）。
            diport::PdpError::Untrusted => AuthnError::TokenInvalid,
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
                    Err(AuthnError::TokenInvalid)
                ),
                "scoped kind 缺 tenant 必须 TokenInvalid: {kind}"
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
                    Err(AuthnError::TokenInvalid)
                ),
                "必须 TokenInvalid: tenant={tenant:?} kind={kind:?}"
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
            Err(AuthnError::TokenInvalid)
        ));
        let empty_svc = VerifiedServiceToken::seal(
            AccessToken::new("opaque"),
            VerifiedClaims::new("", None, None),
        );
        assert!(matches!(
            Principal::from_verified_service_token(&empty_svc),
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

    /// fail-closed：三 `PdpError` 变体均映射到**拒绝**态，never `Ok`，never seal（verify 层纯认证，
    /// Untrusted 与 InvalidSignature 同归 401 `TokenInvalid`，RFC 6750 §3.1）。
    #[tokio::test]
    async fn verify_jwt_pdp_failure_maps_error_and_never_mints() {
        let raw = test_jwt(
            r#"{"sub":"u","tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kind":"user"}"#,
        );
        for (perr, want) in [
            (PdpError::InvalidSignature, AuthnError::TokenInvalid),
            (PdpError::Expired, AuthnError::TokenExpired),
            (PdpError::Untrusted, AuthnError::TokenInvalid),
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

    /// verify 先于 seal：`Pdp` ok 但 raw 结构坏 → `Jwt::parse` 报 `TokenInvalid`（非 seal），无产物。
    #[tokio::test]
    async fn verify_jwt_ok_but_malformed_raw_fails_at_parse() {
        let pdp = boxed(Ok(VerifiedClaims::new(
            "u",
            Some(CANON.to_string()),
            Some("user".to_string()),
        )));
        assert!(matches!(
            verify_jwt("only.two", &pdp).await,
            Err(AuthnError::TokenInvalid)
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
    /// Untrusted 与 InvalidSignature 同归 401 `TokenInvalid`）。
    #[tokio::test]
    async fn verify_service_token_pdp_failure_maps_error_and_never_mints() {
        for (perr, want) in [
            (PdpError::InvalidSignature, AuthnError::TokenInvalid),
            (PdpError::Expired, AuthnError::TokenExpired),
            (PdpError::Untrusted, AuthnError::TokenInvalid),
        ] {
            let pdp = boxed(Err(perr.clone()));
            let result = verify_service_token("opaque-token", &pdp).await;
            assert!(
                matches!(&result, Err(e) if std::mem::discriminant(e) == std::mem::discriminant(&want)),
                "PdpError::{perr:?} 须映射到 {want:?}（且绝不 mint）"
            );
        }
    }

    /// F2（bridge 端到端）：verifier 验签 ok 但返回**空 subject** → fail-closed `TokenInvalid`，绝不 mint。
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
            Err(AuthnError::TokenInvalid)
        ));
        let pdp_svc = boxed(Ok(VerifiedClaims::new("", None, None)));
        assert!(matches!(
            verify_service_token("opaque", &pdp_svc).await,
            Err(AuthnError::TokenInvalid)
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
