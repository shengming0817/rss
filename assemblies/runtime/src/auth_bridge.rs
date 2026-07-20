//! 验签桥（verify-bridge）—— 组合根唯一 [`httpserve::Authenticated`] 证据构造点。
//!
//! 落地 `authn/src/lib.rs` `NOTE(#1109)` 承诺：组合根在 `finalize_auth` 返回 router **外层** `.layer()`
//! 本桥；请求带凭据时经 profile-typed authn funnel（注入验签 provider）验签，成功则据**验签
//! 产物 Principal** 的脱敏标量构造 [`httpserve::Authenticated`] 证据注入请求 extension，enforce 层据此对
//! 匹配 `Require(scheme)` 的路由放行（AUTH-EVIDENCE-REQUIRE-01）。
//!
//! 设计要点：
//! - **ambient context 派生 + 传递（#1105，ADR-002 §D5）**：验签得到已认证 tenant source 时，本桥建
//!   [`runctx::AppCtx`]，**经 `httpserve::PendingScopeCtx` extension 传给内层 enforce**——**scope 不在桥
//!   建立**。JWT tenant 来自已验证 Principal claim；service-token tenant 来自已纳入 HS256 MAC 输入的 canonical
//!   `X-Tenant-ID`。本桥叠在 `AuthenticatedRoutes` **外层**、运行期读不到 route 的 `opt_out`，无法区分 Public / Require；
//!   故由持决策方的 `EnforceService` 在 **`Require`-Allow**（认证路由放行）后建 `runctx::scope` 绑定 handler
//!   （+ 下游 diport emit），使 ambient scope 与 route auth 决策对齐（#1105 F2：避免 Public 路由因携有效 Bearer
//!   被误绑 ambient tenant）。深层经 `runctx::try_current()` 取 tenant/principal 做 RLS/ABAC。跨租户主体
//!   无已认证 tenant source ⇒ 本桥不附 PendingScopeCtx ⇒ 下游 `try_current()` 得 `MissingCtx`（fail-closed，
//!   跨租户读经显式 `audited_cross_tenant` 路径）。
//!   **bootstrap 预认证**（`auth.bootstrap:true` HTTP Basic + `X-Tenant-ID`）当前**未在本 runtime 接线**
//!   （`auth_scheme` 仅 Jwt/ServiceToken/NoAuth，无 basic 路径）⇒ 无 handler 需 ambient scope；bootstrap 落地时
//!   须在其装配点同样经 PendingScopeCtx + enforce 接 scope（与本桥同范式）。
//! - **本桥不自发裁决**：仅「铸证据 + 埋点」，绝不短路 401/403。无证据时透传，由内层 enforce 作**唯一**鉴权
//!   裁决方（Public opt-out 路由放行、Require 路由 fail-closed 401）。理由：① 单一裁决方杜绝双判定点；
//!   ② 可观测结果等价（Require + 坏凭据仍 401，由 enforce 发）；③ 本桥是 blanket 外层、包住含 Public 路由
//!   的整个 listener，不短路即不误伤 Public；④ 统一 envelope 由 enforce 生成、requestId 完整（`request_id`
//!   中间件经唯一 bindable 出口封在本桥**外层**，ROUTE-REQUESTID-OUTERMOST-01，本桥运行时 RequestId 已就位）。
//! - **凭据方案按 listener 静态绑定**（runtime-api.md「单 listener 单 scheme」）：本桥在 finalize_auth 外层，
//!   `AuthPlan` extension 是内层、本桥运行时尚不可读，故由组合根按 listener 注入对应 [`RequiredScheme`]。
//! - **真异步 + Send 安全**：`Pdp` / `DynPdp` 是 `Send + Sync`（#1828），本桥直接 await verifier；合法
//!   `Poll::Pending` 由 serving runtime 正常恢复，不转换为认证结果。唯一 bindable HTTP funnel 的必填
//!   `ServerRequestBudget` / request cancellation drop 包含 verifier 的整条请求 future；bridge 不拥有局部
//!   timeout，无成功产物即不注证据，保持 fail-closed。
//! - **无 PII 埋点**：成功记 `authz.decision=allow` + `principal.kind`（[`vocab::PrincipalKind`] 脱敏枚举）；
//!   失败记 `authz.decision=deny` + 七个固定 `authz.deny_reason` 标签（见 [`deny_reason`]）+ `AuthnError`
//!   变体；**绝不**记 token / subject / claims。
//!
//! `Authenticated::new` callsite 由 `rss_authenticated_callsite` dylint 限组合根
//! （`server`/`rss`/`runtime` 在 allowlist；runtime = assemblies/runtime 组合根）。
//!
//! ref: tower-rs/tower-http tower-http/src/auth/async_require_authorization.rs@main
//!   （`AsyncAuthorizeRequest::authorize` → `request.extensions_mut().insert(principal)` 后透传 next 的范式）。
//!   偏离：授权决策（放行/拒）下沉到内层 enforce（单一裁决方），本桥只铸证据 + 埋点。

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use httpserve::{Authenticated, AuthenticatedRoutes};
use primitives::RequiredScheme;
use tracing::Instrument as _;
use vocab::{PrincipalKind, TenantId};

/// One listener-fixed token profile and its matching verifier.
///
/// The variant is the only runtime source of the required scheme, trusted credential profile, and
/// authn funnel. A caller cannot pass a provider and scheme as independently varying values.
pub(crate) enum ProfileBinding {
    RssAccess(Arc<oidc::OidcProvider<diport::RssAccessProfile>>),
    FederatedAccess(Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>),
    ServiceToken(Arc<oidc::OidcProvider<diport::ServiceTokenProfile>>),
}

impl Clone for ProfileBinding {
    fn clone(&self) -> Self {
        match self {
            Self::RssAccess(provider) => Self::RssAccess(Arc::clone(provider)),
            Self::FederatedAccess(provider) => Self::FederatedAccess(Arc::clone(provider)),
            Self::ServiceToken(provider) => Self::ServiceToken(Arc::clone(provider)),
        }
    }
}

impl ProfileBinding {
    pub(crate) const fn auth_scheme(&self) -> primitives::AuthScheme {
        match self {
            Self::RssAccess(_) => primitives::AuthScheme::RssAccessToken,
            Self::FederatedAccess(_) => primitives::AuthScheme::FederatedAccessToken,
            Self::ServiceToken(_) => primitives::AuthScheme::ServiceToken,
        }
    }

    pub(crate) const fn required_scheme(&self) -> RequiredScheme {
        match self {
            Self::RssAccess(_) => RequiredScheme::RssAccessToken,
            Self::FederatedAccess(_) => RequiredScheme::FederatedAccessToken,
            Self::ServiceToken(_) => RequiredScheme::ServiceToken,
        }
    }

    const fn profile(&self) -> diport::TokenProfile {
        match self {
            Self::RssAccess(_) => diport::TokenProfile::RssAccess,
            Self::FederatedAccess(_) => diport::TokenProfile::FederatedAccess,
            Self::ServiceToken(_) => diport::TokenProfile::ServiceToken,
        }
    }
}

struct VerifiedPrincipal {
    principal: authn::Principal,
    ambient_tenant: Option<TenantId>,
}

enum VerifyFailure {
    Authn(authn::AuthnError),
    ProfileMismatch,
}

/// 在 `finalize_auth` 产出的 [`AuthenticatedRoutes`] **外层**叠验签桥（经 `AuthenticatedRoutes::layer` 只能加层、
/// 不能替换，funnel 封印不破）。scheme、profile 与 provider 均由同一 closed binding 派生。
pub(crate) fn apply_verify_bridge(
    routes: AuthenticatedRoutes,
    binding: ProfileBinding,
) -> AuthenticatedRoutes {
    routes.layer(middleware::from_fn_with_state(binding, verify))
}

/// mTLS remains a transport binding and never shares a token-provider state.
pub(crate) fn apply_mtls_verify_bridge(routes: AuthenticatedRoutes) -> AuthenticatedRoutes {
    routes.layer(middleware::from_fn(verify_mtls))
}

/// Integration seam that preserves the production RSS profile/provider coupling.
#[cfg(feature = "integration")]
pub fn apply_rss_access_verify_bridge_for_test(
    routes: AuthenticatedRoutes,
    provider: Arc<oidc::OidcProvider<diport::RssAccessProfile>>,
) -> AuthenticatedRoutes {
    apply_verify_bridge(routes, ProfileBinding::RssAccess(provider))
}

/// Integration seam that preserves the production federated profile/provider coupling.
#[cfg(feature = "integration")]
pub fn apply_federated_access_verify_bridge_for_test(
    routes: AuthenticatedRoutes,
    provider: Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>,
) -> AuthenticatedRoutes {
    apply_verify_bridge(routes, ProfileBinding::FederatedAccess(provider))
}

/// Integration seam that preserves the production service profile/provider coupling.
#[cfg(feature = "integration")]
pub fn apply_service_token_verify_bridge_for_test(
    routes: AuthenticatedRoutes,
    provider: Arc<oidc::OidcProvider<diport::ServiceTokenProfile>>,
) -> AuthenticatedRoutes {
    apply_verify_bridge(routes, ProfileBinding::ServiceToken(provider))
}

/// Integration seam for the independent mTLS transport bridge.
#[cfg(feature = "integration")]
pub fn apply_mtls_verify_bridge_for_test(routes: AuthenticatedRoutes) -> AuthenticatedRoutes {
    apply_mtls_verify_bridge(routes)
}

#[cfg(feature = "integration")]
enum TestProfileBinding {
    RssAccess(Arc<diport::DynPdp<'static>>),
    ServiceToken(Arc<diport::DynPdp<'static>>),
}

#[cfg(feature = "integration")]
impl Clone for TestProfileBinding {
    fn clone(&self) -> Self {
        match self {
            Self::RssAccess(provider) => Self::RssAccess(Arc::clone(provider)),
            Self::ServiceToken(provider) => Self::ServiceToken(Arc::clone(provider)),
        }
    }
}

#[cfg(feature = "integration")]
impl TestProfileBinding {
    const fn profile(&self) -> diport::TokenProfile {
        match self {
            Self::RssAccess(_) => diport::TokenProfile::RssAccess,
            Self::ServiceToken(_) => diport::TokenProfile::ServiceToken,
        }
    }

    const fn required_scheme(&self) -> RequiredScheme {
        match self {
            Self::RssAccess(_) => RequiredScheme::RssAccessToken,
            Self::ServiceToken(_) => RequiredScheme::ServiceToken,
        }
    }
}

/// Integration-only fixed-profile PDP seam for exercising async/cancellation behavior.
#[cfg(feature = "integration")]
pub fn apply_rss_access_pdp_bridge_for_test<P>(
    routes: AuthenticatedRoutes,
    provider: P,
) -> AuthenticatedRoutes
where
    P: diport::Pdp + Send + Sync + 'static,
{
    apply_test_profile_bridge(
        routes,
        TestProfileBinding::RssAccess(diport::DynPdp::new_arc(provider)),
    )
}

/// Integration-only fixed-profile PDP seam for service replay/outage behavior.
#[cfg(feature = "integration")]
pub fn apply_service_token_pdp_bridge_for_test<P>(
    routes: AuthenticatedRoutes,
    provider: P,
) -> AuthenticatedRoutes
where
    P: diport::Pdp + Send + Sync + 'static,
{
    apply_test_profile_bridge(
        routes,
        TestProfileBinding::ServiceToken(diport::DynPdp::new_arc(provider)),
    )
}

#[cfg(feature = "integration")]
fn apply_test_profile_bridge(
    routes: AuthenticatedRoutes,
    binding: TestProfileBinding,
) -> AuthenticatedRoutes {
    routes.layer(middleware::from_fn_with_state(binding, verify_test_profile))
}

/// 异步验签产物 → `Principal`（profile binding 穷尽选择唯一 typed funnel）。
///
/// `provider` 经 `DynPdp::from_ref` 借为 `&DynPdp` 喂 authn funnel（信任原点单源）；所有失败均不产证据。
async fn verify_principal(
    binding: &ProfileBinding,
    credential: httpserve::ExtractedBearerCredential,
) -> Result<VerifiedPrincipal, VerifyFailure> {
    let (profile, token, service_tenant) = credential.into_parts();
    if profile != binding.profile() {
        return Err(VerifyFailure::ProfileMismatch);
    }

    match binding {
        ProfileBinding::RssAccess(provider) => {
            let pdp = diport::DynPdp::from_ref(provider.as_ref());
            authn::verify_rss_access(&token, pdp)
                .await
                .map(|(_, principal)| {
                    let ambient_tenant = principal.tenant();
                    VerifiedPrincipal {
                        principal,
                        ambient_tenant,
                    }
                })
                .map_err(VerifyFailure::Authn)
        }
        ProfileBinding::FederatedAccess(provider) => {
            let pdp = diport::DynPdp::from_ref(provider.as_ref());
            authn::verify_federated_access(&token, pdp)
                .await
                .map(|(_, principal)| {
                    let ambient_tenant = principal.tenant();
                    VerifiedPrincipal {
                        principal,
                        ambient_tenant,
                    }
                })
                .map_err(VerifyFailure::Authn)
        }
        ProfileBinding::ServiceToken(provider) => {
            let Some((tenant_binding, tenant)) = service_tenant else {
                return Err(VerifyFailure::ProfileMismatch);
            };
            let pdp = diport::DynPdp::from_ref(provider.as_ref());
            authn::verify_service_token(&token, tenant_binding, pdp)
                .await
                .map(|(_, principal)| VerifiedPrincipal {
                    principal,
                    ambient_tenant: Some(tenant),
                })
                .map_err(VerifyFailure::Authn)
        }
    }
}

enum MintEvidenceOutcome {
    Allowed {
        evidence: Authenticated,
        ctx: Option<runctx::AppCtx>,
        principal: Arc<authn::Principal>,
    },
    Rejected,
    ProviderUnavailable,
}

/// 验签 + 埋点 → 铸 [`Authenticated`] 证据，或返回拒绝/安全关键 provider 故障。
///
/// 各分支埋点拆独立 fn（每 fn 一条 `tracing` 宏；宏展开 cognitive-complexity 高，分摊保 ≤15）。
///
/// 埋点变体粒度（#1275，spec SC-006/FR-009）：`Some(Err)` 记 `AuthnError` 变体 + 闭值 `authz.deny_reason`。
/// `verify_jwt` 的 `From<PdpError>` 保真区分三种凭据拒绝与 provider outage；[`deny_reason`] 由此保留
/// 疑似攻击、配置错、过期和基础设施故障四类低基数信号。
/// 本桥不为日志粒度旁路 `verify_jwt` funnel（保「唯一信任原点」姿态）——`deny_reason` 只读已收敛的 `AuthnError`。
async fn mint_evidence(
    binding: &ProfileBinding,
    credential: httpserve::ExtractedBearerCredential,
) -> MintEvidenceOutcome {
    match verify_principal(binding, credential).await {
        Ok(verified) => {
            let Some((evidence, ctx, principal)) =
                allow_evidence(binding.required_scheme(), verified)
            else {
                return MintEvidenceOutcome::Rejected;
            };
            MintEvidenceOutcome::Allowed {
                evidence,
                ctx,
                principal,
            }
        }
        // err = AuthnError 变体（PdpError 经 verify_* 一一保真），脱敏；不产证据 ⇒ enforce fail-closed。
        Err(VerifyFailure::Authn(err)) => {
            log_deny_verify(&err);
            if matches!(err, authn::AuthnError::ProviderUnavailable) {
                MintEvidenceOutcome::ProviderUnavailable
            } else {
                MintEvidenceOutcome::Rejected
            }
        }
        Err(VerifyFailure::ProfileMismatch) => {
            log_deny_tenant_binding_invalid();
            MintEvidenceOutcome::Rejected
        }
    }
}

/// allow 分支：埋点（脱敏：仅 decision + principal.kind 枚举，无 subject/token）+ 铸 [`Authenticated`] 证据
/// + （scoped 主体）经 [`authn::app_ctx`] 派生 ambient [`runctx::AppCtx`]（#1105，ADR-002 §D5）。
///
/// `debug` 级（非 info）：成功鉴权是 per-request 热路径操作数据，非生命周期事件（observability.md 日志分级）。
///
/// 返回的 `Option<AppCtx>` 由 [`verify`] 经 `httpserve::PendingScopeCtx` 传给内层 enforce——**scope 不在桥
/// 建立**，由 enforce 在 `Require`-Allow 后绑定（#1105 F2：scope 与 route auth 决策对齐）。tenant 从 Principal
/// 自身派生（`app_ctx` 内部，#1105 F1）：scoped 主体（User/Device/Admin）⇒ `Some`；跨租户（Service/SuperAdmin，
/// `tenant=None`）⇒ `None`（无 ambient scope）。
fn allow_evidence(
    scheme: RequiredScheme,
    verified: VerifiedPrincipal,
) -> Option<(Authenticated, Option<runctx::AppCtx>, Arc<authn::Principal>)> {
    let principal = Arc::new(verified.principal);
    let kind = principal.kind();
    let tenant = verified.ambient_tenant;
    // `scoped_principal`（闭值 bool，非 PII）：有已认证 tenant source（JWT claim 或 service-token MAC header）
    // ⇒ 桥附 PendingScopeCtx、enforce 在 Require-Allow 后可建 ambient scope；无 tenant source ⇒ false。
    tracing::debug!(
        authz.decision = "allow",
        principal.kind = ?kind,
        scoped_principal = tenant.is_some(),
        "verify-bridge"
    );
    let evidence = match (principal.service_caller_domain(), tenant) {
        (Some(caller), Some(tenant)) => Authenticated::new_service(tenant, caller),
        (None, tenant) => Authenticated::new(scheme, kind, principal.audit_subject(), tenant),
        _ => return None,
    };
    let ctx = tenant.map(|tenant| {
        let facet: Arc<dyn runctx::PrincipalFacet> = principal.clone();
        runctx::RequestCtx::new(tenant, facet)
    });
    Some((evidence, ctx, principal))
}

/// mTLS allow 分支：只消费 httpd mTLS listener 在 TLS handshake 后注入的 [`authn::VerifiedMtlsPeer`]。
fn mtls_evidence(req: &Request) -> Option<Authenticated> {
    let peer = req.extensions().get::<authn::VerifiedMtlsPeer>()?;
    tracing::debug!(
        authz.decision = "allow",
        principal.kind = ?PrincipalKind::Service,
        scoped_principal = false,
        "verify-bridge-mtls"
    );
    Some(Authenticated::new(
        RequiredScheme::Mtls,
        PrincipalKind::Service,
        peer.spiffe_id().as_str(),
        None,
    ))
}

/// 验签失败 deny 埋点（`AuthnError` 变体 + 闭值 `authz.deny_reason`，脱敏）。
fn log_deny_verify(err: &authn::AuthnError) {
    tracing::warn!(
        authz.decision = "deny",
        authz.deny_reason = deny_reason(err),
        error = ?err,
        "verify-bridge"
    );
}

// deny 告警分级闭值集（observability.md「告警 / metrics label 闭值集」：低基数、无 PII）——bridge deny 路
// `authz.deny_reason` 仅取此 8 值（#1275，spec SC-006/FR-009）：
//   `SIGNATURE_INVALID` ← `TokenInvalid` = verifier 报告的**凭据签名/MAC/结构失败**（疑似攻击）；
//   `UNTRUSTED`         ← `TokenUntrusted` = iss/aud/key-path 不受信（疑似配置错）；
//   `EXPIRED`           ← `TokenExpired` = 时间窗越界；
//   `PRINCIPAL_INVALID` ← `PrincipalInvalid` = **验签通过后**的 claims/principal 派生失败（良性，#1275 review
//                          F1：与签名失败分开，杜绝把良性失败误报成 `signature_invalid` 攻击信号）；
//   `PROVIDER_UNAVAILABLE` ← replay store 等安全关键 provider 暂不可用（503，可重试）；
//   `TENANT_BINDING_INVALID` ← service-token tenant binding 缺失 / 非法；
//   `MTLS_PEER_MISSING`      ← mTLS listener 缺 transport 层已验证 peer evidence；
//   `INVALID`           ← `#[non_exhaustive]` 未来 / 本桥不可达变体（`Forbidden`）fail-safe 兜底。
pub(crate) const DENY_REASON_SIGNATURE_INVALID: &str = "signature_invalid";
pub(crate) const DENY_REASON_UNTRUSTED: &str = "untrusted";
pub(crate) const DENY_REASON_EXPIRED: &str = "expired";
pub(crate) const DENY_REASON_PRINCIPAL_INVALID: &str = "principal_invalid";
pub(crate) const DENY_REASON_PROVIDER_UNAVAILABLE: &str = "provider_unavailable";
pub(crate) const DENY_REASON_TENANT_BINDING_INVALID: &str = "tenant_binding_invalid";
pub(crate) const DENY_REASON_MTLS_PEER_MISSING: &str = "mtls_peer_missing";
pub(crate) const DENY_REASON_INVALID: &str = "invalid";

/// `AuthnError` 变体 → deny 告警分级闭值标签（无 PII；闭值集见上 `DENY_REASON_*`）。
fn deny_reason(err: &authn::AuthnError) -> &'static str {
    match err {
        authn::AuthnError::TokenInvalid => DENY_REASON_SIGNATURE_INVALID,
        authn::AuthnError::TokenUntrusted => DENY_REASON_UNTRUSTED,
        authn::AuthnError::TokenExpired => DENY_REASON_EXPIRED,
        authn::AuthnError::PrincipalInvalid => DENY_REASON_PRINCIPAL_INVALID,
        authn::AuthnError::ProviderUnavailable => DENY_REASON_PROVIDER_UNAVAILABLE,
        _ => DENY_REASON_INVALID,
    }
}

/// service-token tenant binding header 解析失败 deny 埋点（与签名 / MAC 失败分流）。
fn log_deny_tenant_binding_invalid() {
    tracing::warn!(
        authz.decision = "deny",
        authz.deny_reason = DENY_REASON_TENANT_BINDING_INVALID,
        "verify-bridge"
    );
}

fn log_service_boundary_invalid(req: &Request, span_name: &'static str) {
    let request_id = httpserve::request_id_str(req.extensions())
        .unwrap_or_default()
        .to_owned();
    let span = tracing::debug_span!(
        "verify_bridge_boundary",
        bridge = span_name,
        scheme = ?RequiredScheme::ServiceToken,
        request_id = %request_id
    );
    let _entered = span.enter();
    log_deny_tenant_binding_invalid();
}

/// Token-profile 验签桥：铸证据 + 埋点 + 透传（不自发裁决，见模块 doc）。
///
/// allow/deny 事件落在 `verify_bridge` span 内（携 `scheme` + `request_id` 上下文，spec FR-009「tracing
/// span」）。request_id 关联已落地（#1320）：`request_id` 中间件经唯一 bindable 出口封在本桥**外层**
/// （ROUTE-REQUESTID-OUTERMOST-01），本桥运行时 RequestId 已就位 ⇒ 经 `httpserve::request_id_str` 读入
/// span（不带凭据请求 request_id 为空——span 仅在有 bearer token 时建，无埋点需求）。
// reason: this is the single request middleware junction for mTLS evidence, bearer extraction,
// verifier result mapping, and audit logging; splitting would obscure request-order semantics.
#[allow(clippy::cognitive_complexity)]
async fn verify(State(binding): State<ProfileBinding>, mut req: Request, next: Next) -> Response {
    match httpserve::extract_bearer_credential(req.headers(), binding.profile()) {
        Ok(Some(credential)) => {
            let request_id = httpserve::request_id_str(req.extensions())
                .unwrap_or_default()
                .to_owned();
            let scheme = binding.required_scheme();
            let span =
                tracing::debug_span!("verify_bridge", scheme = ?scheme, request_id = %request_id);
            match mint_evidence(&binding, credential).instrument(span).await {
                MintEvidenceOutcome::Allowed {
                    evidence,
                    ctx,
                    principal,
                } => {
                    req.extensions_mut().insert(evidence);
                    req.extensions_mut().insert(principal);
                    // **scope 不在桥建立**：把 scoped 主体的 AppCtx 经 `PendingScopeCtx` extension 传给内层 enforce，
                    // 由其在 `Require`-Allow（认证路由放行，非 Public opt-out）后建 `runctx::scope`——使 ambient scope
                    // 与 route auth 决策对齐（#1105 F2，验签桥在 enforce 外层、运行期读不到 opt_out）。跨租户主体
                    // ctx=None ⇒ 不附 ⇒ 下游 `try_current()` fail-closed `MissingCtx`。
                    if let Some(ctx) = ctx {
                        req.extensions_mut()
                            .insert(httpserve::PendingScopeCtx::new(ctx));
                    }
                }
                MintEvidenceOutcome::Rejected => {}
                MintEvidenceOutcome::ProviderUnavailable => {
                    return httpserve::error::service_unavailable(&request_id);
                }
            }
        }
        Ok(None) => {}
        Err(_) => {
            if binding.profile() == diport::TokenProfile::ServiceToken {
                log_service_boundary_invalid(&req, "production");
            }
            return httpserve::error::unauthenticated(
                httpserve::request_id_str(req.extensions()).unwrap_or_default(),
            );
        }
    }
    next.run(req).await
}

#[cfg(feature = "integration")]
async fn mint_test_evidence(
    binding: &TestProfileBinding,
    credential: httpserve::ExtractedBearerCredential,
) -> MintEvidenceOutcome {
    let (profile, token, service_tenant) = credential.into_parts();
    if profile != binding.profile() {
        return MintEvidenceOutcome::Rejected;
    }
    let verified = match binding {
        TestProfileBinding::RssAccess(provider) => authn::verify_rss_access(&token, provider)
            .await
            .map(|(_, principal)| VerifiedPrincipal {
                ambient_tenant: principal.tenant(),
                principal,
            }),
        TestProfileBinding::ServiceToken(provider) => {
            let Some((tenant_binding, tenant)) = service_tenant else {
                return MintEvidenceOutcome::Rejected;
            };
            authn::verify_service_token(&token, tenant_binding, provider)
                .await
                .map(|(_, principal)| VerifiedPrincipal {
                    principal,
                    ambient_tenant: Some(tenant),
                })
        }
    };
    match verified {
        Ok(verified) => {
            let Some((evidence, ctx, principal)) =
                allow_evidence(binding.required_scheme(), verified)
            else {
                return MintEvidenceOutcome::Rejected;
            };
            MintEvidenceOutcome::Allowed {
                evidence,
                ctx,
                principal,
            }
        }
        Err(err) => {
            log_deny_verify(&err);
            if matches!(err, authn::AuthnError::ProviderUnavailable) {
                MintEvidenceOutcome::ProviderUnavailable
            } else {
                MintEvidenceOutcome::Rejected
            }
        }
    }
}

#[cfg(feature = "integration")]
async fn verify_test_profile(
    State(binding): State<TestProfileBinding>,
    mut req: Request,
    next: Next,
) -> Response {
    match httpserve::extract_bearer_credential(req.headers(), binding.profile()) {
        Ok(Some(credential)) => {
            let request_id = httpserve::request_id_str(req.extensions())
                .unwrap_or_default()
                .to_owned();
            let scheme = binding.required_scheme();
            let span = tracing::debug_span!("verify_bridge_test", scheme = ?scheme, request_id = %request_id);
            match mint_test_evidence(&binding, credential)
                .instrument(span)
                .await
            {
                MintEvidenceOutcome::Allowed {
                    evidence,
                    ctx,
                    principal,
                } => {
                    req.extensions_mut().insert(evidence);
                    req.extensions_mut().insert(principal);
                    if let Some(ctx) = ctx {
                        req.extensions_mut()
                            .insert(httpserve::PendingScopeCtx::new(ctx));
                    }
                }
                MintEvidenceOutcome::Rejected => {}
                MintEvidenceOutcome::ProviderUnavailable => {
                    return httpserve::error::service_unavailable(&request_id);
                }
            }
        }
        Ok(None) => {}
        Err(_) => {
            if binding.profile() == diport::TokenProfile::ServiceToken {
                log_service_boundary_invalid(&req, "integration");
            }
            return httpserve::error::unauthenticated(
                httpserve::request_id_str(req.extensions()).unwrap_or_default(),
            );
        }
    }
    next.run(req).await
}

/// mTLS evidence bridge. Transport verification and token verification remain disjoint states.
async fn verify_mtls(mut req: Request, next: Next) -> Response {
    if let Some(evidence) = mtls_evidence(&req) {
        req.extensions_mut().insert(evidence);
    } else {
        tracing::warn!(
            authz.decision = "deny",
            authz.deny_reason = DENY_REASON_MTLS_PEER_MISSING,
            "verify-bridge-mtls"
        );
    }
    next.run(req).await
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{
        DENY_REASON_EXPIRED, DENY_REASON_INVALID, DENY_REASON_MTLS_PEER_MISSING,
        DENY_REASON_PRINCIPAL_INVALID, DENY_REASON_PROVIDER_UNAVAILABLE,
        DENY_REASON_SIGNATURE_INVALID, DENY_REASON_TENANT_BINDING_INVALID, DENY_REASON_UNTRUSTED,
        deny_reason, mtls_evidence,
    };
    use axum::body::Body;
    use axum::http::Request;
    use primitives::RequiredScheme;
    use vocab::PrincipalKind;

    /// `deny_reason` 闭值映射全臂覆盖（含 `_` 兜底）：五路一一保真（含 `PrincipalInvalid`→`principal_invalid`，
    /// #1275 review F1：验签后良性失败不记 `signature_invalid`）+ 本桥不可达的 `Forbidden`
    ///（非 verify funnel 产）fail-safe 落 `INVALID`。各路**端到端**可区分性见 auth_e2e.rs
    /// `tracing_deny_logs_per_variant_reason_no_pii`（断言用 literal 钉死可观测告警 label 契约）。
    #[test]
    fn deny_reason_maps_every_variant_to_closed_value() {
        assert_eq!(
            deny_reason(&authn::AuthnError::TokenInvalid),
            DENY_REASON_SIGNATURE_INVALID
        );
        assert_eq!(
            deny_reason(&authn::AuthnError::TokenUntrusted),
            DENY_REASON_UNTRUSTED
        );
        assert_eq!(
            deny_reason(&authn::AuthnError::TokenExpired),
            DENY_REASON_EXPIRED
        );
        assert_eq!(
            deny_reason(&authn::AuthnError::PrincipalInvalid),
            DENY_REASON_PRINCIPAL_INVALID,
            "验签后良性派生失败 → principal_invalid（非 signature_invalid）"
        );
        assert_eq!(
            deny_reason(&authn::AuthnError::ProviderUnavailable),
            DENY_REASON_PROVIDER_UNAVAILABLE
        );
        assert_eq!(
            deny_reason(&authn::AuthnError::Forbidden),
            DENY_REASON_INVALID,
            "本桥不可达变体 fail-safe 落 INVALID"
        );
    }

    #[test]
    fn deny_reason_labels_are_closed_and_unique() {
        let labels = [
            DENY_REASON_SIGNATURE_INVALID,
            DENY_REASON_UNTRUSTED,
            DENY_REASON_EXPIRED,
            DENY_REASON_PRINCIPAL_INVALID,
            DENY_REASON_PROVIDER_UNAVAILABLE,
            DENY_REASON_TENANT_BINDING_INVALID,
            DENY_REASON_MTLS_PEER_MISSING,
            DENY_REASON_INVALID,
        ];

        for (index, label) in labels.iter().enumerate() {
            assert!(!label.is_empty());
            assert!(
                !labels[..index].contains(label),
                "deny reason label must be unique: {label}"
            );
        }
    }

    #[test]
    fn mtls_evidence_maps_verified_peer_to_service_principal() {
        let allow = authn::MtlsAllowSet::new(["spiffe://example.org/ns/rss/sa/internal"])
            .expect("allow set");
        let peer_id =
            authn::SpiffeId::parse("spiffe://example.org/ns/rss/sa/internal").expect("spiffe id");
        let peer = authn::verify_mtls_peer(peer_id, &allow).expect("verified peer");
        let mut req = Request::new(Body::empty());
        req.extensions_mut().insert(peer);

        let evidence = mtls_evidence(&req).expect("mTLS evidence");
        assert_eq!(evidence.scheme(), RequiredScheme::Mtls);
        assert_eq!(evidence.principal_kind(), PrincipalKind::Service);
        assert_eq!(
            evidence.self_scoped_principal_id(),
            "spiffe://example.org/ns/rss/sa/internal"
        );
        assert_eq!(evidence.tenant_id(), None);
    }
}
