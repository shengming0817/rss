//! 验签桥（verify-bridge）—— 组合根唯一 [`httpserve::Authenticated`] 证据构造点。
//!
//! 落地 `authn/src/lib.rs` `NOTE(#1109)` 承诺：组合根在 `finalize_auth` 返回 router **外层** `.layer()`
//! 本桥；请求带凭据时经 `authn::verify_jwt` / `verify_service_token`（注入验签 provider）验签，成功则据**验签
//! 产物 Principal** 的脱敏标量构造 [`httpserve::Authenticated`] 证据注入请求 extension，enforce 层据此对
//! 匹配 `Require(scheme)` 的路由放行（AUTH-EVIDENCE-REQUIRE-01）。
//!
//! 设计要点：
//! - **本桥不自发裁决**：仅「铸证据 + 埋点」，绝不短路 401/403。无证据时透传，由内层 enforce 作**唯一**鉴权
//!   裁决方（Public opt-out 路由放行、Require 路由 fail-closed 401）。理由：① enforce 的 `request_id` 中间件
//!   在本桥**内层**，本桥自发响应拿不到 requestId → envelope 残缺；② 单一裁决方杜绝双判定点；③ 可观测结果
//!   等价（Require + 坏凭据仍 401，由 enforce 发）；④ 本桥是 blanket 外层、包住含 Public 路由的整个 listener，
//!   不短路即不误伤 Public。
//! - **凭据方案按 listener 静态绑定**（runtime-api.md「单 listener 单 scheme」）：本桥在 finalize_auth 外层，
//!   `AuthPlan` extension 是内层、本桥运行时尚不可读，故由组合根按 listener 注入对应 [`RequiredScheme`]。
//! - **Send 安全**：`verify_jwt(&DynPdp)` 的 future 为 `!Send`（`DynPdp` 非 `Sync`，DIPORT-ASYNC-ARC-SEND-01）。
//!   `OidcProvider::verify` 纯 CPU 无真 await ⇒ future 首 poll 即 ready，经 `now_or_never()` 同步驱动至完成、
//!   不跨本桥自身 `.await`，故中间件 future 保持 `Send`（生产多线程 `serve` 必需）。`None`（理论上 verify 未
//!   同步完成，CPU-only 前提下不可达）按 fail-closed 处理（不注证据、记 deny），不 panic。
//! - **无 PII 埋点**：成功记 `authz.decision=allow` + `principal.kind`（[`vocab::PrincipalKind`] 脱敏枚举）；
//!   失败记 `authz.decision=deny` + 闭值 `authz.deny_reason`（三路告警分级，见 [`deny_reason`]）+ `AuthnError`
//!   变体；**绝不**记 token / subject / claims。
//!
//! `Authenticated::new` callsite 由 `rss_authenticated_callsite` dylint 限组合根（`server`/`rss` 在 allowlist）。
//!
//! ref: tower-rs/tower-http tower-http/src/auth/async_require_authorization.rs@main
//!   （`AsyncAuthorizeRequest::authorize` → `request.extensions_mut().insert(principal)` 后透传 next 的范式）。
//!   偏离：授权决策（放行/拒）下沉到内层 enforce（单一裁决方），本桥只铸证据 + 埋点。

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use futures::FutureExt;
use httpserve::{Authenticated, AuthenticatedRoutes};
use oidc::OidcProvider;
use primitives::RequiredScheme;

/// 验签桥中间件 state：共享验签 provider（多次调用 ⇒ 泛型静态分发的 `Arc<S>` 范式，ADR-003 §注入形态收口；
/// `OidcProvider` 是 `Send + Sync`）+ 本 listener 绑定的已验证方案。
#[derive(Clone)]
struct VerifyState {
    provider: Arc<OidcProvider>,
    scheme: RequiredScheme,
}

/// 在 `finalize_auth` 产出的 [`AuthenticatedRoutes`] **外层**叠验签桥（经 `AuthenticatedRoutes::layer` 只能加层、
/// 不能替换，funnel 封印不破）。组合根按 listener 的已验证 [`RequiredScheme`] 调用。
pub fn apply_verify_bridge(
    routes: AuthenticatedRoutes,
    provider: Arc<OidcProvider>,
    scheme: RequiredScheme,
) -> AuthenticatedRoutes {
    routes.layer(middleware::from_fn_with_state(
        VerifyState { provider, scheme },
        verify,
    ))
}

/// 提取 `Authorization: Bearer <token>` 的裸 token（owned，便于先释放 header 借用再可变借 req）。
///
/// scheme 名大小写不敏感（RFC 7235 §2.1 / RFC 6750）：`Bearer`/`bearer`/`BEARER`/`bEaReR` 均接受（评审 F7）。
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// 同步驱动验签产物 → `Principal`（按 listener scheme 选 jwt / service-token funnel）。
///
/// `OidcProvider::verify` 纯 CPU、future 恒首 poll ready ⇒ `now_or_never()` 恒 `Some`；`None`/`Some(Err)` 均
/// 不产证据（fail-closed）。`provider` 经 `DynPdp::from_ref` 借为 `&DynPdp` 喂 authn funnel（信任原点单源）。
fn verify_principal(
    provider: &OidcProvider,
    scheme: RequiredScheme,
    token: &str,
) -> Option<Result<authn::Principal, authn::AuthnError>> {
    let pdp = diport::DynPdp::from_ref(provider);
    match scheme {
        RequiredScheme::Jwt => authn::verify_jwt(token, pdp)
            .now_or_never()
            .map(|r| r.map(|(_, principal)| principal)),
        RequiredScheme::ServiceToken => authn::verify_service_token(token, pdp)
            .now_or_never()
            .map(|r| r.map(|(_, principal)| principal)),
        // 本桥仅承载 jwt / service-token 验签；其余方案（Mtls / JwtFromAssembly）不产证据 ⇒ enforce fail-closed。
        // reason: Mtls 走传输层、JwtFromAssembly 留后续；二者非本桥职责，无证据 = Require 路由 401（fail-closed）。
        _ => None,
    }
}

/// 验签 + 埋点 → 铸 [`Authenticated`] 证据（成功）或 `None`（无凭据 / 验签失败 / 未同步完成 = 均 fail-closed）。
///
/// 各分支埋点拆独立 fn（每 fn 一条 `tracing` 宏；宏展开 cognitive-complexity 高，分摊保 ≤15）。
///
/// 埋点变体粒度（#1275，spec SC-006/FR-009）：`Some(Err)` 记 `AuthnError` 变体 + 闭值 `authz.deny_reason`。
/// `verify_jwt` 的 `From<PdpError>` 三变体一一保真（`InvalidSignature`→`TokenInvalid`、`Untrusted`→`TokenUntrusted`、
/// `Expired`→`TokenExpired`），故 [`deny_reason`] 据变体记**三路**告警分级（区分疑似攻击 vs 疑似配置错 vs 过期）。
/// 本桥不为日志粒度旁路 `verify_jwt` funnel（保「唯一信任原点」姿态）——`deny_reason` 只读已收敛的 `AuthnError`。
fn mint_evidence(state: &VerifyState, token: &str) -> Option<Authenticated> {
    match verify_principal(&state.provider, state.scheme, token) {
        Some(Ok(principal)) => Some(log_allow(state.scheme, &principal)),
        // err = AuthnError 变体（PdpError 经 verify_* 一一保真，三路），脱敏；不产证据 ⇒ enforce fail-closed。
        Some(Err(err)) => {
            log_deny_verify(&err);
            None
        }
        // COVERAGE/不变式：`OidcProvider::verify` 纯 CPU 无真 await ⇒ future 首 poll 恒 ready ⇒ `now_or_never`
        // 恒 `Some`，本臂结构上不可达（无注入口构造 Pending Pdp，不为覆盖此防御臂 generic 化签名）。防御式
        // fail-closed（不产证据），不 panic。若 #1197 让 verify 变真 async，`valid_jwt_is_200` e2e 会 401 而 FAIL
        // （响亮的 tripwire，非静默故障）——届时 bridge 须随 #1197 改造。
        None => {
            log_deny_not_synchronous();
            None
        }
    }
}

/// allow 分支埋点（脱敏：仅 decision + principal.kind 枚举，无 subject/token）。
///
/// `debug` 级（非 info）：成功鉴权是 per-request 热路径操作数据，非生命周期事件（observability.md 日志分级）。
fn log_allow(scheme: RequiredScheme, principal: &authn::Principal) -> Authenticated {
    let kind = principal.kind();
    tracing::debug!(authz.decision = "allow", principal.kind = ?kind, "verify-bridge");
    Authenticated::new(scheme, kind)
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
// `authz.deny_reason` 仅取此 6 值，与 `AuthnError` deny 变体一一对应（#1275，spec SC-006/FR-009）：
//   `SIGNATURE_INVALID` ← `TokenInvalid` = verifier 报告的**凭据签名/MAC/结构失败**（疑似攻击）；
//   `UNTRUSTED`         ← `TokenUntrusted` = iss/aud/key-path 不受信（疑似配置错）；
//   `EXPIRED`           ← `TokenExpired` = 时间窗越界；
//   `PRINCIPAL_INVALID` ← `PrincipalInvalid` = **验签通过后**的 claims/principal 派生失败（良性，#1275 review
//                          F1：与签名失败分开，杜绝把良性失败误报成 `signature_invalid` 攻击信号）；
//   `INVALID`           ← `#[non_exhaustive]` 未来 / 本桥不可达变体（`SessionNotFound` / `Forbidden`）fail-safe 兜底；
//   `NOT_SYNCHRONOUS`   ← verify future 未同步完成的防御式 deny（CPU-only 前提下不可达）。
pub(crate) const DENY_REASON_SIGNATURE_INVALID: &str = "signature_invalid";
pub(crate) const DENY_REASON_UNTRUSTED: &str = "untrusted";
pub(crate) const DENY_REASON_EXPIRED: &str = "expired";
pub(crate) const DENY_REASON_PRINCIPAL_INVALID: &str = "principal_invalid";
pub(crate) const DENY_REASON_INVALID: &str = "invalid";
pub(crate) const DENY_REASON_NOT_SYNCHRONOUS: &str = "not_synchronous";

/// `AuthnError` 变体 → deny 告警分级闭值标签（无 PII；闭值集见上 `DENY_REASON_*`）。
fn deny_reason(err: &authn::AuthnError) -> &'static str {
    match err {
        authn::AuthnError::TokenInvalid => DENY_REASON_SIGNATURE_INVALID,
        authn::AuthnError::TokenUntrusted => DENY_REASON_UNTRUSTED,
        authn::AuthnError::TokenExpired => DENY_REASON_EXPIRED,
        authn::AuthnError::PrincipalInvalid => DENY_REASON_PRINCIPAL_INVALID,
        _ => DENY_REASON_INVALID,
    }
}

/// future 未同步完成 deny 埋点（CPU-only 前提下不可达）。
fn log_deny_not_synchronous() {
    tracing::warn!(
        authz.decision = "deny",
        authz.deny_reason = DENY_REASON_NOT_SYNCHRONOUS,
        "verify-bridge"
    );
}

/// 验签桥中间件：铸证据 + 埋点 + 透传（不自发裁决，见模块 doc）。
///
/// allow/deny 事件落在 `verify_bridge` span 内（携 `scheme` 上下文，spec FR-009「tracing span」）。
/// request_id 关联待 #1017 将 request_id 中间件移至本桥外层（当前本桥在 finalize_auth 外、request_id 内层，
/// 运行时无 RequestId 可读）。
async fn verify(State(state): State<VerifyState>, mut req: Request, next: Next) -> Response {
    if let Some(token) = bearer_token(req.headers()) {
        let span = tracing::debug_span!("verify_bridge", scheme = ?state.scheme);
        if let Some(evidence) = span.in_scope(|| mint_evidence(&state, &token)) {
            req.extensions_mut().insert(evidence);
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::{
        DENY_REASON_EXPIRED, DENY_REASON_INVALID, DENY_REASON_PRINCIPAL_INVALID,
        DENY_REASON_SIGNATURE_INVALID, DENY_REASON_UNTRUSTED, deny_reason,
    };

    /// `deny_reason` 闭值映射全臂覆盖（含 `_` 兜底）：四路一一保真（含 `PrincipalInvalid`→`principal_invalid`，
    /// #1275 review F1：验签后良性失败不记 `signature_invalid`）+ 本桥不可达的 `SessionNotFound` / `Forbidden`
    /// （非 verify funnel 产）fail-safe 落 `INVALID`。四路**端到端**可区分性见 auth_e2e.rs
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
            deny_reason(&authn::AuthnError::SessionNotFound),
            DENY_REASON_INVALID,
            "本桥不可达变体 fail-safe 落 INVALID"
        );
        assert_eq!(
            deny_reason(&authn::AuthnError::Forbidden),
            DENY_REASON_INVALID
        );
    }
}
