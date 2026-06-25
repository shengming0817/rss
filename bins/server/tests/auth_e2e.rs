//! 验签桥 e2e（ADR-006 §8 ③）：真 `OidcProvider`（静态 key）+ 组合根 `apply_verify_bridge` +
//! `httpserve::finalize_auth` + enforce，经 `tower::oneshot` 驱动已组装 router（不真实绑端口；serve = #1017）。
//!
//! 覆盖：有效 JWT→200+证据放行；无 token/坏签名/过期/错 aud/错 iss/alg:none/跨 scheme→401（拒绝路径全覆盖）；
//! **无 bridge 回归**（T001/T002 单独 merge 态：即便有效 JWT，Require 仍 401）；unsupported scheme(Mtls) fail-closed；
//! Public 路由不被 bridge 误伤；小写 bearer 前缀放行；service-token/HS256 happy；tracing 埋点 `authz.decision`+
//! `principal.kind`、无 subject/token 泄漏。
//!
//! 本批不断言 handler 读完整 `Principal`（属 W，评审 F3）——只断言证据注入放行（200）。
//!
//! NOTE: 与姊妹 bin（server/rss）的同名文件内容同步（仅 crate 名 / use 路径不同，tasks.md T004.2）。

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, StatusCode, header};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use futures::FutureExt as _;
use oidc::OidcProvider;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use primitives::{AuthPlan, AuthScheme, ListenerKind, RequiredScheme, RouteAuthOptOut};
use server::auth_bridge::apply_verify_bridge;
use server::provider_from_b64;
use tower::ServiceExt as _;

/// 合法测试租户（`user` kind 需 tenant；canonical UUID）。
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

const ISS: &str = "https://issuer.test";
const AUD: &str = "rss-test";
const NOW: i64 = 1_700_000_000;

// ── 注入时钟替身（确定性 exp 边界，非系统时钟） ───────────────────────────────────
struct FixedClock(i64);
impl diport::Clock for FixedClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0 as u64)
    }
}

// ── 测试 key + JWT 铸造（dev-only） ──────────────────────────────────────────────
#[allow(clippy::expect_used)]
fn sk_jwt() -> SigningKey {
    let bytes: [u8; 32] = std::array::from_fn(|i| (i + 1) as u8);
    SigningKey::from_slice(&bytes).expect("valid P-256 scalar")
}
#[allow(clippy::expect_used)]
fn sk_other() -> SigningKey {
    let bytes: [u8; 32] = std::array::from_fn(|i| (i + 100) as u8);
    SigningKey::from_slice(&bytes).expect("valid P-256 scalar")
}
fn sec1(sk: &SigningKey) -> Vec<u8> {
    sk.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}
fn mint_es256(sk: &SigningKey, payload: &str) -> String {
    let header = B64.encode(br#"{"alg":"ES256"}"#);
    let body = B64.encode(payload.as_bytes());
    let signing_input = format!("{header}.{body}");
    let sig: Signature = sk.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64.encode(sig.to_bytes()))
}
#[allow(clippy::expect_used)]
fn mint_hs256(secret: &[u8], payload: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let header = B64.encode(br#"{"alg":"HS256"}"#);
    let body = B64.encode(payload.as_bytes());
    let signing_input = format!("{header}.{body}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        B64.encode(mac.finalize().into_bytes())
    )
}
/// `alg:none` 攻击 token（空签名段）——验签器须按 alg 白名单拒。
fn mint_alg_none(payload: &str) -> String {
    format!(
        "{}.{}.",
        B64.encode(br#"{"alg":"none"}"#),
        B64.encode(payload.as_bytes())
    )
}
/// superAdmin JWT payload（无需 tenant claim；trust_kind("superAdmin") 时 kind 透传）。
fn super_admin_payload(exp: i64, iss: &str, aud: &str) -> String {
    format!(r#"{{"sub":"alice","exp":{exp},"iss":"{iss}","aud":"{aud}","kind":"superAdmin"}}"#)
}
fn super_admin_jwt(sk: &SigningKey, exp: i64, iss: &str, aud: &str) -> String {
    mint_es256(sk, &super_admin_payload(exp, iss, aud))
}
/// `user` kind JWT（需 tenant claim；默认 claim 名 `tenant_id`）。
fn user_jwt(sk: &SigningKey, exp: i64, iss: &str, aud: &str) -> String {
    mint_es256(
        sk,
        &format!(
            r#"{{"sub":"alice","exp":{exp},"iss":"{iss}","aud":"{aud}","kind":"user","tenant_id":"{TENANT}"}}"#
        ),
    )
}

// ── provider 构造：经**生产装配路径** `server::provider_from_b64`（真 RustCrypto 验签 + FixedClock）─────
// 评审 F2：e2e 复用生产 builder（含 trusted-kind 注入），杜绝测试/生产配置漂移——若 F1 的 trusted-kind
// 接线缺失，下方任一 JWT 验收会 401 FAIL（生产失效响亮暴露，非静默）。
#[allow(clippy::expect_used)]
fn es256_provider() -> OidcProvider {
    let es256_b64 = B64.encode(sec1(&sk_jwt()));
    // trust superAdmin（无 tenant 路径）+ user（带 tenant 路径），覆盖两类 JWT。
    provider_from_b64(
        ISS,
        AUD,
        "superAdmin,user",
        Some(&es256_b64),
        None,
        Box::new(FixedClock(NOW)),
    )
    .expect("es256 production provider")
}
#[allow(clippy::expect_used)]
fn hs256_provider() -> (OidcProvider, Vec<u8>) {
    let secret = vec![9u8; 32];
    let hs_b64 = B64.encode(&secret);
    // service-token 忽略 kind，trusted-kinds 仅为满足 builder ≥1 约束。
    let provider = provider_from_b64(
        ISS,
        AUD,
        "user",
        None,
        Some(&hs_b64),
        Box::new(FixedClock(NOW)),
    )
    .expect("hs256 production provider");
    (provider, secret)
}

// ── router 装配（Primary/Jwt：Require /protected + Public /public） ────────────────
/// `bridge = None` ⇒ 不挂验签桥（回归用例）；`Some(scheme)` ⇒ 挂 es256_provider 桥（用 `scheme` 验证）。
#[allow(clippy::expect_used)]
fn jwt_router(bridge: Option<RequiredScheme>) -> httpserve::AuthenticatedRoutes {
    // typed Primary builder（`ListenerRouter::new` 是 pub(crate)，外部测试经 `unfinalized_for_test` 构造 funnel 输入）。
    let routes = httpserve::routes::unfinalized_for_test::<httpserve::Primary>(|rb| {
        rb.mount_primary(
            httpserve::PrimaryRoute {
                method: Method::GET,
                path: "/protected",
                contract_id: "test.protected",
                opt_out: None,
            },
            get(|| async { "ok" }),
        )
        .mount_primary(
            httpserve::PrimaryRoute {
                method: Method::GET,
                path: "/public",
                contract_id: "test.public",
                opt_out: Some(RouteAuthOptOut::Public),
            },
            get(|| async { "pub" }),
        )
    });
    let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).expect("plan");
    let authed = httpserve::finalize_auth(routes, plan).expect("finalize_auth");
    match bridge {
        Some(scheme) => apply_verify_bridge(authed, Arc::new(es256_provider()), scheme),
        None => authed,
    }
}

#[allow(clippy::unwrap_used)]
async fn status(
    app: httpserve::AuthenticatedRoutes,
    uri: &str,
    bearer: Option<&str>,
) -> StatusCode {
    let mut builder = axum::http::Request::builder().method(Method::GET).uri(uri);
    if let Some(value) = bearer {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    // 取回裸 Router 做 oneshot（`#[doc(hidden)]` 测试入口；生产经 into_make_service bind，无此出口）。
    let resp = app
        .into_router_for_test()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    resp.status()
}

// ── 验收：成功路径 ────────────────────────────────────────────────────────────────
#[tokio::test]
async fn valid_jwt_is_200() {
    let token = super_admin_jwt(&sk_jwt(), NOW + 3600, ISS, AUD);
    assert_eq!(
        status(
            jwt_router(Some(RequiredScheme::Jwt)),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::OK,
        "有效 JWT → 证据注入放行 200"
    );
}

#[tokio::test]
async fn user_jwt_with_tenant_via_production_builder_is_200() {
    // 评审 F2：经生产 builder（trusted-kind 注入）+ user kind + tenant → 200。若 F1 trusted-kind 缺失则 401 FAIL。
    let token = user_jwt(&sk_jwt(), NOW + 3600, ISS, AUD);
    assert_eq!(
        status(
            jwt_router(Some(RequiredScheme::Jwt)),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::OK,
        "user kind + tenant 经生产装配路径 → 200"
    );
}

#[tokio::test]
async fn lowercase_bearer_scheme_is_200() {
    // RFC 6750 §2.1：scheme 名大小写不敏感；bridge 接受 "bearer " 小写前缀。
    let token = super_admin_jwt(&sk_jwt(), NOW + 3600, ISS, AUD);
    assert_eq!(
        status(
            jwt_router(Some(RequiredScheme::Jwt)),
            "/protected",
            Some(&format!("bearer {token}"))
        )
        .await,
        StatusCode::OK,
        "小写 bearer 前缀仍放行"
    );
}

#[tokio::test]
async fn uppercase_bearer_scheme_is_200() {
    // 评审 F7：scheme 大小写不敏感——大写 BEARER 仍放行。
    let token = super_admin_jwt(&sk_jwt(), NOW + 3600, ISS, AUD);
    assert_eq!(
        status(
            jwt_router(Some(RequiredScheme::Jwt)),
            "/protected",
            Some(&format!("BEARER {token}"))
        )
        .await,
        StatusCode::OK,
        "大写 BEARER 前缀仍放行"
    );
}

/// 评审 F3 tripwire：bridge 依赖 `OidcProvider::verify` 纯 CPU、future 首 poll 即 ready（`now_or_never` 恒 `Some`）。
/// 若 #1197 让 verify 变真 async（live JWKS fetch），此断言 FAIL = 响亮提醒须随 #1197 改造 bridge（非静默全 401）。
#[tokio::test]
#[allow(clippy::expect_used)]
async fn verify_jwt_is_synchronous_now_or_never_tripwire() {
    let provider = es256_provider();
    let pdp = diport::DynPdp::from_ref(&provider);
    let token = super_admin_jwt(&sk_jwt(), NOW + 3600, ISS, AUD);
    assert!(
        authn::verify_jwt(&token, pdp).now_or_never().is_some(),
        "verify_jwt future 须首 poll 即 ready（CPU-only verify 契约；#1197 真 async 化将破此约 → 须改 bridge）"
    );
}

// ── 验收：拒绝路径全覆盖（均 401，由内层 enforce fail-closed 发出） ─────────────────
#[tokio::test]
async fn no_token_require_is_401() {
    assert_eq!(
        status(jwt_router(Some(RequiredScheme::Jwt)), "/protected", None).await,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn bad_signature_is_401() {
    // 用不在 provider 信任集的 key 签 → InvalidSignature → 无证据 → enforce 401。
    let token = super_admin_jwt(&sk_other(), NOW + 3600, ISS, AUD);
    assert_eq!(
        status(
            jwt_router(Some(RequiredScheme::Jwt)),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn expired_is_401() {
    let token = super_admin_jwt(&sk_jwt(), NOW - 3600, ISS, AUD);
    assert_eq!(
        status(
            jwt_router(Some(RequiredScheme::Jwt)),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn wrong_audience_is_401() {
    let token = super_admin_jwt(&sk_jwt(), NOW + 3600, ISS, "wrong-aud");
    assert_eq!(
        status(
            jwt_router(Some(RequiredScheme::Jwt)),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn wrong_issuer_is_401() {
    let token = super_admin_jwt(&sk_jwt(), NOW + 3600, "https://evil.issuer", AUD);
    assert_eq!(
        status(
            jwt_router(Some(RequiredScheme::Jwt)),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "错 issuer → Untrusted → 401"
    );
}
#[tokio::test]
async fn alg_none_is_401() {
    // alg:none 攻击：空签名段，验签器按 alg 白名单拒（组合根全链路覆盖）。
    let token = mint_alg_none(&super_admin_payload(NOW + 3600, ISS, AUD));
    assert_eq!(
        status(
            jwt_router(Some(RequiredScheme::Jwt)),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "alg:none → 401"
    );
}
#[tokio::test]
async fn hs256_token_on_jwt_listener_is_401() {
    // scheme confusion：向 JWT(ES256) listener 提交 HS256 token → ES256 路径验签失败 → 401。
    let token = mint_hs256(&[9u8; 32], &super_admin_payload(NOW + 3600, ISS, AUD));
    assert_eq!(
        status(
            jwt_router(Some(RequiredScheme::Jwt)),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "HS256 token 不被 JWT/ES256 listener 接受"
    );
}
#[tokio::test]
async fn unsupported_scheme_require_is_401() {
    // bridge 配 RequiredScheme::Mtls（本桥不支持）→ verify_principal `_ => None` → 无证据 → enforce 401（fail-closed）。
    let token = super_admin_jwt(&sk_jwt(), NOW + 3600, ISS, AUD);
    assert_eq!(
        status(
            jwt_router(Some(RequiredScheme::Mtls)),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "unsupported scheme(Mtls) → 无证据 → fail-closed 401"
    );
}

// ── 安全同批门回归（ADR-006 §5 / tasks.md:14）：无注入方 ⇒ 即便有效 JWT，Require 仍 401 ──
#[tokio::test]
async fn no_bridge_require_still_401_even_with_valid_jwt() {
    let token = super_admin_jwt(&sk_jwt(), NOW + 3600, ISS, AUD);
    assert_eq!(
        status(
            jwt_router(None),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "无 verify_bridge（T001/T002 单独 merge 态）⇒ enforce 不放行"
    );
}

// ── bridge 外层不误伤 Public 路由 ─────────────────────────────────────────────────
#[tokio::test]
async fn public_route_no_token_is_200() {
    assert_eq!(
        status(jwt_router(Some(RequiredScheme::Jwt)), "/public", None).await,
        StatusCode::OK,
        "Public(opt_out) 路由无 token 仍放行（bridge 不短路）"
    );
}

// ── service-token / HS256 路径 happy（Internal listener） ─────────────────────────
#[tokio::test]
#[allow(clippy::expect_used)]
async fn service_token_hs256_is_200() {
    let (provider, secret) = hs256_provider();
    let token = mint_hs256(
        &secret,
        &format!(
            r#"{{"sub":"svc-1","exp":{},"iss":"{ISS}","aud":"{AUD}"}}"#,
            NOW + 3600
        ),
    );
    let routes = httpserve::routes::unfinalized_for_test::<httpserve::Internal>(|rb| {
        rb.mount(
            httpserve::Route {
                method: Method::GET,
                path: "/svc",
                contract_id: "test.svc",
            },
            get(|| async { "ok" }),
        )
    });
    let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::ServiceToken).expect("plan");
    let authed = httpserve::finalize_auth(routes, plan).expect("finalize_auth");
    let app = apply_verify_bridge(authed, Arc::new(provider), RequiredScheme::ServiceToken);
    assert_eq!(
        status(app, "/svc", Some(&format!("Bearer {token}"))).await,
        StatusCode::OK,
        "有效 HS256 service-token → 证据注入放行 200"
    );
}

// ── tracing 埋点：allow 记 decision+principal.kind；deny 记 decision+变体；无 subject/token 泄漏 ──
#[derive(Clone)]
struct VecWriter(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for VecWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut guard) = self.0.lock() {
            guard.extend_from_slice(b);
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for VecWriter {
    type Writer = VecWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
#[allow(clippy::unwrap_used)]
fn captured(buf: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8(buf.lock().unwrap().clone()).unwrap()
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn tracing_allow_logs_decision_and_kind_no_pii() {
    let buf = Arc::new(Mutex::new(Vec::new()));
    // allow 为 debug 级 + verify_bridge span（debug）⇒ 捕获须开到 DEBUG。
    let sub = tracing_subscriber::fmt()
        .with_writer(VecWriter(buf.clone()))
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let _g = tracing::subscriber::set_default(sub);

    let token = super_admin_jwt(&sk_jwt(), NOW + 3600, ISS, AUD);
    let st = status(
        jwt_router(Some(RequiredScheme::Jwt)),
        "/protected",
        Some(&format!("Bearer {token}")),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let logs = captured(&buf);
    assert!(
        logs.contains("authz.decision"),
        "须记结构化字段键 authz.decision: {logs}"
    );
    assert!(logs.contains("allow"), "allow 决策: {logs}");
    assert!(
        logs.contains("SuperAdmin"),
        "须记脱敏 principal.kind: {logs}"
    );
    assert!(
        logs.contains("verify_bridge"),
        "须有 verify_bridge span: {logs}"
    );
    assert!(!logs.contains("alice"), "禁泄漏 subject: {logs}");
    assert!(!logs.contains(&token), "禁泄漏原始 token: {logs}");
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn tracing_deny_logs_decision_variant_no_token() {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let sub = tracing_subscriber::fmt()
        .with_writer(VecWriter(buf.clone()))
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let _g = tracing::subscriber::set_default(sub);

    let token = super_admin_jwt(&sk_jwt(), NOW - 3600, ISS, AUD); // 过期 → deny
    let st = status(
        jwt_router(Some(RequiredScheme::Jwt)),
        "/protected",
        Some(&format!("Bearer {token}")),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let logs = captured(&buf);
    assert!(
        logs.contains("authz.decision"),
        "须记结构化字段键 authz.decision: {logs}"
    );
    assert!(logs.contains("deny"), "deny 决策: {logs}");
    assert!(
        logs.contains("TokenExpired"),
        "须记 AuthnError 变体（过期→TokenExpired）: {logs}"
    );
    assert!(!logs.contains(&token), "禁泄漏原始 token: {logs}");
    assert!(!logs.contains("alice"), "禁泄漏 subject: {logs}");
}
