//! Signing-key rotation e2e（#1844 T085/T090）：vault Transit 多 kid 动态 ES256 签 →
//! `authn::JwtIssuer`（Active-only mint）→ 真 `OidcProvider` + `RetirementSchedule` 验签桥。
//!
//! hermetic：wiremock 模拟 Vault Transit（按请求 key 名选 SigningKey）；无 PG / 无 live vault。
//! 「过 deadline」用重建 verifier（更大 FixedClock），不用 `tokio::time::advance`。
//!
//! 覆盖：① 计划轮换 overlap 窗口双 token 可验、过期后旧 kid fail-closed；② immediate retire via past
//! `verify_until`（旧 kid 立即拒签，非 `ROTATION_MODE=emergency` 全栈）；③ anti-vacuity：无 schedule 时旧
//! key 过「deadline」仍可验（证 schedule 才是拒因）；④ 多 kid 静态 JWKS（Active + Retiring + Next）
//! 验签窗内/过 deadline 与 verify 闭环对齐。
//!
//! **不在此文件重复的部分**（`pub(crate)`，integration 不破坏封装）：
//! - 多 kid JWKS 导出 kids 合并：`assemblies/runtime/src/infra/vault.rs` 单元测试
//!   `rss_access_jwks_export_kids_merges_active_next_and_retiring`。
//! - `RotationMode::Emergency`（overlap 豁免、probe planned/emergency 分叉）与 rotation readiness 探针
//!   `rss_access_token_signing_rotation`（Healthy / Unhealthy / Degraded）：
//!   `config_tests` + `assemblies/runtime/src/infra/signing_rotation.rs` 单元测试矩阵。
//!   `auth_e2e.rs` / `refresh_mint_e2e.rs` 仍用 `SigningKeyRing::single`（非 rotation 路径）；本文件走生产
//!   `SigningKeyRing::with_rotation` + `rss_access_provider_from_static_config(retirement_schedule)` 单源漏斗。
//!
//! ref: maxlambrecht/rust-spiffe JWT bundle kid selection + refresh
//! ref: jmgilman/vaultrs vaultrs/src/api/transit/requests.rs@master（Transit `sign`）

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, StatusCode, header};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use httpserve::{
    RouteAuthorizationDecision, RouteAuthorizationRequest, RouteAuthorizer,
    TestPrimaryRoute as PrimaryRoute, TestRoutePermission as RoutePermission,
    TestRouteResourceScope as RouteResourceScope,
};
use oidc::{OidcProvider, RetirementSchedule};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use primitives::{AuthPlan, AuthScheme, ListenerKind};
use runtime::auth_bridge::apply_rss_access_verify_bridge_for_test;
use tower::ServiceExt as _;
use vault::VaultSigner;
use wiremock::matchers::{body_partial_json, method as match_method};
use wiremock::{Mock, MockServer, Request as MockRequest, Respond, ResponseTemplate};

const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const USER_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const ISS: &str = "https://issuer.test";
const AUD: &str = "rss-test";
const NOW: i64 = 1_700_000_000;
/// RSS access max TTL = 900s；须保证 deadline+1 仍落在 token exp 之前。
const TTL_SECS: u64 = 900;
const K1: &str = "rss-jwt-es256-k1";
const K2: &str = "rss-jwt-es256-k2";
const K3: &str = "rss-jwt-es256-k3";
/// 计划轮换 verify_until；`NOW < DEADLINE < NOW+TTL`。
const DEADLINE: i64 = NOW + 600;

#[allow(clippy::expect_used)]
fn test_routes(
    build: impl FnOnce(
        httpserve::ListenerRouter<httpserve::Primary>,
    ) -> Result<
        httpserve::ListenerRouter<httpserve::Primary>,
        httpserve::RouteGroupError,
    >,
) -> httpserve::UnfinalizedRoutes {
    httpserve::routes::unfinalized_for_test(build).expect("test routes")
}

#[derive(Clone)]
struct AllowAuthorizer;

impl RouteAuthorizer for AllowAuthorizer {
    fn authorize<'a>(
        &'a self,
        _request: RouteAuthorizationRequest,
    ) -> Pin<Box<dyn Future<Output = RouteAuthorizationDecision> + Send + 'a>> {
        Box::pin(async { RouteAuthorizationDecision::Allow })
    }
}

fn allow_authorizer() -> Arc<dyn RouteAuthorizer> {
    Arc::new(AllowAuthorizer)
}

struct FixedClock(i64);
impl diport::Clock for FixedClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0 as u64)
    }
}

#[allow(clippy::expect_used)]
fn sk_k1() -> SigningKey {
    let bytes: [u8; 32] = std::array::from_fn(|i| (i + 1) as u8);
    SigningKey::from_slice(&bytes).expect("valid P-256 scalar k1")
}

#[allow(clippy::expect_used)]
fn sk_k2() -> SigningKey {
    let bytes: [u8; 32] = std::array::from_fn(|i| (i + 51) as u8);
    SigningKey::from_slice(&bytes).expect("valid P-256 scalar k2")
}

#[allow(clippy::expect_used)]
fn sk_k3() -> SigningKey {
    let bytes: [u8; 32] = std::array::from_fn(|i| (i + 101) as u8);
    SigningKey::from_slice(&bytes).expect("valid P-256 scalar k3")
}

fn sec1(sk: &SigningKey) -> Vec<u8> {
    sk.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

/// wiremock Transit `/sign/{name}`：按 URL 末段 key 名选 SigningKey。
struct MultiKeyTransitSignResponder {
    keys: HashMap<String, SigningKey>,
}

impl Respond for MultiKeyTransitSignResponder {
    #[allow(clippy::expect_used, clippy::panic)]
    fn respond(&self, req: &MockRequest) -> ResponseTemplate {
        let key_name = req
            .url
            .path_segments()
            .and_then(|mut segs| segs.next_back())
            .expect("transit sign path has key segment");
        let sk = self
            .keys
            .get(key_name)
            .unwrap_or_else(|| panic!("mock vault: unknown transit key {key_name}"));
        let body: serde_json::Value =
            serde_json::from_slice(&req.body).expect("mock vault: request body is json");
        let input_b64 = body["input"]
            .as_str()
            .expect("mock vault: transit sign body has string input");
        let message = B64_STD
            .decode(input_b64)
            .expect("mock vault: input is standard base64");
        let sig: Signature = sk.sign(&message);
        let tagged = format!("vault:v1:{}", B64_URL.encode(sig.to_bytes()));
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({ "data": { "signature": tagged } }))
    }
}

#[allow(clippy::expect_used)]
async fn mount_multi_key_vault() -> MockServer {
    let server = MockServer::start().await;
    let mut keys = HashMap::new();
    keys.insert(K1.to_owned(), sk_k1());
    keys.insert(K2.to_owned(), sk_k2());
    Mock::given(match_method("POST"))
        .and(body_partial_json(
            serde_json::json!({ "marshaling_algorithm": "jws" }),
        ))
        .respond_with(MultiKeyTransitSignResponder { keys })
        .mount(&server)
        .await;
    server
}

#[allow(clippy::expect_used)]
fn vault_jwt_issuer(
    vault_uri: &str,
    ring: authn::SigningKeyRing,
    clock: i64,
) -> authn::JwtIssuer<diport::RssAccessProfile, VaultSigner> {
    let config = authn::JwtIssuerConfig::rss_access(ring, ISS, AUD, Duration::from_secs(TTL_SECS));
    let signer = VaultSigner::new_rss_access_allow_http(
        reqwest::Client::new(),
        vault_uri,
        "test-vault-token",
        "transit",
        Duration::from_secs(5),
        config.signing_binding().clone(),
    )
    .expect("vault signer (dev http)");
    authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
        Arc::new(signer),
        Box::new(FixedClock(clock)),
        config,
    )
    .expect("jwt issuer config")
}

/// 与生产 `RssAccessTokenConfig::retirement_schedule` 同源：从 ring.retiring() 派生。
#[allow(clippy::expect_used)]
fn retirement_from_ring(ring: &authn::SigningKeyRing) -> RetirementSchedule {
    RetirementSchedule::from_entries(
        ring.retiring()
            .iter()
            .map(|(kid, until)| (kid.as_str().to_owned(), *until)),
    )
    .expect("SigningKeyRing retiring entries are already validated")
}

#[allow(clippy::expect_used)]
fn ring_active_only(active: &str) -> authn::SigningKeyRing {
    authn::SigningKeyRing::with_rotation(diport::KeyId::new(active), None, Vec::new())
        .expect("disjoint kids")
}

#[allow(clippy::expect_used)]
fn ring_overlap(
    active: &str,
    next: Option<&str>,
    retiring_kid: &str,
    verify_until: i64,
) -> authn::SigningKeyRing {
    authn::SigningKeyRing::with_rotation(
        diport::KeyId::new(active),
        next.map(diport::KeyId::new),
        vec![(diport::KeyId::new(retiring_kid), verify_until)],
    )
    .expect("disjoint kids")
}

/// 真 `OidcProvider`：经生产静态装配门面（含可选 `RetirementSchedule`）+ FixedClock。
#[allow(clippy::expect_used)]
fn oidc_provider(
    keys: &[(&str, SigningKey)],
    schedule: Option<RetirementSchedule>,
    clock: i64,
) -> OidcProvider<diport::RssAccessProfile> {
    let encoded: Vec<(String, String)> = keys
        .iter()
        .map(|(kid, sk)| ((*kid).to_owned(), B64_URL.encode(sec1(sk))))
        .collect();
    let keyed: Vec<runtime::KeyedEs256StaticKey<'_>> = encoded
        .iter()
        .map(|(kid, sec1_b64)| runtime::KeyedEs256StaticKey {
            key_id: kid.as_str(),
            sec1_b64url: sec1_b64.as_str(),
        })
        .collect();
    runtime::rss_access_provider_from_static_config(runtime::RssAccessStaticProviderConfig {
        issuer: ISS,
        audience: AUD,
        keys: &keyed,
        retirement_schedule: schedule,
        clock: Box::new(FixedClock(clock)),
    })
    .expect("static rss access provider")
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
async fn verify_response(
    token: &str,
    provider: OidcProvider<diport::RssAccessProfile>,
) -> (StatusCode, serde_json::Value) {
    let routes = test_routes(|rb| {
        rb.mount_primary_raw_for_test(
            PrimaryRoute::permission(
                Method::GET,
                "/protected",
                "test.protected",
                RoutePermission {
                    permission: vocab::RoutePermissionId::IdentityPolicyRead,
                    scope: RouteResourceScope::None,
                },
            ),
            get(|| async { "ok" }),
        )
    });
    let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).expect("plan");
    let authed =
        httpserve::finalize_primary_auth(routes, plan, allow_authorizer()).expect("finalize_auth");
    let app = apply_rss_access_verify_bridge_for_test(
        authed,
        Arc::new(provider),
        runtime::test_support::always_current_access_grants(),
    );
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/protected")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let response = app
        .into_plaintext_router_for_test()
        .oneshot(req)
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("response body");
    let body = if bytes.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|_| serde_json::json!({}))
    };
    (status, body)
}

async fn verify_status(
    token: &str,
    provider: OidcProvider<diport::RssAccessProfile>,
) -> StatusCode {
    verify_response(token, provider).await.0
}

async fn assert_unauthenticated(
    token: &str,
    provider: OidcProvider<diport::RssAccessProfile>,
    why: &str,
) {
    let (status, body) = verify_response(token, provider).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{why}");
    assert_eq!(
        body["error"]["code"], "ERR_CORE_UNAUTHENTICATED",
        "{why}: error envelope code"
    );
    assert_eq!(
        body["error"]["retryable"], false,
        "{why}: unauthenticated is not retryable"
    );
    assert!(
        body["error"]["requestId"].is_string(),
        "{why}: requestId present"
    );
}

#[allow(clippy::expect_used)]
fn jwt_kid(token: &str) -> String {
    let header_b64 = token.split('.').next().expect("jwt header segment");
    let bytes = B64_URL.decode(header_b64).expect("jwt header b64url");
    let header: serde_json::Value = serde_json::from_slice(&bytes).expect("jwt header json");
    header["kid"].as_str().expect("jwt kid claim").to_owned()
}

#[allow(clippy::expect_used)]
async fn mint_user(issuer: &authn::JwtIssuer<diport::RssAccessProfile, VaultSigner>) -> String {
    let tenant = rss_request_context::TenantId::parse(TENANT).expect("canonical tenant");
    let grant = authn::AuthGrant::new_active(
        tenant,
        ids::UserId::parse(USER_ID).expect("canonical user id"),
        UNIX_EPOCH + Duration::from_secs((NOW - 60) as u64),
        authn::AuthnEpoch::hydrate(3).expect("valid epoch"),
        UNIX_EPOCH + Duration::from_secs((NOW + 10_000) as u64),
        UNIX_EPOCH + Duration::from_secs((NOW - 30) as u64),
    )
    .expect("active grant");
    issuer
        .issue_access(
            grant
                .access_issue_input()
                .expect("active grant issue input"),
        )
        .await
        .expect("mint ok")
        .as_str()
        .to_owned()
}

fn both_keys() -> [(&'static str, SigningKey); 2] {
    [(K1, sk_k1()), (K2, sk_k2())]
}

fn merged_export_keys() -> [(&'static str, SigningKey); 3] {
    [(K1, sk_k1()), (K2, sk_k2()), (K3, sk_k3())]
}

/// 计划轮换：overlap 内双 token 可验；过 deadline 重建 verifier 后仅新 token 可验。
#[tokio::test]
#[allow(clippy::expect_used)]
async fn planned_rotation_overlap_then_retire() {
    let server = mount_multi_key_vault().await;

    // Phase A：k1 Active（+ Next=k2）签发 token_old；mint 走生产 with_rotation，kid=active。
    let ring_k1 = authn::SigningKeyRing::with_rotation(
        diport::KeyId::new(K1),
        Some(diport::KeyId::new(K2)),
        Vec::new(),
    )
    .expect("phase A ring");
    let issuer_k1 = vault_jwt_issuer(&server.uri(), ring_k1, NOW);
    let token_old = mint_user(&issuer_k1).await;
    assert_eq!(jwt_kid(&token_old), K1, "mint must select active kid only");

    // Phase B：切到 k2 Active、k1 Retiring(verify_until=DEADLINE)、Next=k3；schedule 从 ring 派生。
    let ring_k2 = ring_overlap(K2, Some(K3), K1, DEADLINE);
    let schedule = retirement_from_ring(&ring_k2);
    let issuer_k2 = vault_jwt_issuer(&server.uri(), ring_k2, NOW);
    let token_new = mint_user(&issuer_k2).await;
    assert_eq!(jwt_kid(&token_new), K2, "mint must select new active kid");

    // clock ≤ deadline：token_old 与 token_new 均可验过。
    let provider_at_deadline = oidc_provider(&both_keys(), Some(schedule.clone()), DEADLINE);
    assert_eq!(
        verify_status(&token_old, provider_at_deadline).await,
        StatusCode::OK,
        "retiring k1 must still verify at deadline instant"
    );
    let provider_at_deadline = oidc_provider(&both_keys(), Some(schedule.clone()), DEADLINE);
    assert_eq!(
        verify_status(&token_new, provider_at_deadline).await,
        StatusCode::OK,
        "active k2 must verify at deadline instant"
    );

    // clock > deadline：重建 verifier（新 FixedClock），token_old 拒、token_new 仍过。
    let past = DEADLINE + 1;
    let provider_past = oidc_provider(&both_keys(), Some(schedule.clone()), past);
    assert_unauthenticated(
        &token_old,
        provider_past,
        "retired k1 must fail-closed after deadline",
    )
    .await;
    let provider_past = oidc_provider(&both_keys(), Some(schedule), past);
    assert_eq!(
        verify_status(&token_new, provider_past).await,
        StatusCode::OK,
        "active k2 must still verify after k1 deadline"
    );

    // anti-vacuity：无 retirement 时同一 past clock 下旧 token 仍可验（弱行为），证 schedule 才是拒因。
    let legacy = oidc_provider(&both_keys(), None, past);
    assert_eq!(
        verify_status(&token_old, legacy).await,
        StatusCode::OK,
        "without schedule, old key must remain verifiable (legacy weak path)"
    );
}

/// Immediate retire via past `verify_until`：`verify_until < now` 使 k1 在当前时钟下立即 retired → 旧 token
/// 拒签；新 Active 签发正常。`RotationMode::Emergency`（overlap 豁免、probe planned/emergency 分叉）由
/// `config_tests` / `signing_rotation.rs` 单元测试覆盖，本 e2e 不测 env `ROTATION_MODE=emergency` 全栈。
#[tokio::test]
#[allow(clippy::expect_used)]
async fn immediate_retire_via_past_verify_until() {
    let server = mount_multi_key_vault().await;

    let ring_k1 = ring_active_only(K1);
    let issuer_k1 = vault_jwt_issuer(&server.uri(), ring_k1, NOW);
    let token_old = mint_user(&issuer_k1).await;
    assert_eq!(jwt_kid(&token_old), K1);

    let ring_k2 = ring_overlap(K2, None, K1, NOW - 1);
    let schedule = retirement_from_ring(&ring_k2);
    let issuer_k2 = vault_jwt_issuer(&server.uri(), ring_k2, NOW);
    let token_new = mint_user(&issuer_k2).await;
    assert_eq!(jwt_kid(&token_new), K2);

    // verify_until 已过（NOW - 1）：schedule 使 k1 在当前时钟下立即 retired。
    let provider = oidc_provider(&both_keys(), Some(schedule.clone()), NOW);
    assert_unauthenticated(
        &token_old,
        provider,
        "past verify_until k1 must reject immediately",
    )
    .await;

    let provider = oidc_provider(&both_keys(), Some(schedule), NOW);
    assert_eq!(
        verify_status(&token_new, provider).await,
        StatusCode::OK,
        "new active k2 token must verify after emergency cutover"
    );
}

#[allow(clippy::expect_used)]
async fn mount_three_key_vault() -> MockServer {
    let server = MockServer::start().await;
    let mut keys = HashMap::new();
    keys.insert(K1.to_owned(), sk_k1());
    keys.insert(K2.to_owned(), sk_k2());
    keys.insert(K3.to_owned(), sk_k3());
    Mock::given(match_method("POST"))
        .and(body_partial_json(
            serde_json::json!({ "marshaling_algorithm": "jws" }),
        ))
        .respond_with(MultiKeyTransitSignResponder { keys })
        .mount(&server)
        .await;
    server
}

/// 多 kid JWKS（Active + Retiring + Next）验签闭环：模拟 `export-vault-transit` 合并导出后的静态
/// keyset。K3=Next 公钥在场时：窗内 K1/K2 可验；过 `verify_until` 后 K1 fail-closed；另以 K3 Active
/// mint 的 token 证明 Next 公钥已载入（缺 K3 的 keyset 拒签）。rotation probe 状态机见
/// `signing_rotation.rs` 单元测试（本文件不重复 probe API）。
#[tokio::test]
#[allow(clippy::expect_used)]
async fn multi_kid_jwks_overlap_then_retiring_deadline() {
    let server = mount_three_key_vault().await;

    let ring_k1 = ring_active_only(K1);
    let issuer_k1 = vault_jwt_issuer(&server.uri(), ring_k1, NOW);
    let token_old = mint_user(&issuer_k1).await;
    assert_eq!(jwt_kid(&token_old), K1);

    let ring_k2 = ring_overlap(K2, Some(K3), K1, DEADLINE);
    let schedule = retirement_from_ring(&ring_k2);
    let issuer_k2 = vault_jwt_issuer(&server.uri(), ring_k2, NOW);
    let token_new = mint_user(&issuer_k2).await;
    assert_eq!(jwt_kid(&token_new), K2);

    // Next 反例：以 K3 为 Active mint；合并 JWKS 可验，缺 K3 的 both_keys 拒签。
    let ring_k3 = ring_active_only(K3);
    let issuer_k3 = vault_jwt_issuer(&server.uri(), ring_k3, NOW);
    let token_next = mint_user(&issuer_k3).await;
    assert_eq!(jwt_kid(&token_next), K3);
    let provider_merged = oidc_provider(&merged_export_keys(), Some(schedule.clone()), NOW);
    assert_eq!(
        verify_status(&token_next, provider_merged).await,
        StatusCode::OK,
        "Next kid K3 must verify when present in merged JWKS"
    );
    let provider_without_next = oidc_provider(&both_keys(), Some(schedule.clone()), NOW);
    assert_unauthenticated(
        &token_next,
        provider_without_next,
        "Next kid K3 must fail when absent from JWKS",
    )
    .await;

    // K3 = staged Next 公钥在场不改变 K1/K2 overlap 结果。
    let provider_in_window = oidc_provider(&merged_export_keys(), Some(schedule.clone()), NOW);
    assert_eq!(
        verify_status(&token_old, provider_in_window).await,
        StatusCode::OK,
        "retiring k1 must verify while in overlap window with multi-kid JWKS"
    );
    let provider_in_window = oidc_provider(&merged_export_keys(), Some(schedule.clone()), NOW);
    assert_eq!(
        verify_status(&token_new, provider_in_window).await,
        StatusCode::OK,
        "active k2 must verify with merged active+retiring+next JWKS"
    );

    let past = DEADLINE + 1;
    let provider_past = oidc_provider(&merged_export_keys(), Some(schedule.clone()), past);
    assert_unauthenticated(
        &token_old,
        provider_past,
        "retired k1 must fail-closed after verify_until (rotation hygiene)",
    )
    .await;
    let provider_past = oidc_provider(&merged_export_keys(), Some(schedule), past);
    assert_eq!(
        verify_status(&token_new, provider_past).await,
        StatusCode::OK,
        "active k2 must still verify after retiring deadline"
    );
}
