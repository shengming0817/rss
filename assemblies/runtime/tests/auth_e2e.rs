//! 验签桥 e2e（ADR-006 §8 ③）：真 `OidcProvider`（静态 key）+ 组合根 `apply_verify_bridge` +
//! `httpserve::finalize_auth` + enforce，经 `tower::oneshot` 驱动已组装 router（不真实绑端口；serve = #1017）。
//!
//! 覆盖：有效 JWT→200+证据放行；无 token/坏签名/过期/错 aud/错 iss/alg:none/跨 scheme→401（拒绝路径全覆盖）；
//! **无 bridge 回归**（T001/T002 单独 merge 态：即便有效 JWT，Require 仍 401）；mTLS 只接受 transport peer evidence；
//! Public 路由不被 bridge 误伤；小写 bearer 前缀放行；service-token/HS256 happy；tracing 埋点 `authz.decision`+
//! `principal.kind`、无 subject/token 泄漏。
//!
//! 本批不断言 handler 读完整 `Principal`（属 W，评审 F3）——只断言证据注入放行（200）。
//!
//! NOTE: `bins/rss` 与 `bins/server` 已成薄壳（#1309）；验签桥逻辑现集中在 `assemblies/runtime`。

use std::collections::HashSet;
use std::future::Future;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, StatusCode, header};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use diport::{AuditEvent, AuditSink, AuditSinkError, Pdp, PdpError, RawCredential, VerifiedClaims};
use httpserve::{
    RouteAuthorizationDecision, RouteAuthorizationRequest, RouteAuthorizer,
    TestPrimaryRoute as PrimaryRoute, TestRoute as Route, TestRoutePermission as RoutePermission,
    TestRouteResourceScope as RouteResourceScope,
};
use oidc::OidcProvider;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use primitives::{AuthPlan, AuthScheme, ListenerKind, RouteAuthOptOut};
use runtime::auth_bridge::{
    apply_federated_access_verify_bridge_for_test, apply_mtls_verify_bridge_for_test,
    apply_rss_access_pdp_bridge_for_test, apply_rss_access_verify_bridge_for_test,
    apply_service_token_pdp_bridge_for_test, apply_service_token_verify_bridge_for_test,
};
use runtime::{
    KeyedEs256StaticKey, RssAccessStaticProviderConfig, rss_access_provider_from_static_config,
};
use tokio::sync::Notify;
use tower::ServiceExt as _;

/// 合法测试租户（`user` kind 需 tenant；canonical UUID）。
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const OTHER_TENANT: &str = "11111111-2222-4333-8444-555555555555";
const USER_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

const ISS: &str = "https://issuer.test";
const AUD: &str = "rss-test";
const NOW: i64 = 1_700_000_000;
const HS_KID: &str = "cell-a.svc-a";
const RSS_KID: &str = "runtime-e2e-jwt-key";
const FEDERATED_ISS: &str = "https://federated.issuer.test";
const FEDERATED_AUD: &str = "federated-test";
const FEDERATED_KID: &str = "runtime-e2e-federated-key";
const SERVICE_CALLER_ALLOWED: &str = "rss-maintenance-operator";

#[allow(clippy::expect_used)]
fn test_routes<L: httpserve::Listener>(
    build: impl FnOnce(
        httpserve::ListenerRouter<L>,
    ) -> Result<httpserve::ListenerRouter<L>, httpserve::RouteGroupError>,
) -> httpserve::UnfinalizedRoutes {
    httpserve::routes::unfinalized_for_test(build).expect("test routes")
}

// ── 注入时钟替身（确定性 exp 边界，非系统时钟） ───────────────────────────────────
struct FixedClock(i64);
impl diport::Clock for FixedClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0 as u64)
    }
}

fn current_grants() -> Arc<identity::AuthGrantValidationService> {
    runtime::test_support::always_current_access_grants()
}

#[derive(Clone, Copy)]
enum GrantDecision {
    Current,
    Invalid,
    StoreUnavailable,
}

struct RecordingGrantValidator {
    decision: GrantDecision,
    calls: Arc<AtomicUsize>,
    binding_matched: Arc<AtomicBool>,
}

impl identity::ports::AuthGrantValidator for RecordingGrantValidator {
    async fn is_current(
        &self,
        scope: identity::ports::TenantRepoScope,
        input: &authn::AccessGrantValidationInput,
        _observed_at: SystemTime,
    ) -> Result<bool, identity::ports::IdentityError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.binding_matched.store(
            input.grant_id().as_str().len() == 36
                && input.user_id().as_uuid().hyphenated().to_string() == USER_ID
                && input.tenant().to_string() == TENANT
                && scope.tenant() == input.tenant()
                && input.auth_time_unix_secs() == (NOW - 30) as u64
                && input.authn_epoch().get() == 7,
            Ordering::Release,
        );
        match self.decision {
            GrantDecision::Current => Ok(true),
            GrantDecision::Invalid => Ok(false),
            GrantDecision::StoreUnavailable => Err(identity::ports::IdentityError::Storage(
                Box::new(std::io::Error::other("injected grant store outage")),
            )),
        }
    }
}

fn recording_grants(
    decision: GrantDecision,
    calls: Arc<AtomicUsize>,
    binding_matched: Arc<AtomicBool>,
) -> Arc<identity::AuthGrantValidationService> {
    runtime::test_support::access_grant_validation_service(RecordingGrantValidator {
        decision,
        calls,
        binding_matched,
    })
}

#[derive(Default)]
struct TestReplayStore {
    seen: Mutex<HashSet<[u8; 32]>>,
}

impl diport::ServiceTokenReplayStore for TestReplayStore {
    async fn check_and_record(
        &self,
        key: &diport::ServiceTokenReplayKey,
        _expires_at: SystemTime,
        _deadline: diport::ServiceTokenReplayDeadline,
    ) -> Result<diport::ServiceTokenReplayDisposition, diport::ServiceTokenReplayStoreError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| diport::ServiceTokenReplayStoreError::Unavailable)?;
        Ok(if seen.insert(*key.digest_bytes()) {
            diport::ServiceTokenReplayDisposition::Recorded
        } else {
            diport::ServiceTokenReplayDisposition::Replayed
        })
    }
}

fn replay_store() -> Arc<diport::DynServiceTokenReplayStore<'static>> {
    diport::DynServiceTokenReplayStore::new_arc(TestReplayStore::default())
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

#[derive(Clone, Default)]
struct RecordingAuditSink {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl RecordingAuditSink {
    fn events(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl AuditSink for RecordingAuditSink {
    async fn record(&self, event: AuditEvent) -> Result<(), AuditSinkError> {
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

#[allow(clippy::expect_used)]
fn sk_federated() -> SigningKey {
    SigningKey::from_slice(&[0x31; 32]).expect("valid federated test scalar")
}
fn sec1(sk: &SigningKey) -> Vec<u8> {
    sk.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

#[derive(Clone)]
struct P256JwtSigner;

impl diport::Signer for P256JwtSigner {
    async fn sign(
        &self,
        request: diport::SignRequest,
    ) -> Result<diport::Signature, diport::SignerError> {
        let sig: Signature = sk_jwt().sign(request.message.as_bytes());
        Ok(diport::Signature::new(sig.to_bytes().to_vec()))
    }

    async fn shutdown(&self) -> Result<(), diport::SignerError> {
        Ok(())
    }
}

#[derive(Clone)]
struct HmacJwtSigner {
    secret: Vec<u8>,
}

impl diport::Signer for HmacJwtSigner {
    async fn sign(
        &self,
        request: diport::SignRequest,
    ) -> Result<diport::Signature, diport::SignerError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.secret).map_err(diport::SignerError::new)?;
        mac.update(request.message.as_bytes());
        Ok(diport::Signature::new(mac.finalize().into_bytes().to_vec()))
    }

    async fn shutdown(&self) -> Result<(), diport::SignerError> {
        Ok(())
    }
}

#[allow(clippy::expect_used)]
fn production_access_jwt() -> String {
    let issuer = authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
        Arc::new(P256JwtSigner),
        Box::new(FixedClock(NOW)),
        authn::JwtIssuerConfig::rss_access(
            authn::SigningKeyRing::single(diport::KeyId::new(RSS_KID))
                .expect("non-empty signing key id"),
            diport::SigningPurpose::new("auth.rss-access"),
            ISS,
            AUD,
            Duration::from_secs(900),
        ),
    )
    .expect("runtime e2e jwt issuer config");
    let grant = authn::AuthGrant::new_active(
        production_tenant(),
        ids::UserId::parse(USER_ID).expect("canonical user id"),
        UNIX_EPOCH + Duration::from_secs((NOW - 30) as u64),
        authn::AuthnEpoch::hydrate(7).expect("valid epoch"),
        UNIX_EPOCH + Duration::from_secs((NOW + 3_600) as u64),
        UNIX_EPOCH + Duration::from_secs((NOW - 20) as u64),
    )
    .expect("active grant");
    futures::executor::block_on(
        issuer.issue_access(
            grant
                .access_issue_input()
                .expect("active grant issue input"),
        ),
    )
    .expect("runtime e2e production jwt")
    .as_str()
    .to_string()
}

#[allow(clippy::expect_used)]
fn production_tenant() -> vocab::TenantId {
    vocab::TenantId::parse(TENANT).expect("canonical tenant")
}

#[allow(clippy::expect_used)]
fn production_service_token(secret: &[u8]) -> String {
    let issuer = authn::JwtIssuer::<diport::ServiceTokenProfile, _>::new(
        Arc::new(HmacJwtSigner {
            secret: secret.to_vec(),
        }),
        Box::new(FixedClock(NOW)),
        authn::JwtIssuerConfig::service_token(
            authn::SigningKeyRing::single(diport::KeyId::new(HS_KID))
                .expect("non-empty signing key id"),
            diport::SigningPurpose::new("auth.service-token"),
            ISS,
            AUD,
            Duration::from_secs(300),
        ),
    )
    .expect("runtime e2e service-token issuer config");
    futures::executor::block_on(issuer.issue_service_token(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        diport::ServiceTokenTenantBinding::new(production_tenant()),
    ))
    .expect("runtime e2e production service token")
    .as_str()
    .to_owned()
}

fn production_user_jwt() -> String {
    production_access_jwt()
}

fn production_device_jwt() -> String {
    federated_scoped_jwt("device")
}

fn production_admin_jwt() -> String {
    federated_scoped_jwt("admin")
}

fn mint_es256(sk: &SigningKey, payload: &str) -> String {
    let header = B64.encode(format!(
        r#"{{"alg":"ES256","typ":"at+jwt","kid":"{RSS_KID}"}}"#
    ));
    let body = B64.encode(payload.as_bytes());
    let signing_input = format!("{header}.{body}");
    let sig: Signature = sk.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64.encode(sig.to_bytes()))
}
#[allow(clippy::expect_used)]
fn mint_hs256(secret: &[u8], payload: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let header = B64.encode(format!(
        r#"{{"alg":"HS256","typ":"rss-service+jwt","kid":"{HS_KID}"}}"#
    ));
    let body = B64.encode(payload.as_bytes());
    let signing_input = format!("{header}.{body}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        B64.encode(mac.finalize().into_bytes())
    )
}
#[allow(clippy::expect_used)]
fn mint_hs256_bound(secret: &[u8], payload: &str, tenant: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let header = B64.encode(format!(
        r#"{{"alg":"HS256","typ":"rss-service+jwt","kid":"{HS_KID}"}}"#
    ));
    let body = B64.encode(payload.as_bytes());
    let signing_input = format!("{header}.{body}");
    let binding = diport::ServiceTokenTenantBinding::new(
        vocab::tenant::TenantId::parse(tenant).expect("canonical tenant"),
    );
    let mac_input = diport::service_token_mac_input(signing_input.as_bytes(), &binding);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(&mac_input);
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
/// Federated superAdmin JWT payload（无需 tenant claim；由 Federated kind allowlist 放行）。
fn super_admin_payload(exp: i64, iss: &str, aud: &str) -> String {
    format!(
        r#"{{"sub":"alice","iat":{},"exp":{exp},"iss":"{iss}","aud":"{aud}","token_use":"access","kind":"superAdmin"}}"#,
        exp - 900
    )
}
fn super_admin_jwt(sk: &SigningKey, exp: i64, iss: &str, aud: &str) -> String {
    mint_es256(sk, &super_admin_payload(exp, iss, aud))
}

fn federated_super_admin_jwt() -> String {
    let header = B64.encode(format!(
        r#"{{"alg":"ES256","typ":"at+jwt","kid":"{FEDERATED_KID}"}}"#
    ));
    let body = B64.encode(super_admin_payload(NOW + 900, FEDERATED_ISS, FEDERATED_AUD).as_bytes());
    let signing_input = format!("{header}.{body}");
    let signature: Signature = sk_federated().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64.encode(signature.to_bytes()))
}

fn federated_scoped_jwt(kind: &str) -> String {
    let header = B64.encode(format!(
        r#"{{"alg":"ES256","typ":"at+jwt","kid":"{FEDERATED_KID}"}}"#
    ));
    let payload = format!(
        r#"{{"sub":"alice","tenant_id":"{TENANT}","kind":"{kind}","iat":{},"exp":{},"iss":"{FEDERATED_ISS}","aud":"{FEDERATED_AUD}","token_use":"access"}}"#,
        NOW,
        NOW + 900,
    );
    let body = B64.encode(payload.as_bytes());
    let signing_input = format!("{header}.{body}");
    let signature: Signature = sk_federated().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64.encode(signature.to_bytes()))
}

fn service_token_payload(exp: i64, sub: &str) -> String {
    format!(
        r#"{{"sub":"{sub}","iat":{},"exp":{exp},"iss":"{ISS}","aud":"{AUD}","token_use":"service","kind":"service","jti":"mtls-exact-match-{sub}-{exp}"}}"#,
        exp - 300
    )
}

// ── provider 构造：经 static operator/test profile（真 RustCrypto 验签 + FixedClock）─────────────
#[allow(clippy::expect_used)]
fn es256_provider() -> OidcProvider<diport::RssAccessProfile> {
    let es256_b64 = B64.encode(sec1(&sk_jwt()));
    let keys = [KeyedEs256StaticKey {
        key_id: RSS_KID,
        sec1_b64url: &es256_b64,
    }];
    rss_access_provider_from_static_config(RssAccessStaticProviderConfig {
        issuer: ISS,
        audience: AUD,
        keys: &keys,
        retirement_schedule: None,
        clock: Box::new(FixedClock(NOW)),
    })
    .expect("es256 production provider")
}

#[allow(clippy::expect_used)]
fn federated_es256_provider() -> OidcProvider<diport::FederatedAccessProfile> {
    let keys = oidc::AccessStaticKeySource::builder()
        .add_es256_sec1(FEDERATED_KID, &sec1(&sk_federated()))
        .expect("federated keyed ES256 public key")
        .build();
    let config = oidc::VerifierConfigBuilder::<diport::FederatedAccessProfile>::new(
        FEDERATED_ISS,
        FEDERATED_AUD,
    )
    .keys_static(keys)
    .trust_kind("superAdmin")
    .trust_kind("device")
    .trust_kind("admin")
    .build()
    .expect("federated verifier config");
    OidcProvider::new(config, Box::new(FixedClock(NOW)))
}
#[allow(clippy::expect_used)]
fn hs256_provider() -> (OidcProvider<diport::ServiceTokenProfile>, Vec<u8>) {
    let secret = vec![9u8; 32];
    let keys = oidc::ServiceTokenKeySource::builder()
        .add_hs256_secret(HS_KID, &secret)
        .expect("keyed service-token secret")
        .build();
    let config = oidc::VerifierConfigBuilder::<diport::ServiceTokenProfile>::new(ISS, AUD)
        .keys_hs256(keys)
        .replay_store(replay_store(), Duration::from_secs(5))
        .build()
        .expect("service-token verifier config");
    let provider = OidcProvider::new(config, Box::new(FixedClock(NOW)));
    (provider, secret)
}

// ── router 装配（Primary/Jwt：Require /protected + Public /public） ────────────────
/// `with_bridge = false` ⇒ 不挂验签桥（回归用例）；`true` ⇒ 挂 RSS access typed bridge。
#[allow(clippy::expect_used)]
fn jwt_router(with_bridge: bool) -> httpserve::AuthenticatedRoutes {
    jwt_router_with_grants(with_bridge, current_grants())
}

async fn rss_verified_evidence_handler(
    axum::extract::Extension(verified): axum::extract::Extension<Arc<authn::VerifiedJwt>>,
    axum::extract::Extension(authenticated): axum::extract::Extension<httpserve::Authenticated>,
) -> Result<&'static str, StatusCode> {
    let Some(receipt) = verified.grant_receipt() else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };
    if receipt.grant_id().as_str().len() != 36
        || receipt.token_id().to_string().len() != 36
        || receipt.auth_time_unix_secs() != (NOW - 30) as u64
        || receipt.authn_epoch() != 7
        || authenticated.current_auth_grant().is_none()
    {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    Ok("ok")
}

#[allow(clippy::expect_used)]
fn jwt_router_with_grants(
    with_bridge: bool,
    grants: Arc<identity::AuthGrantValidationService>,
) -> httpserve::AuthenticatedRoutes {
    // typed Primary builder（`ListenerRouter::new` 是 pub(crate)，外部测试经 `unfinalized_for_test` 构造 funnel 输入）。
    let routes = test_routes::<httpserve::Primary>(|rb| {
        let rb = rb.mount_primary_raw_for_test(
            PrimaryRoute::permission(
                Method::GET,
                "/protected",
                "test.protected",
                RoutePermission {
                    permission: vocab::RoutePermissionId::IdentityPolicyRead,
                    scope: RouteResourceScope::None,
                },
            ),
            get(rss_verified_evidence_handler),
        )?;
        rb.mount_primary_raw_for_test(
            PrimaryRoute::opt_out(
                Method::GET,
                "/public",
                "test.public",
                RouteAuthOptOut::Public,
            ),
            get(|| async { "pub" }),
        )
    });
    let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).expect("plan");
    let authed =
        httpserve::finalize_primary_auth(routes, plan, allow_authorizer()).expect("finalize_auth");
    if with_bridge {
        apply_rss_access_verify_bridge_for_test(authed, Arc::new(es256_provider()), grants)
    } else {
        authed
    }
}

#[allow(clippy::expect_used)]
fn federated_router_with_calls(handler_calls: Arc<AtomicUsize>) -> httpserve::AuthenticatedRoutes {
    let routes = test_routes::<httpserve::Primary>(|router| {
        router.mount_primary_raw_for_test(
            PrimaryRoute::permission(
                Method::GET,
                "/federated",
                "test.federated",
                RoutePermission {
                    permission: vocab::RoutePermissionId::IdentityPolicyRead,
                    scope: RouteResourceScope::None,
                },
            ),
            get(
                move |axum::extract::Extension(verified): axum::extract::Extension<
                    Arc<authn::VerifiedJwt>,
                >| {
                    let handler_calls = Arc::clone(&handler_calls);
                    async move {
                        if verified.grant_receipt().is_some() {
                            return Err(StatusCode::INTERNAL_SERVER_ERROR);
                        }
                        handler_calls.fetch_add(1, Ordering::AcqRel);
                        Ok("federated")
                    }
                },
            ),
        )
    });
    let plan =
        AuthPlan::new(ListenerKind::Primary, AuthScheme::FederatedAccessToken).expect("plan");
    let authed =
        httpserve::finalize_primary_auth(routes, plan, allow_authorizer()).expect("finalize_auth");
    apply_federated_access_verify_bridge_for_test(authed, Arc::new(federated_es256_provider()))
}

#[derive(Clone)]
struct YieldingRssPdp;

impl Pdp for YieldingRssPdp {
    async fn verify(&self, _raw: &RawCredential) -> Result<VerifiedClaims, PdpError> {
        tokio::task::yield_now().await;
        let facts = diport::VerifiedAccessGrantFacts::try_new(
            "6ba7b810-9dad-41d1-80b4-00c04fd430c8",
            "6ba7b811-9dad-41d1-80b4-00c04fd430c8",
            NOW - 30,
            7,
        )
        .expect("valid grant facts");
        Ok(VerifiedClaims::rss_user(
            ids::UserId::parse(USER_ID).expect("canonical user id"),
            production_tenant(),
            facts,
        ))
    }
}

#[derive(Clone)]
struct YieldingServicePdp;

impl Pdp for YieldingServicePdp {
    async fn verify(&self, _raw: &RawCredential) -> Result<VerifiedClaims, PdpError> {
        tokio::task::yield_now().await;
        Ok(VerifiedClaims::service_token(
            vocab::ServiceCallerDomain::MaintenanceOperator,
        ))
    }
}

#[derive(Clone)]
struct YieldingErrorPdp;

impl Pdp for YieldingErrorPdp {
    async fn verify(&self, _raw: &RawCredential) -> Result<VerifiedClaims, PdpError> {
        tokio::task::yield_now().await;
        Err(PdpError::Untrusted)
    }
}

#[derive(Clone)]
struct CountingPdp {
    calls: Arc<AtomicUsize>,
}

impl Pdp for CountingPdp {
    async fn verify(&self, _raw: &RawCredential) -> Result<VerifiedClaims, PdpError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Err(PdpError::Untrusted)
    }
}

#[derive(Clone)]
struct ProviderUnavailablePdp;

impl Pdp for ProviderUnavailablePdp {
    async fn verify(&self, _raw: &RawCredential) -> Result<VerifiedClaims, PdpError> {
        tokio::task::yield_now().await;
        Err(PdpError::ProviderUnavailable)
    }
}

#[derive(Clone)]
struct PendingPdp {
    entered: Arc<Notify>,
    dropped: Arc<AtomicBool>,
}

struct VerifyDropSignal(Arc<AtomicBool>);

impl Drop for VerifyDropSignal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl Pdp for PendingPdp {
    async fn verify(&self, _raw: &RawCredential) -> Result<VerifiedClaims, PdpError> {
        let _drop_signal = VerifyDropSignal(Arc::clone(&self.dropped));
        self.entered.notify_one();
        std::future::pending().await
    }
}

#[allow(clippy::expect_used)]
fn jwt_router_with_pdp<P>(provider: P) -> httpserve::AuthenticatedRoutes
where
    P: Pdp + Send + Sync + 'static,
{
    jwt_router_with_pdp_and_calls(provider, Arc::new(AtomicUsize::new(0)))
}

#[allow(clippy::expect_used)]
fn jwt_router_with_pdp_and_calls<P>(
    provider: P,
    handler_calls: Arc<AtomicUsize>,
) -> httpserve::AuthenticatedRoutes
where
    P: Pdp + Send + Sync + 'static,
{
    let routes = test_routes::<httpserve::Primary>(|rb| {
        let handler_calls = Arc::clone(&handler_calls);
        rb.mount_primary_raw_for_test(
            PrimaryRoute::permission(
                Method::GET,
                "/protected",
                "test.protected.async-pdp",
                RoutePermission {
                    permission: vocab::RoutePermissionId::IdentityPolicyRead,
                    scope: RouteResourceScope::None,
                },
            ),
            get(move || {
                let handler_calls = Arc::clone(&handler_calls);
                async move {
                    handler_calls.fetch_add(1, Ordering::AcqRel);
                    "ok"
                }
            }),
        )
    });
    let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).expect("plan");
    let authed =
        httpserve::finalize_primary_auth(routes, plan, allow_authorizer()).expect("finalize_auth");
    apply_rss_access_pdp_bridge_for_test(authed, provider, current_grants())
}

#[allow(clippy::expect_used)]
fn public_router_with_counters(
    pdp_calls: Arc<AtomicUsize>,
    handler_calls: Arc<AtomicUsize>,
) -> httpserve::AuthenticatedRoutes {
    let routes = test_routes::<httpserve::Primary>(|router| {
        router.mount_primary_raw_for_test(
            PrimaryRoute::opt_out(
                Method::GET,
                "/public",
                "test.public.boundary",
                RouteAuthOptOut::Public,
            ),
            get(move || {
                let handler_calls = Arc::clone(&handler_calls);
                async move {
                    handler_calls.fetch_add(1, Ordering::AcqRel);
                    "public"
                }
            }),
        )
    });
    let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).expect("plan");
    let authed =
        httpserve::finalize_primary_auth(routes, plan, allow_authorizer()).expect("finalize_auth");
    apply_rss_access_pdp_bridge_for_test(authed, CountingPdp { calls: pdp_calls }, current_grants())
}

#[allow(clippy::expect_used)]
fn service_token_router_with_pdp<P>(provider: P) -> httpserve::AuthenticatedRoutes
where
    P: Pdp + Send + Sync + 'static,
{
    let routes = test_routes::<httpserve::Internal>(|rb| {
        rb.mount_internal_raw_for_test(
            Route {
                method: Method::GET,
                path: "/svc",
                contract_id: "test.svc",
            },
            httpserve::ServiceCallerPolicy::exact(
                "test.svc",
                vocab::ServiceCallerDomain::MaintenanceOperator,
            ),
            get(|| async { "ok" }),
        )
    });
    let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::ServiceToken).expect("plan");
    let authed = httpserve::finalize_auth(routes, plan).expect("finalize_auth");
    apply_service_token_pdp_bridge_for_test(authed, provider)
}

#[allow(clippy::expect_used)]
fn service_token_router_with_policy_and_calls(
    provider: OidcProvider<diport::ServiceTokenProfile>,
    policy: Option<httpserve::ServiceCallerPolicy>,
    handler_calls: Arc<AtomicUsize>,
) -> httpserve::AuthenticatedRoutes {
    let routes = test_routes::<httpserve::Internal>(|router| {
        let route = Route {
            method: Method::GET,
            path: "/svc-policy",
            contract_id: "test.svc.policy",
        };
        let handler = get(move || {
            let handler_calls = Arc::clone(&handler_calls);
            async move {
                handler_calls.fetch_add(1, Ordering::AcqRel);
                "ok"
            }
        });
        match policy {
            Some(policy) => router.mount_internal_raw_for_test(route, policy, handler),
            None => router.mount_raw_for_test(route, handler),
        }
    });
    let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::ServiceToken).expect("plan");
    let authed = httpserve::finalize_auth(routes, plan).expect("finalize_auth");
    apply_service_token_verify_bridge_for_test(authed, Arc::new(provider))
}

#[allow(clippy::expect_used)]
fn mtls_authed_routes() -> httpserve::AuthenticatedRoutes {
    mtls_authed_routes_with_calls(Arc::new(AtomicUsize::new(0)))
}

#[allow(clippy::expect_used)]
fn mtls_authed_routes_with_calls(
    handler_calls: Arc<AtomicUsize>,
) -> httpserve::AuthenticatedRoutes {
    let routes = test_routes::<httpserve::Primary>(|rb| {
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
            get(move || {
                let handler_calls = Arc::clone(&handler_calls);
                async move {
                    handler_calls.fetch_add(1, Ordering::AcqRel);
                    "ok"
                }
            }),
        )
    });
    let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Mtls).expect("plan");
    httpserve::finalize_primary_auth(routes, plan, allow_authorizer()).expect("finalize_auth")
}

fn mtls_router() -> httpserve::AuthenticatedRoutes {
    let authed = mtls_authed_routes();
    apply_mtls_verify_bridge_for_test(authed)
}

#[allow(clippy::expect_used)]
fn internal_mtls_routes() -> httpserve::UnfinalizedRoutes {
    test_routes::<httpserve::Internal>(|rb| {
        rb.mount_internal_raw_for_test(
            Route {
                method: Method::GET,
                path: "/svc",
                contract_id: "test.internal.mtls",
            },
            httpserve::ServiceCallerPolicy::exact(
                "test.internal.mtls",
                vocab::ServiceCallerDomain::MaintenanceOperator,
            ),
            get(|| async { "ok" }),
        )
    })
}

#[allow(clippy::expect_used)]
fn internal_mtls_router_without_authorizer() -> httpserve::AuthenticatedRoutes {
    let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::Mtls).expect("plan");
    let authed = httpserve::finalize_auth(internal_mtls_routes(), plan).expect("finalize_auth");
    apply_mtls_verify_bridge_for_test(authed)
}

#[allow(clippy::expect_used)]
fn internal_mtls_router_with_authorizer(
    authorizer: Arc<dyn RouteAuthorizer>,
) -> httpserve::AuthenticatedRoutes {
    let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::Mtls).expect("plan");
    let authed = httpserve::finalize_auth_with_audit_and_authorizer(
        internal_mtls_routes(),
        plan,
        httpserve::AuditSinkHandle::new(RecordingAuditSink::default()),
        Arc::new(FixedClock(NOW)),
        authorizer,
    )
    .expect("finalize_auth_with_authorizer");
    apply_mtls_verify_bridge_for_test(authed)
}

#[allow(clippy::expect_used)]
fn internal_mtls_scope_router_with_authorizer(
    authorizer: Arc<dyn RouteAuthorizer>,
) -> httpserve::AuthenticatedRoutes {
    let routes = test_routes::<httpserve::Internal>(|rb| {
        rb.mount_internal_raw_for_test(
            Route {
                method: Method::GET,
                path: "/scope",
                contract_id: "test.internal.mtls.scope",
            },
            httpserve::ServiceCallerPolicy::exact(
                "test.internal.mtls.scope",
                vocab::ServiceCallerDomain::MaintenanceOperator,
            ),
            get(scope_probe),
        )
    });
    let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::Mtls).expect("plan");
    let authed = httpserve::finalize_auth_with_audit_and_authorizer(
        routes,
        plan,
        httpserve::AuditSinkHandle::new(RecordingAuditSink::default()),
        Arc::new(FixedClock(NOW)),
        authorizer,
    )
    .expect("finalize_auth_with_authorizer");
    apply_mtls_verify_bridge_for_test(authed)
}

#[allow(clippy::expect_used)]
fn verified_mtls_peer() -> authn::VerifiedMtlsPeer {
    let allow =
        authn::MtlsAllowSet::new(["spiffe://example.org/ns/rss/sa/internal"]).expect("allow-set");
    let id = authn::SpiffeId::parse("spiffe://example.org/ns/rss/sa/internal").expect("spiffe id");
    authn::verify_mtls_peer(id, &allow).expect("verified peer")
}

#[allow(clippy::expect_used)]
fn jwt_router_with_audit(sink: RecordingAuditSink) -> httpserve::AuthenticatedRoutes {
    let routes = test_routes::<httpserve::Primary>(|rb| {
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
    let authed = httpserve::finalize_primary_auth_with_audit(
        routes,
        plan,
        httpserve::AuditSinkHandle::new(sink),
        Arc::new(FixedClock(NOW)),
        allow_authorizer(),
    )
    .expect("finalize_auth_with_audit");
    apply_rss_access_verify_bridge_for_test(authed, Arc::new(es256_provider()), current_grants())
}

#[allow(clippy::unwrap_used)]
async fn status(
    app: httpserve::AuthenticatedRoutes,
    uri: &str,
    bearer: Option<&str>,
) -> StatusCode {
    status_with_tenant(app, uri, bearer, None).await
}

#[allow(clippy::unwrap_used)]
async fn status_with_tenant(
    app: httpserve::AuthenticatedRoutes,
    uri: &str,
    bearer: Option<&str>,
    tenant: Option<&str>,
) -> StatusCode {
    status_with_tenant_values(app, uri, bearer, tenant).await
}

#[allow(clippy::unwrap_used)]
async fn status_with_tenant_values<'a>(
    app: httpserve::AuthenticatedRoutes,
    uri: &str,
    bearer: Option<&str>,
    tenants: impl IntoIterator<Item = &'a str>,
) -> StatusCode {
    status_with_tenant_values_and_request_id(app, uri, bearer, tenants, None).await
}

#[allow(clippy::unwrap_used)]
async fn status_with_tenant_values_and_request_id<'a>(
    app: httpserve::AuthenticatedRoutes,
    uri: &str,
    bearer: Option<&str>,
    tenants: impl IntoIterator<Item = &'a str>,
    request_id: Option<&str>,
) -> StatusCode {
    let mut builder = axum::http::Request::builder().method(Method::GET).uri(uri);
    if let Some(value) = bearer {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    if let Some(value) = request_id {
        builder = builder.header("x-request-id", value);
    }
    for value in tenants {
        builder = builder.header(diport::SERVICE_TOKEN_TENANT_HEADER, value);
    }
    // 取回裸 Router 做 oneshot（`#[doc(hidden)]` 测试入口；生产经 into_make_service bind，无此出口）。
    let resp = app
        .into_router_for_test()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    resp.status()
}

async fn status_with_request_id(
    app: httpserve::AuthenticatedRoutes,
    uri: &str,
    bearer: Option<&str>,
    request_id: &str,
) -> StatusCode {
    status_with_tenant_values_and_request_id(
        app,
        uri,
        bearer,
        std::iter::empty::<&str>(),
        Some(request_id),
    )
    .await
}

#[allow(clippy::unwrap_used)]
async fn status_with_authorization_values<'a>(
    app: httpserve::AuthenticatedRoutes,
    uri: &str,
    values: impl IntoIterator<Item = &'a str>,
) -> StatusCode {
    let mut builder = axum::http::Request::builder().method(Method::GET).uri(uri);
    for value in values {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    let response = app
        .into_router_for_test()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    response.status()
}

// ── BODYLIMIT-BEFORE-AUTH-01 tripwire ───────────────────────────────────────────
/// INVARIANT: BODYLIMIT-BEFORE-AUTH-01 { level = "Medium", exec = "verify", source = "code" }tripwire：
/// JWT-scheme listener + 超大 Content-Length + 无 Authorization → 413（非 401）。
/// 证 body-limit（sealed_router 叠）outer 于验签桥 enforce——超大请求在 auth 验证前已被拦截。
#[tokio::test]
#[allow(clippy::expect_used, clippy::unwrap_used)]
async fn body_limit_blocks_before_jwt_auth_tripwire() {
    let authed = jwt_router(true).with_edge_hardening(httpserve::EdgeHardening {
        // reason: 10 is a known non-zero constant; unwrap is infallible.
        body_limit: httpserve::BodyLimit::new(std::num::NonZeroUsize::new(10).unwrap()), // 极小上限（10 bytes）
        headers: httpserve::SecurityHeaders::default(),
    });

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/protected")
        .header("content-length", "100") // 100 >> 10 limit，无 Authorization header
        .body(Body::empty())
        .unwrap();

    let resp = authed.into_router_for_test().oneshot(req).await.unwrap();
    // BODYLIMIT-BEFORE-AUTH-01：body-limit outer → 先拦截，响应 413 而非 401。
    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "BODYLIMIT-BEFORE-AUTH-01: body-limit outer 于 JWT auth → 非 401"
    );
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "BODYLIMIT-BEFORE-AUTH-01: 超大 CL + 无 auth → 413"
    );
}

// ── RATELIMIT-BEFORE-AUTH-01 tripwire ───────────────────────────────────────────
/// 恒返回 Limited 的测试限流器（tripwire 专用，已耗尽桶的语义等价物）。
struct AlwaysLimitedRateLimiter;

impl diport::RateLimiter for AlwaysLimitedRateLimiter {
    async fn check(
        &self,
        _key: diport::RateLimitKey,
    ) -> Result<diport::RateLimitDecision, diport::RateLimitError> {
        Ok(diport::RateLimitDecision::Limited {
            retry_after: std::time::Duration::from_secs(1),
        })
    }

    async fn shutdown(&self) -> Result<(), diport::RateLimitError> {
        Ok(())
    }
}

/// INVARIANT: RATELIMIT-BEFORE-AUTH-01 { level = "Medium", exec = "verify", source = "code" }tripwire：
/// JWT-scheme listener + 已耗尽限流器 + 无 Authorization → 429（非 401）。
/// 证 rate-limit（verify-bridge 后 .layer ⇒ outer 于桥）在 auth 计算前已拦截请求。
#[tokio::test]
#[allow(clippy::expect_used, clippy::unwrap_used)]
async fn rate_limit_blocks_before_jwt_auth_tripwire() {
    let limiter = Arc::new(AlwaysLimitedRateLimiter);
    // 在 verify-bridge 后叠 rate-limit（对应 assemble_authed_routers 中的叠加顺序）。
    let authed = jwt_router(true).layer(axum::middleware::from_fn_with_state(
        Arc::clone(&limiter),
        httpserve::rate_limit::<AlwaysLimitedRateLimiter>,
    ));

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/protected")
        // 无 Authorization header——rate-limit outer 应先触发 429，不到 401。
        .body(Body::empty())
        .unwrap();

    let resp = authed.into_router_for_test().oneshot(req).await.unwrap();
    // RATELIMIT-BEFORE-AUTH-01：rate-limit outer 于验签桥 → 先拦截，429 而非 401。
    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "RATELIMIT-BEFORE-AUTH-01: rate-limit outer 于 JWT auth → 非 401"
    );
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "RATELIMIT-BEFORE-AUTH-01: 已耗尽 limiter + 无 auth → 429"
    );
}

// ── 验收：成功路径 ────────────────────────────────────────────────────────────────
#[tokio::test]
async fn valid_jwt_is_200() {
    let token = production_user_jwt();
    assert_eq!(
        status(
            jwt_router(true),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::OK,
        "有效 JWT → 证据注入放行 200"
    );
}

#[tokio::test]
async fn rss_request_requires_current_durable_grant_and_exact_verified_binding() {
    let calls = Arc::new(AtomicUsize::new(0));
    let binding_matched = Arc::new(AtomicBool::new(false));
    let grants = recording_grants(
        GrantDecision::Current,
        Arc::clone(&calls),
        Arc::clone(&binding_matched),
    );
    let token = production_user_jwt();
    let response = status(
        jwt_router_with_grants(true, grants),
        "/protected",
        Some(&format!("Bearer {token}")),
    )
    .await;
    assert_eq!(response, StatusCode::OK);
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert!(binding_matched.load(Ordering::Acquire));
}

#[tokio::test]
async fn missing_revoked_expired_or_mismatched_grant_is_401() {
    let calls = Arc::new(AtomicUsize::new(0));
    let binding_matched = Arc::new(AtomicBool::new(false));
    let grants = recording_grants(
        GrantDecision::Invalid,
        Arc::clone(&calls),
        Arc::clone(&binding_matched),
    );
    let token = production_user_jwt();
    let response = status(
        jwt_router_with_grants(true, grants),
        "/protected",
        Some(&format!("Bearer {token}")),
    )
    .await;
    assert_eq!(response, StatusCode::UNAUTHORIZED);
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert!(binding_matched.load(Ordering::Acquire));
}

#[tokio::test]
async fn grant_store_outage_is_503_without_jwt_only_fallback() {
    let calls = Arc::new(AtomicUsize::new(0));
    let grants = recording_grants(
        GrantDecision::StoreUnavailable,
        Arc::clone(&calls),
        Arc::new(AtomicBool::new(false)),
    );
    let token = production_user_jwt();
    let response = jwt_router_with_grants(true, grants)
        .into_router_for_test()
        .oneshot(
            axum::http::Request::builder()
                .method(Method::GET)
                .uri("/protected")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("x-request-id", "grant-store-outage")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible router");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("bounded provider-unavailable envelope");
    let body: serde_json::Value =
        serde_json::from_slice(&bytes).expect("provider-unavailable envelope json");
    assert_eq!(body["error"]["code"], "ERR_CORE_PROVIDER_UNAVAILABLE");
    assert_eq!(body["error"]["requestId"], "grant-store-outage");
    assert_eq!(body["error"]["retryable"], true);
    assert_eq!(body["error"]["details"], serde_json::json!([]));
    assert_eq!(calls.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn crypto_rejection_happens_before_durable_grant_lookup() {
    let calls = Arc::new(AtomicUsize::new(0));
    let grants = recording_grants(
        GrantDecision::Current,
        Arc::clone(&calls),
        Arc::new(AtomicBool::new(false)),
    );
    let invalid = super_admin_jwt(&sk_other(), NOW + 900, ISS, AUD);
    let response = status(
        jwt_router_with_grants(true, grants),
        "/protected",
        Some(&format!("Bearer {invalid}")),
    )
    .await;
    assert_eq!(response, StatusCode::UNAUTHORIZED);
    assert_eq!(calls.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn valid_federated_access_token_is_200_on_federated_listener() {
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let token = federated_super_admin_jwt();
    let status = status(
        federated_router_with_calls(Arc::clone(&handler_calls)),
        "/federated",
        Some(&format!("Bearer {token}")),
    )
    .await;
    assert_eq!(
        (status, handler_calls.load(Ordering::Acquire)),
        (StatusCode::OK, 1)
    );
}

#[tokio::test]
async fn rss_access_token_is_rejected_by_federated_listener_before_handler() {
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let token = production_user_jwt();
    let status = status(
        federated_router_with_calls(Arc::clone(&handler_calls)),
        "/federated",
        Some(&format!("Bearer {token}")),
    )
    .await;
    assert_eq!(
        (status, handler_calls.load(Ordering::Acquire)),
        (StatusCode::UNAUTHORIZED, 0)
    );
}

#[tokio::test]
async fn federated_access_token_is_rejected_by_rss_listener() {
    let token = federated_super_admin_jwt();
    assert_eq!(
        status(
            jwt_router(true),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn user_jwt_with_tenant_via_production_builder_is_200() {
    // 评审 F2：经生产 builder（trusted-kind 注入）+ user kind + tenant → 200。若 F1 trusted-kind 缺失则 401 FAIL。
    let token = production_user_jwt();
    assert_eq!(
        status(
            jwt_router(true),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::OK,
        "user kind + tenant 经生产装配路径 → 200"
    );
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn user_jwt_records_auth_audit_principal_kind() {
    let sink = RecordingAuditSink::default();
    let token = production_user_jwt();
    assert_eq!(
        status(
            jwt_router_with_audit(sink.clone()),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::OK
    );

    let events = sink.events();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.principal_id, USER_ID);
    assert_eq!(format!("{:?}", event.principal_kind), "User");
    assert_eq!(
        event.tenant_id.expect("user auth audit tenant").to_string(),
        TENANT
    );
    assert_eq!(event.resource_id, "test.protected");
    assert_eq!(event.outcome, diport::AuditOutcome::Success);
}

// ── 验收：runctx ambient scope 建立（#1105，ADR-002 §D5） ──────────────────────────
//
// 验签桥得到带 tenant 的 scoped principal ⇒ `runctx::scope` 绑定下游全链；探针 handler 经
// `runctx::try_current()` 取回 ambient——证明「下游经 ambient 取已认证 tenant/principal」端到端成立
// （PR1 前全仓唯一 scope 是 audit 的 `#[tokio::test]`，生产路径从未建立）。两分支：scoped 主体（有 tenant）
// 建 scope / 跨租户主体（tenant=None）+ public 无凭据 不建 scope（fail-closed = MissingCtx）。

/// scope 探针响应：ambient 缺失时的 fail-closed 标记（≥3 处复用，抽 const）。
const SCOPE_MISSING: &str = "scope=missing";

/// 探针 handler：读 ambient `runctx`——经此断言验签桥已绑定 scope；缺 scope 时 fail-closed 落 [`SCOPE_MISSING`]。
async fn scope_probe() -> String {
    match runctx::try_current() {
        Ok(ctx) => format!(
            "tenant={};kind={:?};subject={}",
            ctx.tenant(),
            ctx.principal().kind(),
            ctx.principal().matches_subject(USER_ID) || ctx.principal().matches_subject("alice"),
        ),
        Err(_) => SCOPE_MISSING.to_string(),
    }
}

/// scope 探针 router：`/scope`（Require）+ `/scope-public`（Public opt-out），均挂 [`scope_probe`]，叠 es256 桥。
#[allow(clippy::expect_used)]
fn jwt_router_with_scope_probe() -> httpserve::AuthenticatedRoutes {
    let routes = test_routes::<httpserve::Primary>(|rb| {
        let rb = rb.mount_primary_raw_for_test(
            PrimaryRoute::permission(
                Method::GET,
                "/scope",
                "test.scope",
                RoutePermission {
                    permission: vocab::RoutePermissionId::IdentityPolicyRead,
                    scope: RouteResourceScope::None,
                },
            ),
            get(scope_probe),
        )?;
        rb.mount_primary_raw_for_test(
            PrimaryRoute::opt_out(
                Method::GET,
                "/scope-public",
                "test.scope.public",
                RouteAuthOptOut::Public,
            ),
            get(scope_probe),
        )
    });
    let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).expect("plan");
    let authed =
        httpserve::finalize_primary_auth(routes, plan, allow_authorizer()).expect("finalize_auth");
    apply_rss_access_verify_bridge_for_test(authed, Arc::new(es256_provider()), current_grants())
}

#[allow(clippy::expect_used)]
fn federated_router_with_scope_probe() -> httpserve::AuthenticatedRoutes {
    let routes = test_routes::<httpserve::Primary>(|router| {
        router.mount_primary_raw_for_test(
            PrimaryRoute::permission(
                Method::GET,
                "/scope",
                "test.scope.federated",
                RoutePermission {
                    permission: vocab::RoutePermissionId::IdentityPolicyRead,
                    scope: RouteResourceScope::None,
                },
            ),
            get(scope_probe),
        )
    });
    let plan =
        AuthPlan::new(ListenerKind::Primary, AuthScheme::FederatedAccessToken).expect("plan");
    let authed =
        httpserve::finalize_primary_auth(routes, plan, allow_authorizer()).expect("finalize_auth");
    apply_federated_access_verify_bridge_for_test(authed, Arc::new(federated_es256_provider()))
}

/// oneshot 取回 (status, body)（scope 探针断言响应体）。
#[allow(clippy::unwrap_used)]
async fn body_of(
    app: httpserve::AuthenticatedRoutes,
    uri: &str,
    bearer: Option<&str>,
) -> (StatusCode, String) {
    body_of_with_tenant(app, uri, bearer, None).await
}

#[allow(clippy::unwrap_used)]
async fn body_of_with_tenant(
    app: httpserve::AuthenticatedRoutes,
    uri: &str,
    bearer: Option<&str>,
    tenant: Option<&str>,
) -> (StatusCode, String) {
    let mut builder = axum::http::Request::builder().method(Method::GET).uri(uri);
    if let Some(value) = bearer {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    if let Some(value) = tenant {
        builder = builder.header(diport::SERVICE_TOKEN_TENANT_HEADER, value);
    }
    let resp = app
        .into_router_for_test()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    // size 上限 4096：探针响应是短串（<100B），上限即「超此即 bug」的 tripwire（非 usize::MAX 的无界）。
    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn user_jwt_establishes_runctx_scope_for_downstream() {
    // user JWT 带 tenant claim → 验签桥 runctx::scope 绑定 → 下游 handler 经 try_current() 取到已认证
    // tenant + principal facet（kind=User、受控 subject 匹配 alice）。
    let token = production_user_jwt();
    let (status, body) = body_of(
        jwt_router_with_scope_probe(),
        "/scope",
        Some(&format!("Bearer {token}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        format!("tenant={TENANT};kind=User;subject=true"),
        "下游须经 ambient runctx 取到已认证 tenant + facet（scope 已建立）"
    );
}

#[tokio::test]
async fn super_admin_jwt_without_tenant_leaves_scope_missing() {
    // 跨租户主体（superAdmin，tenant=None）→ 不建 scope → 下游 try_current() = MissingCtx（fail-closed）；
    // 仍放行（有证据）证明「不建 scope」≠「拒绝」。
    let token = federated_super_admin_jwt();
    let (status, body) = body_of(
        federated_router_with_scope_probe(),
        "/scope",
        Some(&format!("Bearer {token}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "superAdmin JWT 仍放行（证据在场）");
    assert_eq!(
        body, SCOPE_MISSING,
        "跨租户主体无单一 ambient tenant ⇒ 不建 scope（fail-closed）"
    );
}

#[tokio::test]
async fn device_jwt_establishes_runctx_scope_for_downstream() {
    // Device kind（scoped，带 tenant）走与 User 同一 allow_evidence 路径 → 建 scope（防 kind 差异化回归）。
    let token = production_device_jwt();
    let (status, body) = body_of(
        federated_router_with_scope_probe(),
        "/scope",
        Some(&format!("Bearer {token}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        format!("tenant={TENANT};kind=Device;subject=true"),
        "Device scoped 主体须建 ambient scope"
    );
}

#[tokio::test]
async fn admin_jwt_establishes_runctx_scope_for_downstream() {
    // Admin kind（scoped，带 tenant）同样建 scope——ABAC 最相关的 scoped 角色，确保非 User 的 scoped 路径也覆盖。
    let token = production_admin_jwt();
    let (status, body) = body_of(
        federated_router_with_scope_probe(),
        "/scope",
        Some(&format!("Bearer {token}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        format!("tenant={TENANT};kind=Admin;subject=true"),
        "Admin scoped 主体须建 ambient scope"
    );
}

#[tokio::test]
async fn public_route_without_token_has_no_scope() {
    // 无凭据 public 路由 → 无证据无 scope → 下游 try_current() = MissingCtx（public 路由本不该碰租户作用域 infra）。
    let (status, body) = body_of(jwt_router_with_scope_probe(), "/scope-public", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, SCOPE_MISSING, "无凭据请求无 ambient scope");
}

#[tokio::test]
async fn public_route_with_valid_bearer_has_no_scope() {
    // #1105 F2（核心回归）：Public 路由即便携**有效** Bearer 也不建 ambient scope。scope 由 enforce 仅在
    // Require-Allow 建立，Public opt-out（requirement=Allow）丢弃 PendingScopeCtx——防「Public handler 因
    // 携 Bearer 误绑 ambient tenant」。修复前（scope 在验签桥建）此用例会取到 tenant 而 FAIL。
    let token = production_user_jwt();
    let (status, body) = body_of(
        jwt_router_with_scope_probe(),
        "/scope-public",
        Some(&format!("Bearer {token}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body, SCOPE_MISSING,
        "Public 路由携有效 Bearer 仍不建 ambient scope（scope 与 route auth 决策对齐，F2）"
    );
}

#[tokio::test]
async fn lowercase_bearer_scheme_is_200() {
    // RFC 6750 §2.1：scheme 名大小写不敏感；bridge 接受 "bearer " 小写前缀。
    let token = production_user_jwt();
    assert_eq!(
        status(
            jwt_router(true),
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
    let token = production_user_jwt();
    assert_eq!(
        status(
            jwt_router(true),
            "/protected",
            Some(&format!("BEARER {token}"))
        )
        .await,
        StatusCode::OK,
        "大写 BEARER 前缀仍放行"
    );
}

#[tokio::test]
async fn yielding_pdp_valid_jwt_is_200() {
    let token = production_user_jwt();
    assert_eq!(
        status(
            jwt_router_with_pdp(YieldingRssPdp),
            "/protected",
            Some(&format!("Bearer {token}")),
        )
        .await,
        StatusCode::OK,
        "合法异步 PDP 首次 Pending 后恢复，仍须铸证据并放行"
    );
}

#[tokio::test]
async fn yielding_pdp_valid_service_token_is_200() {
    assert_eq!(
        status_with_tenant(
            service_token_router_with_pdp(YieldingServicePdp),
            "/svc",
            Some("Bearer yielding-service-token"),
            Some(TENANT),
        )
        .await,
        StatusCode::OK,
        "合法异步 service-token PDP 首次 Pending 后恢复，仍须铸证据并放行"
    );
}

#[tokio::test]
async fn yielding_pdp_error_is_401_and_never_runs_handler() {
    let token = production_user_jwt();
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let app = jwt_router_with_pdp_and_calls(YieldingErrorPdp, Arc::clone(&handler_calls));

    assert_eq!(
        status(app, "/protected", Some(&format!("Bearer {token}")),).await,
        StatusCode::UNAUTHORIZED,
        "异步 provider error 必须 fail-closed"
    );
    assert_eq!(handler_calls.load(Ordering::Acquire), 0);
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn server_budget_times_out_pending_pdp_as_503_and_drops_verifier() {
    fn assert_send<T: Send>(_: &T) {}

    let token = production_user_jwt();
    let entered = Arc::new(Notify::new());
    let dropped = Arc::new(AtomicBool::new(false));
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let app = jwt_router_with_pdp_and_calls(
        PendingPdp {
            entered,
            dropped: Arc::clone(&dropped),
        },
        Arc::clone(&handler_calls),
    );
    let budget = httpserve::ServerRequestBudget::from_millis(
        NonZeroU64::new(50).expect("non-zero test budget"),
    );
    let router = app.into_router_for_test_with_budget(budget);
    let request = router.oneshot(
        axum::http::Request::builder()
            .method(Method::GET)
            .uri("/protected")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header("x-request-id", "pending-pdp-budget")
            .body(Body::empty())
            .expect("request"),
    );
    assert_send(&request);

    let response = request.await.expect("infallible router");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("bounded timeout envelope");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("timeout envelope json");
    assert_eq!(body["error"]["code"], "ERR_CORE_UNAVAILABLE");
    assert_eq!(body["error"]["requestId"], "pending-pdp-budget");
    assert_eq!(body["error"]["retryable"], false);
    assert!(
        dropped.load(Ordering::Acquire),
        "server budget 必须 drop 在途 verifier future"
    );
    assert_eq!(handler_calls.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn cancelling_request_drops_inflight_verifier_without_authorizing() {
    let token = production_user_jwt();
    let entered = Arc::new(Notify::new());
    let entered_wait = entered.notified();
    let dropped = Arc::new(AtomicBool::new(false));
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let app = jwt_router_with_pdp_and_calls(
        PendingPdp {
            entered: Arc::clone(&entered),
            dropped: Arc::clone(&dropped),
        },
        Arc::clone(&handler_calls),
    );
    let request =
        tokio::spawn(
            async move { status(app, "/protected", Some(&format!("Bearer {token}"))).await },
        );

    assert!(
        tokio::time::timeout(Duration::from_secs(1), entered_wait)
            .await
            .is_ok(),
        "verifier 应进入 pending 状态"
    );
    assert!(!request.is_finished(), "请求必须仍在 await verifier");
    request.abort();
    assert!(
        matches!(request.await, Err(error) if error.is_cancelled()),
        "请求任务应被显式取消"
    );
    assert!(
        dropped.load(Ordering::Acquire),
        "request cancellation 必须传播为 verifier future drop"
    );
    assert_eq!(handler_calls.load(Ordering::Acquire), 0);
}

// ── 验收：拒绝路径全覆盖（均 401，由内层 enforce fail-closed 发出） ─────────────────
#[tokio::test]
async fn no_token_require_is_401() {
    assert_eq!(
        status(jwt_router(true), "/protected", None).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn duplicate_authorization_with_same_value_is_401_and_never_runs_handler() {
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let app = jwt_router_with_pdp_and_calls(YieldingRssPdp, Arc::clone(&handler_calls));
    let authorization = format!("Bearer {}", production_user_jwt());

    let status = status_with_authorization_values(
        app,
        "/protected",
        [authorization.as_str(), authorization.as_str()],
    )
    .await;
    assert_eq!(
        (status, handler_calls.load(Ordering::Acquire)),
        (StatusCode::UNAUTHORIZED, 0)
    );
}

#[tokio::test]
async fn duplicate_authorization_with_different_values_is_401_and_never_runs_handler() {
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let app = jwt_router_with_pdp_and_calls(YieldingRssPdp, Arc::clone(&handler_calls));
    let accepted_first = format!("Bearer {}", production_user_jwt());

    let status = status_with_authorization_values(
        app,
        "/protected",
        [accepted_first.as_str(), "Bearer ignored-second"],
    )
    .await;
    assert_eq!(
        (status, handler_calls.load(Ordering::Acquire)),
        (StatusCode::UNAUTHORIZED, 0)
    );
}

#[tokio::test]
async fn bad_signature_is_401() {
    // 用不在 provider 信任集的 key 签 → InvalidSignature → 无证据 → enforce 401。
    let token = super_admin_jwt(&sk_other(), NOW + 900, ISS, AUD);
    assert_eq!(
        status(
            jwt_router(true),
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
            jwt_router(true),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn wrong_audience_is_401() {
    let token = super_admin_jwt(&sk_jwt(), NOW + 900, ISS, "wrong-aud");
    assert_eq!(
        status(
            jwt_router(true),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn wrong_issuer_is_401() {
    let token = super_admin_jwt(&sk_jwt(), NOW + 900, "https://evil.issuer", AUD);
    assert_eq!(
        status(
            jwt_router(true),
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
    let token = mint_alg_none(&super_admin_payload(NOW + 900, ISS, AUD));
    assert_eq!(
        status(
            jwt_router(true),
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
    let token = mint_hs256(&[9u8; 32], &super_admin_payload(NOW + 900, ISS, AUD));
    assert_eq!(
        status(
            jwt_router(true),
            "/protected",
            Some(&format!("Bearer {token}"))
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "HS256 token 不被 JWT/ES256 listener 接受"
    );
}
#[tokio::test]
async fn jwt_evidence_cannot_satisfy_require_mtls() {
    // A valid RSS token is verified and mints RSS evidence, which cannot satisfy Require(Mtls).
    let token = production_user_jwt();
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let app = apply_rss_access_verify_bridge_for_test(
        mtls_authed_routes_with_calls(Arc::clone(&handler_calls)),
        Arc::new(es256_provider()),
        current_grants(),
    );
    assert_eq!(
        status(app, "/protected", Some(&format!("Bearer {token}"))).await,
        StatusCode::UNAUTHORIZED,
        "JWT evidence 不得通过 Require(Mtls)"
    );
    assert_eq!(handler_calls.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn service_token_evidence_cannot_satisfy_require_mtls() {
    let (provider, secret) = hs256_provider();
    let token = mint_hs256_bound(
        &secret,
        &service_token_payload(NOW + 300, SERVICE_CALLER_ALLOWED),
        TENANT,
    );
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let app = apply_service_token_verify_bridge_for_test(
        mtls_authed_routes_with_calls(Arc::clone(&handler_calls)),
        Arc::new(provider),
    );

    assert_eq!(
        status_with_tenant(
            app,
            "/protected",
            Some(&format!("Bearer {token}")),
            Some(TENANT)
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "ServiceToken evidence 不得通过 Require(Mtls)"
    );
    assert_eq!(handler_calls.load(Ordering::Acquire), 0);
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn verified_mtls_peer_satisfies_require_mtls() {
    let mut req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/protected")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(verified_mtls_peer());

    let resp = mtls_router()
        .into_router_for_test()
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "transport-injected VerifiedMtlsPeer passes Require(Mtls)"
    );
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn internal_mtls_requires_route_authorizer() {
    let mut req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/svc")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(verified_mtls_peer());

    let resp = internal_mtls_router_without_authorizer()
        .into_router_for_test()
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "mTLS evidence alone must not bypass route-level caller authorization"
    );
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn internal_mtls_route_authorizer_allows_verified_peer() {
    let mut req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/svc")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(verified_mtls_peer());

    let resp = internal_mtls_router_with_authorizer(allow_authorizer())
        .into_router_for_test()
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "mTLS Internal route must pass only after caller authorization"
    );
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn internal_mtls_verified_peer_remains_tenantless_scope() {
    let mut req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/scope")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(verified_mtls_peer());

    let resp = internal_mtls_scope_router_with_authorizer(allow_authorizer())
        .into_router_for_test()
        .oneshot(req)
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();

    assert_eq!(status, StatusCode::OK, "mTLS service principal is accepted");
    assert_eq!(
        body, SCOPE_MISSING,
        "mTLS/SPIFFE service identity is auth evidence, not a tenant source"
    );
}

// ── 安全同批门回归（ADR-006 §5 / tasks.md:14）：无注入方 ⇒ 即便有效 JWT，Require 仍 401 ──
#[tokio::test]
async fn no_bridge_require_still_401_even_with_valid_jwt() {
    let token = production_user_jwt();
    assert_eq!(
        status(
            jwt_router(false),
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
        status(jwt_router(true), "/public", None).await,
        StatusCode::OK,
        "Public(opt_out) 路由无 token 仍放行（bridge 不短路）"
    );
}

#[tokio::test]
async fn public_route_absent_authorization_is_anonymous_and_reaches_handler() {
    let pdp_calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let status = status(
        public_router_with_counters(Arc::clone(&pdp_calls), Arc::clone(&handler_calls)),
        "/public",
        None,
    )
    .await;
    assert_eq!(
        (
            status,
            pdp_calls.load(Ordering::Acquire),
            handler_calls.load(Ordering::Acquire)
        ),
        (StatusCode::OK, 0, 1)
    );
}

#[tokio::test]
async fn public_route_structurally_bad_authorization_is_401_before_pdp_or_handler() {
    let oversized = format!(
        "Bearer {}",
        "a".repeat(
            diport::TokenProfile::RssAccess
                .policy()
                .maximum_token_length()
                + 1
        )
    );
    let cases = [
        vec!["Bearer"],
        vec!["Bearer "],
        vec!["Basic dXNlcjpwYXNz"],
        vec!["Bearer duplicate", "Bearer duplicate"],
        vec!["Bearer first", "Bearer second"],
        vec![oversized.as_str()],
    ];
    for authorization_values in cases {
        let pdp_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let status = status_with_authorization_values(
            public_router_with_counters(Arc::clone(&pdp_calls), Arc::clone(&handler_calls)),
            "/public",
            authorization_values,
        )
        .await;
        assert_eq!(
            (
                status,
                pdp_calls.load(Ordering::Acquire),
                handler_calls.load(Ordering::Acquire)
            ),
            (StatusCode::UNAUTHORIZED, 0, 0)
        );
    }
}

#[tokio::test]
async fn public_route_structurally_valid_untrusted_bearer_still_reaches_handler() {
    let pdp_calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let status = status(
        public_router_with_counters(Arc::clone(&pdp_calls), Arc::clone(&handler_calls)),
        "/public",
        Some("Bearer structured.but.untrusted"),
    )
    .await;
    assert_eq!(
        (
            status,
            pdp_calls.load(Ordering::Acquire),
            handler_calls.load(Ordering::Acquire)
        ),
        (StatusCode::OK, 1, 1)
    );
}

// ── service-token / HS256 路径 happy（Internal listener） ─────────────────────────
#[tokio::test]
#[allow(clippy::expect_used)]
async fn service_token_hs256_is_200() {
    let (provider, secret) = hs256_provider();
    let token = mint_hs256_bound(
        &secret,
        &service_token_payload(NOW + 300, SERVICE_CALLER_ALLOWED),
        TENANT,
    );
    let app = service_token_router_with_pdp(provider);
    assert_eq!(
        status_with_tenant(app, "/svc", Some(&format!("Bearer {token}")), Some(TENANT)).await,
        StatusCode::OK,
        "有效 HS256 service-token + matching X-Tenant-ID → 证据注入放行 200"
    );
}

#[tokio::test]
async fn service_caller_policy_allows_the_exact_verified_caller() {
    let (provider, secret) = hs256_provider();
    let token = production_service_token(&secret);
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let app = service_token_router_with_policy_and_calls(
        provider,
        Some(httpserve::ServiceCallerPolicy::exact(
            "test.svc.policy",
            vocab::ServiceCallerDomain::MaintenanceOperator,
        )),
        Arc::clone(&handler_calls),
    );
    let status = status_with_tenant(
        app,
        "/svc-policy",
        Some(&format!("Bearer {token}")),
        Some(TENANT),
    )
    .await;
    assert_eq!(
        (status, handler_calls.load(Ordering::Acquire)),
        (StatusCode::OK, 1)
    );
}

#[tokio::test]
async fn service_token_route_without_caller_policy_fails_closed_before_handler() {
    let (provider, secret) = hs256_provider();
    let token = mint_hs256_bound(
        &secret,
        &service_token_payload(NOW + 300, SERVICE_CALLER_ALLOWED),
        TENANT,
    );
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let app =
        service_token_router_with_policy_and_calls(provider, None, Arc::clone(&handler_calls));
    let status = status_with_tenant(
        app,
        "/svc-policy",
        Some(&format!("Bearer {token}")),
        Some(TENANT),
    )
    .await;
    assert_eq!(
        (status, handler_calls.load(Ordering::Acquire)),
        (StatusCode::FORBIDDEN, 0)
    );
}

#[tokio::test]
async fn signed_service_token_with_subject_outside_closed_caller_set_is_401() {
    let (provider, secret) = hs256_provider();
    let token = mint_hs256_bound(
        &secret,
        &service_token_payload(NOW + 300, "arbitrary-service"),
        TENANT,
    );
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let app = service_token_router_with_policy_and_calls(
        provider,
        Some(httpserve::ServiceCallerPolicy::exact(
            "test.svc.policy",
            vocab::ServiceCallerDomain::MaintenanceOperator,
        )),
        Arc::clone(&handler_calls),
    );
    let status = status_with_tenant(
        app,
        "/svc-policy",
        Some(&format!("Bearer {token}")),
        Some(TENANT),
    )
    .await;
    assert_eq!(
        (status, handler_calls.load(Ordering::Acquire)),
        (StatusCode::UNAUTHORIZED, 0)
    );
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn service_token_missing_or_wrong_tenant_header_is_401() {
    let (provider, secret) = hs256_provider();
    let token = mint_hs256_bound(
        &secret,
        &service_token_payload(NOW + 300, SERVICE_CALLER_ALLOWED),
        TENANT,
    );
    let make_authed = || {
        let routes = test_routes::<httpserve::Internal>(|rb| {
            rb.mount_internal_raw_for_test(
                Route {
                    method: Method::GET,
                    path: "/svc",
                    contract_id: "test.svc",
                },
                httpserve::ServiceCallerPolicy::exact(
                    "test.svc",
                    vocab::ServiceCallerDomain::MaintenanceOperator,
                ),
                get(|| async { "ok" }),
            )
        });
        let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::ServiceToken).expect("plan");
        httpserve::finalize_auth(routes, plan).expect("finalize_auth")
    };
    let authed = make_authed();
    let bearer = format!("Bearer {token}");
    assert_eq!(
        status_with_tenant(
            apply_service_token_verify_bridge_for_test(authed, Arc::new(provider)),
            "/svc",
            Some(&bearer),
            None,
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "缺 X-Tenant-ID 不得通过 service-token 验签"
    );

    let (provider, _) = hs256_provider();
    let authed = make_authed();
    assert_eq!(
        status_with_tenant(
            apply_service_token_verify_bridge_for_test(authed, Arc::new(provider)),
            "/svc",
            Some(&bearer),
            Some(OTHER_TENANT),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "跨 tenant replay 必须 401"
    );
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn service_token_duplicate_tenant_header_is_401() {
    let (provider, secret) = hs256_provider();
    let token = mint_hs256_bound(
        &secret,
        &service_token_payload(NOW + 300, SERVICE_CALLER_ALLOWED),
        TENANT,
    );
    let routes = test_routes::<httpserve::Internal>(|rb| {
        rb.mount_internal_raw_for_test(
            Route {
                method: Method::GET,
                path: "/svc",
                contract_id: "test.svc",
            },
            httpserve::ServiceCallerPolicy::exact(
                "test.svc",
                vocab::ServiceCallerDomain::MaintenanceOperator,
            ),
            get(|| async { "ok" }),
        )
    });
    let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::ServiceToken).expect("plan");
    let authed = httpserve::finalize_auth(routes, plan).expect("finalize_auth");
    let app = apply_service_token_verify_bridge_for_test(authed, Arc::new(provider));
    assert_eq!(
        status_with_tenant_values(
            app,
            "/svc",
            Some(&format!("Bearer {token}")),
            [TENANT, OTHER_TENANT],
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "重复 X-Tenant-ID 不得由 bridge 选一个值验签"
    );
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn service_token_establishes_scope_from_mac_bound_tenant() {
    // service 主体自身仍 tenant=None；ambient scope 来自已 MAC 认证的 canonical `X-Tenant-ID`。
    let (provider, secret) = hs256_provider();
    let token = mint_hs256_bound(
        &secret,
        &service_token_payload(NOW + 300, SERVICE_CALLER_ALLOWED),
        TENANT,
    );
    let routes = test_routes::<httpserve::Internal>(|rb| {
        rb.mount_internal_raw_for_test(
            Route {
                method: Method::GET,
                path: "/scope",
                contract_id: "test.svc.scope",
            },
            httpserve::ServiceCallerPolicy::exact(
                "test.svc.scope",
                vocab::ServiceCallerDomain::MaintenanceOperator,
            ),
            get(scope_probe),
        )
    });
    let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::ServiceToken).expect("plan");
    let authed = httpserve::finalize_auth(routes, plan).expect("finalize_auth");
    let app = apply_service_token_verify_bridge_for_test(authed, Arc::new(provider));
    let (status, body) = body_of_with_tenant(
        app,
        "/scope",
        Some(&format!("Bearer {token}")),
        Some(TENANT),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "service-token 仍放行（证据在场）");
    assert_eq!(
        body,
        format!("tenant={TENANT};kind=Service;subject=false"),
        "service-token MAC 绑定 tenant 须进入 ambient scope"
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
fn global_trace_buf() -> &'static Arc<Mutex<Vec<u8>>> {
    static BUF: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    BUF.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
}

fn tracing_capture_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[allow(clippy::expect_used)]
fn ensure_global_trace_capture() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let sub = tracing_subscriber::fmt()
            .with_writer(VecWriter(global_trace_buf().clone()))
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        tracing::subscriber::set_global_default(sub).expect("install test tracing subscriber");
    });
    tracing::callsite::rebuild_interest_cache();
}

#[allow(clippy::unwrap_used)]
fn trace_len() -> usize {
    global_trace_buf()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len()
}

#[allow(clippy::unwrap_used)]
fn captured_since(start: usize) -> String {
    let guard = global_trace_buf().lock().unwrap_or_else(|e| e.into_inner());
    String::from_utf8(guard[start..].to_vec()).unwrap()
}

fn logs_for_request(logs: &str, request_id: &str) -> String {
    logs.lines()
        .filter(|line| line.contains(request_id))
        .collect::<Vec<_>>()
        .join("\n")
}

#[allow(clippy::unwrap_used)]
fn block_on_current_thread<T>(fut: impl std::future::Future<Output = T>) -> T {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(fut)
}

#[test]
#[allow(clippy::unwrap_used)]
fn tracing_allow_logs_decision_and_kind_no_pii() {
    let _capture_guard = tracing_capture_lock().lock().unwrap();
    ensure_global_trace_capture();

    let token = production_user_jwt();
    let request_id = "trace-allow-rss-user";
    let start = trace_len();
    let st = block_on_current_thread(status_with_request_id(
        jwt_router(true),
        "/protected",
        Some(&format!("Bearer {token}")),
        request_id,
    ));
    assert_eq!(st, StatusCode::OK);

    let captured = captured_since(start);
    let logs = logs_for_request(&captured, request_id);
    assert!(
        logs.contains("authz.decision"),
        "须记结构化字段键 authz.decision: {logs}"
    );
    assert!(logs.contains("allow"), "allow 决策: {logs}");
    assert!(logs.contains("User"), "须记脱敏 principal.kind: {logs}");
    assert!(
        logs.contains("verify_bridge"),
        "须有 verify_bridge span: {logs}"
    );
    assert!(!logs.contains(USER_ID), "禁泄漏 subject: {logs}");
    assert!(!logs.contains(&token), "禁泄漏原始 token: {logs}");
}

#[test]
#[allow(clippy::unwrap_used)]
fn tracing_yielding_provider_error_keeps_span_and_redacts_pii() {
    let _capture_guard = tracing_capture_lock().lock().unwrap();
    ensure_global_trace_capture();

    let token = "async-token-canary.subject-canary.claims-canary";
    let tenant = "tenant-canary";
    let request_id = "trace-yielding-provider-error";
    let start = trace_len();
    let st = block_on_current_thread(status_with_tenant_values_and_request_id(
        jwt_router_with_pdp(YieldingErrorPdp),
        "/protected",
        Some(&format!("Bearer {token}")),
        [tenant],
        Some(request_id),
    ));
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let captured = captured_since(start);
    let logs = logs_for_request(&captured, request_id);
    assert!(
        logs.contains("verify_bridge"),
        "Pending 后须保留 span: {logs}"
    );
    assert!(logs.contains("deny"), "provider error 须记 deny: {logs}");
    assert!(logs.contains("untrusted"), "须只记闭值 reason: {logs}");
    for canary in [token, "subject-canary", "claims-canary", tenant] {
        assert!(!logs.contains(canary), "禁泄漏 PII canary {canary}: {logs}");
    }
}

#[test]
#[allow(clippy::expect_used, clippy::unwrap_used)]
fn provider_outage_returns_retryable_503_envelope_and_redacts_pii() {
    let _capture_guard = tracing_capture_lock().lock().unwrap();
    ensure_global_trace_capture();

    let token = "outage-token-canary.subject-canary.claims-canary";
    let tenant = "outage-tenant-canary";
    let request_id = "trace-provider-unavailable";
    let start = trace_len();
    let response = block_on_current_thread(async {
        jwt_router_with_pdp(ProviderUnavailablePdp)
            .into_router_for_test()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri("/protected")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(diport::SERVICE_TOKEN_TENANT_HEADER, tenant)
                    .header("x-request-id", request_id)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("infallible router")
    });
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = block_on_current_thread(async {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("503 body")
    });
    let body = String::from_utf8(body.to_vec()).expect("utf8 error envelope");
    assert!(
        body.contains("ERR_CORE_PROVIDER_UNAVAILABLE"),
        "503 envelope: {body}"
    );
    assert!(body.contains("\"retryable\":true"), "retryable 503: {body}");
    assert!(body.contains(request_id), "request id correlation: {body}");

    let captured = captured_since(start);
    let logs = logs_for_request(&captured, request_id);
    assert!(
        logs.contains("provider_unavailable"),
        "closed reason: {logs}"
    );
    assert!(
        logs.contains("ProviderUnavailable"),
        "operator error variant remains distinct: {logs}"
    );
    for canary in [token, "subject-canary", "claims-canary", tenant] {
        assert!(
            !logs.contains(canary),
            "provider outage leaked {canary}: {logs}"
        );
    }
}

#[test]
#[allow(clippy::expect_used, clippy::unwrap_used)]
fn tracing_server_budget_timeout_uses_closed_reason_and_redacts_pii() {
    let _capture_guard = tracing_capture_lock().lock().unwrap();
    ensure_global_trace_capture();

    let token = "timeout-token-canary.claims-canary";
    let tenant = "timeout-tenant-canary";
    let request_id = "trace-server-budget-timeout";
    let dropped = Arc::new(AtomicBool::new(false));
    let app = jwt_router_with_pdp(PendingPdp {
        entered: Arc::new(Notify::new()),
        dropped: Arc::clone(&dropped),
    });
    let budget = httpserve::ServerRequestBudget::from_millis(
        NonZeroU64::new(20).expect("non-zero test budget"),
    );
    let start = trace_len();
    let status = block_on_current_thread(async move {
        app.into_router_for_test_with_budget(budget)
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri("/protected")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(diport::SERVICE_TOKEN_TENANT_HEADER, tenant)
                    .header("x-request-id", request_id)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("infallible router")
            .status()
    });
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(dropped.load(Ordering::Acquire));

    let captured = captured_since(start);
    let logs = logs_for_request(&captured, request_id);
    assert!(
        logs.contains("server_request_budget_exhausted"),
        "timeout must use the closed reason: {logs}"
    );
    assert!(logs.contains("unavailable"), "closed decision: {logs}");
    for canary in [token, "claims-canary", tenant] {
        assert!(
            !logs.contains(canary),
            "timeout telemetry leaked {canary}: {logs}"
        );
    }
}

/// 四路 deny 分级（#1275 + review F1，spec SC-006/FR-009）：deny 路 tracing 须按 deny 来源记不同
/// `authz.deny_reason` 闭值 **+ 对应 `AuthnError` 变体**（`error=?err`），且均无 PII（无 token / subject）：
///   坏签名（PDP `InvalidSignature`）          → `signature_invalid` / `TokenInvalid`；
///   错 issuer（PDP `Untrusted`）              → `untrusted`         / `TokenUntrusted`；
///   过期（PDP `Expired`）                     → `expired`           / `TokenExpired`；
///   **验签通过但缺 tenant**（authn 派生失败）  → `principal_invalid` / `PrincipalInvalid`。
/// 末路是 review F1 回归锚：验签**通过后**的良性 principal 失败**不得**误报成 `signature_invalid` 攻击信号。
/// 复用既有拒绝路径 token 构造（`bad_signature_is_401` / `wrong_issuer_is_401` / `expired_is_401`）。
#[test]
#[allow(clippy::unwrap_used)]
fn tracing_deny_logs_per_variant_reason_no_pii() {
    let _capture_guard = tracing_capture_lock().lock().unwrap();
    ensure_global_trace_capture();
    // 签名正确但 scoped kind 缺 tenant_id：typed verifier 在铸 Principal 前拒绝为 TokenInvalid。
    let scoped_tenant_invalid_jwt = mint_es256(
        &sk_jwt(),
        &format!(
            r#"{{"sub":"alice","iat":{},"exp":{},"iss":"{ISS}","aud":"{AUD}","token_use":"access","kind":"user"}}"#,
            NOW,
            NOW + 900
        ),
    );
    for (token, want_reason, want_variant, label) in [
        (
            super_admin_jwt(&sk_other(), NOW + 900, ISS, AUD),
            "signature_invalid",
            "TokenInvalid",
            "坏签名→InvalidSignature",
        ),
        (
            super_admin_jwt(&sk_jwt(), NOW + 900, "https://evil.issuer", AUD),
            "untrusted",
            "TokenUntrusted",
            "错 issuer→Untrusted",
        ),
        (
            super_admin_jwt(&sk_jwt(), NOW - 3600, ISS, AUD),
            "expired",
            "TokenExpired",
            "过期→Expired",
        ),
        (
            scoped_tenant_invalid_jwt.clone(),
            "signature_invalid",
            "TokenInvalid",
            "scoped token 缺 tenant→TokenInvalid",
        ),
    ] {
        let request_id = format!("trace-deny-{want_reason}");
        let start = trace_len();
        let st = block_on_current_thread(status_with_request_id(
            jwt_router(true),
            "/protected",
            Some(&format!("Bearer {token}")),
            &request_id,
        ));
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{label}");

        let captured = captured_since(start);
        let logs = logs_for_request(&captured, &request_id);
        assert!(
            logs.contains("authz.decision"),
            "{label}: 须记结构化字段键 authz.decision: {logs}"
        );
        assert!(logs.contains("deny"), "{label}: deny 决策: {logs}");
        assert!(
            logs.contains("authz.deny_reason"),
            "{label}: 须记结构化字段键 authz.deny_reason（闭值告警分级）: {logs}"
        );
        assert!(
            logs.contains(want_reason),
            "{label}: 须记闭值 deny_reason={want_reason}: {logs}"
        );
        // review F2：守 `error=?err` 仍记 `AuthnError` 变体（若 error 字段被移除，此断言 FAIL）。
        assert!(
            logs.contains(want_variant),
            "{label}: 须记 AuthnError 变体 {want_variant}（error=?err）: {logs}"
        );
        assert!(!logs.contains(&token), "{label}: 禁泄漏原始 token: {logs}");
        assert!(!logs.contains("alice"), "{label}: 禁泄漏 subject: {logs}");
    }
}

#[test]
#[allow(clippy::expect_used, clippy::unwrap_used)]
fn tracing_service_token_binding_error_has_distinct_reason_no_pii() {
    let _capture_guard = tracing_capture_lock().lock().unwrap();
    ensure_global_trace_capture();
    let (provider, secret) = hs256_provider();
    let token = mint_hs256_bound(
        &secret,
        &service_token_payload(NOW + 300, SERVICE_CALLER_ALLOWED),
        TENANT,
    );
    let routes = test_routes::<httpserve::Internal>(|rb| {
        rb.mount_internal_raw_for_test(
            Route {
                method: Method::GET,
                path: "/svc",
                contract_id: "test.svc",
            },
            httpserve::ServiceCallerPolicy::exact(
                "test.svc",
                vocab::ServiceCallerDomain::MaintenanceOperator,
            ),
            get(|| async { "ok" }),
        )
    });
    let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::ServiceToken).expect("plan");
    let authed = httpserve::finalize_auth(routes, plan).expect("finalize_auth");
    let app = apply_service_token_verify_bridge_for_test(authed, Arc::new(provider));

    let request_id = "trace-service-token-binding";
    let start = trace_len();
    let st = block_on_current_thread(status_with_request_id(
        app,
        "/svc",
        Some(&format!("Bearer {token}")),
        request_id,
    ));
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let captured = captured_since(start);
    let logs = logs_for_request(&captured, request_id);
    assert!(
        logs.contains("tenant_binding_invalid"),
        "service-token binding parser failure must have its own deny reason: {logs}"
    );
    assert!(
        !logs.contains("signature_invalid"),
        "service-token binding parser failure must not be reported as signature_invalid: {logs}"
    );
    assert!(!logs.contains(&token), "禁泄漏原始 token: {logs}");
    assert!(!logs.contains(TENANT), "禁泄漏 tenant header 值: {logs}");
}
