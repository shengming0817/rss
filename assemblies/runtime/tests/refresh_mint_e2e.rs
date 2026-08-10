//! mint→verify 端到端（#1252）：vault `Signer`（wiremock Transit `/sign`，动态 ES256 签）经
//! `authn::JwtIssuer` 铸 access JWT，真 `OidcProvider` 经**生产** `apply_verify_bridge` 验签放行。
//!
//! 这是单 crate 测试无法覆盖的跨组件闭环：vault adapter（HTTP 编解 + `vault:vN:` 解码）+ authn（claims
//! 组装 + JWS 紧凑序列化）+ oidc adapter（ES256 验签 + Principal 派生）三方同链。hermetic：wiremock 模拟
//! vault Transit（无 live vault / 无 DB），mock 用与 oidc 信任公钥**匹配**的 P-256 私钥动态签 signing-input。
//!
//! 覆盖：① vault-签的 access JWT 经 oidc 桥 → 200（sign→verify 闭环）；② `MintedJwt::expires_at()` 权威
//! exp = NOW+ttl；③ 篡改签名 → 401（anti-vacuity：验签真实生效，非恒放行）。
//!
//! ref: ory/fosite handler/oauth2/flow_refresh.go@master（refresh rotation 先 mint 后 CAS，概念谱系）
//! ref: jmgilman/vaultrs vaultrs/src/api/transit/requests.rs@master（Transit `sign`：`{mount}/sign/{name}` + base64 input）

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, StatusCode, header};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use eventexec::event::ReviewedEvent;
use httpserve::{
    ProducerMarker, RouteAuthorizationDecision, RouteAuthorizationRequest, RouteAuthorizer,
    TestPrimaryRoute as PrimaryRoute, TestRoutePermission as RoutePermission,
    TestRouteResourceScope as RouteResourceScope,
};
use identity::ports::{
    AccountSecurityReadRepo, AccountSecuritySnapshot, AccountSecurityState, AccountStatus,
    AccountStatusSetCommand, AccountStatusSetProducerReceipt, AuthGrantLifecycle,
    CredentialSecurityReceipt, IdentityError, IdentitySecurityLifecycle, LoginGrantMutation,
    LoginProducerReceipt, LogoutAllCommand, LogoutAllProducerReceipt, LogoutCurrentCommand,
    LogoutCurrentProducerReceipt, PasswordChangeCommand, PasswordChangeProducerReceipt,
    RefreshExecutionCommand, RefreshExecutionOutcome, RefreshProducerReceipt, RefreshStatus,
    RefreshTokenHash, RefreshTokenId, RefreshTokenRecord, RefreshTokenSnapshot, RefreshTokenStore,
    SECURITY_EVENT_CONTRACT, SECURITY_EVENT_FACT, TenantRepoScope,
};
use oidc::OidcProvider;
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use primitives::{AuthPlan, AuthScheme, ListenerKind};
use runtime::auth_bridge::apply_rss_access_verify_bridge_for_test;
use runtime::{
    KeyedEs256StaticKey, RssAccessStaticProviderConfig, rss_access_provider_from_static_config,
};
use tower::ServiceExt as _;
use vault::VaultSigner;
use wiremock::matchers::{body_partial_json, method as match_method};
use wiremock::{Mock, MockServer, Request as MockRequest, Respond, ResponseTemplate};

/// 合法测试租户（`user` kind 需 tenant；canonical UUID，与 oidc 验签侧默认 `tenant_id` claim 对齐）。
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const USER_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const ISS: &str = "https://issuer.test";
const AUD: &str = "rss-test";
const NOW: i64 = 1_700_000_000;
const TTL_SECS: u64 = 900;
/// JOSE `kid` = vault Transit sign key 名（mock 不校验 key 名，仅证 issuer 把 kid 注入 header）。
const KEY_ID: &str = "rss-jwt-es256";
const PRESENTED_REFRESH: &str = "runtime-refresh-before-commit";

#[derive(Clone, Copy)]
enum RefreshSettlement {
    ReuseContained,
    Internal,
    CommitUnknown,
}

#[derive(Clone)]
struct RefreshBackend {
    grant: authn::AuthGrant,
    record: RefreshTokenRecord,
    account: AccountSecurityState,
    settlement: RefreshSettlement,
}

fn identity_storage_error(message: &'static str) -> IdentityError {
    IdentityError::Storage(Box::new(std::io::Error::other(message)))
}

impl RefreshTokenStore for RefreshBackend {
    async fn find_by_hash(
        &self,
        scope: TenantRepoScope,
        hash: RefreshTokenHash,
    ) -> Result<Option<RefreshTokenRecord>, IdentityError> {
        Ok(
            (scope.tenant() == self.record.tenant() && self.record.token_hash() == &hash)
                .then(|| self.record.clone()),
        )
    }
}

impl AuthGrantLifecycle for RefreshBackend {
    async fn persist_login_grant(
        &self,
        _receipt: LoginProducerReceipt,
        _scope: TenantRepoScope,
        _mutation: LoginGrantMutation,
        _event: ReviewedEvent,
    ) -> Result<identity::ports::PersistedLoginGrantReceipt, diport::OutboxEmitError> {
        Err(diport::OutboxEmitError::new(std::io::Error::other(
            "refresh-only runtime backend",
        )))
    }

    async fn find_active(
        &self,
        scope: TenantRepoScope,
        grant_id: authn::AuthGrantId,
        observed_at: SystemTime,
    ) -> Result<Option<authn::AuthGrant>, IdentityError> {
        Ok((scope.tenant() == self.grant.tenant()
            && self.grant.id() == &grant_id
            && self.grant.expires_at() > observed_at)
            .then(|| self.grant.clone()))
    }
}

impl AccountSecurityReadRepo for RefreshBackend {
    async fn find(
        &self,
        scope: TenantRepoScope,
        user_id: ids::UserId,
    ) -> Result<Option<AccountSecurityState>, IdentityError> {
        Ok(
            (scope.tenant() == self.account.tenant() && user_id == self.account.user_id())
                .then(|| self.account.clone()),
        )
    }
}

impl IdentitySecurityLifecycle for RefreshBackend {
    async fn execute_refresh(
        &self,
        receipt: RefreshProducerReceipt,
        _scope: TenantRepoScope,
        _command: RefreshExecutionCommand,
    ) -> Result<RefreshExecutionOutcome, IdentityError> {
        let _authorization = receipt
            .authorize(SECURITY_EVENT_FACT, SECURITY_EVENT_CONTRACT)
            .ok_or_else(|| identity_storage_error("refresh receipt rejected"))?;
        match self.settlement {
            RefreshSettlement::ReuseContained => Ok(RefreshExecutionOutcome::ReuseContained),
            RefreshSettlement::Internal => Err(identity_storage_error("internal settlement")),
            RefreshSettlement::CommitUnknown => Err(identity_storage_error("commit unknown")),
        }
    }

    async fn execute_password_change(
        &self,
        _receipt: PasswordChangeProducerReceipt,
        _scope: TenantRepoScope,
        _command: PasswordChangeCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        Err(identity_storage_error("unsupported password change"))
    }

    async fn execute_account_status_set(
        &self,
        _receipt: AccountStatusSetProducerReceipt,
        _scope: TenantRepoScope,
        _command: AccountStatusSetCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        Err(identity_storage_error("unsupported account status"))
    }

    async fn execute_logout_current(
        &self,
        _receipt: LogoutCurrentProducerReceipt,
        _scope: TenantRepoScope,
        _command: LogoutCurrentCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        Err(identity_storage_error("unsupported logout current"))
    }

    async fn execute_logout_all(
        &self,
        _receipt: LogoutAllProducerReceipt,
        _scope: TenantRepoScope,
        _command: LogoutAllCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        Err(identity_storage_error("unsupported logout all"))
    }
}

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

/// 注入时钟替身（确定性 iat/exp；非系统时钟）。
struct FixedClock(i64);
impl diport::Clock for FixedClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0 as u64)
    }
}

// ── 测试 P-256 key（mock vault 签私钥 == oidc 信任公钥来源，dev-only） ─────────────────
#[allow(clippy::expect_used)]
fn sk_jwt() -> SigningKey {
    let bytes: [u8; 32] = std::array::from_fn(|i| (i + 1) as u8);
    SigningKey::from_slice(&bytes).expect("valid P-256 scalar")
}
fn sec1(sk: &SigningKey) -> Vec<u8> {
    sk.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

/// wiremock Transit `/sign` 响应器：解 `{"input": base64std(signing_input)}` → 用 `sk` 对 signing-input
/// 字节做 ES256 签（r‖s 64B，JWS marshaling）→ 回 `{"data":{"signature":"vault:v1:<base64std(r‖s)>"}}`
/// （镜像真实 vault Transit）。动态签：signing-input 含 issuer 内部计算的 iat/exp，无法预制。
struct TransitSignResponder {
    sk: SigningKey,
}

impl Respond for TransitSignResponder {
    #[allow(clippy::expect_used)]
    fn respond(&self, req: &MockRequest) -> ResponseTemplate {
        let body: serde_json::Value =
            serde_json::from_slice(&req.body).expect("mock vault: request body is json");
        let input_b64 = body["input"]
            .as_str()
            .expect("mock vault: transit sign body has string input");
        let message = B64_STD
            .decode(input_b64)
            .expect("mock vault: input is standard base64");
        // ES256 over signing-input bytes（p256 内部 SHA-256 prehash）；to_bytes() = 定长 r‖s（JWS 形态）。
        // 真 vault `marshaling_algorithm=jws` 输出 **URL-safe** base64（非 standard）——mock 同形，
        // VaultSigner(Jws) 按 url-safe 解码（默认 asn1 会返 DER + std base64，oidc 验签失败，故必须 jws）。
        let sig: Signature = self.sk.sign(&message);
        let tagged = format!("vault:v1:{}", B64_URL.encode(sig.to_bytes()));
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({ "data": { "signature": tagged } }))
    }
}

/// 经 `new_allow_http`（mock 是 http）+ 注入 mock URI 构造 RSS access issuer（ES256，FixedClock）。
#[allow(clippy::expect_used)]
fn vault_jwt_issuer(vault_uri: &str) -> authn::JwtIssuer<diport::RssAccessProfile, VaultSigner> {
    let signer = VaultSigner::new_rss_access_allow_http(
        reqwest::Client::new(),
        vault_uri,
        "test-vault-token",
        "transit",
        Duration::from_secs(5),
        diport::JwtSigningBinding::rss_access(diport::KeyId::new(KEY_ID)),
    )
    .expect("vault signer (dev http)");
    authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
        Arc::new(signer),
        Box::new(FixedClock(NOW)),
        authn::JwtIssuerConfig::rss_access(
            authn::SigningKeyRing::single(diport::KeyId::new(KEY_ID))
                .expect("non-empty signing key id"),
            ISS,
            AUD,
            Duration::from_secs(TTL_SECS),
        ),
    )
    .expect("jwt issuer config")
}

#[allow(clippy::expect_used)]
fn refresh_backend(settlement: RefreshSettlement) -> RefreshBackend {
    let tenant = vocab::TenantId::parse(TENANT).expect("tenant");
    let user_id = ids::UserId::parse(USER_ID).expect("user");
    let epoch = authn::AuthnEpoch::hydrate(5).expect("epoch");
    let issued_at = UNIX_EPOCH + Duration::from_secs((NOW - 30) as u64);
    let expires_at = UNIX_EPOCH + Duration::from_secs((NOW + 3_600) as u64);
    let grant = authn::AuthGrant::new_active(
        tenant,
        user_id,
        UNIX_EPOCH + Duration::from_secs((NOW - 60) as u64),
        epoch,
        expires_at,
        issued_at,
    )
    .expect("active grant");
    let refresh_id = RefreshTokenId::hydrate("aaaaaaaa-0001-4000-8000-000000000001");
    let record = RefreshTokenRecord::hydrate(RefreshTokenSnapshot {
        id: refresh_id.clone(),
        tenant,
        auth_grant_id: grant.id().clone(),
        user_id,
        authn_epoch_at_issue: epoch,
        auth_grant_status: authn::AuthGrantStatus::Active,
        token_hash: RefreshTokenHash::hydrate(secure::digest(PRESENTED_REFRESH)),
        parent_id: None,
        lineage_id: refresh_id,
        status: RefreshStatus::Active,
        issued_at,
        expires_at,
    })
    .expect("active refresh");
    let account = AccountSecurityState::try_from(AccountSecuritySnapshot {
        tenant,
        user_id,
        status: AccountStatus::Active,
        authn_epoch: epoch.get(),
        version: 1,
        status_changed_at: issued_at,
        updated_at: issued_at,
    })
    .expect("active account");
    RefreshBackend {
        grant,
        record,
        account,
        settlement,
    }
}

fn refresh_service(
    vault_uri: &str,
    settlement: RefreshSettlement,
) -> Arc<identity::RefreshService<VaultSigner>> {
    let backend = refresh_backend(settlement);
    identity::AuthGrantServices::from_provider(
        backend.clone(),
        identity::ports::DynAccountSecurityReadRepo::new_box(backend),
        Arc::new(vault_jwt_issuer(vault_uri)),
        Box::new(FixedClock(NOW)),
        Duration::from_secs(TTL_SECS),
    )
    .refresh_service()
}

/// 真 `OidcProvider`（经静态 RSS User-only profile 装配）。
#[allow(clippy::expect_used)]
fn oidc_provider() -> OidcProvider<diport::RssAccessProfile> {
    let es256_b64 = B64_URL.encode(sec1(&sk_jwt()));
    let keys = [KeyedEs256StaticKey {
        key_id: KEY_ID,
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

/// 经生产 `apply_verify_bridge` 验 `token`：返回 `/protected`（Require Jwt）的状态码。
#[allow(clippy::unwrap_used, clippy::expect_used)]
async fn verify_status(token: &str) -> StatusCode {
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
        Arc::new(oidc_provider()),
        runtime::test_support::always_current_access_grants(),
    );
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/protected")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    app.into_plaintext_router_for_test()
        .oneshot(req)
        .await
        .unwrap()
        .status()
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn vault_signed_access_jwt_verifies_via_oidc_bridge() {
    // 1. 起 wiremock vault Transit：任意 POST（/v1/transit/sign/{key}）→ 动态 ES256 签。
    let server = MockServer::start().await;
    // anti-vacuity：仅匹配带 marshaling_algorithm=jws 的请求——若 VaultSigner 回退 asn1（DER），请求不匹配 →
    // 404 → sign 失败 → mint 失败（守住「JWS marshaling 必须请求」这层正确性，否则 oidc 验签会 silently 失败）。
    Mock::given(match_method("POST"))
        .and(body_partial_json(
            serde_json::json!({ "marshaling_algorithm": "jws" }),
        ))
        .respond_with(TransitSignResponder { sk: sk_jwt() })
        .mount(&server)
        .await;

    // 2. 经 vault Signer（mock）从完整 AuthGrant 铸 RSS User access JWT。
    let issuer = vault_jwt_issuer(&server.uri());
    let tenant = vocab::TenantId::parse(TENANT).expect("canonical tenant");
    let grant = authn::AuthGrant::new_active(
        tenant,
        ids::UserId::parse(USER_ID).expect("canonical user id"),
        UNIX_EPOCH + Duration::from_secs((NOW - 60) as u64),
        authn::AuthnEpoch::hydrate(5).expect("valid epoch"),
        UNIX_EPOCH + Duration::from_secs((NOW + 3_600) as u64),
        UNIX_EPOCH + Duration::from_secs((NOW - 30) as u64),
    )
    .expect("active grant");
    let user = issuer
        .issue_access(
            grant
                .access_issue_input()
                .expect("active grant issue input"),
        )
        .await
        .expect("vault-signed user mint ok");

    // 3. 权威 exp = NOW + ttl（与紧凑串内 exp claim 同源同次计算）。
    assert_eq!(
        user.expires_at(),
        NOW + TTL_SECS as i64,
        "MintedJwt::expires_at 须 = NOW + ttl"
    );

    // 4. vault-签的 access JWT 经真 oidc 桥验签 → 200（sign→verify 闭环成立）。
    assert_eq!(
        verify_status(user.as_str()).await,
        StatusCode::OK,
        "vault Transit 签的 grant-bound User access JWT 须经 oidc 验签放行"
    );

    // 5. anti-vacuity：篡改签名段 → 验签失败 → 401（证验签真实生效、非恒放行）。
    let tampered = format!("{}x", user.as_str());
    assert_eq!(
        verify_status(&tampered).await,
        StatusCode::UNAUTHORIZED,
        "篡改签名的 JWT 须 401（验签非恒真）"
    );
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn refresh_non_acknowledged_settlements_never_release_bearers() {
    let server = MockServer::start().await;
    Mock::given(match_method("POST"))
        .and(body_partial_json(
            serde_json::json!({ "marshaling_algorithm": "jws" }),
        ))
        .respond_with(TransitSignResponder { sk: sk_jwt() })
        .mount(&server)
        .await;
    let tenant = vocab::TenantId::parse(TENANT).expect("tenant");

    // The fake deliberately has no Applied branch: only the PostgreSQL settlement funnel may mint
    // the commit acknowledgement. The real Applied path is covered by
    // `identity_login_wire_e2e::wire_identity_two_routers_concurrent_refresh_reuse_closes_security_loop_e2e`.
    for (label, settlement, replay) in [
        ("reuse", RefreshSettlement::ReuseContained, true),
        ("internal", RefreshSettlement::Internal, false),
        ("commit-unknown", RefreshSettlement::CommitUnknown, false),
    ] {
        let result = refresh_service(&server.uri(), settlement)
            .rotate(
                ProducerMarker::for_test(generated::http::identity_v1::refresh::PRODUCER)
                    .into_receipt(),
                tenant,
                &authn::RefreshToken::new(PRESENTED_REFRESH),
            )
            .await;
        let error = result.expect_err("non-applied settlement must not release bearer bundle");
        if replay {
            assert!(matches!(&error, identity::RefreshError::Replayed));
        } else {
            assert!(matches!(&error, identity::RefreshError::Store(_)));
        }
        let public_error = error.to_string();
        assert!(!public_error.contains(PRESENTED_REFRESH), "{label}");
        assert!(!public_error.contains("eyJ"), "{label}");
    }

    assert_eq!(
        server
            .received_requests()
            .await
            .expect("wiremock request log")
            .len(),
        3,
        "every non-acknowledged path mints before settlement but releases no pending secrets"
    );
}
