//! identity login + refresh + current/all logout 生产 wire e2e（#1252/#1840）：wiremock vault Transit mock（动态 ES256 签）+
//! postgres credential/AuthGrant/refresh store → `wire_identity_with` → Primary router handler。
//!
//! 覆盖：
//! ① login → 201 + accessToken/refreshToken/accessExpiresAt/sessionId（vault mock 真实签发，生产 wire 通路）；
//! ② refresh → 201 + 新 token bundle（rotation 闭环：旧 token 轮换、新 token 铸出）；
//! ③ 同 refreshToken 再用 → 401（one-shot rotation reuse detection，refresh store 已废弃旧 token）。
//!
//! hermetic：wiremock 模拟 vault Transit（无 live vault），postgres testcontainer 或 env pg。
//! login/refresh 是 Public 端点，verify bridge 不拦截；响应 access token 仍经生产 OIDC
//! provider 验签，并对照 raw payload 检查闭合 RSS quartet。

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use diport::Clock as _;
use diport::Pdp as _;
use generated::event::settings_v1::TOPIC as SETTINGS_VERSION_CHANGED_TOPIC;
use generated::http::identity_v1::account_status_set::PRODUCER as ACCOUNT_STATUS_SET_PRODUCER;
use generated::http::identity_v1::login::SPEC as LOGIN_SPEC;
use generated::http::identity_v1::logout::SPEC as LOGOUT_SPEC;
use generated::http::identity_v1::logout_all::SPEC as LOGOUT_ALL_SPEC;
use generated::http::identity_v1::refresh::SPEC as REFRESH_SPEC;
use generated::http::identity_v1::roles_assign::{
    PRODUCER as ROLES_ASSIGN_PRODUCER, SPEC as ROLES_ASSIGN_SPEC,
};
use generated::http::identity_v1::roles_list::SPEC as ROLES_LIST_SPEC;
use generated::http::identity_v1::roles_revoke::SPEC as ROLES_REVOKE_SPEC;
use generated::http::settings_v1::SPEC as SETTINGS_CONFIG_SPEC;
use httpserve::ProducerMarker;
use identity::ports::{
    AccountSecurityReadRepo as _, AccountStatus, AuthGrantProvider as _, Credential,
    CredentialRepo as _, DynRoleBindingLifecycle, DynRoleReadRepo, IdentitySecurityLifecycle as _,
    Role, RoleWriteRepo as _, TenantId, TenantRepoScope,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use postgres::{PgConfig, PgPassword, PgRuntimeDeps, PgSslMode, PgTenantReadConfig, caps};
use runtime::support::{SystemClock, TracingAuthAuditSink};
use runtime::test_support::{
    IdentityTestValues, build_s3_runtime_deps_from_values, build_shared_runtime_deps,
    build_unused_redis_runtime_deps, finalize_federated_listener, finalize_rss_listener,
    test_private_ca_pem, wire_identity_with, wire_settings,
};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use tower::ServiceExt as _;
use vault::{
    SignatureMarshaling, StoreBinding, TenantStoreAllowlist, VaultKeyProvider, VaultRuntimeDeps,
    VaultSecretResolver, VaultSigner,
};
use wiremock::matchers::{body_partial_json, method as match_method, path};
use wiremock::{Mock, MockServer, Request as MockRequest, Respond, ResponseTemplate};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn identity_signer(vault_uri: &str) -> TestResult<Arc<VaultSigner>> {
    Ok(Arc::new(VaultSigner::new_allow_http(
        reqwest::Client::new(),
        vault_uri,
        "test-token",
        "transit",
        Duration::from_secs(5),
        SignatureMarshaling::Jws,
    )?))
}

const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const CANON_USER: &str = "11111111-2222-4333-8444-555555555555";
const SUSPENDED_USER: &str = "22222222-3333-4444-8555-666666666666";
const LOCKED_USER: &str = "33333333-4444-4555-8666-777777777777";
const LOGIN_USERNAME: &str = "alice";
const SUSPENDED_USERNAME: &str = "suspended-alice";
const LOCKED_USERNAME: &str = "locked-alice";
const PASSWORD: &str = "correct-horse";
const TEST_APP_ROLE: &str = "rss_app";
const TEST_APP_PASSWORD: &str = "rss_app_test_pw";
const TEST_READ_ROLE: &str = "rss_app_read";
const TEST_READ_PASSWORD: &str = "rss_app_read_test_pw";
const ADMIN_ROLE: &str = "tenant-admin";
const OPERATOR_ROLE: &str = "operator";
const TARGET_SUBJECT: &str = "bob@example.test";
const KEYPROVIDER_CONFIG_FIELD: &str = "settings.config.value";
const KEYPROVIDER_CONFIG_SCHEME: u32 = 1;

fn unused_tenant_store_allowlist() -> TestResult<TenantStoreAllowlist> {
    Ok(TenantStoreAllowlist::new([(
        (
            TenantId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")?,
            "vault".to_owned(),
        ),
        StoreBinding {
            mount: "secret".to_owned(),
            kv_path_prefix: "tenants/a".to_owned(),
        },
    )])?)
}

struct NoopDomainTransport;

impl distributed::DomainTransport for NoopDomainTransport {
    fn dispatch(
        &self,
        _request: distributed::DomainRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<distributed::DomainResponse, distributed::DomainTransportError>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async {
            Ok(distributed::DomainResponse::new(
                204,
                Vec::new(),
                Vec::new(),
            ))
        })
    }
}

fn noop_domain_transport() -> Arc<dyn distributed::DomainTransport> {
    Arc::new(NoopDomainTransport)
}

fn test_password_blocklist() -> Arc<secure::DigestPasswordBlocklist> {
    Arc::new(
        crypto::load_password_blocklist_from_reader(std::io::Cursor::new(include_bytes!(
            "../../../deploy/password-blocklist.demo.sha256"
        )))
        .unwrap_or_else(|_| unreachable!()),
    )
}

// ── vault Transit mock helpers（mirror refresh_mint_e2e.rs） ────────────────────────────────────

/// 测试 P-256 私钥（静态，dev-only；mock vault 用此 key 签）。
#[allow(clippy::expect_used)]
fn sk_jwt() -> SigningKey {
    let bytes: [u8; 32] = std::array::from_fn(|i| (i + 1) as u8);
    SigningKey::from_slice(&bytes).expect("valid P-256 scalar")
}

#[allow(clippy::expect_used)]
fn readiness_context_b64(tenant: &str) -> String {
    let tenant = vocab::TenantId::parse(tenant).expect("canonical readiness tenant");
    let aad = secure::ProtectionContext::authenticated_request(
        tenant,
        "readiness.probe",
        KEYPROVIDER_CONFIG_FIELD,
        KEYPROVIDER_CONFIG_SCHEME,
    )
    .expect("valid readiness aad")
    .derive();
    B64_STD.encode(aad.as_canonical_bytes())
}

fn sec1(sk: &SigningKey) -> Vec<u8> {
    sk.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

fn mint_es256(sk: &SigningKey, payload: &str) -> String {
    let header = B64_URL.encode(br#"{"alg":"ES256","typ":"at+jwt","kid":"federated-jwt-es256"}"#);
    let body = B64_URL.encode(payload.as_bytes());
    let signing_input = format!("{header}.{body}");
    let sig: Signature = sk.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64_URL.encode(sig.to_bytes()))
}

fn federated_access_jwt(kind: &str, permissions: &[vocab::RoutePermissionId]) -> String {
    let iat = SystemClock
        .now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let payload = serde_json::json!({
        "sub": CANON_USER,
        "iat": iat,
        "exp": iat + 900,
        "iss": "https://issuer.test",
        "aud": "rss",
        "kind": kind,
        "tenant_id": CANON_TENANT,
        "token_use": "access",
        "permissions": permissions
            .iter()
            .map(|permission| permission.as_str())
            .collect::<Vec<_>>(),
    });
    mint_es256(&sk_jwt(), &payload.to_string())
}

fn admin_jwt() -> String {
    federated_access_jwt("admin", &[vocab::RoutePermissionId::SettingsConfigPublish])
}

fn operator_jwt() -> String {
    federated_access_jwt(
        "user",
        &[
            vocab::RoutePermissionId::IdentityRoleAssign,
            vocab::RoutePermissionId::SettingsConfigPublish,
        ],
    )
}

/// wiremock Transit `/sign` 响应器：解 `{"input": base64std(signing_input)}` → 用 `sk` 对 signing-input
/// 字节做 ES256 签（r‖s 64B，JWS marshaling）→ 回 `{"data":{"signature":"vault:v1:<base64url(r‖s)>"}}`
/// （镜像真实 vault Transit JWS 响应）。动态签：signing-input 含 issuer 内部计算的 iat/exp，无法预制。
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
        // 真 vault `marshaling_algorithm=jws` 输出 URL-safe base64（非 standard），VaultSigner(Jws) 同形解码。
        let sig: Signature = self.sk.sign(&message);
        let tagged = format!("vault:v1:{}", B64_URL.encode(sig.to_bytes()));
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({ "data": { "signature": tagged } }))
    }
}

async fn mount_settings_keyprovider_mocks(vault_server: &MockServer) {
    let readiness_context = readiness_context_b64("00000000-0000-4000-8000-000000000147");
    let mismatch_context = readiness_context_b64("00000000-0000-4000-8000-000000000148");
    Mock::given(match_method("POST"))
        .and(path("/v1/transit/encrypt/settings-config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "ciphertext": "vault:v1:cnNzLWtleXByb3ZpZGVyLXJlYWR5",
                "key_version": 1
            }
        })))
        .mount(vault_server)
        .await;
    Mock::given(match_method("POST"))
        .and(path("/v1/transit/decrypt/settings-config"))
        .and(body_partial_json(serde_json::json!({
            "context": mismatch_context
        })))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "errors": ["ciphertext verification failed"]
        })))
        .mount(vault_server)
        .await;
    Mock::given(match_method("POST"))
        .and(path("/v1/transit/decrypt/settings-config"))
        .and(body_partial_json(serde_json::json!({
            "context": readiness_context
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "plaintext": B64_STD.encode(b"rss-keyprovider-ready")
            }
        })))
        .mount(vault_server)
        .await;
}

// ── postgres fixture helpers ────────────────────────────────────────────────────────────────────

async fn connect_pg()
-> Result<(testkit::PgFixture, PgRuntimeDeps), Box<dyn std::error::Error + Send + Sync>> {
    let fixture = testkit::env_or_postgres().await?;
    let p = fixture.params();
    let owner_config = pg_config(p, &p.username, &p.password);
    testkit::provision_postgres_test_logins(
        p,
        &[
            testkit::PostgresTestLogin::new(TEST_APP_ROLE, TEST_APP_PASSWORD),
            testkit::PostgresTestLogin::new(TEST_READ_ROLE, TEST_READ_PASSWORD),
        ],
    )
    .await?;
    let tenant_read_config =
        PgTenantReadConfig::new(pg_config(p, TEST_READ_ROLE, TEST_READ_PASSWORD));
    let workflow = eventexec::WorkflowRuntimePlan::disabled_fixture();
    let deps = PgRuntimeDeps::setup_test_fixture(
        &owner_config,
        &pg_config(p, TEST_APP_ROLE, TEST_APP_PASSWORD),
        &tenant_read_config,
        None,
        workflow.projection_capture(),
    )
    .await?;
    Ok((fixture, deps))
}

fn pg_config(p: &testkit::PgConnParams, username: &str, password: &str) -> PgConfig {
    PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        username.to_string(),
        PgPassword::new(password.to_string()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(Duration::from_secs(5))
}

fn pg_connect_options(
    p: &testkit::PgConnParams,
    username: &str,
    password: &str,
) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(&p.host)
        .port(p.port)
        .database(&p.database)
        .username(username)
        .password(password)
        .ssl_mode(SqlxPgSslMode::Prefer)
}

async fn assertion_pool(
    p: &testkit::PgConnParams,
) -> Result<PgPool, Box<dyn std::error::Error + Send + Sync>> {
    let options = pg_connect_options(p, &p.username, &p.password);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?;
    Ok(pool)
}

fn test_provider() -> oidc::OidcProvider<diport::RssAccessProfile> {
    let public_key = B64_URL.encode(sec1(&sk_jwt()));
    let keys = [runtime::KeyedEs256StaticKey {
        key_id: "rss-jwt-es256",
        sec1_b64url: &public_key,
    }];
    #[allow(clippy::expect_used)]
    runtime::rss_access_provider_from_static_config(runtime::RssAccessStaticProviderConfig {
        issuer: "https://issuer.test",
        audience: "rss",
        keys: &keys,
        retirement_schedule: None,
        clock: Box::new(SystemClock),
    })
    .expect("test provider")
}

fn decode_access_claims(token: &str) -> TestResult<serde_json::Value> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or("access token is missing its payload segment")?;
    let decoded = B64_URL.decode(payload)?;
    Ok(serde_json::from_slice(&decoded)?)
}

fn assert_canonical_uuid_v4(raw: &str, field: &str) -> TestResult {
    let parsed = uuid::Uuid::parse_str(raw)?;
    assert_eq!(
        parsed.get_version(),
        Some(uuid::Version::Random),
        "{field} must be UUIDv4"
    );
    assert_eq!(
        parsed.hyphenated().to_string(),
        raw,
        "{field} must be lowercase canonical UUIDv4"
    );
    Ok(())
}

async fn verified_access_claims(token: &str) -> TestResult<serde_json::Value> {
    let decoded = decode_access_claims(token)?;
    let verified = test_provider()
        .verify(&diport::RawCredential::rss_access(token))
        .await?;
    let grant = match verified.view() {
        diport::VerifiedClaimsView::RssUser { grant, .. } => grant,
        diport::VerifiedClaimsView::FederatedAccess { .. }
        | diport::VerifiedClaimsView::ServiceToken { .. }
        | diport::VerifiedClaimsView::ProjectionOperator { .. } => {
            return Err("production verifier did not return RSS user grant evidence".into());
        }
    };

    assert_eq!(
        decoded["sid"].as_str().map(str::to_owned),
        Some(grant.session_id().to_string())
    );
    assert_eq!(
        decoded["jti"].as_str().map(str::to_owned),
        Some(grant.token_id().to_string())
    );
    assert_eq!(
        decoded["auth_time"].as_u64(),
        Some(grant.auth_time_unix_secs())
    );
    assert_eq!(decoded["authn_epoch"].as_u64(), Some(grant.authn_epoch()));
    Ok(decoded)
}

fn federated_test_provider() -> TestResult<oidc::OidcProvider<diport::FederatedAccessProfile>> {
    let keys = oidc::AccessStaticKeySource::builder()
        .add_es256_sec1("federated-jwt-es256", &sec1(&sk_jwt()))?
        .build();
    let permissions = oidc::FederatedPermissionUniverse::try_new([
        vocab::GrantPermission::route(vocab::RoutePermissionId::IdentityRoleAssign),
        vocab::GrantPermission::route(vocab::RoutePermissionId::SettingsConfigPublish),
    ])?;
    let config = oidc::VerifierConfigBuilder::<diport::FederatedAccessProfile>::new(
        "https://issuer.test",
        "rss",
        permissions,
    )
    .keys_static(keys)
    .trust_kind("user")
    .trust_kind("admin")
    .build()?;
    Ok(oidc::OidcProvider::new(config, Box::new(SystemClock)))
}

fn identity_test_values() -> IdentityTestValues {
    IdentityTestValues {
        access_token_issuer: "https://issuer.test".to_string(),
        access_token_audience: "rss".to_string(),
        access_token_key_id: "rss-jwt-es256".to_string(),
        access_token_ttl: Duration::from_secs(900),
        auth_grant_ttl: Duration::from_secs(2_592_000),
        refresh_ttl: Duration::from_secs(2_592_000),
    }
}

async fn login_refresh_token(app: &axum::Router, username: &str) -> TestResult<String> {
    let body = login_bundle(app, username).await?;
    Ok(body["data"]["refreshToken"]
        .as_str()
        .ok_or("login response missing data.refreshToken")?
        .to_owned())
}

async fn login_bundle(app: &axum::Router, username: &str) -> TestResult<serde_json::Value> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LOGIN_SPEC.route.path())
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Tenant-ID", CANON_TENANT)
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "password": PASSWORD,
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "{username} login must issue a refresh token before the durable status transition"
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let body: serde_json::Value = serde_json::from_slice(&bytes)?;
    Ok(body)
}

async fn refresh_rotation_snapshot(
    pool: &PgPool,
    secret: &str,
) -> TestResult<Option<(String, i64)>> {
    Ok(sqlx::query_as::<_, (String, i64)>(
        "SELECT root.status, count(child.id)::bigint \
         FROM refresh_tokens AS root \
         LEFT JOIN refresh_tokens AS child \
           ON child.tenant_id = root.tenant_id AND child.parent_id = root.id \
         WHERE root.tenant_id = $1::uuid AND root.token_hash = $2 \
         GROUP BY root.id, root.status",
    )
    .bind(CANON_TENANT)
    .bind(secure::digest(secret).as_slice())
    .fetch_optional(pool)
    .await?)
}

async fn assert_revoked_refresh_rejected_without_rotation(
    app: &axum::Router,
    pool: &PgPool,
    token: &str,
    status: AccountStatus,
) -> TestResult {
    let before = refresh_rotation_snapshot(pool, token)
        .await?
        .ok_or("seeded refresh token is missing before account-security rejection")?;
    assert_eq!(
        before,
        ("revoked".to_owned(), 0),
        "account-status transition must revoke the initial refresh token without a successor"
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(REFRESH_SPEC.route.path())
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Tenant-ID", CANON_TENANT)
                .body(Body::from(
                    serde_json::json!({ "refreshToken": token }).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "{status:?} account must be rejected through the production refresh wiring"
    );
    assert_eq!(
        refresh_rotation_snapshot(pool, token).await?,
        Some(before),
        "{status:?} rejection must leave the original refresh revoked with zero successors"
    );
    Ok(())
}

async fn outbox_topic_count(
    pool: &PgPool,
    domain: &str,
    topic: &str,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM outbox WHERE domain = $1 AND topic = $2")
            .bind(domain)
            .bind(topic)
            .fetch_one(pool)
            .await?;
    Ok(count)
}

async fn refresh_family_security_snapshot(
    pool: &PgPool,
    presented: &str,
) -> TestResult<(String, Option<String>, i64, bool)> {
    let row = sqlx::query_as::<_, (String, Option<String>, i64, bool)>(
        "SELECT grant_root.status, grant_root.close_reason, count(family.id)::bigint, \
                bool_and(family.status = 'revoked' AND family.auth_grant_status = 'compromised') \
         FROM refresh_tokens AS presented \
         JOIN auth_grants AS grant_root \
           ON grant_root.tenant_id = presented.tenant_id \
          AND grant_root.grant_id = presented.auth_grant_id \
         JOIN refresh_tokens AS family \
           ON family.tenant_id = grant_root.tenant_id \
          AND family.auth_grant_id = grant_root.grant_id \
         WHERE presented.tenant_id = $1::uuid AND presented.token_hash = $2 \
         GROUP BY grant_root.grant_id, grant_root.status, grant_root.close_reason",
    )
    .bind(CANON_TENANT)
    .bind(secure::digest(presented).as_slice())
    .fetch_one(pool)
    .await?;
    Ok(row)
}

async fn role_binding_count(
    pool: &PgPool,
    role_id: &str,
    subject: &str,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM role_bindings WHERE tenant_id = $1::uuid AND role_id = $2 AND subject = $3",
    )
    .bind(CANON_TENANT)
    .bind(role_id)
    .bind(subject)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

async fn config_entry_count(
    pool: &PgPool,
    key: &str,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2",
    )
    .bind(CANON_TENANT)
    .bind(key)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

// ── 端到端测试 ───────────────────────────────────────────────────────────────────────────────────

/// login + refresh 生产 wire 端到端：vault Transit mock（hermetic）→ token bundle 铸出 → rotation → reuse-detect。
///
/// 断言 a: POST /api/v1/identity/login → 201 + accessToken/refreshToken/accessExpiresAt/sessionId。
/// 断言 b: POST /api/v1/identity/refresh（login 取的 refreshToken）→ 201 + 新 token bundle。
/// 断言 c: 再用同一 refreshToken → 401（one-shot rotation reuse detection）。
#[tokio::test(flavor = "multi_thread")]
async fn wire_identity_logout_current_all_e2e() -> TestResult {
    // 1. hermetic vault Transit mock：任意 POST + marshaling_algorithm=jws → 动态 ES256 签。
    //    anti-vacuity matcher（body_partial_json）保证 VaultSigner 必须请求 JWS marshaling，否则 404 → 失败。
    let vault_server = MockServer::start().await;
    Mock::given(match_method("POST"))
        .and(body_partial_json(
            serde_json::json!({ "marshaling_algorithm": "jws" }),
        ))
        .respond_with(TransitSignResponder { sk: sk_jwt() })
        .mount(&vault_server)
        .await;
    let vault_uri = vault_server.uri();

    // 2. postgres fixture + credential seed（login 凭据）。
    let (fixture, pg_owner) = connect_pg().await?;
    let observation_pool = assertion_pool(fixture.params()).await?;
    let pg = pg_owner.handle();
    let tenant = TenantId::parse(CANON_TENANT)?;
    let tenant_scope = TenantRepoScope::for_test(tenant);
    let credential = Credential::hydrate(
        LOGIN_USERNAME,
        ids::UserId::parse(CANON_USER)?,
        tenant,
        secure::PasswordHash::for_test(secure::RawPassword::new(PASSWORD.to_owned()))?,
        1,
    );
    pg.for_domain::<caps::Identity>()
        .credential_repo()
        .insert(tenant_scope, credential)
        .await?;
    for (username, user_id) in [
        (SUSPENDED_USERNAME, SUSPENDED_USER),
        (LOCKED_USERNAME, LOCKED_USER),
    ] {
        pg.for_domain::<caps::Identity>()
            .credential_repo()
            .insert(
                TenantRepoScope::for_test(tenant),
                Credential::hydrate(
                    username,
                    ids::UserId::parse(user_id)?,
                    tenant,
                    secure::PasswordHash::for_test(secure::RawPassword::new(PASSWORD.to_owned()))?,
                    1,
                ),
            )
            .await?;
    }
    let identity = pg.for_domain::<caps::Identity>();
    let logout_role = Role::hydrate(
        "session-owner",
        "Current and all session logout",
        &[
            "identity:session:logout-current".to_string(),
            "identity:role:read".to_string(),
        ],
    )?;
    let logout_role_id = logout_role.id().clone();
    identity.role_repo().save(tenant_scope, logout_role).await?;
    let setup_rbac = identity::RbacAdminService::new(
        Arc::from(DynRoleReadRepo::new_box(identity.role_repo())),
        Arc::from(DynRoleBindingLifecycle::new_box(
            identity.role_binding_lifecycle(Box::new(SystemClock)),
        )),
        Box::new(SystemClock),
    );
    setup_rbac
        .assign_role(
            ProducerMarker::for_test(ROLES_ASSIGN_PRODUCER).into_receipt(),
            tenant,
            ids::UserId::parse(CANON_USER)?,
            vocab::PrincipalKind::User,
            CANON_USER.to_string(),
            logout_role_id,
        )
        .await?;

    // 3. vault bundle（#1498）：合法但未使用的单条 allowlist binding；secret resolver 不触 vault，
    //    仅构造器结构满足 SharedRuntimeDeps.vault 字段。mock URL 仅在构造期校验，不建立连接。
    let stores = unused_tenant_store_allowlist()?;
    let vault = VaultRuntimeDeps::new(
        VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            vault_uri.clone(),
            "test-token",
            Duration::from_secs(5),
            stores,
        )?,
        VaultKeyProvider::new_allow_http(
            reqwest::Client::new(),
            vault_uri.clone(),
            "test-token",
            "transit",
            Duration::from_secs(5),
        )?,
    );
    // Identity wiring does not consume Redis; a lazy no-connect bundle satisfies the shared shape.
    let redis_ca = test_private_ca_pem();
    let redis = build_unused_redis_runtime_deps()?;
    let s3 = build_s3_runtime_deps_from_values(
        "https://127.0.0.1:1".to_string(),
        "rss-test-bucket".to_string(),
        "access-key".to_string(),
        "secret-key".to_string(),
        true,
        redis_ca,
    )?;
    let deps = build_shared_runtime_deps(
        test_password_blocklist(),
        pg.clone(),
        redis,
        s3,
        vault,
        identity_signer(&vault_uri)?,
        diport::KeyName::try_new("settings-config")?,
        noop_domain_transport(),
    );

    // 4. wire_identity_with（复用 SharedRuntimeDeps 中的 mock-Vault signer，仅注入显式 JWT/AuthGrant 配置）。
    let identity_binding = wire_identity_with(&deps, identity_test_values())?;

    // 5. 装配 Primary router（compose → assemble_authed_routers → into_router_for_test）。
    let mut bindings = vec![identity_binding];
    let (mut registry, _) = bootstrap::compose_bindings(&mut bindings)?;
    let primary = finalize_rss_listener(
        &mut registry,
        Arc::new(test_provider()),
        runtime::test_support::access_grant_validation_service(
            pg.for_domain::<caps::Identity>().auth_grant_validator(),
        ),
        httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
        Arc::new(SystemClock),
        assembly_schema::AssemblyListenerKind::Primary,
    )?;
    let app = primary.into_router_for_test();

    // Login while both accounts are Active so each receives a durable refresh record, then move
    // the authoritative rows to non-Active states. A decoy/wrong production reader would return
    // Active and make the following HTTP assertions fail with 201 instead of 401.
    let suspended_refresh = login_refresh_token(&app, SUSPENDED_USERNAME).await?;
    let locked_refresh = login_refresh_token(&app, LOCKED_USERNAME).await?;
    let account_security = pg.for_domain::<caps::Identity>().account_security_repo();
    for (user_id, next_status, token) in [
        (
            SUSPENDED_USER,
            AccountStatus::Suspended,
            suspended_refresh.as_str(),
        ),
        (LOCKED_USER, AccountStatus::Locked, locked_refresh.as_str()),
    ] {
        let user_id = ids::UserId::parse(user_id)?;
        let scope = TenantRepoScope::for_test(tenant);
        let current = account_security
            .find(scope, user_id)
            .await?
            .ok_or("credential save omitted its account-security state")?;
        let (_, _, lifecycle) = pg
            .for_domain::<caps::Identity>()
            .auth_grant_provider(
                Box::new(SystemClock),
                postgres::identity_pseudonym_keys_for_test(),
            )
            .into_auth_grant_parts();
        let occurred_at = current.updated_at() + Duration::from_secs(1);
        let command =
            identity::test_support::account_status_set_command(current, next_status, occurred_at);
        let _receipt = lifecycle
            .execute_account_status_set(
                ProducerMarker::for_test(ACCOUNT_STATUS_SET_PRODUCER).into_receipt(),
                TenantRepoScope::for_test(tenant),
                command,
            )
            .await?;
        let transitioned = account_security
            .find(TenantRepoScope::for_test(tenant), user_id)
            .await?
            .ok_or("account-status set removed account-security state")?;
        assert_eq!(transitioned.status(), next_status);
        assert_revoked_refresh_rejected_without_rotation(
            &app,
            &observation_pool,
            token,
            next_status,
        )
        .await?;
    }

    // ── 断言 a: login → 201 + token bundle ────────────────────────────────────────────────────
    let login_body = format!(r#"{{"username":"{LOGIN_USERNAME}","password":"{PASSWORD}"}}"#);
    let login_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LOGIN_SPEC.route.path())
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Tenant-ID", CANON_TENANT)
                .body(Body::from(login_body))?,
        )
        .await?;
    assert_eq!(
        login_resp.status(),
        StatusCode::CREATED,
        "login should return 201 (public identity.login + vault mock sign)"
    );
    let login_bytes = axum::body::to_bytes(login_resp.into_body(), usize::MAX).await?;
    let login_text = String::from_utf8(login_bytes.to_vec())?;
    assert!(
        login_text.contains(r#""accessToken":"#),
        "login response must contain accessToken; body: {login_text}"
    );
    assert!(
        login_text.contains(r#""refreshToken":"#),
        "login response must contain refreshToken; body: {login_text}"
    );
    assert!(
        login_text.contains(r#""accessExpiresAt":"#),
        "login response must contain accessExpiresAt; body: {login_text}"
    );
    assert!(
        login_text.contains(r#""sessionId":"#),
        "login response must contain sessionId; body: {login_text}"
    );

    // 提取 refreshToken 供后续断言（rotation + reuse-detect）。
    let login_json: serde_json::Value = serde_json::from_str(&login_text)?;
    let login_access_token = login_json["data"]["accessToken"]
        .as_str()
        .ok_or("login response missing data.accessToken")?;
    let login_session_id = login_json["data"]["sessionId"]
        .as_str()
        .ok_or("login response missing data.sessionId")?;
    let login_claims = verified_access_claims(login_access_token).await?;
    let login_sid = login_claims["sid"]
        .as_str()
        .ok_or("login access token missing sid")?;
    let login_jti = login_claims["jti"]
        .as_str()
        .ok_or("login access token missing jti")?;
    assert_eq!(login_sid, login_session_id);
    assert_canonical_uuid_v4(login_sid, "login sid")?;
    assert_canonical_uuid_v4(login_jti, "login jti")?;
    let refresh_token_orig = login_json["data"]["refreshToken"]
        .as_str()
        .ok_or("login response missing data.refreshToken")?
        .to_string();

    // ── 断言 b: 首次 refresh → 201 + 新 token bundle（rotation 成功）──────────────────────────
    let refresh_body = serde_json::json!({ "refreshToken": refresh_token_orig }).to_string();
    let refresh_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(REFRESH_SPEC.route.path())
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Tenant-ID", CANON_TENANT)
                .body(Body::from(refresh_body.clone()))?,
        )
        .await?;
    assert_eq!(
        refresh_resp.status(),
        StatusCode::CREATED,
        "first refresh should return 201 (valid token rotation)"
    );
    let refresh_bytes = axum::body::to_bytes(refresh_resp.into_body(), usize::MAX).await?;
    let refresh_text = String::from_utf8(refresh_bytes.to_vec())?;
    assert!(
        refresh_text.contains(r#""accessToken":"#),
        "refresh response must contain accessToken; body: {refresh_text}"
    );
    assert!(
        refresh_text.contains(r#""refreshToken":"#),
        "refresh response must contain refreshToken; body: {refresh_text}"
    );
    let refresh_json: serde_json::Value = serde_json::from_str(&refresh_text)?;
    let refresh_access_token = refresh_json["data"]["accessToken"]
        .as_str()
        .ok_or("refresh response missing data.accessToken")?
        .to_owned();
    let refresh_token_next = refresh_json["data"]["refreshToken"]
        .as_str()
        .ok_or("refresh response missing data.refreshToken")?
        .to_owned();
    let refresh_claims = verified_access_claims(&refresh_access_token).await?;
    let refresh_jti = refresh_claims["jti"]
        .as_str()
        .ok_or("refreshed access token missing jti")?;
    assert_canonical_uuid_v4(
        refresh_claims["sid"]
            .as_str()
            .ok_or("refreshed access token missing sid")?,
        "refreshed sid",
    )?;
    assert_canonical_uuid_v4(refresh_jti, "refreshed jti")?;
    for stable_claim in ["sid", "auth_time", "authn_epoch"] {
        assert_eq!(
            login_claims[stable_claim], refresh_claims[stable_claim],
            "{stable_claim} must remain stable across refresh"
        );
    }
    assert_ne!(login_jti, refresh_jti, "jti must rotate on refresh");

    let protected_uri = format!("{}?limit=20", ROLES_LIST_SPEC.route.path());
    let current_access_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&protected_uri)
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {refresh_access_token}"),
                )
                .body(Body::empty())?,
        )
        .await?;
    assert_ne!(
        current_access_resp.status(),
        StatusCode::UNAUTHORIZED,
        "the real PostgreSQL grant validator must accept the access token before replay"
    );

    let grant_b = login_bundle(&app, LOGIN_USERNAME).await?;
    let access_b = grant_b["data"]["accessToken"]
        .as_str()
        .ok_or("second login missing access token")?
        .to_owned();
    let refresh_b = grant_b["data"]["refreshToken"]
        .as_str()
        .ok_or("second login missing refresh token")?
        .to_owned();

    let current_logout = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LOGOUT_SPEC.route.path())
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {refresh_access_token}"),
                )
                .body(Body::from("{}"))?,
        )
        .await?;
    assert_eq!(
        current_logout.status(),
        StatusCode::OK,
        "current logout must commit through the credential-security producer transaction"
    );

    let revoked_access = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&protected_uri)
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {refresh_access_token}"),
                )
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        revoked_access.status(),
        StatusCode::UNAUTHORIZED,
        "current logout must immediately fence its access grant"
    );
    let revoked_refresh = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(REFRESH_SPEC.route.path())
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Tenant-ID", CANON_TENANT)
                .body(Body::from(
                    serde_json::json!({"refreshToken": refresh_token_next}).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(revoked_refresh.status(), StatusCode::UNAUTHORIZED);

    let grant_b_before_all = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&protected_uri)
                .header(header::AUTHORIZATION, format!("Bearer {access_b}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_ne!(
        grant_b_before_all.status(),
        StatusCode::UNAUTHORIZED,
        "current logout must not invalidate the account's other grant",
    );

    let missing_all_evidence = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LOGOUT_ALL_SPEC.route.path())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))?,
        )
        .await?;
    assert_eq!(missing_all_evidence.status(), StatusCode::UNAUTHORIZED);

    let denied_all = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LOGOUT_ALL_SPEC.route.path())
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {access_b}"))
                .body(Body::from("{}"))?,
        )
        .await?;
    assert_eq!(denied_all.status(), StatusCode::FORBIDDEN);
    identity
        .role_repo()
        .save(
            tenant_scope,
            Role::hydrate(
                "session-owner",
                "All-session logout only",
                &[
                    "identity:session:logout-all".to_string(),
                    "identity:role:read".to_string(),
                ],
            )?,
        )
        .await?;
    let denied_current = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LOGOUT_SPEC.route.path())
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {access_b}"))
                .body(Body::from("{}"))?,
        )
        .await?;
    assert_eq!(
        denied_current.status(),
        StatusCode::FORBIDDEN,
        "logout-all permission must not imply logout-current"
    );
    identity
        .role_repo()
        .save(
            tenant_scope,
            Role::hydrate(
                "session-owner",
                "Current and all session logout",
                &[
                    "identity:session:logout-current".to_string(),
                    "identity:session:logout-all".to_string(),
                    "identity:role:read".to_string(),
                ],
            )?,
        )
        .await?;
    let targeted_all = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LOGOUT_ALL_SPEC.route.path())
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {access_b}"))
                .body(Body::from(r#"{"sessionId":"forbidden"}"#))?,
        )
        .await?;
    assert_eq!(targeted_all.status(), StatusCode::BAD_REQUEST);
    let all_logout = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LOGOUT_ALL_SPEC.route.path())
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {access_b}"))
                .body(Body::from("{}"))?,
        )
        .await?;
    assert_eq!(all_logout.status(), StatusCode::OK);

    for (uri, body) in [
        (protected_uri.as_str(), None),
        (
            REFRESH_SPEC.route.path(),
            Some(serde_json::json!({"refreshToken": refresh_b}).to_string()),
        ),
    ] {
        let mut request = Request::builder().uri(uri);
        let request = if let Some(body) = body {
            request = request
                .method(Method::POST)
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Tenant-ID", CANON_TENANT);
            request.body(Body::from(body))?
        } else {
            request = request
                .method(Method::GET)
                .header(header::AUTHORIZATION, format!("Bearer {access_b}"));
            request.body(Body::empty())?
        };
        assert_eq!(
            app.clone().oneshot(request).await?.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    Ok(())
}

/// 两个独立 runtime/router 共享 PostgreSQL，对同一 bearer 并发 refresh：只能有一个轮换
/// 响应，CAS loser 必须在同一个 durable security closure 中 compromise grant、撤销完整
/// family，并 exactly-once 追加 `identity.security-event`。
#[tokio::test(flavor = "multi_thread")]
async fn wire_identity_two_routers_concurrent_refresh_reuse_closes_security_loop_e2e() -> TestResult
{
    let vault_server = MockServer::start().await;
    Mock::given(match_method("POST"))
        .and(body_partial_json(
            serde_json::json!({ "marshaling_algorithm": "jws" }),
        ))
        .respond_with(TransitSignResponder { sk: sk_jwt() })
        .mount(&vault_server)
        .await;
    let vault_uri = vault_server.uri();

    let (fixture, pg_owner) = connect_pg().await?;
    let observation_pool = assertion_pool(fixture.params()).await?;
    let pg = pg_owner.handle();
    let tenant = TenantId::parse(CANON_TENANT)?;
    pg.for_domain::<caps::Identity>()
        .credential_repo()
        .insert(
            TenantRepoScope::for_test(tenant),
            Credential::hydrate(
                LOGIN_USERNAME,
                ids::UserId::parse(CANON_USER)?,
                tenant,
                secure::PasswordHash::for_test(secure::RawPassword::new(PASSWORD.to_owned()))?,
                1,
            ),
        )
        .await?;

    let vault = VaultRuntimeDeps::new(
        VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            vault_uri.clone(),
            "test-token",
            Duration::from_secs(5),
            unused_tenant_store_allowlist()?,
        )?,
        VaultKeyProvider::new_allow_http(
            reqwest::Client::new(),
            vault_uri.clone(),
            "test-token",
            "transit",
            Duration::from_secs(5),
        )?,
    );
    let redis_ca = test_private_ca_pem();
    let redis = build_unused_redis_runtime_deps()?;
    let s3 = build_s3_runtime_deps_from_values(
        "https://127.0.0.1:1".to_string(),
        "rss-test-bucket".to_string(),
        "access-key".to_string(),
        "secret-key".to_string(),
        true,
        redis_ca,
    )?;
    let deps = build_shared_runtime_deps(
        test_password_blocklist(),
        pg.clone(),
        redis,
        s3,
        vault,
        identity_signer(&vault_uri)?,
        diport::KeyName::try_new("settings-config")?,
        noop_domain_transport(),
    );

    let mut binding_a = vec![wire_identity_with(&deps, identity_test_values())?];
    let (mut registry_a, _) = bootstrap::compose_bindings(&mut binding_a)?;
    let router_a = finalize_rss_listener(
        &mut registry_a,
        Arc::new(test_provider()),
        runtime::test_support::access_grant_validation_service(
            pg.for_domain::<caps::Identity>().auth_grant_validator(),
        ),
        httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
        Arc::new(SystemClock),
        assembly_schema::AssemblyListenerKind::Primary,
    )?
    .into_router_for_test();

    let mut binding_b = vec![wire_identity_with(&deps, identity_test_values())?];
    let (mut registry_b, _) = bootstrap::compose_bindings(&mut binding_b)?;
    let router_b = finalize_rss_listener(
        &mut registry_b,
        Arc::new(test_provider()),
        runtime::test_support::access_grant_validation_service(
            pg.for_domain::<caps::Identity>().auth_grant_validator(),
        ),
        httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
        Arc::new(SystemClock),
        assembly_schema::AssemblyListenerKind::Primary,
    )?
    .into_router_for_test();

    let initial = login_bundle(&router_a, LOGIN_USERNAME).await?;
    let presented = initial["data"]["refreshToken"]
        .as_str()
        .ok_or("login response missing data.refreshToken")?
        .to_owned();
    let facts_before = outbox_topic_count(
        &observation_pool,
        "identity",
        generated::event::identity_v1::security_event::TOPIC,
    )
    .await?;
    let body = serde_json::json!({ "refreshToken": presented }).to_string();
    let request = |body: String| {
        Request::builder()
            .method(Method::POST)
            .uri(REFRESH_SPEC.route.path())
            .header(header::CONTENT_TYPE, "application/json")
            .header("X-Tenant-ID", CANON_TENANT)
            .body(Body::from(body))
    };
    let (response_a, response_b) = tokio::join!(
        router_a.clone().oneshot(request(body.clone())?),
        router_b.clone().oneshot(request(body)?),
    );
    let response_a = response_a?;
    let response_b = response_b?;
    let statuses = [response_a.status(), response_b.status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CREATED)
            .count(),
        1,
        "two independent routers must release at most one rotated bearer; statuses={statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::UNAUTHORIZED)
            .count(),
        1,
        "the CAS loser must be an indistinguishable replay rejection; statuses={statuses:?}"
    );
    let winning_response = if response_a.status() == StatusCode::CREATED {
        response_a
    } else {
        response_b
    };
    let winning_body = axum::body::to_bytes(winning_response.into_body(), usize::MAX).await?;
    let winning_json: serde_json::Value = serde_json::from_slice(&winning_body)?;
    let winning_access = winning_json["data"]["accessToken"]
        .as_str()
        .ok_or("winning refresh response missing data.accessToken")?
        .to_owned();

    let (grant_status, close_reason, family_count, family_closed) =
        refresh_family_security_snapshot(&observation_pool, &presented).await?;
    assert_eq!(grant_status, "compromised");
    assert_eq!(close_reason.as_deref(), Some("refresh_reuse_detected"));
    assert_eq!(family_count, 2, "winner must persist exactly one child");
    assert!(
        family_closed,
        "the whole grant-bound refresh family must be revoked and fenced"
    );
    assert_eq!(
        outbox_topic_count(
            &observation_pool,
            "identity",
            generated::event::identity_v1::security_event::TOPIC,
        )
        .await?,
        facts_before + 1,
        "refresh reuse closure must append exactly one identity.security-event"
    );

    let fenced = router_a
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("{}?limit=20", ROLES_LIST_SPEC.route.path()))
                .header(header::AUTHORIZATION, format!("Bearer {winning_access}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        fenced.status(),
        StatusCode::UNAUTHORIZED,
        "the winner access token must be rejected by the real durable grant validator after reuse compromises its grant"
    );

    Ok(())
}

/// RBAC role binding 生产 wire 端到端：admin JWT → Primary router/auth middleware →
/// PgRoleBindingLifecycle co-tx → role_bindings + outbox。
#[tokio::test(flavor = "multi_thread")]
async fn wire_identity_roles_binding_http_persists_and_emits_outbox_e2e() -> TestResult {
    // 1. hermetic vault Transit mock：identity wiring 需要 JwtIssuer；本测试请求使用手铸 admin JWT。
    let vault_server = MockServer::start().await;
    Mock::given(match_method("POST"))
        .and(body_partial_json(
            serde_json::json!({ "marshaling_algorithm": "jws" }),
        ))
        .respond_with(TransitSignResponder { sk: sk_jwt() })
        .mount(&vault_server)
        .await;
    mount_settings_keyprovider_mocks(&vault_server).await;
    let vault_uri = vault_server.uri();

    // 2. postgres fixture + RBAC seed：admin 角色、operator 角色、admin 自身 role binding。
    let (fixture, pg_owner) = connect_pg().await?;
    let pg = pg_owner.handle();
    let assertion_pool = assertion_pool(fixture.params()).await?;
    let tenant = TenantId::parse(CANON_TENANT)?;
    let actor = ids::UserId::parse(CANON_USER)?;
    let id = pg.for_domain::<caps::Identity>();
    let admin_role = Role::hydrate(
        ADMIN_ROLE,
        "Tenant admin",
        &[
            "identity:role:assign".to_string(),
            "identity:role:read".to_string(),
            "identity:role:revoke".to_string(),
        ],
    )?;
    let admin_role_id = admin_role.id().clone();
    let tenant_scope = TenantRepoScope::for_test(tenant);
    id.role_repo().save(tenant_scope, admin_role).await?;
    id.role_repo()
        .save(
            tenant_scope,
            Role::hydrate(
                OPERATOR_ROLE,
                "Operator",
                &["identity:profile:read".to_string()],
            )?,
        )
        .await?;
    let setup_roles: Arc<DynRoleReadRepo<'static>> =
        Arc::from(DynRoleReadRepo::new_box(id.role_repo()));
    let setup_bindings: Arc<DynRoleBindingLifecycle<'static>> = Arc::from(
        DynRoleBindingLifecycle::new_box(id.role_binding_lifecycle(Box::new(SystemClock))),
    );
    let setup_rbac =
        identity::RbacAdminService::new(setup_roles, setup_bindings, Box::new(SystemClock));
    setup_rbac
        .assign_role(
            ProducerMarker::for_test(ROLES_ASSIGN_PRODUCER).into_receipt(),
            tenant,
            actor,
            vocab::PrincipalKind::Admin,
            CANON_USER.to_string(),
            admin_role_id,
        )
        .await?;

    let assigned_before =
        outbox_topic_count(&assertion_pool, "identity", "identity.role-assigned").await?;
    let revoked_before =
        outbox_topic_count(&assertion_pool, "identity", "identity.role-revoked").await?;
    let settings_key = "app.timeout";
    let settings_before = config_entry_count(&assertion_pool, settings_key).await?;
    let settings_outbox_before =
        outbox_topic_count(&assertion_pool, "settings", SETTINGS_VERSION_CHANGED_TOPIC).await?;

    // 3. production runtime deps + Primary router/auth middleware.
    let stores = unused_tenant_store_allowlist()?;
    let vault = VaultRuntimeDeps::new(
        VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            vault_uri.clone(),
            "test-token",
            Duration::from_secs(5),
            stores,
        )?,
        VaultKeyProvider::new_allow_http(
            reqwest::Client::new(),
            vault_uri.clone(),
            "test-token",
            "transit",
            Duration::from_secs(5),
        )?,
    );
    let redis_ca = test_private_ca_pem();
    let redis = build_unused_redis_runtime_deps()?;
    let s3 = build_s3_runtime_deps_from_values(
        "https://127.0.0.1:1".to_string(),
        "rss-test-bucket".to_string(),
        "access-key".to_string(),
        "secret-key".to_string(),
        true,
        redis_ca,
    )?;
    let deps = build_shared_runtime_deps(
        test_password_blocklist(),
        pg.clone(),
        redis,
        s3,
        vault,
        identity_signer(&vault_uri)?,
        diport::KeyName::try_new("settings-config")?,
        noop_domain_transport(),
    );
    let identity_binding = wire_identity_with(&deps, identity_test_values())?;
    let settings_binding = wire_settings(&deps).await?;
    let mut bindings = vec![identity_binding, settings_binding];
    let (mut registry, _) = bootstrap::compose_bindings(&mut bindings)?;
    let primary = finalize_federated_listener(
        &mut registry,
        Arc::new(federated_test_provider()?),
        httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
        Arc::new(SystemClock),
        assembly_schema::AssemblyListenerKind::Primary,
    )?;
    let app = primary.into_router_for_test();

    // 4. POST /roles/{roleId}/bindings：operator JWT 无 role:assign 权限 → route gate 403，且 zero-write。
    let assign_path = ROLES_ASSIGN_SPEC
        .route
        .path()
        .replace("{roleId}", OPERATOR_ROLE);
    let operator_bearer = format!("Bearer {}", operator_jwt());
    let denied_assign_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(assign_path.clone())
                .header(header::AUTHORIZATION, &operator_bearer)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "subject": TARGET_SUBJECT,
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(
        denied_assign_resp.status(),
        StatusCode::FORBIDDEN,
        "user without role:assign must be denied by Primary route gate"
    );
    assert_eq!(
        role_binding_count(&assertion_pool, OPERATOR_ROLE, TARGET_SUBJECT).await?,
        0,
        "denied role assign must not commit binding"
    );
    assert_eq!(
        outbox_topic_count(&assertion_pool, "identity", "identity.role-assigned").await?,
        assigned_before,
        "denied role assign must not append identity.role-assigned outbox"
    );

    // 5. POST /settings/configs：user JWT 无 settings permission → route gate 403，且 config/outbox 零写。
    let denied_settings_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(SETTINGS_CONFIG_SPEC.route.path())
                .header(header::AUTHORIZATION, &operator_bearer)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "key": settings_key,
                        "value": "30s",
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(
        denied_settings_resp.status(),
        StatusCode::FORBIDDEN,
        "user without settings permission must be denied by Primary route gate"
    );
    assert_eq!(
        config_entry_count(&assertion_pool, settings_key).await?,
        settings_before,
        "denied settings publish must not write config_entries"
    );
    assert_eq!(
        outbox_topic_count(&assertion_pool, "settings", SETTINGS_VERSION_CHANGED_TOPIC).await?,
        settings_outbox_before,
        "denied settings publish must not append settings outbox"
    );

    // 6. POST /settings/configs：trusted Admin 内置 settings permission → route gate 放行，config + outbox 同事务落库。
    let admin_bearer = format!("Bearer {}", admin_jwt());
    let settings_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(SETTINGS_CONFIG_SPEC.route.path())
                .header(header::AUTHORIZATION, &admin_bearer)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "key": settings_key,
                        "value": "30s",
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(
        settings_resp.status(),
        StatusCode::CREATED,
        "admin settings config publish should pass through Primary auth"
    );
    assert_eq!(
        config_entry_count(&assertion_pool, settings_key).await?,
        settings_before + 1,
        "settings config publish must commit config entry"
    );
    assert_eq!(
        outbox_topic_count(&assertion_pool, "settings", SETTINGS_VERSION_CHANGED_TOPIC).await?,
        settings_outbox_before + 1,
        "settings config publish must append settings outbox"
    );

    // 7. POST /roles/{roleId}/bindings：真实 auth middleware 放行 admin JWT，binding + role-assigned outbox 同事务落库。
    let assign_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(assign_path)
                .header(header::AUTHORIZATION, &admin_bearer)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "subject": TARGET_SUBJECT,
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(
        assign_resp.status(),
        StatusCode::CREATED,
        "admin role assign should pass through Primary auth and persist binding"
    );
    assert_eq!(
        role_binding_count(&assertion_pool, OPERATOR_ROLE, TARGET_SUBJECT).await?,
        1,
        "role binding row must be committed"
    );
    assert_eq!(
        outbox_topic_count(&assertion_pool, "identity", "identity.role-assigned").await?,
        assigned_before + 1,
        "role assign must append identity.role-assigned outbox"
    );

    // 8. GET /roles：同一 admin JWT 通过 role:read 权限，真实 repo list 返回 seeded roles。
    let list_uri = format!("{}?limit=20", ROLES_LIST_SPEC.route.path());
    let list_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(list_uri)
                .header(header::AUTHORIZATION, &admin_bearer)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(list_resp.status(), StatusCode::OK, "roles list should pass");
    let list_bytes = axum::body::to_bytes(list_resp.into_body(), usize::MAX).await?;
    let list_text = String::from_utf8(list_bytes.to_vec())?;
    assert!(
        list_text.contains(ADMIN_ROLE) && list_text.contains(OPERATOR_ROLE),
        "roles list should include seeded roles; body: {list_text}"
    );

    // 9. DELETE /roles/{roleId}/bindings/{subject}：真实 auth + Pg lifecycle 删除 binding 并写 revoked outbox。
    let revoke_path = ROLES_REVOKE_SPEC
        .route
        .path()
        .replace("{roleId}", OPERATOR_ROLE)
        .replace("{subject}", TARGET_SUBJECT);
    let revoke_resp = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(revoke_path)
                .header(header::AUTHORIZATION, &admin_bearer)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        revoke_resp.status(),
        StatusCode::OK,
        "admin role revoke should pass through Primary auth"
    );
    assert_eq!(
        role_binding_count(&assertion_pool, OPERATOR_ROLE, TARGET_SUBJECT).await?,
        0,
        "role binding row must be removed"
    );
    assert_eq!(
        outbox_topic_count(&assertion_pool, "identity", "identity.role-revoked").await?,
        revoked_before + 1,
        "role revoke must append identity.role-revoked outbox"
    );

    assertion_pool.close().await;
    Ok(())
}
