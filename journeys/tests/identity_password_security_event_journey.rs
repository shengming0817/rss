//! Password/account-status journey through production composition, HTTP and PostgreSQL.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use diport::Clock as _;
use generated::http::identity_v1::account_status_set::{
    IdentityAccountStatusSetResponse, SPEC as ACCOUNT_STATUS_SPEC,
};
use generated::http::identity_v1::login::{IdentityLoginResponse, SPEC as LOGIN_SPEC};
use generated::http::identity_v1::password_change::{
    IdentityPasswordChangeResponse, SPEC as PASSWORD_CHANGE_SPEC,
};
use generated::http::identity_v1::profile::SPEC as PROFILE_SPEC;
use generated::http::identity_v1::refresh::SPEC as REFRESH_SPEC;
use generated::http::identity_v1::roles_assign::PRODUCER as ROLES_ASSIGN_PRODUCER;
use httpserve::ProducerMarker;
use identity::ports::{
    AccountSecurityReadRepo as _, Credential, CredentialRepo as _, DynRoleBindingLifecycle,
    DynRoleReadRepo, Role, RoleWriteRepo as _, TenantId, TenantRepoScope,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use postgres::{PgConfig, PgPassword, PgRuntimeDeps, PgSslMode, PgTenantReadConfig, caps};
use runtime::support::{SystemClock, TracingAuthAuditSink};
use runtime::test_support::{
    IdentityTestValues, build_redis_runtime_deps_from_values, build_s3_runtime_deps_from_values,
    build_shared_runtime_deps, build_vault_runtime_from_values, finalize_rss_listener,
    test_private_ca_pem, wire_identity_with_password_change_barrier,
};
use serde::Deserialize;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use tower::ServiceExt as _;
use vault::{SignatureMarshaling, VaultSigner};
use wiremock::matchers::{body_partial_json, method as match_method};
use wiremock::{Mock, MockServer, Request as MockRequest, Respond, ResponseTemplate};

const FIXTURE: &str = include_str!("../../fixtures/identity-password-security-event.toml");
const JOURNEY_ID: &str = "identity-password-security-event";
const JOURNEY_SPEC: &str = "journeys/identity-password-security-event-journey.toml";
const JOURNEY_RUNNER: &str = "journeys/tests/identity_password_security_event_journey.rs";
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const OTHER_TENANT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const USER: &str = "11111111-2222-4333-8444-555555555555";
const OTHER_TENANT_USER: &str = "22222222-3333-4444-8555-666666666666";
const USERNAME: &str = "password-security-alice";
const CURRENT_PASSWORD: &str = "journey-current-password-sentinel";
const NEW_PASSWORD: &str = "journey-new-password-sentinel";
const FAILURE_NEW_PASSWORD: &str = "journey-failure-new-password-sentinel";
const WRONG_CURRENT_PASSWORD: &str = "journey-wrong-current-password-sentinel";
const POLICY_REJECTED_PASSWORD: &str = "policy-bad";
const TEST_APP_ROLE: &str = "rss_app";
const TEST_APP_PASSWORD: &str = "rss_app_test_pw";
const TEST_READ_ROLE: &str = "rss_app_read";
const TEST_READ_PASSWORD: &str = "rss_app_read_test_pw";

type TestResult<T = ()> = anyhow::Result<T>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JourneyFixture {
    schema_version: u8,
    id: String,
    contract_id: String,
    tx_model: String,
    spec: String,
    runner: String,
    marker: String,
    delegated_evidence: Vec<String>,
    cases: Vec<JourneyCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JourneyCase {
    id: String,
    scenario: String,
    operation: String,
    http_status: u16,
    #[serde(default)]
    competing_http_status: u16,
    #[serde(default)]
    commits: u32,
    #[serde(default)]
    initial_credential_version: u32,
    #[serde(default)]
    credential_version_delta: u32,
    #[serde(default)]
    account_epoch_delta: u64,
    #[serde(default)]
    revoked_grants: u32,
    #[serde(default)]
    revoked_families: u32,
    #[serde(default)]
    event_kind: String,
    #[serde(default)]
    old_access_status: u16,
    #[serde(default)]
    old_refresh_status: u16,
    #[serde(default)]
    redact_sentinels: Vec<String>,
}

impl JourneyFixture {
    fn case(&self, id: &str) -> Result<&JourneyCase> {
        self.cases
            .iter()
            .find(|case| case.id == id)
            .with_context(|| format!("fixture case `{id}` is missing"))
    }
}

struct NoopDomainTransport;

impl distributed::HttpContractTransport for NoopDomainTransport {
    fn dispatch(
        &self,
        _request: distributed::HttpContractRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        distributed::HttpContractResponse,
                        distributed::HttpContractTransportError,
                    >,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async { distributed::HttpContractResponse::try_new(204, Vec::new()) })
    }
}

fn validate_fixture() -> Result<JourneyFixture> {
    let fixture: JourneyFixture =
        toml::from_str(FIXTURE).context("parse password journey fixture")?;
    ensure!(fixture.schema_version == 1);
    ensure!(fixture.id == JOURNEY_ID);
    ensure!(fixture.contract_id == PASSWORD_CHANGE_SPEC.route.contract_id());
    ensure!(fixture.tx_model == "producer-transaction");
    ensure!(fixture.spec == JOURNEY_SPEC);
    ensure!(fixture.runner == JOURNEY_RUNNER);
    ensure!(fixture.marker == "IDENTITY_PASSWORD_CHANGE");
    ensure!(
        fixture.delegated_evidence
            == [
                "adapters/postgres::identity_security_full_snapshot_cas_rejects_timestamp_only_staleness",
                "adapters/postgres::password_change_security_event_fault_matrix_rolls_back_every_stage",
            ]
    );
    let case = fixture.case("identity-password-security-event-happy")?;
    ensure!(case.id == "identity-password-security-event-happy");
    ensure!(case.scenario == "password-security-event");
    ensure!(case.operation == "password-change");
    ensure!(case.http_status == 200 && case.commits == 1);
    ensure!(case.credential_version_delta == 1 && case.account_epoch_delta == 1);
    ensure!(case.revoked_grants == 2 && case.revoked_families == 2);
    ensure!(case.event_kind == "passwordChanged");
    ensure!(case.old_access_status == 401 && case.old_refresh_status == 401);
    ensure!(case.redact_sentinels == [CURRENT_PASSWORD, NEW_PASSWORD]);
    let case = fixture.case("identity-password-security-event-concurrent-conflict")?;
    ensure!(case.scenario == "password-security-event-concurrent-conflict");
    ensure!(case.operation == "password-change");
    ensure!(case.http_status == 200 && case.competing_http_status == 409);
    ensure!(case.commits == 1);
    ensure!(case.initial_credential_version == 1);
    ensure!(case.credential_version_delta == 1 && case.account_epoch_delta == 1);
    ensure!(case.revoked_grants == 2 && case.revoked_families == 2);
    ensure!(case.event_kind == "passwordChanged");
    ensure!(case.redact_sentinels == [CURRENT_PASSWORD, NEW_PASSWORD]);
    for (id, operation, status) in [
        (
            "identity-password-security-event-unauthenticated",
            "password-change",
            401,
        ),
        (
            "identity-password-security-event-invalid-subject",
            "password-change",
            401,
        ),
        (
            "identity-password-security-event-wrong-current-password",
            "password-change",
            403,
        ),
        (
            "identity-password-security-event-policy-rejected",
            "password-change",
            400,
        ),
        (
            "identity-account-status-set-unauthenticated",
            "account-status-set",
            401,
        ),
        (
            "identity-account-status-set-invalid-subject",
            "account-status-set",
            401,
        ),
        (
            "identity-account-status-set-invalid-user-id",
            "account-status-set",
            400,
        ),
        (
            "identity-account-status-set-invalid-payload",
            "account-status-set",
            400,
        ),
        (
            "identity-account-status-set-unknown-target",
            "account-status-set",
            404,
        ),
        (
            "identity-account-status-set-cross-tenant-target",
            "account-status-set",
            404,
        ),
    ] {
        let case = fixture.case(id)?;
        ensure!(case.scenario == "failure-zero-effects");
        ensure!(case.operation == operation);
        ensure!(case.http_status == status);
        ensure!(case.commits == 0);
    }
    Ok(fixture)
}

fn pg_config(params: &testkit::PgConnParams, username: &str, password: &str) -> PgConfig {
    PgConfig::new(
        params.host.clone(),
        params.port,
        params.database.clone(),
        username.to_owned(),
        PgPassword::new(password.to_owned()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(Duration::from_secs(5))
}

async fn production_postgres() -> TestResult<(testkit::OwnedPgFixture, PgRuntimeDeps)> {
    let fixture = testkit::owned_postgres().await?;
    let params = fixture.owner_params();
    let [app, reader] = fixture
        .resolve_app_roles([
            testkit::PgAppRoleSpec::new(TEST_APP_ROLE, TEST_APP_PASSWORD),
            testkit::PgAppRoleSpec::new(TEST_READ_ROLE, TEST_READ_PASSWORD),
        ])
        .await?;
    let tenant_read = PgTenantReadConfig::new(pg_config(
        reader.params(),
        &reader.params().username,
        &reader.params().password,
    ));
    let workflow = eventexec::WorkflowRuntimePlan::disabled_fixture();
    let deps = PgRuntimeDeps::setup_owned_test_fixture(
        &pg_config(params, &params.username, &params.password),
        &pg_config(app.params(), &app.params().username, &app.params().password),
        &tenant_read,
        None,
        workflow.projection_capture(),
    )
    .await?;
    Ok((fixture, deps))
}

async fn observation_pool(params: &testkit::PgConnParams) -> TestResult<PgPool> {
    let options = PgConnectOptions::new()
        .host(&params.host)
        .port(params.port)
        .database(&params.database)
        .username(&params.username)
        .password(&params.password)
        .ssl_mode(SqlxPgSslMode::Prefer);
    Ok(PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?)
}

fn identity_values() -> IdentityTestValues {
    IdentityTestValues {
        access_token_issuer: "https://issuer.test".to_owned(),
        access_token_audience: "rss".to_owned(),
        access_token_key_id: "rss-jwt-es256".to_owned(),
        access_token_ttl: Duration::from_secs(900),
        auth_grant_ttl: Duration::from_secs(2_592_000),
        refresh_ttl: Duration::from_secs(2_592_000),
    }
}

#[allow(clippy::expect_used)]
fn signing_key() -> SigningKey {
    let bytes: [u8; 32] = std::array::from_fn(|index| (index + 1) as u8);
    SigningKey::from_slice(&bytes).expect("valid P-256 scalar")
}

fn sec1(signing_key: &SigningKey) -> Vec<u8> {
    signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

fn mint_es256(payload: &serde_json::Value) -> String {
    let header = B64_URL.encode(br#"{"alg":"ES256","typ":"at+jwt","kid":"rss-jwt-es256"}"#);
    let body = B64_URL.encode(payload.to_string().as_bytes());
    let signing_input = format!("{header}.{body}");
    let signature: Signature = signing_key().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64_URL.encode(signature.to_bytes()))
}

fn invalid_subject_access_token(session_id: &str) -> Result<String> {
    let issued_at = SystemClock
        .now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(mint_es256(&serde_json::json!({
        "sub": "not-a-canonical-rss-user",
        "tenant_id": TENANT,
        "kind": "user",
        "sid": session_id,
        "jti": "77777777-7777-4777-8777-777777777777",
        "auth_time": issued_at,
        "authn_epoch": 0,
        "token_use": "access",
        "iat": issued_at,
        "exp": issued_at + 900,
        "iss": "https://issuer.test",
        "aud": "rss",
    })))
}

struct TransitSignResponder(SigningKey);

impl Respond for TransitSignResponder {
    #[allow(clippy::expect_used)]
    fn respond(&self, request: &MockRequest) -> ResponseTemplate {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("Transit request must be JSON");
        let message = B64_STD
            .decode(
                body["input"]
                    .as_str()
                    .expect("Transit input must be present"),
            )
            .expect("Transit input must be base64");
        let signature: Signature = self.0.sign(&message);
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "signature": format!("vault:v1:{}", B64_URL.encode(signature.to_bytes())) }
        }))
    }
}

fn verifier() -> oidc::OidcProvider<diport::RssAccessProfile> {
    let public_key = B64_URL.encode(sec1(&signing_key()));
    let keys = [runtime::KeyedEs256StaticKey {
        key_id: "rss-jwt-es256",
        sec1_b64url: &public_key,
    }];
    runtime::rss_access_provider_from_static_config(runtime::RssAccessStaticProviderConfig {
        issuer: "https://issuer.test",
        audience: "rss",
        keys: &keys,
        retirement_schedule: None,
        clock: Box::new(SystemClock),
    })
    .unwrap_or_else(|_| unreachable!())
}

async fn request(
    app: &axum::Router,
    method: Method,
    path: &str,
    tenant: &str,
    bearer: Option<&str>,
    body: serde_json::Value,
) -> TestResult<(StatusCode, Vec<u8>)> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-Tenant-ID", tenant);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_string()))?)
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await?.to_vec();
    Ok((status, bytes))
}

async fn login(app: &axum::Router, password: &str) -> TestResult<IdentityLoginResponse> {
    let (status, body) = request(
        app,
        Method::POST,
        LOGIN_SPEC.route.path(),
        TENANT,
        None,
        serde_json::json!({ "username": USERNAME, "password": password }),
    )
    .await?;
    ensure!(
        status == StatusCode::CREATED,
        "login returned {status}: {}",
        String::from_utf8_lossy(&body)
    );
    Ok(serde_json::from_slice(&body)?)
}

async fn seed_rbac(pg: &postgres::PgRuntimeHandle, tenant: TenantId) -> TestResult {
    let identity = pg.for_domain::<caps::Identity>();
    let role = Role::hydrate(
        "credential-security-owner",
        "Password and account security mutations",
        &[
            "identity:profile:write".to_owned(),
            "identity:account-security:write".to_owned(),
        ],
    )?;
    let role_id = role.id().clone();
    identity
        .role_repo()
        .save(TenantRepoScope::for_test(tenant), role)
        .await?;
    let service = identity::RbacAdminService::new(
        Arc::from(DynRoleReadRepo::new_box(identity.role_repo())),
        Arc::from(DynRoleBindingLifecycle::new_box(
            identity.role_binding_lifecycle(Box::new(SystemClock)),
        )),
        Box::new(SystemClock),
    );
    service
        .assign_role(
            ProducerMarker::for_test(ROLES_ASSIGN_PRODUCER).into_receipt(),
            tenant,
            ids::UserId::parse(USER)?,
            vocab::PrincipalKind::User,
            USER.to_owned(),
            role_id,
        )
        .await?;
    Ok(())
}

fn assert_redacted(body: &[u8], sentinels: &[&str]) -> TestResult {
    let rendered = String::from_utf8_lossy(body);
    for sentinel in sentinels {
        ensure!(
            !rendered.contains(sentinel),
            "HTTP response leaked a security sentinel"
        );
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct SecuritySnapshot {
    credential: Option<(i64, String)>,
    account: Option<(String, i64, i64)>,
    grants: Vec<(String, String, Option<String>)>,
    refresh_families: Vec<(String, String, String)>,
    security_outbox: i64,
    published_security_outbox: i64,
}

async fn security_snapshot(
    pool: &PgPool,
    tenant: &str,
    user: &str,
) -> TestResult<SecuritySnapshot> {
    let credential = sqlx::query_as::<_, (i64, String)>(
        "SELECT version, password_hash FROM credentials \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(tenant)
    .bind(user)
    .fetch_optional(pool)
    .await?;
    let account = sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT status, authn_epoch, version FROM account_security_states \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(tenant)
    .bind(user)
    .fetch_optional(pool)
    .await?;
    let grants = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT grant_id, status, close_reason FROM auth_grants \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid ORDER BY grant_id",
    )
    .bind(tenant)
    .bind(user)
    .fetch_all(pool)
    .await?;
    let refresh_families = sqlx::query_as::<_, (String, String, String)>(
        "SELECT id::text, status, auth_grant_status FROM refresh_tokens \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid ORDER BY id",
    )
    .bind(tenant)
    .bind(user)
    .fetch_all(pool)
    .await?;
    let (security_outbox, published_security_outbox) = sqlx::query_as::<_, (i64, i64)>(
        "SELECT count(*), count(*) FILTER (WHERE status = 'published' AND published_at IS NOT NULL) \
         FROM outbox WHERE tenant_id = $1::uuid AND domain = 'identity' \
         AND topic = 'identity.security-event'",
    )
    .bind(tenant)
    .fetch_one(pool)
    .await?;
    Ok(SecuritySnapshot {
        credential,
        account,
        grants,
        refresh_families,
        security_outbox,
        published_security_outbox,
    })
}

async fn assert_zero_effect_failure(
    fixture: &JourneyFixture,
    pool: &PgPool,
    case_id: &str,
    before: &SecuritySnapshot,
    status: StatusCode,
    body: &[u8],
    extra_sentinels: &[&str],
) -> TestResult {
    let case = fixture.case(case_id)?;
    ensure!(
        status.as_u16() == case.http_status,
        "{} returned {status}: {}",
        case.id,
        String::from_utf8_lossy(body)
    );
    let mut sentinels = case
        .redact_sentinels
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    sentinels.extend_from_slice(extra_sentinels);
    assert_redacted(body, &sentinels)?;
    let after = security_snapshot(pool, TENANT, USER).await?;
    ensure!(
        &after == before,
        "{} changed credential/account/grant/family/outbox/publish state:\nbefore={before:#?}\nafter={after:#?}",
        case.id
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn identity_password_security_event_journey() -> TestResult {
    let fixture_book = validate_fixture()?;
    let happy_case = fixture_book.case("identity-password-security-event-happy")?;
    let concurrent_case =
        fixture_book.case("identity-password-security-event-concurrent-conflict")?;
    let vault_server = MockServer::start().await;
    Mock::given(match_method("POST"))
        .and(body_partial_json(
            serde_json::json!({ "marshaling_algorithm": "jws" }),
        ))
        .respond_with(TransitSignResponder(signing_key()))
        .mount(&vault_server)
        .await;

    let (postgres_fixture, postgres_owner) = production_postgres().await?;
    let observer = observation_pool(postgres_fixture.owner_params()).await?;
    let pg = postgres_owner.handle();
    let tenant = TenantId::parse(TENANT)?;
    let identity = pg.for_domain::<caps::Identity>();
    identity
        .credential_repo()
        .insert(
            TenantRepoScope::for_test(tenant),
            Credential::hydrate(
                USERNAME,
                ids::UserId::parse(USER)?,
                tenant,
                secure::PasswordHash::for_test(secure::RawPassword::new(
                    CURRENT_PASSWORD.to_owned(),
                ))?,
                concurrent_case.initial_credential_version,
            ),
        )
        .await?;
    identity
        .credential_repo()
        .insert(
            TenantRepoScope::for_test(TenantId::parse(OTHER_TENANT)?),
            Credential::hydrate(
                "other-tenant-target",
                ids::UserId::parse(OTHER_TENANT_USER)?,
                TenantId::parse(OTHER_TENANT)?,
                secure::PasswordHash::for_test(secure::RawPassword::new(
                    CURRENT_PASSWORD.to_owned(),
                ))?,
                1,
            ),
        )
        .await?;
    seed_rbac(&pg, tenant).await?;
    let account_before = identity
        .account_security_repo()
        .find(TenantRepoScope::for_test(tenant), ids::UserId::parse(USER)?)
        .await?
        .context("credential insert omitted account-security state")?;

    let redis_fixture = testkit::env_or_redis().await?;
    let private_ca = test_private_ca_pem();
    let redis =
        build_redis_runtime_deps_from_values(redis_fixture.url().to_owned(), private_ca.clone())
            .await?;
    let s3 = build_s3_runtime_deps_from_values(
        "http://127.0.0.1:1".to_owned(),
        "rss-password-security-test".to_owned(),
        "access-key".to_owned(),
        "secret-key".to_owned(),
        true,
        private_ca,
    )?;
    let (vault, _unused_signer, settings_key) = build_vault_runtime_from_values(
        "https://127.0.0.1:1".to_owned(),
        "test-token".to_owned(),
        "transit".to_owned(),
        "settings-config".to_owned(),
        format!(
            r#"{{"bindings":[{{"tenantId":"{OTHER_TENANT}","storeId":"vault","mount":"secret","kvPathPrefix":"tenants/a"}}]}}"#
        ),
    )?;
    let signer = Arc::new(VaultSigner::new_allow_http(
        reqwest::Client::new(),
        vault_server.uri(),
        "test-token",
        "transit",
        Duration::from_secs(5),
        SignatureMarshaling::Jws,
    )?);
    let blocklist =
        Arc::new(secure::DigestPasswordBlocklist::from_nonempty_sha256_digests([0xA5; 32], []));
    let deps = build_shared_runtime_deps(
        Arc::clone(&blocklist),
        pg.clone(),
        redis,
        s3,
        vault,
        signer,
        settings_key,
        Arc::new(NoopDomainTransport),
    );
    let password_change_barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut bindings = vec![wire_identity_with_password_change_barrier(
        &deps,
        identity_values(),
        password_change_barrier,
    )?];
    let (mut registry, _output) = bootstrap::compose_bindings(&mut bindings)?;
    let routes = finalize_rss_listener(
        &mut registry,
        Arc::new(verifier()),
        runtime::test_support::access_grant_validation_service(identity.auth_grant_validator()),
        httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
        Arc::new(SystemClock),
        assembly_schema::AssemblyListenerKind::Primary,
    )?;
    let app = routes.into_router_for_test();

    let first = login(&app, CURRENT_PASSWORD).await?;
    let second = login(&app, CURRENT_PASSWORD).await?;
    let (pre_status, _) = request(
        &app,
        Method::GET,
        PROFILE_SPEC.route.path(),
        TENANT,
        Some(&first.data.access_token),
        serde_json::json!({}),
    )
    .await?;
    ensure!(
        pre_status == StatusCode::OK,
        "old access precondition must be current"
    );

    let before_password_failures = security_snapshot(&observer, TENANT, USER).await?;
    let (status, body) = request(
        &app,
        Method::POST,
        PASSWORD_CHANGE_SPEC.route.path(),
        TENANT,
        None,
        serde_json::json!({
            "currentPassword": CURRENT_PASSWORD,
            "newPassword": FAILURE_NEW_PASSWORD,
        }),
    )
    .await?;
    assert_zero_effect_failure(
        &fixture_book,
        &observer,
        "identity-password-security-event-unauthenticated",
        &before_password_failures,
        status,
        &body,
        &[],
    )
    .await?;

    let invalid_subject = invalid_subject_access_token(&first.data.session_id)?;
    let (status, body) = request(
        &app,
        Method::POST,
        PASSWORD_CHANGE_SPEC.route.path(),
        TENANT,
        Some(&invalid_subject),
        serde_json::json!({
            "currentPassword": CURRENT_PASSWORD,
            "newPassword": FAILURE_NEW_PASSWORD,
        }),
    )
    .await?;
    assert_zero_effect_failure(
        &fixture_book,
        &observer,
        "identity-password-security-event-invalid-subject",
        &before_password_failures,
        status,
        &body,
        &[&invalid_subject],
    )
    .await?;

    let (status, body) = request(
        &app,
        Method::POST,
        PASSWORD_CHANGE_SPEC.route.path(),
        TENANT,
        Some(&first.data.access_token),
        serde_json::json!({
            "currentPassword": WRONG_CURRENT_PASSWORD,
            "newPassword": FAILURE_NEW_PASSWORD,
        }),
    )
    .await?;
    assert_zero_effect_failure(
        &fixture_book,
        &observer,
        "identity-password-security-event-wrong-current-password",
        &before_password_failures,
        status,
        &body,
        &[&first.data.access_token],
    )
    .await?;

    let (status, body) = request(
        &app,
        Method::POST,
        PASSWORD_CHANGE_SPEC.route.path(),
        TENANT,
        Some(&first.data.access_token),
        serde_json::json!({
            "currentPassword": CURRENT_PASSWORD,
            "newPassword": POLICY_REJECTED_PASSWORD,
        }),
    )
    .await?;
    assert_zero_effect_failure(
        &fixture_book,
        &observer,
        "identity-password-security-event-policy-rejected",
        &before_password_failures,
        status,
        &body,
        &[&first.data.access_token],
    )
    .await?;

    let password_request = || {
        request(
            &app,
            Method::POST,
            PASSWORD_CHANGE_SPEC.route.path(),
            TENANT,
            Some(&first.data.access_token),
            serde_json::json!({
                "currentPassword": CURRENT_PASSWORD,
                "newPassword": NEW_PASSWORD,
            }),
        )
    };
    let (left, right) = tokio::join!(password_request(), password_request());
    let mut password_results = [left?, right?];
    password_results.sort_by_key(|(status, _)| status.as_u16());
    ensure!(
        password_results[0].0.as_u16() == concurrent_case.http_status
            && password_results[1].0.as_u16() == concurrent_case.competing_http_status,
        "concurrent password change must have one winner and one CAS conflict, got {} and {}",
        password_results[0].0,
        password_results[1].0,
    );
    let password_response: IdentityPasswordChangeResponse =
        serde_json::from_slice(&password_results[0].1)?;
    ensure!(password_response.data.changed);
    for (_, body) in &password_results {
        assert_redacted(body, &[CURRENT_PASSWORD, NEW_PASSWORD])?;
    }

    for old_access in [&first.data.access_token, &second.data.access_token] {
        let (status, body) = request(
            &app,
            Method::GET,
            PROFILE_SPEC.route.path(),
            TENANT,
            Some(old_access),
            serde_json::json!({}),
        )
        .await?;
        ensure!(status.as_u16() == happy_case.old_access_status);
        assert_redacted(&body, &[old_access])?;
    }
    for old_refresh in [&first.data.refresh_token, &second.data.refresh_token] {
        let (status, body) = request(
            &app,
            Method::POST,
            REFRESH_SPEC.route.path(),
            TENANT,
            None,
            serde_json::json!({ "refreshToken": old_refresh }),
        )
        .await?;
        ensure!(status.as_u16() == happy_case.old_refresh_status);
        assert_redacted(&body, &[old_refresh])?;
    }

    let credential_after_password = identity
        .credential_repo()
        .find_by_user_id(TenantRepoScope::for_test(tenant), ids::UserId::parse(USER)?)
        .await?
        .context("credential disappeared after password change")?;
    ensure!(
        credential_after_password.version()
            == concurrent_case.initial_credential_version
                + concurrent_case.credential_version_delta
    );
    let account_after_password = identity
        .account_security_repo()
        .find(TenantRepoScope::for_test(tenant), ids::UserId::parse(USER)?)
        .await?
        .context("account-security state disappeared after password change")?;
    ensure!(account_after_password.status() == identity::AccountStatus::Active);
    ensure!(
        account_after_password.authn_epoch().get()
            == account_before.authn_epoch().get() + concurrent_case.account_epoch_delta
    );
    let password_revoked_grants = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM auth_grants WHERE tenant_id = $1::uuid AND user_id = $2::uuid \
         AND status = 'revoked' AND close_reason = 'password_changed'",
    )
    .bind(TENANT)
    .bind(USER)
    .fetch_one(&observer)
    .await?;
    ensure!(password_revoked_grants == i64::from(concurrent_case.revoked_grants));
    let password_revoked_families = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM refresh_tokens WHERE tenant_id = $1::uuid AND user_id = $2::uuid \
         AND status = 'revoked' AND auth_grant_status = 'revoked'",
    )
    .bind(TENANT)
    .bind(USER)
    .fetch_one(&observer)
    .await?;
    ensure!(password_revoked_families == i64::from(concurrent_case.revoked_families));
    let password_events = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM outbox WHERE domain = 'identity' \
         AND topic = 'identity.security-event' \
         AND (convert_from(payload, 'UTF8')::jsonb)->>'kind' = 'passwordChanged'",
    )
    .fetch_one(&observer)
    .await?;
    ensure!(password_events == i64::from(concurrent_case.commits));

    let (old_login_status, old_login_body) = request(
        &app,
        Method::POST,
        LOGIN_SPEC.route.path(),
        TENANT,
        None,
        serde_json::json!({ "username": USERNAME, "password": CURRENT_PASSWORD }),
    )
    .await?;
    ensure!(old_login_status == StatusCode::UNAUTHORIZED);
    assert_redacted(&old_login_body, &[CURRENT_PASSWORD])?;
    let replacement = login(&app, NEW_PASSWORD).await?;

    let before_account_status_failures = security_snapshot(&observer, TENANT, USER).await?;
    let account_status_path = ACCOUNT_STATUS_SPEC.route.path().replace("{userId}", USER);
    let (status, body) = request(
        &app,
        Method::PUT,
        &account_status_path,
        TENANT,
        None,
        serde_json::json!({ "targetStatus": "suspended" }),
    )
    .await?;
    assert_zero_effect_failure(
        &fixture_book,
        &observer,
        "identity-account-status-set-unauthenticated",
        &before_account_status_failures,
        status,
        &body,
        &[],
    )
    .await?;

    let invalid_subject = invalid_subject_access_token(&replacement.data.session_id)?;
    let (status, body) = request(
        &app,
        Method::PUT,
        &account_status_path,
        TENANT,
        Some(&invalid_subject),
        serde_json::json!({ "targetStatus": "suspended" }),
    )
    .await?;
    assert_zero_effect_failure(
        &fixture_book,
        &observer,
        "identity-account-status-set-invalid-subject",
        &before_account_status_failures,
        status,
        &body,
        &[&invalid_subject],
    )
    .await?;

    let (status, body) = request(
        &app,
        Method::PUT,
        &ACCOUNT_STATUS_SPEC
            .route
            .path()
            .replace("{userId}", "not-a-user-id"),
        TENANT,
        Some(&replacement.data.access_token),
        serde_json::json!({ "targetStatus": "suspended" }),
    )
    .await?;
    assert_zero_effect_failure(
        &fixture_book,
        &observer,
        "identity-account-status-set-invalid-user-id",
        &before_account_status_failures,
        status,
        &body,
        &[&replacement.data.access_token],
    )
    .await?;

    let (status, body) = request(
        &app,
        Method::PUT,
        &account_status_path,
        TENANT,
        Some(&replacement.data.access_token),
        serde_json::json!({ "targetStatus": "invalid-status" }),
    )
    .await?;
    assert_zero_effect_failure(
        &fixture_book,
        &observer,
        "identity-account-status-set-invalid-payload",
        &before_account_status_failures,
        status,
        &body,
        &[&replacement.data.access_token],
    )
    .await?;

    let (status, body) = request(
        &app,
        Method::PUT,
        &ACCOUNT_STATUS_SPEC
            .route
            .path()
            .replace("{userId}", "33333333-4444-4555-8666-777777777777"),
        TENANT,
        Some(&replacement.data.access_token),
        serde_json::json!({ "targetStatus": "suspended" }),
    )
    .await?;
    assert_zero_effect_failure(
        &fixture_book,
        &observer,
        "identity-account-status-set-unknown-target",
        &before_account_status_failures,
        status,
        &body,
        &[&replacement.data.access_token],
    )
    .await?;

    let decoy_before = security_snapshot(&observer, OTHER_TENANT, OTHER_TENANT_USER).await?;
    let (cross_tenant_status, cross_tenant_body) = request(
        &app,
        Method::PUT,
        &ACCOUNT_STATUS_SPEC
            .route
            .path()
            .replace("{userId}", OTHER_TENANT_USER),
        TENANT,
        Some(&replacement.data.access_token),
        serde_json::json!({ "targetStatus": "suspended" }),
    )
    .await?;
    assert_zero_effect_failure(
        &fixture_book,
        &observer,
        "identity-account-status-set-cross-tenant-target",
        &before_account_status_failures,
        cross_tenant_status,
        &cross_tenant_body,
        &[&replacement.data.access_token],
    )
    .await?;
    let decoy_after = security_snapshot(&observer, OTHER_TENANT, OTHER_TENANT_USER).await?;
    ensure!(
        decoy_after == decoy_before,
        "cross-tenant account-status set changed decoy durable state"
    );
    let decoy = identity
        .account_security_repo()
        .find(
            TenantRepoScope::for_test(TenantId::parse(OTHER_TENANT)?),
            ids::UserId::parse(OTHER_TENANT_USER)?,
        )
        .await?
        .context("other-tenant decoy disappeared")?;
    ensure!(decoy.status() == identity::AccountStatus::Active);

    let (set_status, set_body) = request(
        &app,
        Method::PUT,
        &ACCOUNT_STATUS_SPEC.route.path().replace("{userId}", USER),
        TENANT,
        Some(&replacement.data.access_token),
        serde_json::json!({ "targetStatus": "suspended" }),
    )
    .await?;
    ensure!(set_status == StatusCode::OK);
    let set_response: IdentityAccountStatusSetResponse = serde_json::from_slice(&set_body)?;
    ensure!(set_response.data.status.to_string() == "suspended");
    assert_redacted(&set_body, &[&replacement.data.access_token])?;
    let (suspended_access, body) = request(
        &app,
        Method::GET,
        PROFILE_SPEC.route.path(),
        TENANT,
        Some(&replacement.data.access_token),
        serde_json::json!({}),
    )
    .await?;
    ensure!(suspended_access == StatusCode::UNAUTHORIZED);
    assert_redacted(&body, &[&replacement.data.access_token])?;
    let (suspended_refresh, body) = request(
        &app,
        Method::POST,
        REFRESH_SPEC.route.path(),
        TENANT,
        None,
        serde_json::json!({ "refreshToken": replacement.data.refresh_token }),
    )
    .await?;
    ensure!(suspended_refresh == StatusCode::UNAUTHORIZED);
    assert_redacted(&body, &[&replacement.data.refresh_token])?;

    let account_after = identity
        .account_security_repo()
        .find(TenantRepoScope::for_test(tenant), ids::UserId::parse(USER)?)
        .await?
        .context("account-security state disappeared")?;
    ensure!(account_after.status() == identity::AccountStatus::Suspended);
    ensure!(account_after.authn_epoch().get() == account_before.authn_epoch().get() + 2);

    let outbox_payloads = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT convert_from(payload, 'UTF8')::jsonb FROM outbox \
         WHERE domain = 'identity' AND topic = 'identity.security-event'",
    )
    .fetch_all(&observer)
    .await?;
    ensure!(outbox_payloads.len() == 2);
    ensure!(outbox_payloads.iter().any(|payload| {
        payload.get("kind").and_then(serde_json::Value::as_str)
            == Some(happy_case.event_kind.as_str())
    }));
    for payload in outbox_payloads {
        let rendered = payload.to_string();
        ensure!(!rendered.contains(CURRENT_PASSWORD));
        ensure!(!rendered.contains(NEW_PASSWORD));
        ensure!(!rendered.contains(&first.data.access_token));
        ensure!(!rendered.contains(&first.data.refresh_token));
    }

    observer.close().await;
    drop(redis_fixture);
    drop(postgres_fixture);
    Ok(())
}
