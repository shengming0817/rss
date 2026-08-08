//! `identity.refresh` OutboxFact producer-transaction acceptance journey.

use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use generated::http::identity_v1::login::SPEC as LOGIN_SPEC;
use generated::http::identity_v1::refresh::SPEC as REFRESH_SPEC;
use identity::ports::{Credential, CredentialRepo as _, TenantId, TenantRepoScope};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use postgres::{PgConfig, PgPassword, PgRuntimeDeps, PgSslMode, PgTenantReadConfig, caps};
use runtime::support::{SystemClock, TracingAuthAuditSink};
use runtime::test_support::{
    IdentityTestValues, build_redis_runtime_deps_from_values, build_s3_runtime_deps_from_values,
    build_shared_runtime_deps, build_vault_runtime_from_values, finalize_rss_listener,
    test_private_ca_pem, wire_identity_with,
};
use serde::Deserialize;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use tower::ServiceExt as _;
use vault::{SignatureMarshaling, VaultSigner};
use wiremock::matchers::{body_partial_json, method as match_method};
use wiremock::{Mock, MockServer, Request as MockRequest, Respond, ResponseTemplate};

type TestResult<T = ()> = anyhow::Result<T>;

const FIXTURE: &str = include_str!("../../fixtures/identity-refresh-producer-transaction.toml");
const SPEC: &str = include_str!("../identity-refresh-producer-transaction-journey.toml");
const POSTGRES_EVIDENCE: &str =
    include_str!("../../adapters/postgres/src/integration_tests/identity_persistence_tests.rs");
const JOURNEY_ID: &str = "identity-refresh-producer-transaction";
const JOURNEY_SPEC: &str = "journeys/identity-refresh-producer-transaction-journey.toml";
const JOURNEY_RUNNER: &str = "journeys/tests/identity_refresh_producer_transaction_journey.rs";
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const USER: &str = "11111111-2222-4333-8444-555555555555";
const USERNAME: &str = "refresh-journey-user";
const PASSWORD: &str = "refresh-journey-password";
const TEST_APP_ROLE: &str = "rss_app";
const TEST_APP_PASSWORD: &str = "rss_app_test_pw";
const TEST_READ_ROLE: &str = "rss_app_read";
const TEST_READ_PASSWORD: &str = "rss_app_read_test_pw";

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
    http_status: u16,
    durable_mutations: u16,
    security_events: u16,
    settlement: String,
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

fn validate_acceptance_carriers() -> Result<JourneyFixture> {
    const REFRESH_OUTBOX_ROUTE: ::vocab::HttpRouteBinding<
        ::generated::http::identity_v1::refresh::RouteMarker,
        ::vocab::http::OutboxFact,
    > = ::generated::http::identity_v1::refresh::ROUTE;
    let _ = REFRESH_OUTBOX_ROUTE;

    ensure!(!FIXTURE.contains("LocalTx") && !SPEC.contains("LocalTx"));
    let fixture: JourneyFixture = toml::from_str(FIXTURE)?;
    ensure!(fixture.schema_version == 1);
    ensure!(fixture.id == JOURNEY_ID);
    ensure!(fixture.contract_id == REFRESH_SPEC.route.contract_id());
    ensure!(fixture.tx_model == "producer-transaction");
    ensure!(fixture.spec == JOURNEY_SPEC && fixture.runner == JOURNEY_RUNNER);
    ensure!(fixture.marker == "IDENTITY_REFRESH");
    ensure!(
        fixture.delegated_evidence
            == [
                "adapters/postgres::refresh_rotation_commit_unknown_never_returns_a_persisted_receipt"
            ]
    );
    ensure!(
        POSTGRES_EVIDENCE.contains(
            "async fn refresh_rotation_commit_unknown_never_returns_a_persisted_receipt()"
        )
    );
    ensure!(POSTGRES_EVIDENCE.contains(
        "a lost commit acknowledgement must not return Applied or its persisted receipt"
    ));

    let expected = [
        (
            "identity-refresh-happy-no-event",
            "rotation-without-security-event",
            201,
            2,
            0,
            "committed",
        ),
        (
            "identity-refresh-malformed",
            "failure-zero-effects",
            400,
            0,
            0,
            "not-started",
        ),
        (
            "identity-refresh-unknown",
            "failure-zero-effects",
            401,
            0,
            0,
            "not-started",
        ),
        (
            "identity-refresh-contention-winner",
            "concurrent-reuse-containment",
            201,
            2,
            0,
            "committed",
        ),
        (
            "identity-refresh-contention-loser",
            "concurrent-reuse-containment",
            401,
            3,
            1,
            "committed",
        ),
        (
            "identity-refresh-commit-unknown",
            "commit-unknown-without-bearer",
            500,
            0,
            0,
            "commit-unknown",
        ),
    ];
    ensure!(fixture.cases.len() == expected.len());
    for (id, scenario, status, mutations, events, settlement) in expected {
        let case = fixture.case(id)?;
        ensure!(case.scenario == scenario);
        ensure!(case.http_status == status);
        ensure!(case.durable_mutations == mutations);
        ensure!(case.security_events == events);
        ensure!(case.settlement == settlement);
        ensure!(!case.redact_sentinels.is_empty());
    }
    Ok(fixture)
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
    let public_key = B64_URL.encode(
        signing_key()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
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

async fn send(app: &axum::Router, body: Vec<u8>) -> TestResult<(StatusCode, Vec<u8>)> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(REFRESH_SPEC.route.path())
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Tenant-ID", TENANT)
                .body(Body::from(body))?,
        )
        .await?;
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await?.to_vec();
    Ok((status, body))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ProducerAccounting {
    attempts: u16,
    commits: u16,
    durable_mutations: u16,
    committed: u16,
    rolled_back: u16,
    commit_unknown: u16,
    rollback_failed: u16,
}

impl ProducerAccounting {
    fn from_prometheus(rendered: &str) -> Result<Self> {
        Ok(Self {
            attempts: metric_sum(rendered, "identity_refresh_producer_attempt_total")?,
            commits: metric_sum(rendered, "identity_refresh_producer_commit_total")?,
            durable_mutations: metric_sum(rendered, "identity_refresh_durable_mutations_total")?,
            committed: settlement_sum(rendered, "committed")?,
            rolled_back: settlement_sum(rendered, "rolled_back")?,
            commit_unknown: settlement_sum(rendered, "commit_unknown")?,
            rollback_failed: settlement_sum(rendered, "rollback_failed")?,
        })
    }
}

fn metric_sum(rendered: &str, metric: &str) -> Result<u16> {
    rendered
        .lines()
        .filter(|line| line.starts_with(metric))
        .try_fold(0_u16, |sum, line| {
            let value: f64 = line
                .split_ascii_whitespace()
                .last()
                .with_context(|| format!("metric `{metric}` omitted its value"))?
                .parse()
                .with_context(|| format!("metric `{metric}` value is invalid"))?;
            ensure!(value.is_finite() && value >= 0.0 && value.fract() == 0.0);
            sum.checked_add(u16::try_from(value as u64)?)
                .with_context(|| format!("metric `{metric}` overflow"))
        })
}

fn settlement_sum(rendered: &str, final_status: &str) -> Result<u16> {
    let status = format!("final_status=\"{final_status}\"");
    rendered
        .lines()
        .filter(|line| {
            line.starts_with("tx_settlement_final_total")
                && line.contains("boundary=\"outbox.producer\"")
                && line.contains(&status)
        })
        .try_fold(0_u16, |sum, line| {
            let value: f64 = line
                .split_ascii_whitespace()
                .last()
                .context("producer settlement metric omitted its value")?
                .parse()
                .context("producer settlement metric value is invalid")?;
            ensure!(value.is_finite() && value >= 0.0 && value.fract() == 0.0);
            sum.checked_add(u16::try_from(value as u64)?)
                .context("producer settlement metric overflow")
        })
}

async fn poll_with_local_recorder<R, F>(recorder: &R, future: F) -> F::Output
where
    R: metrics::Recorder,
    F: Future,
{
    let mut future = Box::pin(future);
    poll_fn(|cx| metrics::with_local_recorder(recorder, || future.as_mut().poll(cx))).await
}

async fn send_recorded(
    app: &axum::Router,
    body: Vec<u8>,
) -> TestResult<(StatusCode, Vec<u8>, ProducerAccounting)> {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let (status, body) = poll_with_local_recorder(&recorder, send(app, body)).await?;
    Ok((
        status,
        body,
        ProducerAccounting::from_prometheus(&handle.render())?,
    ))
}

fn assert_runtime_accounting(cases: &[&JourneyCase], accounting: ProducerAccounting) -> Result<()> {
    let expected_mutations = cases.iter().try_fold(0_u16, |sum, case| {
        sum.checked_add(case.durable_mutations)
            .context("fixture durable mutation total overflow")
    })?;
    let expected_committed = u16::try_from(
        cases
            .iter()
            .filter(|case| case.settlement == "committed")
            .count(),
    )?;
    let expected_not_started = u16::try_from(
        cases
            .iter()
            .filter(|case| case.settlement == "not-started")
            .count(),
    )?;
    ensure!(expected_committed + expected_not_started == u16::try_from(cases.len())?);
    ensure!(accounting.durable_mutations == expected_mutations);
    ensure!(accounting.attempts == expected_committed);
    ensure!(accounting.commits == expected_committed);
    ensure!(accounting.committed == expected_committed);
    ensure!(accounting.rolled_back == 0);
    ensure!(accounting.commit_unknown == 0);
    ensure!(accounting.rollback_failed == 0);
    Ok(())
}

async fn login(app: &axum::Router) -> TestResult<String> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LOGIN_SPEC.route.path())
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Tenant-ID", TENANT)
                .body(Body::from(
                    serde_json::json!({"username": USERNAME, "password": PASSWORD}).to_string(),
                ))?,
        )
        .await?;
    ensure!(response.status() == StatusCode::CREATED);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    Ok(body["data"]["refreshToken"]
        .as_str()
        .context("login response omitted refresh bearer")?
        .to_owned())
}

async fn security_event_count(pool: &PgPool) -> TestResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM outbox WHERE tenant_id = $1::uuid AND domain = 'identity' \
         AND topic = 'identity.security-event'",
    )
    .bind(TENANT)
    .fetch_one(pool)
    .await?)
}

async fn refresh_snapshot(pool: &PgPool, token: &str) -> TestResult<(String, i64)> {
    Ok(sqlx::query_as(
        "SELECT root.status, count(child.id)::bigint FROM refresh_tokens AS root \
         LEFT JOIN refresh_tokens AS child ON child.tenant_id = root.tenant_id \
           AND child.parent_id = root.id \
         WHERE root.tenant_id = $1::uuid AND root.token_hash = $2 \
         GROUP BY root.id, root.status",
    )
    .bind(TENANT)
    .bind(secure::digest(token).as_slice())
    .fetch_one(pool)
    .await?)
}

async fn family_is_contained(pool: &PgPool, token: &str) -> TestResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT grant_root.status = 'compromised' \
                AND count(family.id) = 2 \
                AND bool_and(family.status = 'revoked') \
         FROM refresh_tokens AS presented \
         JOIN auth_grants AS grant_root ON grant_root.tenant_id = presented.tenant_id \
           AND grant_root.grant_id = presented.auth_grant_id \
         JOIN refresh_tokens AS family ON family.tenant_id = grant_root.tenant_id \
           AND family.auth_grant_id = grant_root.grant_id \
         WHERE presented.tenant_id = $1::uuid AND presented.token_hash = $2 \
         GROUP BY grant_root.grant_id, grant_root.status",
    )
    .bind(TENANT)
    .bind(secure::digest(token).as_slice())
    .fetch_one(pool)
    .await?)
}

fn assert_status_and_redaction(
    case: &JourneyCase,
    status: StatusCode,
    body: &[u8],
    dynamic_sentinel: Option<&str>,
) -> Result<()> {
    ensure!(status.as_u16() == case.http_status);
    let rendered = String::from_utf8_lossy(body);
    for sentinel in case
        .redact_sentinels
        .iter()
        .map(String::as_str)
        .chain(dynamic_sentinel)
    {
        ensure!(
            !rendered.contains(sentinel),
            "refresh response leaked a bearer sentinel"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn identity_refresh_producer_transaction_journey() -> TestResult {
    let fixture = validate_acceptance_carriers()?;
    let vault_server = MockServer::start().await;
    Mock::given(match_method("POST"))
        .and(body_partial_json(
            serde_json::json!({"marshaling_algorithm": "jws"}),
        ))
        .respond_with(TransitSignResponder(signing_key()))
        .mount(&vault_server)
        .await;

    let (postgres_fixture, postgres_owner) = production_postgres().await?;
    let observer = observation_pool(postgres_fixture.owner_params()).await?;
    let pg = postgres_owner.handle();
    let tenant = TenantId::parse(TENANT)?;
    pg.for_domain::<caps::Identity>()
        .credential_repo()
        .insert(
            TenantRepoScope::for_test(tenant),
            Credential::hydrate(
                USERNAME,
                ids::UserId::parse(USER)?,
                tenant,
                secure::PasswordHash::for_test(secure::RawPassword::new(PASSWORD.to_owned()))?,
                1,
            ),
        )
        .await?;

    let redis_fixture = testkit::env_or_redis().await?;
    let private_ca = test_private_ca_pem();
    let redis =
        build_redis_runtime_deps_from_values(redis_fixture.url().to_owned(), private_ca.clone())
            .await?;
    let s3 = build_s3_runtime_deps_from_values(
        "http://127.0.0.1:1".to_owned(),
        "rss-refresh-journey".to_owned(),
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
        r#"{"bindings":[{"tenantId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","storeId":"vault","mount":"secret","kvPathPrefix":"tenants/a"}]}"#.to_owned(),
    )?;
    let signer = Arc::new(VaultSigner::new_allow_http(
        reqwest::Client::new(),
        vault_server.uri(),
        "test-token",
        "transit",
        Duration::from_secs(5),
        SignatureMarshaling::Jws,
    )?);
    let deps = build_shared_runtime_deps(
        Arc::new(secure::DigestPasswordBlocklist::from_nonempty_sha256_digests([0xA5; 32], [])),
        pg.clone(),
        redis,
        s3,
        vault,
        signer,
        settings_key,
        Arc::new(NoopDomainTransport),
    );
    let build_router = || -> TestResult<axum::Router> {
        let mut bindings = vec![wire_identity_with(&deps, identity_values())?];
        let (mut registry, _) = bootstrap::compose_bindings(&mut bindings)?;
        Ok(finalize_rss_listener(
            &mut registry,
            Arc::new(verifier()),
            runtime::test_support::access_grant_validation_service(
                pg.for_domain::<caps::Identity>().auth_grant_validator(),
            ),
            httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
            Arc::new(SystemClock),
            assembly_schema::AssemblyListenerKind::Primary,
        )?
        .into_plaintext_router_for_test())
    };
    let router_a = build_router()?;
    let router_b = build_router()?;

    let happy_token = login(&router_a).await?;
    let events_before = security_event_count(&observer).await?;
    let (status, body, accounting) = send_recorded(
        &router_a,
        serde_json::json!({"refreshToken": happy_token})
            .to_string()
            .into_bytes(),
    )
    .await?;
    assert_status_and_redaction(
        fixture.case("identity-refresh-happy-no-event")?,
        status,
        &body,
        Some(&happy_token),
    )?;
    assert_runtime_accounting(
        &[fixture.case("identity-refresh-happy-no-event")?],
        accounting,
    )?;
    ensure!(refresh_snapshot(&observer, &happy_token).await? == ("consumed".to_owned(), 1));
    ensure!(security_event_count(&observer).await? == events_before);

    let snapshot_before = security_event_count(&observer).await?;
    let malformed = fixture.case("identity-refresh-malformed")?;
    let (status, body, accounting) = send_recorded(
        &router_a,
        br#"{"refreshToken":42,"bait":"malformed-refresh-sentinel"}"#.to_vec(),
    )
    .await?;
    assert_status_and_redaction(malformed, status, &body, None)?;
    assert_runtime_accounting(&[malformed], accounting)?;
    ensure!(security_event_count(&observer).await? == snapshot_before);

    let unknown = fixture.case("identity-refresh-unknown")?;
    let unknown_secret = "unknown-refresh-secret-sentinel";
    let (status, body, accounting) = send_recorded(
        &router_a,
        serde_json::json!({"refreshToken": unknown_secret})
            .to_string()
            .into_bytes(),
    )
    .await?;
    assert_status_and_redaction(unknown, status, &body, Some(unknown_secret))?;
    assert_runtime_accounting(&[unknown], accounting)?;
    ensure!(security_event_count(&observer).await? == snapshot_before);

    let contention_token = login(&router_a).await?;
    let contention_body = serde_json::json!({"refreshToken": contention_token})
        .to_string()
        .into_bytes();
    let events_before = security_event_count(&observer).await?;
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let pair = poll_with_local_recorder(
        &recorder,
        tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(
                send(&router_a, contention_body.clone()),
                send(&router_b, contention_body)
            )
        }),
    )
    .await?;
    let responses = [pair.0?, pair.1?];
    ensure!(
        responses
            .iter()
            .filter(|(status, _)| *status == StatusCode::CREATED)
            .count()
            == 1
    );
    ensure!(
        responses
            .iter()
            .filter(|(status, _)| *status == StatusCode::UNAUTHORIZED)
            .count()
            == 1
    );
    for (status, body) in &responses {
        let case = if *status == StatusCode::CREATED {
            fixture.case("identity-refresh-contention-winner")?
        } else {
            fixture.case("identity-refresh-contention-loser")?
        };
        assert_status_and_redaction(case, *status, body, Some(&contention_token))?;
    }
    let contention_cases = [
        fixture.case("identity-refresh-contention-winner")?,
        fixture.case("identity-refresh-contention-loser")?,
    ];
    assert_runtime_accounting(
        &contention_cases,
        ProducerAccounting::from_prometheus(&handle.render())?,
    )?;
    ensure!(family_is_contained(&observer, &contention_token).await?);
    ensure!(security_event_count(&observer).await? == events_before + 1);
    Ok(())
}
