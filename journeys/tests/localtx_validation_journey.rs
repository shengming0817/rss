//! #1706 active LocalTx durable validation journey.
//!
//! The three scoped HTTP contracts are driven through the production
//! `compose -> finalize_routes -> finalize_primary_auth` funnel.  Mutations land in a real
//! PostgreSQL instance supplied by `testkit::env_or_postgres`; the only test doubles are read-side
//! barriers which deterministically make two requests observe the same CAS version.

#![cfg(feature = "integration")]

mod common;

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result, anyhow, ensure};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use diport::{
    DynKeyProvider, EncryptOutput, KeyName, KeyProvider, KeyProviderError, KeyRef, KeyVersion,
    ManagedResource, RedactedBytes,
};
use generated::http::identity_v1::{
    login::IdentityLoginRequest,
    logout::{IdentityLogoutRequest, IdentityLogoutResponse},
    password_change::{IdentityPasswordChangeRequest, IdentityPasswordChangeResponse},
};
use generated::http::settings_v2::{SettingsSecretPublishRequest, SettingsSecretPublishResponse};
use identity::LoginService;
use identity::ports::{
    AuthOutcome, Credential, CredentialRepo, DynCredentialRepo, DynSessionLifecycle, IdentityError,
    LoginIdentifier, PasswordChangeMutation, TenantRepoScope as IdentityScope,
};
use memory::{FixedClock, MemBus, MemEmitter};
use postgres::{
    ConfigValueProtections, PgConfig, PgCredentialRepo, PgPassword, PgRuntimeDeps, PgSslMode, caps,
};
use primitives::{AuthPlan, AuthScheme, ListenerKind, RequiredScheme};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use settings::ports::{
    DynSecretRepo, SecretEntry, SecretKey, SecretRepo, SecretRepoError,
    TenantRepoScope as SettingsScope,
};
use settings::{SettingsDomain, SettingsService};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use tokio::sync::Barrier;
use tower::ServiceExt;
use vocab::{PrincipalKind, TenantId};

const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const TENANT_B: &str = "a47ac10b-58cc-4372-a567-0e02b2c3d470";
const HAPPY_USER: &str = "11111111-2222-4333-8444-555555555551";
const CONFLICT_USER: &str = "11111111-2222-4333-8444-555555555552";
const SESSION_USER: &str = "11111111-2222-4333-8444-555555555553";
const OTHER_USER: &str = "11111111-2222-4333-8444-555555555554";
const TENANT_B_USER: &str = "11111111-2222-4333-8444-555555555555";
const NOW_SECS: u64 = 1_000;
const TTL_SECS: u64 = 3_600;
const RSS_APP_ROLE: &str = "rss_app";
const RSS_APP_PASSWORD: &str = "rss_app_test_pw";
const CURRENT_PASSWORD: &str = "journey-current-password-sentinel";
const NEW_PASSWORD: &str = "journey-new-password-sentinel";
const CONFLICT_PASSWORD_A: &str = "journey-conflict-password-a-sentinel";
const CONFLICT_PASSWORD_B: &str = "journey-conflict-password-b-sentinel";

const SETTINGS_FIXTURE: &str = include_str!("../../fixtures/settings-secret-publish-localtx.toml");
const PASSWORD_FIXTURE: &str = include_str!("../../fixtures/identity-password-change-localtx.toml");
const LOGOUT_FIXTURE: &str = include_str!("../../fixtures/identity-logout-localtx.toml");

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
    cases: Vec<JourneyCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JourneyCase {
    id: String,
    scenario: String,
    http_status: u16,
    error_code: String,
    retryable: bool,
    attempts: u16,
    commits: u16,
    redact_sentinels: Vec<String>,
    #[serde(skip)]
    observation: Arc<CaseObservation>,
}

#[derive(Debug, Default)]
struct CaseObservation(AtomicU8);

impl JourneyCase {
    const RESPONSE_OBSERVED: u8 = 1;
    const ACCOUNTING_OBSERVED: u8 = 2;

    fn mark_response_observed(&self) {
        self.observation
            .0
            .fetch_or(Self::RESPONSE_OBSERVED, Ordering::Relaxed);
    }

    fn mark_accounting_observed(&self) {
        self.observation
            .0
            .fetch_or(Self::ACCOUNTING_OBSERVED, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
struct FixtureIdentity<'a> {
    id: &'a str,
    contract_id: &'a str,
    tx_model: &'a str,
    spec: &'a str,
    marker: &'a str,
}

struct FixtureBook {
    fixture_id: String,
    cases: HashMap<String, JourneyCase>,
    receipts: Vec<(String, Arc<CaseObservation>)>,
}

impl FixtureBook {
    fn load(source: &str, expected: FixtureIdentity<'_>) -> Result<Self> {
        let fixture: JourneyFixture = toml::from_str(source).context("parse closed v1 fixture")?;
        ensure!(
            fixture.schema_version == 1,
            "fixture schemaVersion must be 1"
        );
        ensure!(fixture.id == expected.id, "fixture id drift");
        ensure!(
            fixture.contract_id == expected.contract_id,
            "fixture contractId drift"
        );
        ensure!(
            fixture.tx_model == expected.tx_model,
            "fixture txModel drift"
        );
        ensure!(fixture.spec == expected.spec, "fixture spec drift");
        ensure!(
            fixture.runner == "journeys/tests/localtx_validation_journey.rs",
            "fixture runner drift"
        );
        ensure!(fixture.marker == expected.marker, "fixture marker drift");

        let mut cases = HashMap::with_capacity(fixture.cases.len());
        let mut receipts = Vec::with_capacity(fixture.cases.len());
        for case in fixture.cases {
            receipts.push((case.id.clone(), Arc::clone(&case.observation)));
            ensure!(
                cases.insert(case.id.clone(), case).is_none(),
                "fixture `{}` contains duplicate case ids",
                expected.id
            );
        }
        Ok(Self {
            fixture_id: fixture.id,
            cases,
            receipts,
        })
    }

    fn take_case(&mut self, id: &str) -> Result<JourneyCase> {
        self.cases
            .remove(id)
            .with_context(|| format!("fixture `{}` is missing case `{id}`", self.fixture_id))
    }

    fn assert_exhausted(&self) -> Result<()> {
        ensure!(
            self.cases.is_empty(),
            "fixture `{}` has unconsumed cases: {:?}",
            self.fixture_id,
            self.cases.keys().collect::<Vec<_>>()
        );
        for (case_id, receipt) in &self.receipts {
            ensure!(
                receipt.0.load(Ordering::Relaxed)
                    == JourneyCase::RESPONSE_OBSERVED | JourneyCase::ACCOUNTING_OBSERVED,
                "fixture `{}` case `{case_id}` did not observe both response and LocalTx accounting",
                self.fixture_id
            );
        }
        Ok(())
    }
}

#[derive(Clone)]
struct JourneyKeyProvider;

impl KeyProvider for JourneyKeyProvider {
    async fn encrypt(
        &self,
        key: KeyName,
        plaintext: secure::Plaintext,
        _aad: secure::DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        let ciphertext: Vec<u8> = plaintext.expose().iter().map(|byte| byte ^ 0xa5).collect();
        Ok(EncryptOutput::new(
            ciphertext,
            KeyRef::new(key, KeyVersion::new(1)),
        ))
    }

    async fn decrypt(
        &self,
        ciphertext: RedactedBytes,
        _key: KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, KeyProviderError> {
        Ok(secure::Plaintext::new(
            ciphertext
                .into_bytes()
                .into_iter()
                .map(|byte| byte ^ 0xa5)
                .collect(),
        ))
    }

    async fn rewrap(
        &self,
        ciphertext: RedactedBytes,
        key: KeyRef,
        aad: secure::DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        let plaintext = self.decrypt(ciphertext, key, aad.clone()).await?;
        self.encrypt(
            KeyName::try_new("settings-config").map_err(|error| {
                KeyProviderError::new(diport::key_provider::KeyProviderErrorKind::Rejected, error)
            })?,
            plaintext,
            aad,
        )
        .await
    }

    async fn shutdown(&self) -> Result<(), KeyProviderError> {
        Ok(())
    }
}

fn protections() -> Result<ConfigValueProtections> {
    Ok(ConfigValueProtections::new(
        DynKeyProvider::new_box(JourneyKeyProvider),
        DynKeyProvider::new_box(JourneyKeyProvider),
        KeyName::try_new("settings-config")?,
    ))
}

struct BarrierSecretRepo {
    inner: Box<DynSecretRepo<'static>>,
    conflict_key: String,
    barrier: Arc<Barrier>,
}

impl SecretRepo for BarrierSecretRepo {
    async fn find(
        &self,
        scope: SettingsScope,
        key: &SecretKey,
    ) -> Result<Option<SecretEntry>, SecretRepoError> {
        self.inner.find(scope, key).await
    }

    async fn find_version(
        &self,
        scope: SettingsScope,
        key: &SecretKey,
        version: u64,
    ) -> Result<Option<SecretEntry>, SecretRepoError> {
        self.inner.find_version(scope, key, version).await
    }

    async fn latest_version(
        &self,
        scope: SettingsScope,
        key: &SecretKey,
    ) -> Result<Option<u64>, SecretRepoError> {
        let version = self.inner.latest_version(scope, key).await?;
        if key.as_str() == self.conflict_key {
            self.barrier.wait().await;
        }
        Ok(version)
    }
}

struct BarrierCredentialRepo {
    inner: PgCredentialRepo,
    conflict_user: ids::UserId,
    barrier: Arc<Barrier>,
}

impl CredentialRepo for BarrierCredentialRepo {
    async fn find_by_user_id(
        &self,
        scope: IdentityScope,
        user_id: ids::UserId,
    ) -> Result<Option<Credential>, IdentityError> {
        let credential = self.inner.find_by_user_id(scope, user_id).await?;
        if user_id == self.conflict_user {
            self.barrier.wait().await;
        }
        Ok(credential)
    }

    async fn authenticate(
        &self,
        scope: IdentityScope,
        login: LoginIdentifier,
        candidate: String,
        now: SystemTime,
    ) -> Result<AuthOutcome, IdentityError> {
        self.inner.authenticate(scope, login, candidate, now).await
    }

    async fn save(
        &self,
        scope: IdentityScope,
        credential: Credential,
    ) -> Result<(), IdentityError> {
        self.inner.save(scope, credential).await
    }

    async fn apply_password_change(
        &self,
        scope: IdentityScope,
        mutation: PasswordChangeMutation,
    ) -> Result<(), IdentityError> {
        self.inner.apply_password_change(scope, mutation).await
    }

    async fn lockout_status(
        &self,
        scope: IdentityScope,
        login: LoginIdentifier,
        now: SystemTime,
    ) -> Result<bool, IdentityError> {
        self.inner.lockout_status(scope, login, now).await
    }
}

struct HttpResult {
    status: StatusCode,
    request_id: String,
    body: String,
}

struct RecordedHttpResult {
    response: HttpResult,
    localtx: LocalTxMetrics,
}

#[derive(Clone, Copy, Default)]
struct LocalTxMetrics {
    attempts: u16,
    failed_attempts: u16,
    finals: u16,
    committed: u16,
    rolled_back: u16,
}

impl LocalTxMetrics {
    fn combine(results: &[&Self]) -> Result<Self> {
        results.iter().try_fold(Self::default(), |sum, sample| {
            Ok(Self {
                attempts: sum
                    .attempts
                    .checked_add(sample.attempts)
                    .context("LocalTx attempt sum overflow")?,
                failed_attempts: sum
                    .failed_attempts
                    .checked_add(sample.failed_attempts)
                    .context("LocalTx failed-attempt sum overflow")?,
                finals: sum
                    .finals
                    .checked_add(sample.finals)
                    .context("LocalTx final sum overflow")?,
                committed: sum
                    .committed
                    .checked_add(sample.committed)
                    .context("LocalTx committed sum overflow")?,
                rolled_back: sum
                    .rolled_back
                    .checked_add(sample.rolled_back)
                    .context("LocalTx rolled-back sum overflow")?,
            })
        })
    }

    fn from_prometheus(rendered: &str, contract_id: &str) -> Result<Self> {
        Ok(Self {
            attempts: metric_sum(rendered, "localtx_attempts_sum", contract_id, None)?,
            failed_attempts: metric_sum(
                rendered,
                "localtx_retry_attempts_total",
                contract_id,
                None,
            )?,
            finals: metric_sum(rendered, "localtx_final_total", contract_id, None)?,
            committed: metric_sum(
                rendered,
                "localtx_final_total",
                contract_id,
                Some(("final_status", "committed")),
            )?,
            rolled_back: metric_sum(
                rendered,
                "localtx_final_total",
                contract_id,
                Some(("final_status", "rolled_back")),
            )?,
        })
    }
}

fn metric_sum(
    rendered: &str,
    metric: &str,
    contract_id: &str,
    label: Option<(&str, &str)>,
) -> Result<u16> {
    let contract_label = format!("contract_id=\"{contract_id}\"");
    let label = label.map(|(key, value)| format!("{key}=\"{value}\""));
    rendered
        .lines()
        .filter(|line| {
            line.starts_with(metric)
                && line.contains(&contract_label)
                && label.as_ref().is_none_or(|label| line.contains(label))
        })
        .try_fold(0_u16, |sum, line| {
            let raw = line
                .split_ascii_whitespace()
                .last()
                .with_context(|| format!("metric `{metric}` sample has no value"))?;
            let value: f64 = raw
                .parse()
                .with_context(|| format!("metric `{metric}` sample value is invalid"))?;
            ensure!(
                value.is_finite() && value >= 0.0 && value.fract() == 0.0,
                "metric `{metric}` sample must be a non-negative integer"
            );
            sum.checked_add(u16::try_from(value as u64)?)
                .context("LocalTx metric sum overflow")
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireErrorEnvelope {
    error: WireError,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireError {
    code: String,
    message: String,
    retryable: bool,
    details: Vec<serde_json::Value>,
    request_id: String,
}

async fn send(
    router: &axum::Router,
    uri: &str,
    body: Vec<u8>,
    request_id: &str,
) -> Result<HttpResult> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-request-id", request_id)
                .body(Body::from(body))?,
        )
        .await?;
    let status = response.status();
    let response_request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    Ok(HttpResult {
        status,
        request_id: response_request_id,
        body,
    })
}

async fn send_recorded(
    router: &axum::Router,
    uri: &str,
    body: Vec<u8>,
    request_id: &str,
    contract_id: &str,
) -> Result<RecordedHttpResult> {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let response = poll_with_local_recorder(&recorder, send(router, uri, body, request_id)).await?;
    let localtx = LocalTxMetrics::from_prometheus(&handle.render(), contract_id)?;
    Ok(RecordedHttpResult { response, localtx })
}

fn case_sentinels(
    case: &JourneyCase,
    request_bodies: &[&[u8]],
    session_id: Option<&str>,
) -> Result<Vec<String>> {
    ensure!(
        !case.redact_sentinels.is_empty(),
        "case `{}` has no redact sentinels",
        case.id
    );
    let mut resolved = Vec::with_capacity(case.redact_sentinels.len());
    for declared in &case.redact_sentinels {
        let sentinel = match declared.as_str() {
            "$sessionId" => session_id
                .context("$sessionId requires the case's durable session id")?
                .to_owned(),
            token if token.starts_with('$') => {
                return Err(anyhow!(
                    "case `{}` declares unsupported sentinel token `{token}`",
                    case.id
                ));
            }
            literal => literal.to_owned(),
        };
        ensure!(
            request_bodies
                .iter()
                .any(|body| String::from_utf8_lossy(body).contains(&sentinel)),
            "case `{}` sentinel `{declared}` is not present in its request payload",
            case.id
        );
        resolved.push(sentinel);
    }
    Ok(resolved)
}

fn assert_redacted(responses: &[&HttpResult], sentinels: &[String]) -> Result<()> {
    for response in responses {
        for sentinel in sentinels {
            ensure!(
                !response.body.contains(sentinel),
                "response leaked fixture sentinel `{sentinel}`"
            );
        }
    }
    Ok(())
}

fn assert_request_id(response: &HttpResult, request_id: &str) -> Result<()> {
    ensure!(
        response.request_id == request_id,
        "request id header was not preserved: expected `{request_id}`, got `{}`",
        response.request_id
    );
    Ok(())
}

fn decode_success<T: DeserializeOwned>(
    response: &HttpResult,
    status: StatusCode,
    request_id: &str,
    sentinels: &[String],
) -> Result<T> {
    ensure!(
        response.status == status,
        "unexpected response: {}",
        response.body
    );
    assert_request_id(response, request_id)?;
    assert_redacted(&[response], sentinels)?;
    serde_json::from_str(&response.body).context("decode generated success response")
}

fn decode_case_success<T: DeserializeOwned>(
    case: &JourneyCase,
    response: &HttpResult,
    request_id: &str,
    sentinels: &[String],
) -> Result<T> {
    ensure!(
        case.error_code == "none",
        "success case must use errorCode=none"
    );
    ensure!(!case.retryable, "success case cannot be retryable");
    let status = StatusCode::from_u16(case.http_status)?;
    let decoded = decode_success(response, status, request_id, sentinels)?;
    case.mark_response_observed();
    Ok(decoded)
}

fn assert_case_error(
    case: &JourneyCase,
    response: &HttpResult,
    request_id: &str,
    sentinels: &[String],
) -> Result<()> {
    let status = StatusCode::from_u16(case.http_status)?;
    ensure!(
        response.status == status,
        "unexpected response: {}",
        response.body
    );
    assert_request_id(response, request_id)?;
    let body: WireErrorEnvelope = serde_json::from_str(&response.body)?;
    ensure!(body.error.code == case.error_code, "wire errorCode drift");
    ensure!(
        body.error.retryable == case.retryable,
        "wire retryable drift"
    );
    ensure!(body.error.request_id == request_id, "wire requestId drift");
    ensure!(
        !body.error.message.is_empty(),
        "wire error message is empty"
    );
    let _ = body.error.details;
    assert_redacted(&[response], sentinels)?;
    case.mark_response_observed();
    Ok(())
}

#[derive(Clone, Copy)]
enum ExpectedLocalTxFinal {
    None,
    Committed,
}

fn assert_accounting(
    case: &JourneyCase,
    samples: &[&LocalTxMetrics],
    commits: u16,
    expected_final: ExpectedLocalTxFinal,
) -> Result<()> {
    let expected_scenario = match case.id.as_str() {
        "settings-secret-publish-happy"
        | "identity-password-change-happy"
        | "identity-logout-happy" => "happy",
        "settings-secret-publish-auth-failure"
        | "identity-password-change-unauthenticated"
        | "identity-password-change-invalid-subject"
        | "identity-logout-unauthenticated"
        | "identity-logout-other-owner" => "auth-failure",
        "settings-secret-publish-validation-failure"
        | "identity-password-change-validation-failure"
        | "identity-logout-validation-failure" => "validation-failure",
        "settings-secret-publish-conflict" | "identity-password-change-conflict" => "conflict",
        "identity-logout-contention"
        | "identity-logout-repeat"
        | "identity-logout-cross-tenant" => "contention",
        other => return Err(anyhow!("unknown executable fixture case `{other}`")),
    };
    ensure!(
        case.scenario == expected_scenario,
        "case `{}` scenario drift",
        case.id
    );
    let observed = LocalTxMetrics::combine(samples)?;
    ensure!(
        case.attempts == observed.attempts,
        "case `{}` attempts drift: fixture={}, observed={}",
        case.id,
        case.attempts,
        observed.attempts
    );
    match expected_final {
        ExpectedLocalTxFinal::None => ensure!(
            observed.failed_attempts == 0
                && observed.finals == 0
                && observed.committed == 0
                && observed.rolled_back == 0,
            "case `{}` unexpectedly reached LocalTx settlement",
            case.id
        ),
        ExpectedLocalTxFinal::Committed => ensure!(
            observed.failed_attempts == 0
                && observed.finals == u16::try_from(samples.len())?
                && observed.committed == observed.finals
                && observed.rolled_back == 0,
            "case `{}` did not commit exactly one LocalTx final per invocation",
            case.id
        ),
    }
    ensure!(
        case.commits == commits,
        "case `{}` commits drift: fixture={}, observed={commits}",
        case.id,
        case.commits
    );
    case.mark_accounting_observed();
    Ok(())
}

fn assert_cas_conflict_accounting(
    case: &JourneyCase,
    winner: &LocalTxMetrics,
    loser: &LocalTxMetrics,
    pair_commits: u16,
) -> Result<()> {
    ensure!(
        winner.attempts == case.attempts
            && winner.failed_attempts == 0
            && winner.finals == 1
            && winner.committed == 1
            && winner.rolled_back == 0,
        "CAS winner LocalTx accounting drift"
    );
    ensure!(
        loser.attempts == case.attempts
            && loser.failed_attempts == 1
            && loser.finals == 1
            && loser.committed == 0
            && loser.rolled_back == 1,
        "CAS loser LocalTx accounting drift"
    );
    ensure!(
        case.commits == 0,
        "CAS loser fixture must declare zero commits"
    );
    ensure!(
        pair_commits == winner.committed && loser.committed == 0,
        "CAS pair durable commit did not match winner/loser settlement"
    );
    case.mark_accounting_observed();
    Ok(())
}

fn finalized_router(
    domain: &dyn bootstrap::Domain,
    principal: Option<(PrincipalKind, &str, TenantId)>,
    fallback_authorizer: Option<Arc<dyn httpserve::RouteAuthorizer>>,
) -> Result<axum::Router> {
    let mut registry = bootstrap::compose(&[domain])?;
    let authorizer = match fallback_authorizer {
        Some(authorizer) => authorizer,
        None => registry.take_primary_authorizer()?,
    };
    let mut finalized = registry.finalize_routes()?;
    ensure!(
        finalized.len() == 1,
        "journey domain must expose one listener"
    );
    let (listener, routes) = finalized
        .pop()
        .ok_or_else(|| anyhow!("journey route group missing"))?;
    ensure!(listener == ListenerKind::Primary);
    let authenticated = httpserve::finalize_primary_auth(
        routes,
        AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt)?,
        authorizer,
    )?;
    Ok(match principal {
        Some((kind, subject, tenant)) => authenticated
            .layer(axum::Extension(httpserve::Authenticated::new(
                RequiredScheme::Jwt,
                kind,
                subject,
                Some(tenant),
            )))
            .into_router_for_test(),
        None => authenticated.into_router_for_test(),
    })
}

fn pg_config(params: &testkit::PgConnParams) -> PgConfig {
    PgConfig::new(
        params.host.clone(),
        params.port,
        params.database.clone(),
        params.username.clone(),
        PgPassword::new(params.password.clone()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(Duration::from_secs(5))
}

fn pg_config_for(params: &testkit::PgConnParams, username: &str, password: &str) -> PgConfig {
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

async fn provision_rss_app_login(params: &testkit::PgConnParams) -> Result<()> {
    let options = PgConnectOptions::new()
        .host(&params.host)
        .port(params.port)
        .database(&params.database)
        .username(&params.username)
        .password(&params.password)
        .ssl_mode(SqlxPgSslMode::Prefer);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?;
    sqlx::query(
        r#"
        DO $$
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtext('rss_app'));
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_app') THEN
                CREATE ROLE rss_app LOGIN PASSWORD 'rss_app_test_pw' NOBYPASSRLS;
            ELSE
                ALTER ROLE rss_app LOGIN PASSWORD 'rss_app_test_pw' NOBYPASSRLS;
            END IF;
        END
        $$;
        "#,
    )
    .execute(&pool)
    .await?;
    pool.close().await;
    Ok(())
}

async fn observation_pool(params: &testkit::PgConnParams) -> Result<sqlx::PgPool> {
    let options = PgConnectOptions::new()
        .host(&params.host)
        .port(params.port)
        .database(&params.database)
        .username(&params.username)
        .password(&params.password)
        .ssl_mode(SqlxPgSslMode::Prefer);
    Ok(PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?)
}

#[derive(PartialEq, Eq)]
struct SecretSnapshot(Vec<Option<SecretSnapshotRow>>);

type SecretSnapshotRow = (u64, String, String, Option<String>);

async fn secret_snapshot(
    repo: &DynSecretRepo<'static>,
    tenants: [TenantId; 2],
    key: &SecretKey,
) -> Result<SecretSnapshot> {
    let mut rows = Vec::with_capacity(2);
    for tenant in tenants {
        rows.push(
            repo.find(SettingsScope::for_test(tenant), key)
                .await?
                .map(|entry| {
                    (
                        entry.version(),
                        entry.secret_ref().store_id().as_str().to_owned(),
                        entry.secret_ref().ref_key().to_owned(),
                        entry.secret_ref().ref_version().map(str::to_owned),
                    )
                }),
        );
    }
    Ok(SecretSnapshot(rows))
}

#[derive(PartialEq, Eq)]
struct CredentialSnapshot(Vec<Option<CredentialSnapshotRow>>);

type CredentialSnapshotRow = (String, String, u32);

async fn credential_snapshot(
    repo: &PgCredentialRepo,
    probes: [(TenantId, ids::UserId); 2],
) -> Result<CredentialSnapshot> {
    let mut rows = Vec::with_capacity(2);
    for (tenant, user) in probes {
        rows.push(
            repo.find_by_user_id(IdentityScope::for_test(tenant), user)
                .await?
                .map(|credential| {
                    (
                        credential.login().as_str().to_owned(),
                        credential.password_hash().as_str().to_owned(),
                        credential.version(),
                    )
                }),
        );
    }
    Ok(CredentialSnapshot(rows))
}

#[derive(PartialEq, Eq)]
struct SessionSnapshot(Vec<bool>);

async fn session_snapshot(
    pool: &sqlx::PgPool,
    tenants: [TenantId; 2],
    session_id: &str,
) -> Result<SessionSnapshot> {
    let mut rows = Vec::with_capacity(2);
    for tenant in tenants {
        let state = sqlx::query_scalar::<_, bool>(
            "SELECT NOT revoked FROM sessions WHERE tenant_id = $1::uuid AND session_id = $2",
        )
        .bind(tenant.to_string())
        .bind(session_id)
        .fetch_optional(pool)
        .await?
        .unwrap_or(false);
        rows.push(state);
    }
    Ok(SessionSnapshot(rows))
}

async fn seed_credential(
    repo: &PgCredentialRepo,
    tenant: TenantId,
    user: ids::UserId,
    login: &str,
    password: &str,
) -> Result<()> {
    repo.save(
        IdentityScope::for_test(tenant),
        Credential::hydrate(login, user, tenant, secure::hash_password(password)?, 1),
    )
    .await?;
    Ok(())
}

fn finish_with_pg_cleanup(body: Result<()>, cleanup: Result<()>) -> Result<()> {
    match (body, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup)) => Err(cleanup).context("shut down LocalTx journey postgres"),
        (Err(error), Err(cleanup)) => {
            Err(error).context(format!("postgres cleanup also failed: {cleanup:#}"))
        }
    }
}

struct SettingsCases {
    happy: JourneyCase,
    auth_failure: JourneyCase,
    validation_failure: JourneyCase,
    conflict: JourneyCase,
}

struct PasswordCases {
    happy: JourneyCase,
    unauthenticated: JourneyCase,
    invalid_subject: JourneyCase,
    validation_failure: JourneyCase,
    conflict: JourneyCase,
}

struct LogoutCases {
    happy: JourneyCase,
    unauthenticated: JourneyCase,
    other_owner: JourneyCase,
    validation_failure: JourneyCase,
    contention: JourneyCase,
    repeat: JourneyCase,
    cross_tenant: JourneyCase,
}

fn secret_commit_delta(before: &SecretSnapshot, after: &SecretSnapshot) -> Result<u16> {
    ensure!(before.0.len() == 2 && after.0.len() == 2);
    ensure!(
        before.0[1] == after.0[1],
        "second-tenant secret snapshot changed"
    );
    let before_version = before.0[0].as_ref().map_or(0, |row| row.0);
    let after_version = after.0[0].as_ref().map_or(0, |row| row.0);
    ensure!(after_version >= before_version, "secret version regressed");
    u16::try_from(after_version - before_version).context("secret commit delta exceeds u16")
}

async fn drive_settings_permission_denial(
    router: &axum::Router,
    observer: &DynSecretRepo<'static>,
    tenants: [TenantId; 2],
    key: &SecretKey,
    body: Vec<u8>,
    sentinels: &[String],
) -> Result<()> {
    let before = secret_snapshot(observer, tenants, key).await?;
    let denied = send_recorded(
        router,
        generated::http::settings_v2::PATH,
        body,
        "rid-secret-permission-denied",
        generated::http::settings_v2::CONTRACT_ID,
    )
    .await?;
    ensure!(
        denied.response.status == StatusCode::FORBIDDEN,
        "unbound user bypassed the production settings authorizer"
    );
    assert_request_id(&denied.response, "rid-secret-permission-denied")?;
    let envelope: WireErrorEnvelope = serde_json::from_str(&denied.response.body)?;
    ensure!(
        envelope.error.code == "ERR_CORE_FORBIDDEN"
            && !envelope.error.retryable
            && envelope.error.request_id == "rid-secret-permission-denied",
        "settings permission denial envelope drift"
    );
    assert_redacted(&[&denied.response], sentinels)?;
    ensure!(
        denied.localtx.attempts == 0 && denied.localtx.finals == 0,
        "settings permission denial reached LocalTx"
    );
    let after = secret_snapshot(observer, tenants, key).await?;
    ensure!(
        before == after,
        "settings permission denial mutated durable state"
    );
    Ok(())
}

async fn drive_settings(
    deps: &PgRuntimeDeps,
    tenant_a: TenantId,
    tenant_b: TenantId,
    primary_authorizer: Arc<dyn httpserve::RouteAuthorizer>,
    cases: SettingsCases,
) -> Result<()> {
    let settings_deps = deps.handle().for_domain::<caps::Settings>();
    let (_config_repo, _config_uow, secret_repo, secret_uow) = settings_deps
        .settings_bundle(Arc::new(FixedClock::at_unix_secs(NOW_SECS)), protections()?)
        .into_parts();
    let (_observer_config_repo, _observer_config_uow, secret_observer, _observer_secret_uow) =
        settings_deps
            .settings_bundle(Arc::new(FixedClock::at_unix_secs(NOW_SECS)), protections()?)
            .into_parts();
    let conflict_secret = "conflict.coordinate";
    let secret_route_repo: Arc<DynSecretRepo<'static>> =
        Arc::from(DynSecretRepo::new_box(BarrierSecretRepo {
            inner: secret_repo,
            conflict_key: conflict_secret.to_owned(),
            barrier: Arc::new(Barrier::new(2)),
        }));
    let settings_domain = SettingsDomain::new(
        Arc::new(SettingsService::with_seed(
            MemEmitter::with_tenant_metadata_signer(MemBus::new(), common::memory_tenant_signer()),
            Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        )),
        secret_route_repo,
        Arc::from(secret_uow),
    );
    let settings_authed = finalized_router(
        &settings_domain,
        Some((PrincipalKind::Admin, HAPPY_USER, tenant_a)),
        Some(Arc::clone(&primary_authorizer)),
    )?;
    let settings_unauthed = finalized_router(
        &settings_domain,
        None,
        Some(Arc::clone(&primary_authorizer)),
    )?;
    let settings_permission_denied = finalized_router(
        &settings_domain,
        Some((PrincipalKind::User, HAPPY_USER, tenant_a)),
        Some(primary_authorizer),
    )?;

    let happy_key = SecretKey::parse("happy.coordinate")?;
    let before = secret_snapshot(&secret_observer, [tenant_a, tenant_b], &happy_key).await?;
    let happy_request = SettingsSecretPublishRequest {
        key: happy_key.as_str().to_owned(),
        store_id: "journey-vault".to_owned(),
        ref_key: "tenant-a/happy-secret-sentinel".to_owned(),
        ref_version: Some("v1".to_owned()),
    };
    let happy_body = serde_json::to_vec(&happy_request)?;
    let happy_sentinels = case_sentinels(&cases.happy, &[&happy_body], None)?;
    let happy = send_recorded(
        &settings_authed,
        generated::http::settings_v2::PATH,
        happy_body,
        "rid-secret-happy",
        generated::http::settings_v2::CONTRACT_ID,
    )
    .await?;
    let decoded: SettingsSecretPublishResponse = decode_case_success(
        &cases.happy,
        &happy.response,
        "rid-secret-happy",
        &happy_sentinels,
    )?;
    ensure!(decoded.data.key == happy_key.as_str() && decoded.data.version == 1);
    let after = secret_snapshot(&secret_observer, [tenant_a, tenant_b], &happy_key).await?;
    assert_accounting(
        &cases.happy,
        &[&happy.localtx],
        secret_commit_delta(&before, &after)?,
        ExpectedLocalTxFinal::Committed,
    )?;

    let auth_key = SecretKey::parse("auth.coordinate")?;
    let before = secret_snapshot(&secret_observer, [tenant_a, tenant_b], &auth_key).await?;
    let auth_request = SettingsSecretPublishRequest {
        key: auth_key.as_str().to_owned(),
        store_id: "auth-store-sentinel".to_owned(),
        ref_key: "auth/ref-sentinel".to_owned(),
        ref_version: None,
    };
    let auth_body = serde_json::to_vec(&auth_request)?;
    let auth_sentinels = case_sentinels(&cases.auth_failure, &[&auth_body], None)?;
    let missing_auth = send_recorded(
        &settings_unauthed,
        generated::http::settings_v2::PATH,
        auth_body.clone(),
        "rid-secret-auth",
        generated::http::settings_v2::CONTRACT_ID,
    )
    .await?;
    assert_case_error(
        &cases.auth_failure,
        &missing_auth.response,
        "rid-secret-auth",
        &auth_sentinels,
    )?;
    let after = secret_snapshot(&secret_observer, [tenant_a, tenant_b], &auth_key).await?;
    ensure!(
        before == after,
        "secret auth rejection mutated durable state"
    );
    assert_accounting(
        &cases.auth_failure,
        &[&missing_auth.localtx],
        0,
        ExpectedLocalTxFinal::None,
    )?;

    drive_settings_permission_denial(
        &settings_permission_denied,
        &secret_observer,
        [tenant_a, tenant_b],
        &auth_key,
        auth_body,
        &auth_sentinels,
    )
    .await?;

    let invalid_key = SecretKey::parse("invalid.coordinate")?;
    let before = secret_snapshot(&secret_observer, [tenant_a, tenant_b], &invalid_key).await?;
    let invalid_body =
        br#"{"key":"invalid.coordinate","storeId":"invalid-store-sentinel","refKey":"../invalid-ref-sentinel"}"#.to_vec();
    let invalid_sentinels = case_sentinels(&cases.validation_failure, &[&invalid_body], None)?;
    let invalid = send_recorded(
        &settings_authed,
        generated::http::settings_v2::PATH,
        invalid_body,
        "rid-secret-validation",
        generated::http::settings_v2::CONTRACT_ID,
    )
    .await?;
    assert_case_error(
        &cases.validation_failure,
        &invalid.response,
        "rid-secret-validation",
        &invalid_sentinels,
    )?;
    let after = secret_snapshot(&secret_observer, [tenant_a, tenant_b], &invalid_key).await?;
    ensure!(
        before == after,
        "secret validation rejection mutated durable state"
    );
    assert_accounting(
        &cases.validation_failure,
        &[&invalid.localtx],
        0,
        ExpectedLocalTxFinal::None,
    )?;

    let conflict_key = SecretKey::parse(conflict_secret)?;
    let before = secret_snapshot(&secret_observer, [tenant_a, tenant_b], &conflict_key).await?;
    let conflict_a = SettingsSecretPublishRequest {
        key: conflict_secret.to_owned(),
        store_id: "conflict-store-a-sentinel".to_owned(),
        ref_key: "conflict/ref-a-sentinel".to_owned(),
        ref_version: None,
    };
    let conflict_b = SettingsSecretPublishRequest {
        key: conflict_secret.to_owned(),
        store_id: "conflict-store-b-sentinel".to_owned(),
        ref_key: "conflict/ref-b-sentinel".to_owned(),
        ref_version: None,
    };
    let conflict_body_a = serde_json::to_vec(&conflict_a)?;
    let conflict_body_b = serde_json::to_vec(&conflict_b)?;
    let conflict_sentinels =
        case_sentinels(&cases.conflict, &[&conflict_body_a, &conflict_body_b], None)?;
    let conflict_pair = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            send_recorded(
                &settings_authed,
                generated::http::settings_v2::PATH,
                conflict_body_a,
                "rid-secret-conflict-a",
                generated::http::settings_v2::CONTRACT_ID,
            ),
            send_recorded(
                &settings_authed,
                generated::http::settings_v2::PATH,
                conflict_body_b,
                "rid-secret-conflict-b",
                generated::http::settings_v2::CONTRACT_ID,
            )
        )
    })
    .await?;
    let (secret_a, secret_b) = (conflict_pair.0?, conflict_pair.1?);
    let (secret_ok, ok_request_id, secret_conflict, conflict_request_id) =
        if secret_a.response.status == StatusCode::CREATED {
            (
                &secret_a,
                "rid-secret-conflict-a",
                &secret_b,
                "rid-secret-conflict-b",
            )
        } else {
            (
                &secret_b,
                "rid-secret-conflict-b",
                &secret_a,
                "rid-secret-conflict-a",
            )
        };
    let decoded: SettingsSecretPublishResponse = decode_success(
        &secret_ok.response,
        StatusCode::CREATED,
        ok_request_id,
        &conflict_sentinels,
    )?;
    ensure!(decoded.data.key == conflict_secret && decoded.data.version == 1);
    assert_case_error(
        &cases.conflict,
        &secret_conflict.response,
        conflict_request_id,
        &conflict_sentinels,
    )?;
    let after = secret_snapshot(&secret_observer, [tenant_a, tenant_b], &conflict_key).await?;
    assert_cas_conflict_accounting(
        &cases.conflict,
        &secret_ok.localtx,
        &secret_conflict.localtx,
        secret_commit_delta(&before, &after)?,
    )?;
    Ok(())
}

struct IdentityHarness {
    tenant_a: TenantId,
    tenant_b: TenantId,
    happy_user: ids::UserId,
    conflict_user: ids::UserId,
    tenant_b_user: ids::UserId,
    primary_authorizer: Arc<dyn httpserve::RouteAuthorizer>,
    login: Arc<LoginService<identity::SeedSigner>>,
    happy_identity: axum::Router,
    conflict_identity: axum::Router,
    identity_unauthed: axum::Router,
    invalid_subject: axum::Router,
    other_identity: axum::Router,
    session_identity: axum::Router,
    tenant_b_identity: axum::Router,
    credential_observer: PgCredentialRepo,
}

async fn build_identity_harness(
    deps: &PgRuntimeDeps,
    tenant_a: TenantId,
    tenant_b: TenantId,
) -> Result<IdentityHarness> {
    let happy_user = ids::UserId::parse(HAPPY_USER)?;
    let conflict_user = ids::UserId::parse(CONFLICT_USER)?;
    let session_user = ids::UserId::parse(SESSION_USER)?;
    let other_user = ids::UserId::parse(OTHER_USER)?;
    let tenant_b_user = ids::UserId::parse(TENANT_B_USER)?;
    let identity_deps = deps.handle().for_domain::<caps::Identity>();
    let seed_repo = identity_deps.credential_repo();
    seed_credential(
        &seed_repo,
        tenant_a,
        happy_user,
        "happy-login",
        CURRENT_PASSWORD,
    )
    .await?;
    seed_credential(
        &seed_repo,
        tenant_a,
        conflict_user,
        "conflict-login",
        CURRENT_PASSWORD,
    )
    .await?;
    seed_credential(
        &seed_repo,
        tenant_a,
        session_user,
        "session-login",
        CURRENT_PASSWORD,
    )
    .await?;
    seed_credential(
        &seed_repo,
        tenant_a,
        other_user,
        "other-login",
        CURRENT_PASSWORD,
    )
    .await?;
    seed_credential(
        &seed_repo,
        tenant_b,
        tenant_b_user,
        "tenant-b-login",
        CURRENT_PASSWORD,
    )
    .await?;

    let credentials: Arc<DynCredentialRepo<'static>> =
        Arc::from(DynCredentialRepo::new_box(BarrierCredentialRepo {
            inner: identity_deps.credential_repo(),
            conflict_user,
            barrier: Arc::new(Barrier::new(2)),
        }));
    let lifecycle: Arc<DynSessionLifecycle<'static>> = Arc::from(DynSessionLifecycle::new_box(
        identity_deps.session_lifecycle(Box::new(FixedClock::at_unix_secs(NOW_SECS))),
    ));
    let refresh = identity::seed_refresh_service(
        || Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
    );
    let login = Arc::new(LoginService::new(
        credentials,
        lifecycle,
        Arc::clone(&refresh),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
    ));
    let identity_domain = common::identity_domain(Arc::clone(&login), refresh);
    let primary_authorizer = {
        let mut registry = bootstrap::compose(&[&identity_domain])?;
        registry.take_primary_authorizer()?
    };
    Ok(IdentityHarness {
        tenant_a,
        tenant_b,
        happy_user,
        conflict_user,
        tenant_b_user,
        primary_authorizer,
        login,
        happy_identity: finalized_router(
            &identity_domain,
            Some((PrincipalKind::User, HAPPY_USER, tenant_a)),
            None,
        )?,
        conflict_identity: finalized_router(
            &identity_domain,
            Some((PrincipalKind::User, CONFLICT_USER, tenant_a)),
            None,
        )?,
        identity_unauthed: finalized_router(&identity_domain, None, None)?,
        invalid_subject: finalized_router(
            &identity_domain,
            Some((PrincipalKind::Service, "not-a-canonical-user", tenant_a)),
            None,
        )?,
        other_identity: finalized_router(
            &identity_domain,
            Some((PrincipalKind::User, OTHER_USER, tenant_a)),
            None,
        )?,
        session_identity: finalized_router(
            &identity_domain,
            Some((PrincipalKind::User, SESSION_USER, tenant_a)),
            None,
        )?,
        tenant_b_identity: finalized_router(
            &identity_domain,
            Some((PrincipalKind::User, TENANT_B_USER, tenant_b)),
            None,
        )?,
        credential_observer: identity_deps.credential_repo(),
    })
}

fn credential_commit_delta(before: &CredentialSnapshot, after: &CredentialSnapshot) -> Result<u16> {
    ensure!(before.0.len() == 2 && after.0.len() == 2);
    ensure!(
        before.0[1] == after.0[1],
        "second-tenant credential snapshot changed"
    );
    let before_version = before.0[0]
        .as_ref()
        .context("credential missing before case")?;
    let after_version = after.0[0]
        .as_ref()
        .context("credential missing after case")?;
    ensure!(
        after_version.2 >= before_version.2,
        "credential version regressed"
    );
    u16::try_from(after_version.2 - before_version.2).context("credential commit delta exceeds u16")
}

fn password_probes(harness: &IdentityHarness, user: ids::UserId) -> [(TenantId, ids::UserId); 2] {
    [
        (harness.tenant_a, user),
        (harness.tenant_b, harness.tenant_b_user),
    ]
}

async fn drive_password_happy(harness: &IdentityHarness, case: &JourneyCase) -> Result<()> {
    let probes = password_probes(harness, harness.happy_user);
    let request = IdentityPasswordChangeRequest {
        current_password: CURRENT_PASSWORD.to_owned(),
        new_password: NEW_PASSWORD.to_owned(),
    };
    let body = serde_json::to_vec(&request)?;
    let sentinels = case_sentinels(case, &[&body], None)?;
    let before = credential_snapshot(&harness.credential_observer, probes).await?;
    let changed = send_recorded(
        &harness.happy_identity,
        generated::http::identity_v1::password_change::PATH,
        body,
        "rid-password-happy",
        generated::http::identity_v1::password_change::CONTRACT_ID,
    )
    .await?;
    let decoded: IdentityPasswordChangeResponse =
        decode_case_success(case, &changed.response, "rid-password-happy", &sentinels)?;
    ensure!(
        decoded.data.changed,
        "password success response must be changed=true"
    );
    let stored = harness
        .credential_observer
        .find_by_user_id(
            IdentityScope::for_test(harness.tenant_a),
            harness.happy_user,
        )
        .await?
        .context("happy credential missing")?;
    ensure!(!secure::verify_password(
        CURRENT_PASSWORD,
        stored.password_hash()
    ));
    ensure!(secure::verify_password(
        NEW_PASSWORD,
        stored.password_hash()
    ));
    let after = credential_snapshot(&harness.credential_observer, probes).await?;
    assert_accounting(
        case,
        &[&changed.localtx],
        credential_commit_delta(&before, &after)?,
        ExpectedLocalTxFinal::Committed,
    )
}

async fn drive_password_auth_failure(
    harness: &IdentityHarness,
    case: &JourneyCase,
    router: &axum::Router,
    request_id: &str,
) -> Result<()> {
    let probes = password_probes(harness, harness.happy_user);
    let body = serde_json::to_vec(&IdentityPasswordChangeRequest {
        current_password: CURRENT_PASSWORD.to_owned(),
        new_password: NEW_PASSWORD.to_owned(),
    })?;
    let sentinels = case_sentinels(case, &[&body], None)?;
    let before = credential_snapshot(&harness.credential_observer, probes).await?;
    let response = send_recorded(
        router,
        generated::http::identity_v1::password_change::PATH,
        body,
        request_id,
        generated::http::identity_v1::password_change::CONTRACT_ID,
    )
    .await?;
    assert_case_error(case, &response.response, request_id, &sentinels)?;
    let after = credential_snapshot(&harness.credential_observer, probes).await?;
    ensure!(
        before == after,
        "password auth rejection mutated durable state"
    );
    assert_accounting(case, &[&response.localtx], 0, ExpectedLocalTxFinal::None)
}

async fn drive_password_validation(harness: &IdentityHarness, case: &JourneyCase) -> Result<()> {
    let probes = password_probes(harness, harness.happy_user);
    let body =
        br#"{"currentPassword":"journey-current-password-sentinel","unexpected":"journey-new-password-sentinel"}"#.to_vec();
    let sentinels = case_sentinels(case, &[&body], None)?;
    let before = credential_snapshot(&harness.credential_observer, probes).await?;
    let response = send_recorded(
        &harness.happy_identity,
        generated::http::identity_v1::password_change::PATH,
        body,
        "rid-password-validation",
        generated::http::identity_v1::password_change::CONTRACT_ID,
    )
    .await?;
    assert_case_error(
        case,
        &response.response,
        "rid-password-validation",
        &sentinels,
    )?;
    let after = credential_snapshot(&harness.credential_observer, probes).await?;
    ensure!(
        before == after,
        "password validation rejection mutated durable state"
    );
    assert_accounting(case, &[&response.localtx], 0, ExpectedLocalTxFinal::None)
}

async fn drive_password_conflict(harness: &IdentityHarness, case: &JourneyCase) -> Result<()> {
    let request_a = IdentityPasswordChangeRequest {
        current_password: CURRENT_PASSWORD.to_owned(),
        new_password: CONFLICT_PASSWORD_A.to_owned(),
    };
    let request_b = IdentityPasswordChangeRequest {
        current_password: CURRENT_PASSWORD.to_owned(),
        new_password: CONFLICT_PASSWORD_B.to_owned(),
    };
    let body_a = serde_json::to_vec(&request_a)?;
    let body_b = serde_json::to_vec(&request_b)?;
    let sentinels = case_sentinels(case, &[&body_a, &body_b], None)?;
    let probes = password_probes(harness, harness.conflict_user);
    let before = credential_snapshot(&harness.credential_observer, probes).await?;
    let pair = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            send_recorded(
                &harness.conflict_identity,
                generated::http::identity_v1::password_change::PATH,
                body_a,
                "rid-password-conflict-a",
                generated::http::identity_v1::password_change::CONTRACT_ID,
            ),
            send_recorded(
                &harness.conflict_identity,
                generated::http::identity_v1::password_change::PATH,
                body_b,
                "rid-password-conflict-b",
                generated::http::identity_v1::password_change::CONTRACT_ID,
            )
        )
    })
    .await?;
    let (response_a, response_b) = (pair.0?, pair.1?);
    let (winner, winner_id, loser, loser_id) = if response_a.response.status == StatusCode::OK {
        (
            &response_a,
            "rid-password-conflict-a",
            &response_b,
            "rid-password-conflict-b",
        )
    } else {
        (
            &response_b,
            "rid-password-conflict-b",
            &response_a,
            "rid-password-conflict-a",
        )
    };
    let decoded: IdentityPasswordChangeResponse =
        decode_success(&winner.response, StatusCode::OK, winner_id, &sentinels)?;
    ensure!(
        decoded.data.changed,
        "password CAS winner must report changed=true"
    );
    assert_case_error(case, &loser.response, loser_id, &sentinels)?;
    let stored = harness
        .credential_observer
        .find_by_user_id(
            IdentityScope::for_test(harness.tenant_a),
            harness.conflict_user,
        )
        .await?
        .context("conflict credential missing")?;
    let password_a_won = secure::verify_password(CONFLICT_PASSWORD_A, stored.password_hash());
    let password_b_won = secure::verify_password(CONFLICT_PASSWORD_B, stored.password_hash());
    ensure!(
        password_a_won ^ password_b_won,
        "exactly one new password must win"
    );
    let after = credential_snapshot(&harness.credential_observer, probes).await?;
    assert_cas_conflict_accounting(
        case,
        &winner.localtx,
        &loser.localtx,
        credential_commit_delta(&before, &after)?,
    )
}

async fn drive_password(harness: &IdentityHarness, cases: PasswordCases) -> Result<()> {
    drive_password_happy(harness, &cases.happy).await?;
    drive_password_auth_failure(
        harness,
        &cases.unauthenticated,
        &harness.identity_unauthed,
        "rid-password-auth",
    )
    .await?;
    drive_password_auth_failure(
        harness,
        &cases.invalid_subject,
        &harness.invalid_subject,
        "rid-password-forbidden",
    )
    .await?;
    drive_password_validation(harness, &cases.validation_failure).await?;
    drive_password_conflict(harness, &cases.conflict).await
}

fn session_commit_delta(before: &SessionSnapshot, after: &SessionSnapshot) -> Result<u16> {
    ensure!(
        before.0.len() == 2 && after.0.len() == 2,
        "session snapshot shape drift"
    );
    let mut commits = 0_u16;
    for (old, new) in before.0.iter().zip(&after.0) {
        ensure!(*old || !*new, "revoked session became active");
        if *old && !new {
            commits += 1;
        }
    }
    Ok(commits)
}

async fn seed_logout_session(harness: &IdentityHarness) -> Result<String> {
    Ok(harness
        .login
        .login(
            harness.tenant_a,
            IdentityLoginRequest {
                username: "session-login".to_owned(),
                password: CURRENT_PASSWORD.to_owned(),
            },
        )
        .await?
        .data
        .session_id)
}

fn logout_payload(case: &JourneyCase, session_id: &str) -> Result<(Vec<u8>, Vec<String>)> {
    let body = serde_json::to_vec(&IdentityLogoutRequest {
        session_id: session_id.to_owned(),
    })?;
    let sentinels = case_sentinels(case, &[&body], Some(session_id))?;
    Ok((body, sentinels))
}

fn assert_logout_success(
    case: &JourneyCase,
    response: &HttpResult,
    request_id: &str,
    sentinels: &[String],
) -> Result<()> {
    let decoded: IdentityLogoutResponse =
        decode_case_success(case, response, request_id, sentinels)?;
    ensure!(
        decoded.data.logged_out,
        "logout success response must be loggedOut=true"
    );
    Ok(())
}

async fn drive_logout_error_case(
    harness: &IdentityHarness,
    observation_pool: &sqlx::PgPool,
    case: &JourneyCase,
    router: &axum::Router,
    observed_session: &str,
    body: Vec<u8>,
    request_id: &str,
) -> Result<()> {
    let probes = [harness.tenant_a, harness.tenant_b];
    let sentinel_session = case
        .redact_sentinels
        .iter()
        .any(|sentinel| sentinel == "$sessionId")
        .then_some(observed_session);
    let sentinels = case_sentinels(case, &[&body], sentinel_session)?;
    let before = session_snapshot(observation_pool, probes, observed_session).await?;
    let response = send_recorded(
        router,
        generated::http::identity_v1::logout::PATH,
        body,
        request_id,
        generated::http::identity_v1::logout::CONTRACT_ID,
    )
    .await?;
    assert_case_error(case, &response.response, request_id, &sentinels)?;
    let after = session_snapshot(observation_pool, probes, observed_session).await?;
    ensure!(before == after, "logout rejection mutated durable state");
    assert_accounting(case, &[&response.localtx], 0, ExpectedLocalTxFinal::None)
}

async fn drive_logout_cross_tenant(
    harness: &IdentityHarness,
    observation_pool: &sqlx::PgPool,
    case: &JourneyCase,
) -> Result<()> {
    let session = seed_logout_session(harness).await?;
    let (body, sentinels) = logout_payload(case, &session)?;
    let probes = [harness.tenant_a, harness.tenant_b];
    let before = session_snapshot(observation_pool, probes, &session).await?;
    let response = send_recorded(
        &harness.tenant_b_identity,
        generated::http::identity_v1::logout::PATH,
        body,
        "rid-logout-cross-tenant",
        generated::http::identity_v1::logout::CONTRACT_ID,
    )
    .await?;
    assert_logout_success(
        case,
        &response.response,
        "rid-logout-cross-tenant",
        &sentinels,
    )?;
    let after = session_snapshot(observation_pool, probes, &session).await?;
    ensure!(
        after.0 == vec![true, false],
        "cross-tenant logout must preserve owner session"
    );
    assert_accounting(
        case,
        &[&response.localtx],
        session_commit_delta(&before, &after)?,
        ExpectedLocalTxFinal::None,
    )
}

async fn drive_logout_happy_and_repeat(
    harness: &IdentityHarness,
    observation_pool: &sqlx::PgPool,
    happy_case: &JourneyCase,
    repeat_case: &JourneyCase,
) -> Result<()> {
    let session = seed_logout_session(harness).await?;
    let probes = [harness.tenant_a, harness.tenant_b];

    let (happy_body, happy_sentinels) = logout_payload(happy_case, &session)?;
    let before = session_snapshot(observation_pool, probes, &session).await?;
    let happy = send_recorded(
        &harness.session_identity,
        generated::http::identity_v1::logout::PATH,
        happy_body,
        "rid-logout-happy",
        generated::http::identity_v1::logout::CONTRACT_ID,
    )
    .await?;
    assert_logout_success(
        happy_case,
        &happy.response,
        "rid-logout-happy",
        &happy_sentinels,
    )?;
    let after = session_snapshot(observation_pool, probes, &session).await?;
    assert_accounting(
        happy_case,
        &[&happy.localtx],
        session_commit_delta(&before, &after)?,
        ExpectedLocalTxFinal::Committed,
    )?;

    let (repeat_body, repeat_sentinels) = logout_payload(repeat_case, &session)?;
    let before = after;
    let repeat = send_recorded(
        &harness.session_identity,
        generated::http::identity_v1::logout::PATH,
        repeat_body,
        "rid-logout-repeat",
        generated::http::identity_v1::logout::CONTRACT_ID,
    )
    .await?;
    assert_logout_success(
        repeat_case,
        &repeat.response,
        "rid-logout-repeat",
        &repeat_sentinels,
    )?;
    let after = session_snapshot(observation_pool, probes, &session).await?;
    ensure!(
        after.0 == vec![false, false],
        "repeat logout must converge to revoked"
    );
    assert_accounting(
        repeat_case,
        &[&repeat.localtx],
        session_commit_delta(&before, &after)?,
        ExpectedLocalTxFinal::None,
    )
}

async fn drive_logout_contention(
    harness: &IdentityHarness,
    observation_pool: &sqlx::PgPool,
    case: &JourneyCase,
) -> Result<()> {
    let session = seed_logout_session(harness).await?;
    let (body, sentinels) = logout_payload(case, &session)?;
    let probes = [harness.tenant_a, harness.tenant_b];
    let before = session_snapshot(observation_pool, probes, &session).await?;
    let pair = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            send_recorded(
                &harness.session_identity,
                generated::http::identity_v1::logout::PATH,
                body.clone(),
                "rid-logout-contention-a",
                generated::http::identity_v1::logout::CONTRACT_ID,
            ),
            send_recorded(
                &harness.session_identity,
                generated::http::identity_v1::logout::PATH,
                body,
                "rid-logout-contention-b",
                generated::http::identity_v1::logout::CONTRACT_ID,
            )
        )
    })
    .await
    .context("concurrent logout exceeded 15 seconds")?;
    let (response_a, response_b) = (pair.0?, pair.1?);
    assert_logout_success(
        case,
        &response_a.response,
        "rid-logout-contention-a",
        &sentinels,
    )?;
    assert_logout_success(
        case,
        &response_b.response,
        "rid-logout-contention-b",
        &sentinels,
    )?;
    let after = session_snapshot(observation_pool, probes, &session).await?;
    ensure!(
        after.0 == vec![false, false],
        "concurrent logout must converge to revoked"
    );
    assert_accounting(
        case,
        &[&response_a.localtx, &response_b.localtx],
        session_commit_delta(&before, &after)?,
        ExpectedLocalTxFinal::Committed,
    )
}

async fn drive_logout(
    harness: &IdentityHarness,
    observation_pool: &sqlx::PgPool,
    cases: LogoutCases,
) -> Result<()> {
    let unauth_session = seed_logout_session(harness).await?;
    let (unauth_body, _) = logout_payload(&cases.unauthenticated, &unauth_session)?;
    drive_logout_error_case(
        harness,
        observation_pool,
        &cases.unauthenticated,
        &harness.identity_unauthed,
        &unauth_session,
        unauth_body,
        "rid-logout-auth",
    )
    .await?;

    let other_session = seed_logout_session(harness).await?;
    let (other_body, _) = logout_payload(&cases.other_owner, &other_session)?;
    drive_logout_error_case(
        harness,
        observation_pool,
        &cases.other_owner,
        &harness.other_identity,
        &other_session,
        other_body,
        "rid-logout-forbidden",
    )
    .await?;

    let validation_session = seed_logout_session(harness).await?;
    drive_logout_error_case(
        harness,
        observation_pool,
        &cases.validation_failure,
        &harness.session_identity,
        &validation_session,
        br#"{"unexpected":"logout-shape-sentinel"}"#.to_vec(),
        "rid-logout-validation",
    )
    .await?;

    drive_logout_cross_tenant(harness, observation_pool, &cases.cross_tenant).await?;
    drive_logout_happy_and_repeat(harness, observation_pool, &cases.happy, &cases.repeat).await?;
    drive_logout_contention(harness, observation_pool, &cases.contention).await
}

#[test]
fn changed_fixture_behavior_is_observably_red() -> Result<()> {
    let changed = SETTINGS_FIXTURE.replacen("ERR_CORE_UNAUTHENTICATED", "ERR_CORE_FORBIDDEN", 1);
    let fixture: JourneyFixture = toml::from_str(&changed)?;
    let case = fixture
        .cases
        .iter()
        .find(|case| case.id == "settings-secret-publish-auth-failure")
        .context("synthetic fixture case missing")?;
    let response = HttpResult {
        status: StatusCode::UNAUTHORIZED,
        request_id: "rid-synthetic-red".to_owned(),
        body: r#"{"error":{"code":"ERR_CORE_UNAUTHENTICATED","message":"unauthenticated","retryable":false,"details":[],"requestId":"rid-synthetic-red"}}"#.to_owned(),
    };
    ensure!(
        assert_case_error(case, &response, "rid-synthetic-red", &[]).is_err(),
        "changing fixture errorCode must make the executable assertion red"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn active_localtx_validation_journey() -> Result<()> {
    const LOCALTX_JOURNEY_SETTINGS_SECRET_PUBLISH: ::vocab::HttpRouteBinding<
        ::generated::http::settings_v2::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::settings_v2::ROUTE;
    const LOCALTX_JOURNEY_IDENTITY_LOGOUT: ::vocab::HttpRouteBinding<
        ::generated::http::identity_v1::logout::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::identity_v1::logout::ROUTE;
    const LOCALTX_JOURNEY_IDENTITY_PASSWORD_CHANGE: ::vocab::HttpRouteBinding<
        ::generated::http::identity_v1::password_change::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::identity_v1::password_change::ROUTE;
    let _ = (
        LOCALTX_JOURNEY_SETTINGS_SECRET_PUBLISH,
        LOCALTX_JOURNEY_IDENTITY_LOGOUT,
        LOCALTX_JOURNEY_IDENTITY_PASSWORD_CHANGE,
    );

    let mut settings_fixtures = FixtureBook::load(
        SETTINGS_FIXTURE,
        FixtureIdentity {
            id: "settings-secret-publish-localtx",
            contract_id: generated::http::settings_v2::CONTRACT_ID,
            tx_model: "repo-atomic-cas",
            spec: "journeys/settings-secret-publish-localtx-journey.toml",
            marker: "SETTINGS_SECRET_PUBLISH",
        },
    )?;
    let settings_happy = settings_fixtures.take_case("settings-secret-publish-happy")?;
    let settings_auth_failure =
        settings_fixtures.take_case("settings-secret-publish-auth-failure")?;
    let settings_validation_failure =
        settings_fixtures.take_case("settings-secret-publish-validation-failure")?;
    let settings_conflict = settings_fixtures.take_case("settings-secret-publish-conflict")?;
    let settings_cases = SettingsCases {
        happy: settings_happy,
        auth_failure: settings_auth_failure,
        validation_failure: settings_validation_failure,
        conflict: settings_conflict,
    };
    let mut password_fixtures = FixtureBook::load(
        PASSWORD_FIXTURE,
        FixtureIdentity {
            id: "identity-password-change-localtx",
            contract_id: generated::http::identity_v1::password_change::CONTRACT_ID,
            tx_model: "repo-atomic-cas",
            spec: "journeys/identity-password-change-localtx-journey.toml",
            marker: "IDENTITY_PASSWORD_CHANGE",
        },
    )?;
    let password_happy = password_fixtures.take_case("identity-password-change-happy")?;
    let password_unauthenticated =
        password_fixtures.take_case("identity-password-change-unauthenticated")?;
    let password_invalid_subject =
        password_fixtures.take_case("identity-password-change-invalid-subject")?;
    let password_validation_failure =
        password_fixtures.take_case("identity-password-change-validation-failure")?;
    let password_conflict = password_fixtures.take_case("identity-password-change-conflict")?;
    let password_cases = PasswordCases {
        happy: password_happy,
        unauthenticated: password_unauthenticated,
        invalid_subject: password_invalid_subject,
        validation_failure: password_validation_failure,
        conflict: password_conflict,
    };
    let mut logout_fixtures = FixtureBook::load(
        LOGOUT_FIXTURE,
        FixtureIdentity {
            id: "identity-logout-localtx",
            contract_id: generated::http::identity_v1::logout::CONTRACT_ID,
            tx_model: "tenant-scoped-uow",
            spec: "journeys/identity-logout-localtx-journey.toml",
            marker: "IDENTITY_LOGOUT",
        },
    )?;
    let logout_happy = logout_fixtures.take_case("identity-logout-happy")?;
    let logout_unauthenticated = logout_fixtures.take_case("identity-logout-unauthenticated")?;
    let logout_other_owner = logout_fixtures.take_case("identity-logout-other-owner")?;
    let logout_validation_failure =
        logout_fixtures.take_case("identity-logout-validation-failure")?;
    let logout_contention = logout_fixtures.take_case("identity-logout-contention")?;
    let logout_repeat = logout_fixtures.take_case("identity-logout-repeat")?;
    let logout_cross_tenant = logout_fixtures.take_case("identity-logout-cross-tenant")?;
    let logout_cases = LogoutCases {
        happy: logout_happy,
        unauthenticated: logout_unauthenticated,
        other_owner: logout_other_owner,
        validation_failure: logout_validation_failure,
        contention: logout_contention,
        repeat: logout_repeat,
        cross_tenant: logout_cross_tenant,
    };
    let pg = testkit::env_or_postgres().await?;
    provision_rss_app_login(pg.params()).await?;
    let owner = pg_config(pg.params());
    let app = pg_config_for(pg.params(), RSS_APP_ROLE, RSS_APP_PASSWORD);
    let deps = PgRuntimeDeps::setup(
        &owner,
        &app,
        generated::event::PROJECTION_INPUT_GENERATION,
        generated::event::PROJECTION_INPUTS,
    )
    .await?;
    let observer = observation_pool(pg.params()).await?;
    let body = async {
        let tenant_a = TenantId::parse(TENANT_A)?;
        let tenant_b = TenantId::parse(TENANT_B)?;
        let identity = build_identity_harness(&deps, tenant_a, tenant_b).await?;
        drive_settings(
            &deps,
            tenant_a,
            tenant_b,
            Arc::clone(&identity.primary_authorizer),
            settings_cases,
        )
        .await?;
        drive_password(&identity, password_cases).await?;
        drive_logout(&identity, &observer, logout_cases).await
    }
    .await;
    observer.close().await;
    let cleanup: Result<()> = async {
        let (resources, _sampler_factory) = deps.into_runtime_parts(Duration::from_secs(1));
        for resource in resources.into_iter().rev() {
            resource.shutdown().await?;
        }
        Ok(())
    }
    .await;
    finish_with_pg_cleanup(body, cleanup)?;
    settings_fixtures.assert_exhausted()?;
    password_fixtures.assert_exhausted()?;
    logout_fixtures.assert_exhausted()
}
