//! Shared harness for contract-scoped Active LocalTx durable journeys.
//!
//! Every active LocalTx HTTP contract is driven through its production compose/finalize funnel.
//! Mutations land in a fixture-owned PostgreSQL instance; the only
//! test doubles are read-side barriers/probes that make concurrency and ordering deterministic.

#[path = "../common/mod.rs"]
mod common;

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result, anyhow, ensure};
use audit::ports::{
    AuditAdminRepo, AuditChainHasher, AuditError, AuditLedgerVerifyReport, AuditListResult,
    AuditOutcome, AuditPage, AuditRecord, AuditWriteRepo, CrossTenantReadScope, DynAuditAdminRepo,
    DynAuditReadRepo, ResourceRef, TenantRepoScope as AuditScope,
};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use diport::{
    DynKeyProvider, DynSecretResolver, EncryptOutput, KeyName, KeyProvider, KeyProviderError,
    KeyRef, KeyVersion, ManagedResource, RedactedBytes, SecretCoordinate, SecretMaterial,
    SecretResolver, SecretResolverError,
};
use generated::http::audit_v1::list_tenant_entries::AuditListTenantEntriesResponse;
use generated::http::settings_v2::{SettingsSecretPublishRequest, SettingsSecretPublishResponse};
use identity::ports::{
    Credential, CredentialRepo, DynAccountSecurityReadRepo, DynCredentialRepo,
    TenantRepoScope as IdentityScope,
};
use identity::{CredentialSecurityService, LoginService};
use memory::{FixedClock, MemBus, MemEmitter};
use postgres::{
    ConfigValueProtections, PgAuditAdminRepo, PgConfig, PgCredentialRepo, PgPassword,
    PgRuntimeDeps, PgSslMode, PgTenantReadConfig, caps,
};
use primitives::{AuthPlan, AuthScheme, ListenerKind, MacKey};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use settings::ports::{
    DynSecretRepo, SecretEntry, SecretKey, SecretRepo, SecretRepoError,
    TenantRepoScope as SettingsScope,
};
use settings::{SecretResolveService, SettingsDomain, SettingsService};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use tokio::sync::Barrier;
use tower::ServiceExt;
use uuid::Uuid;
use vocab::{PrincipalKind, TenantId};

const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const TENANT_B: &str = "a47ac10b-58cc-4372-a567-0e02b2c3d470";
const HAPPY_USER: &str = "11111111-2222-4333-8444-555555555551";
const NOW_SECS: u64 = 1_000;
const TTL_SECS: u64 = 3_600;

struct MissingSecretResolver;

impl SecretResolver for MissingSecretResolver {
    async fn resolve(
        &self,
        _tenant: TenantId,
        _coordinate: &SecretCoordinate,
    ) -> Result<SecretMaterial, SecretResolverError> {
        Err(SecretResolverError::NotFound)
    }
}
static RSS_APP_LOGIN: TestPgCredential = TestPgCredential::new("rss_app", "rss_app_test_pw");
static RSS_APP_READ_LOGIN: TestPgCredential =
    TestPgCredential::new("rss_app_read", "rss_app_read_test_pw");
static RSS_AUDIT_ADMIN_LOGIN: TestPgCredential =
    TestPgCredential::new("rss_audit_admin", "rss_audit_admin_test_pw");
const IDENTITY_SEED_PASSWORD: &str = "journey-identity-seed-password-sentinel";
const AUDIT_LEDGER_ACTION: &str = "audit:journey_entry";
const AUDIT_LEDGER_RESOURCE_KIND: &str = "journey-audit-resource";
const AUDIT_LEDGER_RESOURCE_SENTINEL: &str = "audit-ledger-resource-sentinel";

const SETTINGS_FIXTURE: &str =
    include_str!("../../../fixtures/settings-secret-publish-localtx.toml");
const AUDIT_TENANT_FIXTURE: &str =
    include_str!("../../../fixtures/audit-list-tenant-entries-localtx.toml");
const AUDIT_ROUTE_ACTION: &str = "audit:list-cross-tenant";

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
pub(crate) struct JourneyCase {
    id: String,
    scenario: String,
    http_status: u16,
    error_code: String,
    retryable: bool,
    attempts: u16,
    commits: Option<u16>,
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

fn assert_active_case_scenario(case: &JourneyCase) -> Result<()> {
    let expected = match case.id.as_str() {
        "identity-refresh-happy" | "audit-list-tenant-entries-happy" => "happy",
        "identity-refresh-unknown"
        | "audit-list-tenant-entries-unauthenticated"
        | "audit-list-tenant-entries-non-superadmin-deny" => "auth-failure",
        "identity-refresh-malformed" | "audit-list-tenant-entries-validation" => {
            "validation-failure"
        }
        "identity-refresh-contention-winner"
        | "identity-refresh-contention-loser"
        | "audit-list-tenant-entries-contention" => "contention",
        "identity-refresh-commit-unknown" => "commit-unknown",
        other => return Err(anyhow!("unknown active journey case `{other}`")),
    };
    ensure!(
        case.scenario == expected,
        "case `{}` scenario drift: expected `{expected}`, got `{}`",
        case.id,
        case.scenario
    );
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) struct FixtureIdentity<'a> {
    pub(crate) id: &'a str,
    pub(crate) contract_id: &'a str,
    pub(crate) tx_model: &'a str,
    pub(crate) spec: &'a str,
    pub(crate) runner: &'a str,
    pub(crate) marker: &'a str,
}

pub(crate) struct FixtureBook {
    fixture_id: String,
    cases: HashMap<String, JourneyCase>,
    receipts: Vec<(String, Arc<CaseObservation>)>,
}

impl FixtureBook {
    pub(crate) fn load(source: &str, expected: FixtureIdentity<'_>) -> Result<Self> {
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
        ensure!(fixture.runner == expected.runner, "fixture runner drift");
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

    pub(crate) fn take_case(&mut self, id: &str) -> Result<JourneyCase> {
        self.cases
            .remove(id)
            .with_context(|| format!("fixture `{}` is missing case `{id}`", self.fixture_id))
    }

    pub(crate) fn assert_exhausted(&self) -> Result<()> {
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
    commit_unknown: u16,
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
                commit_unknown: sum
                    .commit_unknown
                    .checked_add(sample.commit_unknown)
                    .context("LocalTx commit-unknown sum overflow")?,
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
            commit_unknown: metric_sum(
                rendered,
                "localtx_final_total",
                contract_id,
                Some(("final_status", "commit_unknown")),
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

async fn send_request(router: &axum::Router, request: Request<Body>) -> Result<HttpResult> {
    let response = router.clone().oneshot(request).await?;
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

async fn send_request_recorded(
    router: &axum::Router,
    request: Request<Body>,
    contract_id: &str,
) -> Result<RecordedHttpResult> {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let response = poll_with_local_recorder(&recorder, send_request(router, request)).await?;
    let localtx = LocalTxMetrics::from_prometheus(&handle.render(), contract_id)?;
    Ok(RecordedHttpResult { response, localtx })
}

async fn send_recorded(
    router: &axum::Router,
    uri: &str,
    body: Vec<u8>,
    request_id: &str,
    contract_id: &str,
) -> Result<RecordedHttpResult> {
    send_request_recorded(
        router,
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-request-id", request_id)
            .body(Body::from(body))?,
        contract_id,
    )
    .await
}

async fn send_audit_recorded(
    router: &axum::Router,
    uri: String,
    request_id: &str,
) -> Result<RecordedHttpResult> {
    send_request_recorded(
        router,
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("x-request-id", request_id)
            .body(Body::empty())?,
        generated::http::audit_v1::list_tenant_entries::CONTRACT_ID,
    )
    .await
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
        "settings-secret-publish-happy" | "identity-logout-happy" => "happy",
        "settings-secret-publish-auth-failure"
        | "identity-logout-unauthenticated"
        | "identity-logout-other-owner" => "auth-failure",
        "settings-secret-publish-validation-failure" | "identity-logout-validation-failure" => {
            "validation-failure"
        }
        "settings-secret-publish-conflict" => "conflict",
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
        case.commits == Some(commits),
        "case `{}` commits drift: fixture={:?}, observed={commits}",
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
        case.commits == Some(0),
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
    let auth_scheme = match principal {
        Some((PrincipalKind::User, _, _)) | None => AuthScheme::RssAccessToken,
        Some(_) => AuthScheme::FederatedAccessToken,
    };
    let authenticated = httpserve::finalize_primary_auth(
        routes,
        AuthPlan::new(ListenerKind::Primary, auth_scheme)?,
        authorizer,
    )?;
    Ok(match principal {
        Some((kind, subject, tenant)) => authenticated
            .layer(axum::Extension(test_authenticated(
                kind,
                subject,
                Some(tenant),
            )?))
            .into_router_for_test(),
        None => authenticated.into_router_for_test(),
    })
}

fn test_authenticated(
    kind: PrincipalKind,
    subject: &str,
    tenant: Option<TenantId>,
) -> Result<httpserve::Authenticated> {
    if kind == PrincipalKind::User {
        return Ok(httpserve::Authenticated::new_rss_user_for_test(
            subject,
            tenant.context("RSS user test evidence requires tenant")?,
        ));
    }
    let permissions = diport::VerifiedFederatedPermissions::new([vocab::GrantPermission::route(
        vocab::RoutePermissionId::SettingsConfigPublish,
    )])?;
    Ok(httpserve::Authenticated::new_federated_for_test(
        kind,
        subject,
        tenant,
        &permissions,
    ))
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

struct TestPgCredential {
    role: &'static str,
    password: &'static str,
}

impl TestPgCredential {
    const fn new(role: &'static str, password: &'static str) -> Self {
        Self { role, password }
    }
}

/// Capability minted only after the matching role/password DDL transaction commits.
struct ProvisionedTestPgCredential {
    role: testkit::PgAppRole,
}

impl ProvisionedTestPgCredential {
    fn config(&self) -> PgConfig {
        let params = self.role.params();
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
}

async fn provision_test_logins(
    fixture: &testkit::OwnedPgFixture,
) -> Result<(
    ProvisionedTestPgCredential,
    ProvisionedTestPgCredential,
    ProvisionedTestPgCredential,
)> {
    let [app, reader, audit_admin] = fixture
        .resolve_app_roles([
            testkit::PgAppRoleSpec::new(RSS_APP_LOGIN.role, RSS_APP_LOGIN.password),
            testkit::PgAppRoleSpec::new(RSS_APP_READ_LOGIN.role, RSS_APP_READ_LOGIN.password),
            testkit::PgAppRoleSpec::new(RSS_AUDIT_ADMIN_LOGIN.role, RSS_AUDIT_ADMIN_LOGIN.password),
        ])
        .await?;
    Ok((
        ProvisionedTestPgCredential { role: app },
        ProvisionedTestPgCredential { role: reader },
        ProvisionedTestPgCredential { role: audit_admin },
    ))
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

async fn seed_credential(
    repo: &PgCredentialRepo,
    tenant: TenantId,
    user: ids::UserId,
    login: &str,
    password: &str,
) -> Result<()> {
    repo.insert(
        IdentityScope::for_test(tenant),
        Credential::hydrate(
            login,
            user,
            tenant,
            secure::PasswordHash::for_test(secure::RawPassword::new(password.to_owned()))?,
            1,
        ),
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

pub(crate) struct SettingsCases {
    pub(crate) happy: JourneyCase,
    pub(crate) auth_failure: JourneyCase,
    pub(crate) validation_failure: JourneyCase,
    pub(crate) conflict: JourneyCase,
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
    let secret_resolve = Arc::new(SecretResolveService::new(
        Arc::clone(&secret_route_repo),
        DynSecretResolver::new_box(MissingSecretResolver),
    ));
    let settings_domain = SettingsDomain::new(
        Arc::new(SettingsService::with_seed(
            MemEmitter::with_tenant_metadata_signer(MemBus::new(), common::memory_tenant_signer()),
            Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        )),
        secret_route_repo,
        Arc::from(secret_uow),
        secret_resolve,
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

async fn build_identity_authorizer(
    deps: &PgRuntimeDeps,
    tenant: TenantId,
) -> Result<Arc<dyn httpserve::RouteAuthorizer>> {
    let identity_deps = deps.handle().for_domain::<caps::Identity>();
    seed_credential(
        &identity_deps.credential_repo(),
        tenant,
        ids::UserId::parse(HAPPY_USER)?,
        "settings-authorizer-login",
        IDENTITY_SEED_PASSWORD,
    )
    .await?;
    let credentials: Arc<DynCredentialRepo<'static>> =
        Arc::from(DynCredentialRepo::new_box(identity_deps.credential_repo()));
    let pseudonym_keys = postgres::identity_pseudonym_keys_for_test();
    let auth_grants = identity::seed_auth_grant_services(
        identity_deps.auth_grant_provider(
            Box::new(FixedClock::at_unix_secs(NOW_SECS)),
            Arc::clone(&pseudonym_keys),
        ),
        DynAccountSecurityReadRepo::new_box(identity_deps.account_security_repo()),
        || Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
    );
    let refresh = auth_grants.refresh_service();
    let grants = auth_grants.lifecycle();
    let security = auth_grants.security_lifecycle();
    let credential_security = Arc::new(CredentialSecurityService::new_with_shared_lifecycle(
        Arc::clone(&credentials),
        grants,
        DynAccountSecurityReadRepo::new_box(identity_deps.account_security_repo()),
        security,
        identity_deps.account_reactivation_lifecycle(),
        common::password_policy(),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
    ));
    let login = Arc::new(LoginService::new(
        credentials,
        auth_grants,
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
    ));
    let identity_domain = common::identity_domain(login, refresh, credential_security);
    let mut registry = bootstrap::compose(&[&identity_domain])?;
    Ok(registry.take_primary_authorizer()?)
}

pub(crate) struct AuditCases {
    pub(crate) happy: JourneyCase,
    pub(crate) unauthenticated: JourneyCase,
    pub(crate) non_superadmin_deny: JourneyCase,
    pub(crate) validation: JourneyCase,
    pub(crate) contention: JourneyCase,
}

struct AuditRequestIds {
    happy: String,
    unauthenticated: String,
    denied: String,
    validation: String,
    contention_a: String,
    contention_b: String,
}

impl AuditRequestIds {
    fn new(run_namespace: Uuid) -> Self {
        Self {
            happy: format!("rid-audit-happy-{run_namespace}"),
            unauthenticated: format!("rid-audit-unauthenticated-{run_namespace}"),
            denied: format!("rid-audit-denied-{run_namespace}"),
            validation: format!("rid-audit-validation-{run_namespace}"),
            contention_a: format!("rid-audit-contention-a-{run_namespace}"),
            contention_b: format!("rid-audit-contention-b-{run_namespace}"),
        }
    }
}

#[derive(Clone)]
struct AuditReadAuthorizer;

impl httpserve::RouteAuthorizer for AuditReadAuthorizer {
    fn authorize<'a>(
        &'a self,
        request: httpserve::RouteAuthorizationRequest,
    ) -> std::pin::Pin<Box<dyn Future<Output = httpserve::RouteAuthorizationDecision> + Send + 'a>>
    {
        Box::pin(async move {
            if request.contract_id == generated::http::audit_v1::list_tenant_entries::CONTRACT_ID
                && request.permission == vocab::AUDIT_READ_PERMISSION
            {
                httpserve::RouteAuthorizationDecision::Allow
            } else {
                httpserve::RouteAuthorizationDecision::Deny
            }
        })
    }
}

struct OrderedAuditAdminRepo {
    inner: PgAuditAdminRepo<common::CapturingVerifier>,
    observation_pool: sqlx::PgPool,
    expected_request_id: String,
    read_barrier: Option<Arc<Barrier>>,
    list_calls: Arc<AtomicUsize>,
}

impl AuditAdminRepo for OrderedAuditAdminRepo {
    async fn list_tenant(
        &self,
        scope: CrossTenantReadScope,
        page: AuditPage,
    ) -> Result<AuditListResult, AuditError> {
        let durable = route_audit_request_count(
            &self.observation_pool,
            &self.expected_request_id,
            Some("success"),
        )
        .await
        .map_err(AuditError::storage)?;
        if durable != 1 {
            return Err(AuditError::storage(std::io::Error::other(
                "target-tenant admin read lacks its request-bound durable audit append",
            )));
        }
        if let Some(barrier) = &self.read_barrier {
            barrier.wait().await;
        }
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.list_tenant(scope, page).await
    }

    async fn verify_tenant(
        &self,
        tenant: TenantId,
        batch: vocab::Limit,
    ) -> Result<AuditLedgerVerifyReport, AuditError> {
        self.inner.verify_tenant(tenant, batch).await
    }
}

struct AuditHarness {
    happy: axum::Router,
    validation: axum::Router,
    contention_a: axum::Router,
    contention_b: axum::Router,
    admin: axum::Router,
    unauthenticated: axum::Router,
    list_calls: Arc<AtomicUsize>,
}

fn audit_hasher() -> Result<AuditChainHasher<common::CapturingVerifier>> {
    AuditChainHasher::new(
        common::CapturingVerifier::default(),
        MacKey::from_bytes(common::AUDIT_KEY.to_vec()),
    )
    .context("journey audit key must satisfy minimum strength")
}

async fn seed_audit_projection_row(deps: &PgRuntimeDeps, target: TenantId) -> Result<()> {
    let repo = deps
        .handle()
        .for_domain::<caps::Audit>()
        .audit_repo(audit_hasher()?);
    repo.append(
        AuditScope::for_test(target),
        AuditRecord {
            tenant: target,
            actor: ids::UserId::parse(HAPPY_USER)?,
            actor_kind: PrincipalKind::SuperAdmin,
            action: vocab::Action::parse(AUDIT_LEDGER_ACTION)?,
            resource: ResourceRef::new(AUDIT_LEDGER_RESOURCE_KIND, AUDIT_LEDGER_RESOURCE_SENTINEL),
            outcome: AuditOutcome::Success,
            recorded_at: SystemTime::UNIX_EPOCH + Duration::from_secs(NOW_SECS),
        },
    )
    .await?;
    Ok(())
}

fn assert_seeded_audit_projection(page: &AuditListTenantEntriesResponse) -> Result<()> {
    ensure!(
        page.data.len() == 1,
        "target audit journey must return the seeded ledger row"
    );
    let entry = &page.data[0];
    ensure!(entry.action == AUDIT_LEDGER_ACTION);
    ensure!(entry.resource_kind == AUDIT_LEDGER_RESOURCE_KIND);
    ensure!(entry.outcome == "success");
    ensure!(entry.actor_kind == "superAdmin");
    ensure!(
        entry.tenant_id == "<redacted>"
            && entry.actor == "<redacted>"
            && entry.resource_id == "<redacted>",
        "target audit projection must mask tenant, actor, and resource id"
    );
    Ok(())
}

async fn route_audit_request_count(
    pool: &sqlx::PgPool,
    request_id: &str,
    outcome: Option<&str>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM auth_audit_events \
         WHERE action = $1 AND request_id = $2 AND ($3::text IS NULL OR outcome = $3)",
    )
    .bind(AUDIT_ROUTE_ACTION)
    .bind(request_id)
    .bind(outcome)
    .fetch_one(pool)
    .await
}

fn finalized_audit_router(
    domain: &dyn bootstrap::Domain,
    auth_sink: postgres::PgAuthAuditSink,
    principal_kind: Option<PrincipalKind>,
    target: TenantId,
) -> Result<axum::Router> {
    let mut registry = bootstrap::compose(&[domain])?;
    let routes = registry.finalize_routes()?;
    let (_, admin) = routes
        .into_iter()
        .find(|(listener, _)| *listener == ListenerKind::Admin)
        .context("audit admin routes missing")?;
    let plan = AuthPlan::new(ListenerKind::Admin, AuthScheme::FederatedAccessToken)?;
    let router = httpserve::finalize_auth_with_audit_and_authorizer(
        admin,
        plan,
        httpserve::AuditSinkHandle::new(auth_sink),
        Arc::new(FixedClock::at_unix_secs(NOW_SECS)),
        Arc::new(AuditReadAuthorizer),
    )?
    .into_router_for_test();
    let Some(kind) = principal_kind else {
        return Ok(router);
    };
    let evidence_tenant = (kind != PrincipalKind::SuperAdmin).then_some(target);
    let principal = Arc::new(authn::test_support::principal(
        kind,
        HAPPY_USER,
        evidence_tenant,
    ));
    let authenticated = test_authenticated(kind, HAPPY_USER, evidence_tenant)?;
    Ok(router.layer(axum::middleware::from_fn(
        move |mut request: axum::extract::Request, next: axum::middleware::Next| {
            let principal = Arc::clone(&principal);
            let authenticated = authenticated.clone();
            async move {
                request.extensions_mut().insert(authenticated);
                request.extensions_mut().insert(principal);
                request
                    .extensions_mut()
                    .insert(httpserve::PendingScopeCtx::new(
                        runctx::test_support::app_ctx_with_kind(target, kind, HAPPY_USER),
                    ));
                next.run(request).await
            }
        },
    )))
}

fn ordered_audit_router(
    deps: &PgRuntimeDeps,
    observation_pool: &sqlx::PgPool,
    target: TenantId,
    expected_request_id: &str,
    principal_kind: Option<PrincipalKind>,
    read_barrier: Option<Arc<Barrier>>,
    list_calls: Arc<AtomicUsize>,
) -> Result<axum::Router> {
    let audit_deps = deps.handle().for_domain::<caps::Audit>();
    let read: Arc<DynAuditReadRepo<'static>> = Arc::from(DynAuditReadRepo::new_box(
        audit_deps.audit_repo(audit_hasher()?),
    ));
    let admin = audit_deps
        .audit_admin_repo(audit_hasher()?)
        .context("audit-admin capability must be configured")?;
    let ordered_admin: Arc<DynAuditAdminRepo<'static>> =
        Arc::from(DynAuditAdminRepo::new_box(OrderedAuditAdminRepo {
            inner: admin,
            observation_pool: observation_pool.clone(),
            expected_request_id: expected_request_id.to_owned(),
            read_barrier,
            list_calls,
        }));
    let domain = audit::AuditDomain::new(
        read,
        Some(ordered_admin),
        audit_deps.auth_audit_sink(),
        Arc::new(FixedClock::at_unix_secs(NOW_SECS)),
    );
    finalized_audit_router(
        &domain,
        audit_deps.auth_audit_sink(),
        principal_kind,
        target,
    )
}

fn build_audit_harness(
    deps: &PgRuntimeDeps,
    observation_pool: &sqlx::PgPool,
    target: TenantId,
    request_ids: &AuditRequestIds,
) -> Result<AuditHarness> {
    let list_calls = Arc::new(AtomicUsize::new(0));
    let contention_barrier = Arc::new(Barrier::new(2));
    Ok(AuditHarness {
        happy: ordered_audit_router(
            deps,
            observation_pool,
            target,
            &request_ids.happy,
            Some(PrincipalKind::SuperAdmin),
            None,
            Arc::clone(&list_calls),
        )?,
        validation: ordered_audit_router(
            deps,
            observation_pool,
            target,
            &request_ids.validation,
            Some(PrincipalKind::SuperAdmin),
            None,
            Arc::clone(&list_calls),
        )?,
        contention_a: ordered_audit_router(
            deps,
            observation_pool,
            target,
            &request_ids.contention_a,
            Some(PrincipalKind::SuperAdmin),
            Some(Arc::clone(&contention_barrier)),
            Arc::clone(&list_calls),
        )?,
        contention_b: ordered_audit_router(
            deps,
            observation_pool,
            target,
            &request_ids.contention_b,
            Some(PrincipalKind::SuperAdmin),
            Some(contention_barrier),
            Arc::clone(&list_calls),
        )?,
        admin: ordered_audit_router(
            deps,
            observation_pool,
            target,
            &request_ids.denied,
            Some(PrincipalKind::Admin),
            None,
            Arc::clone(&list_calls),
        )?,
        unauthenticated: ordered_audit_router(
            deps,
            observation_pool,
            target,
            &request_ids.unauthenticated,
            None,
            None,
            Arc::clone(&list_calls),
        )?,
        list_calls,
    })
}

fn audit_uri(target: &str, query: &str) -> String {
    format!(
        "{}{}",
        generated::http::audit_v1::list_tenant_entries::PATH.replace("{tenantId}", target),
        query
    )
}

fn assert_audit_accounting(
    case: &JourneyCase,
    samples: &[&LocalTxMetrics],
    expected_committed: u16,
) -> Result<()> {
    assert_active_case_scenario(case)?;
    let observed = LocalTxMetrics::combine(samples)?;
    ensure!(observed.attempts == case.attempts, "audit attempts drift");
    ensure!(
        observed.failed_attempts == 0
            && observed.finals == expected_committed
            && observed.committed == expected_committed
            && observed.rolled_back == 0
            && observed.commit_unknown == 0,
        "audit LocalTx accounting drift"
    );
    ensure!(case.commits == Some(expected_committed));
    case.mark_accounting_observed();
    Ok(())
}

async fn drive_audit_rejections(
    harness: &AuditHarness,
    pool: &sqlx::PgPool,
    target: TenantId,
    cases: &AuditCases,
    request_ids: &AuditRequestIds,
) -> Result<()> {
    let unauth = send_audit_recorded(
        &harness.unauthenticated,
        audit_uri(&target.to_string(), "?limit=1"),
        &request_ids.unauthenticated,
    )
    .await?;
    assert_case_error(
        &cases.unauthenticated,
        &unauth.response,
        &request_ids.unauthenticated,
        &cases.unauthenticated.redact_sentinels,
    )?;
    ensure!(route_audit_request_count(pool, &request_ids.unauthenticated, None).await? == 0);
    assert_audit_accounting(&cases.unauthenticated, &[&unauth.localtx], 0)?;

    let reads_before = harness.list_calls.load(Ordering::SeqCst);
    let denied = send_audit_recorded(
        &harness.admin,
        audit_uri(&target.to_string(), "?limit=1"),
        &request_ids.denied,
    )
    .await?;
    assert_case_error(
        &cases.non_superadmin_deny,
        &denied.response,
        &request_ids.denied,
        &cases.non_superadmin_deny.redact_sentinels,
    )?;
    ensure!(route_audit_request_count(pool, &request_ids.denied, Some("failure")).await? == 1);
    ensure!(harness.list_calls.load(Ordering::SeqCst) == reads_before);
    assert_audit_accounting(&cases.non_superadmin_deny, &[&denied.localtx], 1)?;

    let validation = send_audit_recorded(
        &harness.validation,
        audit_uri("audit-validation-sentinel", "?limit=1"),
        &request_ids.validation,
    )
    .await?;
    assert_case_error(
        &cases.validation,
        &validation.response,
        &request_ids.validation,
        &cases.validation.redact_sentinels,
    )?;
    ensure!(route_audit_request_count(pool, &request_ids.validation, None).await? == 0);
    ensure!(harness.list_calls.load(Ordering::SeqCst) == reads_before);
    assert_audit_accounting(&cases.validation, &[&validation.localtx], 0)
}

async fn drive_audit_happy_and_contention(
    harness: &AuditHarness,
    pool: &sqlx::PgPool,
    target: TenantId,
    cases: &AuditCases,
    request_ids: &AuditRequestIds,
) -> Result<()> {
    let happy = send_audit_recorded(
        &harness.happy,
        audit_uri(&target.to_string(), "?limit=1"),
        &request_ids.happy,
    )
    .await?;
    let page: AuditListTenantEntriesResponse = decode_case_success(
        &cases.happy,
        &happy.response,
        &request_ids.happy,
        &cases.happy.redact_sentinels,
    )?;
    assert_seeded_audit_projection(&page)?;
    ensure!(route_audit_request_count(pool, &request_ids.happy, Some("success")).await? == 1);
    ensure!(harness.list_calls.load(Ordering::SeqCst) == 1);
    assert_audit_accounting(&cases.happy, &[&happy.localtx], 1)?;

    ensure!(
        cases.contention.error_code == "none" && !cases.contention.retryable,
        "audit contention fixture must describe its successful responses"
    );
    let contention_status = StatusCode::from_u16(cases.contention.http_status)?;
    let uri = audit_uri(&target.to_string(), "?limit=1");
    let pair = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            send_audit_recorded(
                &harness.contention_a,
                uri.clone(),
                &request_ids.contention_a,
            ),
            send_audit_recorded(&harness.contention_b, uri, &request_ids.contention_b,)
        )
    })
    .await
    .context("concurrent audit reads exceeded 15 seconds")?;
    let (a, b) = (pair.0?, pair.1?);
    let page_a: AuditListTenantEntriesResponse = decode_success(
        &a.response,
        contention_status,
        &request_ids.contention_a,
        &cases.contention.redact_sentinels,
    )?;
    let page_b: AuditListTenantEntriesResponse = decode_success(
        &b.response,
        contention_status,
        &request_ids.contention_b,
        &cases.contention.redact_sentinels,
    )?;
    assert_seeded_audit_projection(&page_a)?;
    assert_seeded_audit_projection(&page_b)?;
    cases.contention.mark_response_observed();
    ensure!(
        route_audit_request_count(pool, &request_ids.contention_a, Some("success")).await? == 1
    );
    ensure!(
        route_audit_request_count(pool, &request_ids.contention_b, Some("success")).await? == 1
    );
    ensure!(harness.list_calls.load(Ordering::SeqCst) == 3);
    assert_audit_accounting(&cases.contention, &[&a.localtx, &b.localtx], 2)
}

async fn drive_audit(
    deps: &PgRuntimeDeps,
    observation_pool: &sqlx::PgPool,
    target: TenantId,
    run_namespace: Uuid,
    cases: AuditCases,
) -> Result<()> {
    let request_ids = AuditRequestIds::new(run_namespace);
    seed_audit_projection_row(deps, target).await?;
    let harness = build_audit_harness(deps, observation_pool, target, &request_ids)?;
    drive_audit_rejections(&harness, observation_pool, target, &cases, &request_ids).await?;
    drive_audit_happy_and_contention(&harness, observation_pool, target, &cases, &request_ids).await
}

pub(crate) fn changed_fixture_behavior_is_observably_red() -> Result<()> {
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

struct LocalTxJourneyRuntime {
    _pg: testkit::OwnedPgFixture,
    deps: PgRuntimeDeps,
    observer: sqlx::PgPool,
    tenant_a: TenantId,
    tenant_b: TenantId,
}

impl LocalTxJourneyRuntime {
    async fn setup() -> Result<Self> {
        let pg = testkit::owned_postgres().await?;
        let owned = &pg;
        let params = owned.owner_params();
        let (app_login, tenant_read_login, audit_admin_login) =
            provision_test_logins(owned).await?;
        let owner = pg_config(params);
        let app = app_login.config();
        let tenant_read = PgTenantReadConfig::new(tenant_read_login.config());
        let audit_admin = audit_admin_login.config();
        let workflow = eventexec::WorkflowRuntimePlan::disabled_fixture();
        let deps = PgRuntimeDeps::setup_owned_test_fixture(
            &owner,
            &app,
            &tenant_read,
            Some(&audit_admin),
            workflow.projection_capture(),
        )
        .await?;
        let observer = observation_pool(params).await?;
        let tenant_a = TenantId::parse(TENANT_A)?;
        let tenant_b = TenantId::parse(TENANT_B)?;
        Ok(Self {
            _pg: pg,
            deps,
            observer,
            tenant_a,
            tenant_b,
        })
    }

    async fn finish(self, body: Result<()>) -> Result<()> {
        self.observer.close().await;
        let cleanup: Result<()> = async {
            let deps = self.deps;
            let (resources, _sampler_factory) = deps.into_runtime_parts(Duration::from_secs(1));
            for resource in resources.into_iter().rev() {
                resource.shutdown().await?;
            }
            Ok(())
        }
        .await;
        finish_with_pg_cleanup(body, cleanup)
    }
}

pub(crate) async fn drive_settings_journey(cases: SettingsCases) -> Result<()> {
    let runtime = LocalTxJourneyRuntime::setup().await?;
    let primary_authorizer = build_identity_authorizer(&runtime.deps, runtime.tenant_a).await?;
    let body = drive_settings(
        &runtime.deps,
        runtime.tenant_a,
        runtime.tenant_b,
        primary_authorizer,
        cases,
    )
    .await;
    runtime.finish(body).await
}

pub(crate) async fn drive_audit_journey(cases: AuditCases) -> Result<()> {
    let runtime = LocalTxJourneyRuntime::setup().await?;
    let body = drive_audit(
        &runtime.deps,
        &runtime.observer,
        runtime.tenant_a,
        Uuid::new_v4(),
        cases,
    )
    .await;
    runtime.finish(body).await
}
