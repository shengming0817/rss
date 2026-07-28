//! #1433 durable settings journey：Postgres config write -> co-tx outbox -> relay -> metrics/readyz.
//!
//! This is the standard template for durable domain-module acceptance:
//! - settings publish uses the production `PgConfigUnitOfWork` path;
//! - config row and outbox row are committed in the same transaction;
//! - a real `PgOutbox` relay settles the settings event as published;
//! - relay/sampler metrics and relay readyz are observable for the active settings event.
//!
//! This journey deliberately injects a test `Publisher` instead of
//! `wire_event_transport`'s AMQP publisher so the test can assert the settings relay
//! path without provisioning RabbitMQ; production wiring now includes settings because
//! `settings.config-version-changed` has active subscriber topology.
//!
//! `#![cfg(feature = "integration")]`: requires a real Postgres fixture. Without
//! Docker, `cargo test -p runtime --features integration --no-run` is the compile gate.

#![cfg(feature = "integration")]

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use consistency::{BacklogSample, Disposition};
use diport::{
    DynKeyProvider, DynPublisher, EncryptOutput, KeyName, KeyProvider, KeyProviderError, KeyRef,
    KeyVersion, ManagedResource as _, OpaqueActorId, OutboxActor, PublishRequest, Publisher,
    PublisherError, RedactedBytes,
};
use eventexec::{
    OutboxMetricScope, OutboxMetrics, RelayBudget, RelayConfig, RelayPhase, SamplerConfig,
    WorkerHealth, backlog_sampler_loop,
};
use generated::event::settings_v1::{
    self, SettingsConfigChangeKind, SettingsConfigVersionChangedPayload,
};
use generated::http::settings_v1::SettingsConfigPublishRequest;
use postgres::{
    ConfigValueProtections, DlxPayloadProtector, PgConfig, PgPassword, PgRuntimeDeps,
    PgTenantReadConfig,
};
use postgres::{PgSslMode, caps};
use primitives::healthz::{HealthCheck, ProbeName};
use secure::{DerivedAad, Plaintext};
use settings::{SettingsService, empty_flag_store};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;
use vocab::{PrincipalKind, ScopedTenant, TenantId};

type TestResult = Result<()>;

const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const NOW_SECS: u64 = 1_700_000_000;
const TEST_APP_ROLE: &str = "rss_app";
const TEST_APP_PASSWORD: &str = "rss_app_test_pw";
const TEST_READ_ROLE: &str = "rss_app_read";
const TEST_READ_PASSWORD: &str = "rss_app_read_test_pw";
const SETTINGS_RELAY_PROBE: &str = "outbox_relay_settings";

/// Deterministic test clock for settings event payload and outbox metadata.
struct FixedClock(SystemTime);

impl FixedClock {
    fn at_unix_secs(secs: u64) -> Self {
        Self(UNIX_EPOCH + Duration::from_secs(secs))
    }
}

impl diport::Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

#[derive(Clone)]
struct TestKeyProvider;

impl KeyProvider for TestKeyProvider {
    async fn encrypt(
        &self,
        key: KeyName,
        plaintext: Plaintext,
        _aad: DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        let ciphertext: Vec<u8> = plaintext.expose().iter().map(|byte| byte ^ 0xA5).collect();
        Ok(EncryptOutput::new(
            ciphertext,
            KeyRef::new(key, KeyVersion::new(1)),
        ))
    }

    async fn decrypt(
        &self,
        ciphertext: RedactedBytes,
        _key: KeyRef,
        _aad: DerivedAad,
    ) -> Result<Plaintext, KeyProviderError> {
        let plaintext: Vec<u8> = ciphertext
            .into_bytes()
            .into_iter()
            .map(|byte| byte ^ 0xA5)
            .collect();
        Ok(Plaintext::new(plaintext))
    }

    async fn rewrap(
        &self,
        _ciphertext: RedactedBytes,
        _key: KeyRef,
        _aad: DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        Err(KeyProviderError::new(
            diport::key_provider::KeyProviderErrorKind::Forbidden,
            std::io::Error::other("test key provider does not rewrap"),
        ))
    }

    async fn shutdown(&self) -> Result<(), KeyProviderError> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct CapturedPublish {
    topic: String,
    event_id: String,
    payload: Vec<u8>,
    tenant_id: Option<String>,
    tenant_authority: Option<String>,
}

#[derive(Clone, Default)]
struct CapturingPublisher {
    published: Arc<Mutex<Vec<CapturedPublish>>>,
}

impl CapturingPublisher {
    fn published(&self) -> Vec<CapturedPublish> {
        self.published
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[allow(unknown_lints, rss_diport_impl_allowlist)]
impl Publisher for CapturingPublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
        let captured = CapturedPublish {
            topic: request.topic().as_str().to_owned(),
            event_id: request.event_id().as_str().to_owned(),
            payload: request.payload().to_vec(),
            tenant_id: request
                .metadata()
                .get(diport::KEY_TENANT_ID)
                .map(str::to_owned),
            tenant_authority: request
                .metadata()
                .get(diport::KEY_TENANT_AUTHORITY)
                .map(str::to_owned),
        };
        self.published
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(captured);
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
struct PublishMetric {
    domain: String,
    contract_id: String,
    tenant_id: String,
    status: &'static str,
}

#[derive(Clone, Debug, PartialEq)]
struct BacklogMetric {
    domain: String,
    contract_id: String,
    tenant_id: String,
    depth: u64,
    oldest_age_seconds: u64,
}

#[derive(Clone, Default)]
struct TestTelemetry {
    publishes: Arc<Mutex<Vec<PublishMetric>>>,
    backlogs: Arc<Mutex<Vec<BacklogMetric>>>,
    tick_phases: Arc<Mutex<Vec<&'static str>>>,
}

impl TestTelemetry {
    fn has_ack_for_settings(&self) -> bool {
        self.publishes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|m| {
                m.domain == "settings"
                    && m.contract_id == settings_v1::CONTRACT_ID
                    && m.tenant_id == CANON_TENANT
                    && m.status == "ack"
            })
    }

    fn has_pending_settings_backlog(&self) -> bool {
        self.backlogs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|m| {
                m.domain == "settings"
                    && m.contract_id == settings_v1::CONTRACT_ID
                    && m.tenant_id == CANON_TENANT
                    && m.depth >= 1
            })
    }
}

impl OutboxMetrics for TestTelemetry {
    fn record_publish(&self, scope: &OutboxMetricScope<'_>, disposition: Disposition) {
        self.publishes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(PublishMetric {
                domain: scope.domain_label().to_owned(),
                contract_id: scope.contract_id_label().to_owned(),
                tenant_id: scope.tenant_id_label(),
                status: disposition.as_label(),
            });
    }

    fn record_backlog(&self, scope: &OutboxMetricScope<'_>, sample: BacklogSample) {
        self.backlogs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(BacklogMetric {
                domain: scope.domain_label().to_owned(),
                contract_id: scope.contract_id_label().to_owned(),
                tenant_id: scope.tenant_id_label(),
                depth: sample.depth(),
                oldest_age_seconds: sample.oldest_age_seconds(),
            });
    }

    fn record_partition_blocked(&self, _scope: &OutboxMetricScope<'_>, _blocked_depth: u64) {}

    fn record_tick_duration(&self, phase: RelayPhase, _seconds: f64) {
        self.tick_phases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(phase.as_label());
    }
}

impl diport::MetricsExporter for TestTelemetry {
    fn render(&self) -> String {
        let mut out = String::new();
        for metric in self
            .publishes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            out.push_str(&format!(
                "outbox_publish_total{{domain=\"{}\",contract_id=\"{}\",tenant_id=\"{}\",status=\"{}\"}} 1\n",
                metric.domain, metric.contract_id, metric.tenant_id, metric.status
            ));
        }
        for metric in self
            .backlogs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            out.push_str(&format!(
                "outbox_pending_depth{{domain=\"{}\",contract_id=\"{}\",tenant_id=\"{}\"}} {}\n",
                metric.domain, metric.contract_id, metric.tenant_id, metric.depth
            ));
            out.push_str(&format!(
                "outbox_oldest_pending_age_seconds{{domain=\"{}\",contract_id=\"{}\",tenant_id=\"{}\"}} {}\n",
                metric.domain, metric.contract_id, metric.tenant_id, metric.oldest_age_seconds
            ));
        }
        for phase in self
            .tick_phases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            out.push_str(&format!(
                "outbox_relay_tick_duration_seconds{{phase=\"{}\"}} 0\n",
                phase
            ));
        }
        out
    }
}

struct WorkerProbe {
    name: ProbeName,
    health: Arc<WorkerHealth>,
}

impl bootstrap::HealthProbe for WorkerProbe {
    fn check(&self) -> HealthCheck {
        HealthCheck::new(
            self.name.clone(),
            self.health.status(),
            self.health.detail(),
        )
    }
}

#[derive(Debug)]
struct OutboxRow {
    event_id: String,
    contract_id: String,
    status: String,
    payload: Vec<u8>,
    metadata: String,
}

async fn connect_pg() -> Result<(testkit::PgFixture, PgRuntimeDeps)> {
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
    let deps = PgRuntimeDeps::setup_test_fixture(
        &owner_config,
        &pg_config(p, TEST_APP_ROLE, TEST_APP_PASSWORD),
        &tenant_read_config,
        None,
        generated::event::PROJECTION_INPUT_GENERATION,
        generated::event::PROJECTION_INPUTS,
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

fn owner_connect_options(p: &testkit::PgConnParams) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(&p.host)
        .port(p.port)
        .database(&p.database)
        .username(&p.username)
        .password(&p.password)
        .ssl_mode(SqlxPgSslMode::Prefer)
}

fn config_value_protections() -> Result<ConfigValueProtections> {
    let key = KeyName::try_new("settings-config-durable")?;
    Ok(ConfigValueProtections::new(
        DynKeyProvider::new_box(TestKeyProvider),
        DynKeyProvider::new_box(TestKeyProvider),
        key,
    ))
}

fn dlx_payload_protector() -> Result<DlxPayloadProtector> {
    let key = eventexec::DlxHotKeyName::try_new("settings-durable-dlx")?;
    Ok(DlxPayloadProtector::new(
        DynKeyProvider::new_box(TestKeyProvider),
        key,
    ))
}

fn unique_setting_key() -> Result<String> {
    #[allow(clippy::disallowed_methods)]
    // reason: integration test isolation only; business time still uses FixedClock injection.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_nanos();
    Ok(format!("app.durable{}", nanos))
}

fn test_actor(tenant: TenantId) -> Result<OutboxActor> {
    Ok(OutboxActor::scoped(
        PrincipalKind::Admin,
        OpaqueActorId::from_opaque("settings-durable-e2e")?,
        tenant,
        ScopedTenant::Tenant,
    ))
}

async fn find_settings_outbox_row(pool: &sqlx::PgPool, key: &str) -> Result<Option<OutboxRow>> {
    let rows: Vec<(String, String, String, Vec<u8>, String)> = sqlx::query_as(
        r#"
        SELECT event_id, contract_id, status, payload, metadata::text
        FROM outbox
        WHERE domain = 'settings' AND topic = $1
        ORDER BY created_at DESC
        LIMIT 50
        "#,
    )
    .bind(settings_v1::TOPIC)
    .fetch_all(pool)
    .await?;
    for (event_id, contract_id, status, payload, metadata) in rows {
        let Ok(decoded) = serde_json::from_slice::<SettingsConfigVersionChangedPayload>(&payload)
        else {
            continue;
        };
        if decoded.key == key {
            return Ok(Some(OutboxRow {
                event_id,
                contract_id,
                status,
                payload,
                metadata,
            }));
        }
    }
    Ok(None)
}

async fn wait_until<F>(timeout: Duration, mut condition: F) -> Result<()>
where
    F: FnMut() -> bool,
{
    tokio::time::timeout(timeout, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("condition timed out")
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_config_publish_durable_e2e() -> TestResult {
    let (pg_fixture, pg_owner) = connect_pg().await?;
    let pg = pg_owner.handle();
    let assertion_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(owner_connect_options(pg_fixture.params()))
        .await?;
    let tenant = TenantId::parse(CANON_TENANT)?;
    let key = unique_setting_key()?;
    let value = "30s";

    let settings_deps = pg.for_domain::<caps::Settings>();
    let (configs, writer, _secrets, _secret_writer) = settings_deps
        .settings_bundle(
            Arc::new(FixedClock::at_unix_secs(NOW_SECS)),
            config_value_protections()?,
        )
        .into_parts();
    let service = SettingsService::with_postgres(
        configs,
        writer,
        empty_flag_store(),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
    );

    let response = service
        .publish_config(
            settings::config_publish_receipt_for_test(),
            tenant,
            test_actor(tenant)?,
            SettingsConfigPublishRequest {
                key: key.clone(),
                value: value.to_string(),
            },
        )
        .await?;
    assert_eq!(response.data.key, key);
    assert_eq!(response.data.version, 1, "first publish must create v1");

    let cfg_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2 AND version = 1",
    )
    .bind(CANON_TENANT)
    .bind(&key)
    .fetch_one(&assertion_pool)
    .await?;
    assert_eq!(cfg_count.0, 1, "config v1 row must be committed");

    let row = find_settings_outbox_row(&assertion_pool, &key)
        .await?
        .context("settings publish must append a matching outbox row")?;
    assert_eq!(row.contract_id, settings_v1::CONTRACT_ID);
    assert_eq!(row.status, "pending", "outbox starts pending before relay");
    let payload: SettingsConfigVersionChangedPayload = serde_json::from_slice(&row.payload)?;
    assert_eq!(payload.key, key);
    assert_eq!(payload.version, 1);
    assert_eq!(payload.change_kind, SettingsConfigChangeKind::Published);
    assert_eq!(payload.source_version, None);
    assert_eq!(payload.tenant_id, CANON_TENANT);
    assert_eq!(payload.occurred_at, i64::try_from(NOW_SECS)?);
    assert!(row.metadata.contains(diport::KEY_TENANT_ID), "{row:?}");
    assert!(row.metadata.contains(CANON_TENANT), "{row:?}");
    assert!(
        row.metadata.contains(diport::KEY_OCCURRED_AT),
        "metadata must carry occurredAt: {row:?}"
    );
    assert!(
        !row.metadata.contains(value),
        "outbox metadata must not leak config value: {row:?}"
    );
    assert!(
        !String::from_utf8_lossy(&row.payload).contains(value),
        "settings config-version-changed payload must not include config value"
    );

    let telemetry = Arc::new(TestTelemetry::default());
    let sampler_config = SamplerConfig::new(vec!["settings".to_string()], Duration::from_secs(1))?;
    let sampler_health = Arc::new(WorkerHealth::healthy());
    let sampler_token = CancellationToken::new();
    let sampler_task = tokio::spawn(backlog_sampler_loop(
        Arc::new(pg.infra().outbox_maintenance()),
        sampler_config,
        sampler_token.clone(),
        Arc::clone(&sampler_health),
        Arc::clone(&telemetry) as Arc<dyn OutboxMetrics>,
    ));
    wait_until(Duration::from_secs(5), || {
        telemetry.has_pending_settings_backlog()
    })
    .await?;

    let publisher = CapturingPublisher::default();
    let outbox = settings_deps.outbox(
        DynPublisher::new_box(publisher.clone()),
        RelayBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(40),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )?,
        journeys_common_tenant_authority()?,
        dlx_payload_protector()?,
    );
    let relay_health = Arc::new(WorkerHealth::healthy());
    let relay = eventexec::spawn_relay(
        "settings-durable-e2e-relay".to_string(),
        outbox,
        RelayConfig::new(Duration::from_millis(100), 16)?,
        Arc::new(FixedClock::at_unix_secs(NOW_SECS)),
        CancellationToken::new(),
        Arc::clone(&relay_health),
        Arc::clone(&telemetry) as Arc<dyn OutboxMetrics>,
    );

    wait_until(Duration::from_secs(10), || {
        publisher
            .published()
            .iter()
            .any(|p| p.event_id == row.event_id)
    })
    .await?;
    wait_until(Duration::from_secs(10), || telemetry.has_ack_for_settings()).await?;

    let published = publisher
        .published()
        .into_iter()
        .find(|p| p.event_id == row.event_id)
        .context("captured settings publish")?;
    assert_eq!(published.topic, settings_v1::TOPIC);
    assert_eq!(published.payload, row.payload);
    assert_eq!(published.tenant_id.as_deref(), Some(CANON_TENANT));
    assert!(
        published.tenant_authority.is_some(),
        "relay must stamp tenantAuthority metadata before publishing"
    );

    let status: (String,) = sqlx::query_as("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&row.event_id)
        .fetch_one(&assertion_pool)
        .await?;
    assert_eq!(
        status.0, "published",
        "relay must settle settings outbox row"
    );

    let mut reg = bootstrap::compose(&[])?;
    reg.probe(
        ProbeName::parse(SETTINGS_RELAY_PROBE)?,
        Box::new(WorkerProbe {
            name: ProbeName::parse(SETTINGS_RELAY_PROBE)?,
            health: Arc::clone(&relay_health),
        }),
    )?;
    let reporter = Arc::new(reg.take_health_reporter());
    let metrics_exporter: Arc<dyn diport::MetricsExporter> = telemetry.clone();
    let authed = runtime::test_support::finalize_health_listener(reporter, metrics_exporter)?;
    let router = authed.into_router_for_test();
    let readyz = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health/v1/readyz")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(readyz.status(), StatusCode::OK);
    let readyz_body = String::from_utf8(
        axum::body::to_bytes(readyz.into_body(), usize::MAX)
            .await?
            .to_vec(),
    )?;
    assert!(
        readyz_body.contains(r#""name":"outbox_relay_settings""#),
        "readyz must include settings relay probe: {readyz_body}"
    );
    assert!(
        readyz_body.contains(r#""status":"healthy""#),
        "readyz must show settings relay healthy, not only HTTP 200: {readyz_body}"
    );

    let metrics = router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health/v1/metrics")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(metrics.status(), StatusCode::OK);
    let metrics_body = String::from_utf8(
        axum::body::to_bytes(metrics.into_body(), usize::MAX)
            .await?
            .to_vec(),
    )?;
    assert!(
        metrics_body.contains(&format!(
            r#"outbox_publish_total{{domain="settings",contract_id="{}",tenant_id="{}",status="ack"}}"#,
            settings_v1::CONTRACT_ID,
            CANON_TENANT
        )),
        "metrics must expose settings ack counter: {metrics_body}"
    );
    assert!(
        metrics_body.contains(&format!(
            r#"outbox_pending_depth{{domain="settings",contract_id="{}",tenant_id="{}"}}"#,
            settings_v1::CONTRACT_ID,
            CANON_TENANT
        )),
        "metrics must expose settings backlog gauge: {metrics_body}"
    );

    relay.shutdown().await?;
    sampler_token.cancel();
    sampler_task.await?;
    assertion_pool.close().await;
    drop(pg);
    drop(pg_fixture);
    Ok(())
}

fn journeys_common_tenant_authority() -> Result<Arc<eventexec::TenantAuthority>> {
    use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};

    #[derive(Clone, Default)]
    struct CapturingVerifier;

    impl MacVerifier for CapturingVerifier {
        fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
            let mut out = [0u8; 32];
            for (idx, byte) in key.as_bytes().iter().chain(message).enumerate() {
                out[idx % 32] ^= *byte;
            }
            Mac::from_bytes(out.to_vec())
        }

        fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
            primitives::constant_time_eq(
                self.sign(key, algorithm, message).as_bytes(),
                tag.as_bytes(),
            )
        }
    }

    Ok(Arc::new(eventexec::TenantAuthority::new(
        Arc::new(CapturingVerifier),
        MacKey::from_bytes(vec![0x42; 32]),
        3600,
        60,
        Arc::new(|| NOW_SECS as i64),
    )?))
}
