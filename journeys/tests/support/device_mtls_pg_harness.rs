use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use diport::SecretMaterial;
use eventexec::{RelayBudget, WorkflowRuntimePlan};
use iotdevice::{DraftSimulatorConfig, DraftTlsMaterial, DraftTopics};
use mqtt::{
    BrokerAssertionVerifier, CredentialGeneration, CredentialRevision, DeviceScope, MqttSession,
    MqttSessionConfig, MqttTlsMaterial, MqttTopicPolicy, MqttsEndpoint, SessionExpiry,
};
use postgres::{PgConfig, PgPassword, PgSslMode, PgTenantReadConfig, PoolReadiness};
use testkit::{MqttCredential, MqttMtlsFixture, PgConnParams};
use tokio_util::sync::CancellationToken;

pub(super) struct DeviceJourneyCoordinate {
    tenant: vocab::TenantId,
    device: ids::DeviceId,
}

impl DeviceJourneyCoordinate {
    pub(super) fn parse(tenant: &str, device: &str) -> anyhow::Result<Self> {
        Ok(Self {
            tenant: vocab::TenantId::parse(tenant)?,
            device: ids::DeviceId::parse(device)?,
        })
    }

    pub(super) fn mqtt_scope(&self, credential: &MqttCredential) -> anyhow::Result<DeviceScope> {
        Ok(DeviceScope::new(
            self.tenant,
            self.device,
            CredentialGeneration::new(credential.revision())?,
        ))
    }

    pub(super) fn certificate_scope(
        &self,
    ) -> identity::ports::device_certificate::DeviceCertificateScope {
        identity::ports::device_certificate::DeviceCertificateScope::for_test(
            self.tenant,
            self.device,
        )
    }
}

#[derive(Clone, Copy)]
pub(super) struct PgAdminPoolBudget {
    max_connections: u32,
    acquire_timeout: Duration,
}

impl PgAdminPoolBudget {
    pub(super) const fn new(max_connections: u32, acquire_timeout: Duration) -> Self {
        Self {
            max_connections,
            acquire_timeout,
        }
    }
}

pub(super) fn pg_config(params: &PgConnParams, role: &str, password: &str) -> PgConfig {
    PgConfig::new(
        params.host.clone(),
        params.port,
        params.database.clone(),
        role,
        PgPassword::new(password),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(Duration::from_secs(5))
}

pub(super) async fn admin_pool(
    params: &PgConnParams,
    budget: PgAdminPoolBudget,
) -> anyhow::Result<sqlx::PgPool> {
    anyhow::ensure!(
        budget.max_connections > 0,
        "admin pool must be bounded above zero"
    );
    let options = sqlx::postgres::PgConnectOptions::new()
        .host(&params.host)
        .port(params.port)
        .database(&params.database)
        .username(&params.username)
        .password(&params.password)
        .ssl_mode(sqlx::postgres::PgSslMode::Prefer);
    Ok(sqlx::postgres::PgPoolOptions::new()
        .max_connections(budget.max_connections)
        .acquire_timeout(budget.acquire_timeout)
        .connect_with(options)
        .await?)
}

pub(super) fn migrator_through(
    embedded: &sqlx::migrate::Migrator,
    version: i64,
) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: Cow::Owned(
            embedded
                .iter()
                .filter(|migration| migration.version <= version)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: embedded.no_tx,
    }
}

fn mqtt_material(credential: &MqttCredential) -> anyhow::Result<MqttTlsMaterial> {
    let tls = credential.tls();
    Ok(MqttTlsMaterial::new(
        SecretMaterial::new(tls.ca_pem().as_bytes().to_vec()),
        SecretMaterial::new(
            tls.certificate_pem()
                .context("fixture credential certificate")?
                .as_bytes()
                .to_vec(),
        ),
        SecretMaterial::new(
            tls.private_key_pem()
                .context("fixture credential private key")?
                .as_bytes()
                .to_vec(),
        ),
    ))
}

fn mqtt_topic_policy(
    coordinate: &DeviceJourneyCoordinate,
    device: &MqttCredential,
) -> anyhow::Result<MqttTopicPolicy> {
    Ok(MqttTopicPolicy::new(vec![coordinate.mqtt_scope(device)?])?)
}

/// Transport identity and topic-generation authority are fixed to different fixture owners.
pub(super) fn mqtt_session_config(
    coordinate: &DeviceJourneyCoordinate,
    fixture: &MqttMtlsFixture,
) -> anyhow::Result<MqttSessionConfig> {
    let transport = fixture.rss_a();
    let device = fixture.device_current();
    let policy = mqtt_topic_policy(coordinate, device)?;
    let topic_generation = policy
        .scopes()
        .first()
        .context("mqtt topic policy requires the device scope")?
        .generation()
        .get();
    anyhow::ensure!(
        topic_generation == device.revision(),
        "topic policy generation must follow device_current"
    );
    anyhow::ensure!(
        topic_generation != transport.revision(),
        "RSS transport revision must not become topic generation authority"
    );
    Ok(MqttSessionConfig::new(
        MqttsEndpoint::parse(fixture.url())?,
        transport.stable_client_id(),
        mqtt_material(transport)?,
        BrokerAssertionVerifier::new(*fixture.broker_assertion_public_key())?,
        policy,
        SessionExpiry::new(Duration::from_secs(3_600))?,
        CredentialRevision::new(transport.revision())?,
    )?)
}

pub(super) async fn mqtt_session(
    coordinate: &DeviceJourneyCoordinate,
    fixture: &MqttMtlsFixture,
) -> anyhow::Result<Arc<MqttSession>> {
    Ok(Arc::new(
        MqttSession::connect(mqtt_session_config(coordinate, fixture)?).await?,
    ))
}

pub(super) fn draft_device_config(
    coordinate: &DeviceJourneyCoordinate,
    fixture: &MqttMtlsFixture,
    wait: Duration,
) -> anyhow::Result<DraftSimulatorConfig> {
    let credential = fixture.device_current();
    let tls = credential.tls();
    let scope = coordinate.mqtt_scope(credential)?;
    let policy = mqtt_topic_policy(coordinate, credential)?;
    let topics = DraftTopics::new(
        policy
            .command_topic(&scope)
            .context("configured command topic")?
            .as_str()
            .to_owned(),
        policy
            .command_acked_topic(&scope)
            .context("configured ACK topic")?
            .as_str()
            .to_owned(),
        policy
            .certificate_reported_topic(&scope)
            .context("configured report topic")?
            .as_str()
            .to_owned(),
        policy
            .application_receipt_topic(&scope)
            .context("configured receipt topic")?
            .as_str()
            .to_owned(),
    )?;
    Ok(DraftSimulatorConfig::new(
        url::Url::parse(fixture.url())?,
        credential.stable_client_id().to_owned(),
        credential.revision(),
        DraftTlsMaterial::new(
            tls.ca_pem().to_owned(),
            tls.certificate_pem()
                .context("fixture device certificate")?
                .to_owned(),
            tls.private_key_pem()
                .context("fixture device private key")?
                .to_owned(),
        )?,
        topics,
        wait,
    )?)
}

pub(super) fn relay_budget() -> anyhow::Result<RelayBudget> {
    Ok(RelayBudget::new(
        Duration::from_secs(60),
        Duration::from_secs(40),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )?)
}

pub(super) struct ConnectedPgRuntime {
    handle: postgres::PgRuntimeHandle,
    resources: Vec<Box<diport::DynManagedResource<'static>>>,
    sampler: postgres::PgReadinessSampler,
}

impl ConnectedPgRuntime {
    pub(super) async fn connect(
        app: &PgConnParams,
        reader_role: &PgConnParams,
    ) -> anyhow::Result<Self> {
        let serving = pg_config(app, &app.username, &app.password);
        let reader = PgTenantReadConfig::new(pg_config(
            reader_role,
            &reader_role.username,
            &reader_role.password,
        ));
        let workflow = WorkflowRuntimePlan::disabled_fixture();
        let owner = postgres::PgRuntimeDeps::connect_serving(
            &serving,
            &reader,
            None,
            workflow.projection_capture(),
        )
        .await?;
        let handle = owner.handle();
        handle.validate_relay_budget(relay_budget()?)?;
        let (resources, sampler_factory) = owner.into_runtime_parts(Duration::from_millis(100));
        let sampler = sampler_factory.spawn(CancellationToken::new());
        let readiness = handle.readiness_handle();
        testkit::await_map(Duration::from_secs(10), async || {
            (readiness.snapshot() == PoolReadiness::Ready).then_some(())
        })
        .await
        .context("postgres pool readiness")?;
        Ok(Self {
            handle,
            resources,
            sampler,
        })
    }

    pub(super) fn handle(&self) -> &postgres::PgRuntimeHandle {
        &self.handle
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        postgres::PgRuntimeHandle,
        Vec<Box<diport::DynManagedResource<'static>>>,
        postgres::PgReadinessSampler,
    ) {
        (self.handle, self.resources, self.sampler)
    }
}
