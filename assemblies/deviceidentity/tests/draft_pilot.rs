#![cfg(feature = "integration")]
#![allow(clippy::disallowed_methods, clippy::expect_used, clippy::unwrap_used)] // reason: hermetic T2 fixture values fail loudly and the injected clock is process-real.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use diport::{Clock, ManagedResource as _, SecretMaterial};
use eventexec::command::{CommandAliasKey, CommandIdempotencyKeyring};
use eventexec::reconcile::{
    BackoffPolicy, DeviceCertificateSystemProducer, ReconcileMaxInFlight, Tenancy, Trigger,
};
use eventexec::{RelayBudget, RelayConfig, WorkflowRuntimePlan};
use identity::ports::device_certificate::{
    AcceptDesiredPolicy, DesiredPolicyAcceptOutcome, DeviceCertificateRepository as _,
    DeviceCertificateScope, DevicePolicyIdempotencyKey, DraftEligibility, ExpectedGeneration,
};
use mqtt::{
    BrokerAssertionVerifier, CredentialGeneration, CredentialRevision, DeviceScope, MqttSession,
    MqttSessionConfig, MqttTlsMaterial, MqttTopicPolicy, MqttsEndpoint, SessionExpiry,
};
use postgres::{PgConfig, PgPassword, PgSslMode, PgTenantReadConfig, PoolReadiness};
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::{Filter, Packet, PublishProperties, SubscribeReasonCode};
use rumqttc::v5::{AsyncClient, Event, EventLoop, MqttOptions};
use rumqttc::{TlsConfiguration, Transport};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use testkit::{MqttCredential, MqttMtlsFixture, PgConnParams, PostgresTestLogin};
use tokio_util::sync::CancellationToken;

const TENANT: &str = "11111111-1111-4111-8111-111111111111";
const DEVICE: &str = "22222222-2222-4222-8222-222222222222";
const CREDENTIAL_GENERATION: u64 = 2;
const RSS_APP_PASSWORD: &str = "deviceidentity-rss-app-test";
const RSS_READ_PASSWORD: &str = "deviceidentity-rss-read-test";
const ACK_EVENT_ID: &str = "draft-pilot-command-ack-1";

struct ProcessClock;

impl Clock for ProcessClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

struct RunningPilot {
    assembly: deviceidentity::DeviceIdentityAssembly,
    repository: postgres::PgDeviceCertificateRepository<DraftEligibility>,
    sampler: postgres::PgReadinessSampler,
    resources: Vec<Box<diport::DynManagedResource<'static>>>,
}

impl RunningPilot {
    async fn shutdown(self) -> anyhow::Result<()> {
        let assembly_result = self.assembly.shutdown().await;
        let sampler_result = self.sampler.shutdown().await;
        let mut resource_result = Ok(());
        for resource in self.resources.into_iter().rev() {
            if let Err(error) = resource.shutdown().await {
                resource_result = Err(error);
            }
        }
        assembly_result.context("deviceidentity pilot shutdown")?;
        sampler_result.context("postgres readiness sampler shutdown")?;
        resource_result.context("postgres runtime resource shutdown")?;
        Ok(())
    }
}

struct Downlink {
    correlation: Vec<u8>,
    payload: Vec<u8>,
}

struct CommandCoordinates {
    command_id: String,
    generation: u64,
    fence_epoch: u64,
    artifact_digest: String,
}

fn pg_config(params: &PgConnParams, role: &str, password: &str) -> PgConfig {
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

async fn admin_pool(params: &PgConnParams) -> anyhow::Result<sqlx::PgPool> {
    let options = sqlx::postgres::PgConnectOptions::new()
        .host(&params.host)
        .port(params.port)
        .database(&params.database)
        .username(&params.username)
        .password(&params.password)
        .ssl_mode(sqlx::postgres::PgSslMode::Prefer);
    Ok(sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?)
}

async fn migrate_0094_to_0095(params: &PgConnParams) -> anyhow::Result<sqlx::PgPool> {
    testkit::provision_postgres_test_logins(
        params,
        &[
            PostgresTestLogin::new("rss_app", RSS_APP_PASSWORD),
            PostgresTestLogin::new("rss_app_read", RSS_READ_PASSWORD),
        ],
    )
    .await?;
    let pool = admin_pool(params).await?;
    let embedded = sqlx::migrate!("../../adapters/postgres/migrations");
    let migrations = embedded
        .iter()
        .filter(|migration| migration.version <= 94)
        .cloned()
        .collect();
    let through_0094 = sqlx::migrate::Migrator {
        migrations: Cow::Owned(migrations),
        ignore_missing: false,
        locking: true,
        no_tx: embedded.no_tx,
    };
    through_0094.run(&pool).await?;

    let before: (i64, bool) = sqlx::query_as(
        "SELECT max(version), EXISTS ( \
           SELECT 1 FROM information_schema.columns \
           WHERE table_schema='public' \
             AND table_name='device_certificate_authorized_artifacts' \
             AND column_name='artifact_eligibility') \
         FROM public._sqlx_migrations",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(before, (94, false), "journey must begin on exact 0094");

    let migrations = embedded
        .iter()
        .filter(|migration| migration.version <= 95)
        .cloned()
        .collect();
    let through_0095 = sqlx::migrate::Migrator {
        migrations: Cow::Owned(migrations),
        ignore_missing: false,
        locking: true,
        no_tx: embedded.no_tx,
    };
    through_0095.run(&pool).await?;
    let after: (i64, bool, bool) = sqlx::query_as(
        "SELECT max(version), \
           EXISTS (SELECT 1 FROM information_schema.columns \
             WHERE table_schema='public' \
               AND table_name='device_certificate_authorized_artifacts' \
               AND column_name='artifact_eligibility'), \
           to_regprocedure('public.rss_claim_device_mqtt_outbox(smallint,bigint,bigint,bigint)') \
             IS NOT NULL \
         FROM public._sqlx_migrations",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        after,
        (95, true, true),
        "0095 eligibility and durable MQTT claim funnels must be installed"
    );
    embedded.run(&pool).await?;
    let enrollment: (i64, bool) = sqlx::query_as(
        "SELECT max(version), \
           to_regprocedure('public.rss_enroll_device_certificate_reconcile_target(uuid,uuid,bigint)') \
             IS NOT NULL \
         FROM public._sqlx_migrations",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        enrollment,
        (96, true),
        "narrow device-certificate enrollment must extend the verified 0095 boundary"
    );
    Ok(pool)
}

fn mqtt_scope() -> anyhow::Result<DeviceScope> {
    Ok(DeviceScope::new(
        vocab::TenantId::parse(TENANT)?,
        ids::DeviceId::parse(DEVICE)?,
        CredentialGeneration::new(CREDENTIAL_GENERATION)?,
    ))
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

fn mqtt_session_config(
    fixture: &MqttMtlsFixture,
    credential: &MqttCredential,
) -> anyhow::Result<MqttSessionConfig> {
    Ok(MqttSessionConfig::new(
        MqttsEndpoint::parse(fixture.url())?,
        credential.stable_client_id(),
        mqtt_material(credential)?,
        BrokerAssertionVerifier::new(*fixture.broker_assertion_public_key())?,
        MqttTopicPolicy::new(vec![mqtt_scope()?])?,
        SessionExpiry::new(Duration::from_secs(3_600))?,
        CredentialRevision::new(credential.revision())?,
    )?)
}

fn rustls_client(credential: &MqttCredential) -> anyhow::Result<Arc<ClientConfig>> {
    let tls = credential.tls();
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(tls.ca_pem().as_bytes()) {
        roots.add(certificate?)?;
    }
    let certificates = CertificateDer::pem_slice_iter(
        tls.certificate_pem()
            .context("device certificate")?
            .as_bytes(),
    )
    .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(
        tls.private_key_pem()
            .context("device private key")?
            .as_bytes(),
    )?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_client_auth_cert(certificates, key)?,
    ))
}

async fn connect_device(fixture: &MqttMtlsFixture) -> anyhow::Result<(AsyncClient, EventLoop)> {
    let credential = fixture.device_current();
    let endpoint = url::Url::parse(fixture.url())?;
    let mut options = MqttOptions::new(
        credential.stable_client_id(),
        endpoint.host_str().context("MQTT fixture host")?,
        endpoint.port().context("MQTT fixture port")?,
    );
    options
        .set_transport(Transport::tls_with_config(TlsConfiguration::Rustls(
            rustls_client(credential)?,
        )))
        .set_keep_alive(Duration::from_secs(30))
        .set_clean_start(true)
        .set_manual_acks(true);
    let (client, mut events) = AsyncClient::new(options, 16);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(events.poll().await?, Event::Incoming(Packet::ConnAck(_))) {
                return Ok::<(), rumqttc::v5::ConnectionError>(());
            }
        }
    })
    .await
    .context("device MQTT ConnAck timeout")??;

    let topics = MqttTopicPolicy::new(vec![mqtt_scope()?])?;
    let command_topic = topics
        .command_topic(&mqtt_scope()?)
        .context("configured command topic")?;
    let receipt_topic = topics
        .application_receipt_topic(&mqtt_scope()?)
        .context("configured receipt topic")?;
    client
        .subscribe_many([
            Filter::new(command_topic.as_str(), QoS::AtLeastOnce),
            Filter::new(receipt_topic.as_str(), QoS::AtLeastOnce),
        ])
        .await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Event::Incoming(Packet::SubAck(ack)) = events.poll().await? {
                anyhow::ensure!(
                    ack.return_codes
                        == [
                            SubscribeReasonCode::Success(QoS::AtLeastOnce),
                            SubscribeReasonCode::Success(QoS::AtLeastOnce),
                        ],
                    "device downlink subscriptions were rejected: {:?}",
                    ack.return_codes
                );
                return Ok::<(), anyhow::Error>(());
            }
        }
    })
    .await
    .context("device MQTT SubAck timeout")??;
    Ok((client, events))
}

fn relay_budget() -> anyhow::Result<RelayBudget> {
    Ok(RelayBudget::new(
        Duration::from_secs(60),
        Duration::from_secs(40),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )?)
}

fn command_keyring() -> anyhow::Result<Arc<CommandIdempotencyKeyring>> {
    Ok(Arc::new(CommandIdempotencyKeyring::new(
        CommandAliasKey::new("draft-pilot-v1", vec![0x42; 32])?,
        Vec::new(),
    )?))
}

async fn seed_desired_generation_two(
    repository: &postgres::PgDeviceCertificateRepository<DraftEligibility>,
) -> anyhow::Result<()> {
    let scope = DeviceCertificateScope::for_test(
        vocab::TenantId::parse(TENANT)?,
        ids::DeviceId::parse(DEVICE)?,
    );
    repository
        .enroll_reconcile_target(scope, SystemTime::now())
        .await?;
    for (expected, san) in [
        (0, "draft-pilot-one.example"),
        (1, "draft-pilot-two.example"),
    ] {
        let policy = deviceloop::CertificatePolicy::restore(
            7_200,
            900,
            vec!["clientAuth".to_owned()],
            vec![san.to_owned()],
        )?;
        let outcome = repository
            .accept_desired_policy(AcceptDesiredPolicy::for_test(
                scope,
                ExpectedGeneration::try_new(expected)?,
                DevicePolicyIdempotencyKey::new(uuid::Uuid::new_v4()),
                policy,
            )?)
            .await?;
        let accepted_generation = match outcome {
            DesiredPolicyAcceptOutcome::Accepted { result, .. } => {
                result.accepted_generation().get()
            }
            unexpected => anyhow::bail!("unexpected desired-policy outcome: {unexpected:?}"),
        };
        assert_eq!(accepted_generation, expected + 1);
    }
    Ok(())
}

async fn start_pilot(
    params: &PgConnParams,
    mqtt_fixture: &MqttMtlsFixture,
    receipt_poll_interval: Duration,
    holder: &str,
) -> anyhow::Result<RunningPilot> {
    let serving = pg_config(params, "rss_app", RSS_APP_PASSWORD);
    let reader = PgTenantReadConfig::new(pg_config(params, "rss_app_read", RSS_READ_PASSWORD));
    let workflow = WorkflowRuntimePlan::disabled_fixture();
    let owner = postgres::PgRuntimeDeps::connect_serving(
        &serving,
        &reader,
        None,
        workflow.projection_capture(),
    )
    .await?;
    let handle = owner.handle();
    let budget = relay_budget()?;
    handle.validate_relay_budget(budget)?;
    let (resources, sampler_factory) = owner.into_runtime_parts(Duration::from_millis(100));
    let sampler = sampler_factory.spawn(CancellationToken::new());
    let readiness = handle.readiness_handle();
    testkit::await_map(Duration::from_secs(10), async || {
        (readiness.snapshot() == PoolReadiness::Ready).then_some(())
    })
    .await?;

    let identity = handle.for_domain::<postgres::caps::Identity>();
    let repository = identity.device_certificate_repository::<DraftEligibility>();
    seed_desired_generation_two(&repository).await?;
    let assembly_postgres = handle.device_identity_draft_runtime();
    let session = Arc::new(
        MqttSession::connect(mqtt_session_config(mqtt_fixture, mqtt_fixture.rss_a())?).await?,
    );
    let now_seconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let not_after = diport::CertNotAfter::try_from_system_time(
        SystemTime::UNIX_EPOCH + Duration::from_secs(now_seconds + 86_400),
    )?;
    let config = identity_composition::DeviceIdentityPilotConfig::new(
        identity_composition::DeviceIdentitySchedulerConfig::new(
            Arc::new(ProcessClock),
            command_keyring()?,
            DeviceCertificateSystemProducer::install(),
            vocab::TenantId::parse(TENANT)?,
            holder,
            Tenancy::tenant_scoped(),
            identity_composition::DeviceIdentitySchedulerTiming::new(
                Trigger::interval(Duration::from_millis(100))?,
                BackoffPolicy::new(Duration::from_millis(100), Duration::from_secs(1))?,
                Duration::from_secs(30),
                ReconcileMaxInFlight::try_new(1)?,
            ),
        ),
        identity_composition::DeviceIdentityRelayConfig::new(
            identity_composition::DeviceCertificateCommandTtl::try_new(Duration::from_secs(300))?,
            RelayConfig::new(Duration::from_millis(100), 4)?,
            RelayConfig::new(receipt_poll_interval, 4)?,
            budget,
        ),
        Duration::from_secs(10),
    );
    let assembly = deviceidentity::DeviceIdentityAssembly::start(
        assembly_postgres,
        identity_composition::DraftArtifactSimulator::new([0x19; 32], not_after),
        session,
        config,
    )
    .await?;
    Ok(RunningPilot {
        assembly,
        repository,
        sampler,
        resources,
    })
}

async fn wait_receipt_relay_ready(pilot: &RunningPilot) -> anyhow::Result<()> {
    testkit::await_map(Duration::from_secs(10), async || {
        (pilot.assembly.readiness().receipt_relay()
            == identity_composition::PilotComponentReadiness::Ready)
            .then_some(())
    })
    .await?;
    Ok(())
}

async fn publish_ack(
    client: &AsyncClient,
    coordinates: &CommandCoordinates,
    event_id: &str,
    device_sequence: u64,
) -> anyhow::Result<()> {
    let topic = MqttTopicPolicy::new(vec![mqtt_scope()?])?
        .command_acked_topic(&mqtt_scope()?)
        .context("configured ACK topic")?;
    let payload = serde_json::to_vec(&serde_json::json!({
        "commandId": coordinates.command_id,
        "desiredGeneration": coordinates.generation,
        "deviceId": DEVICE,
        "deviceSequence": device_sequence,
        "fenceEpoch": coordinates.fence_epoch,
        "observedAt": 1_700_000_000_000_000_i64 + i64::try_from(device_sequence)?,
        "reason": "None",
        "result": "received"
    }))?;
    client
        .publish_with_properties(
            topic.as_str(),
            QoS::AtLeastOnce,
            false,
            payload,
            PublishProperties {
                correlation_data: Some(event_id.as_bytes().to_vec().into()),
                ..PublishProperties::default()
            },
        )
        .await?;
    Ok(())
}

async fn assert_no_receipt(events: &mut EventLoop, duration: Duration) -> anyhow::Result<()> {
    let receipt_topic = MqttTopicPolicy::new(vec![mqtt_scope()?])?
        .application_receipt_topic(&mqtt_scope()?)
        .context("configured receipt topic")?;
    let observed = tokio::time::timeout(duration, async {
        loop {
            if let Event::Incoming(Packet::Publish(publish)) = events.poll().await? {
                let topic = std::str::from_utf8(publish.topic.as_ref())?;
                if topic == receipt_topic.as_str() {
                    return Ok::<(), anyhow::Error>(());
                }
            }
        }
    })
    .await;
    match observed {
        Err(_) => Ok(()),
        Ok(Ok(())) => anyhow::bail!("receipt was published before durable ingress commit"),
        Ok(Err(error)) => Err(error),
    }
}

async fn wait_downlink(
    client: &AsyncClient,
    events: &mut EventLoop,
    expected_topic: &str,
    expected_ingress: Option<&str>,
) -> anyhow::Result<Downlink> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Event::Incoming(Packet::Publish(publish)) = events.poll().await? {
                let topic = std::str::from_utf8(publish.topic.as_ref())?;
                let payload = publish.payload.to_vec();
                let matches_ingress = expected_ingress.is_none_or(|expected| {
                    serde_json::from_slice::<serde_json::Value>(&payload)
                        .ok()
                        .and_then(|value| value["ingressEnvelopeId"].as_str().map(str::to_owned))
                        .is_some_and(|actual| actual == expected)
                });
                if topic != expected_topic || !matches_ingress {
                    client.ack(&publish).await?;
                    continue;
                }
                let correlation = publish
                    .properties
                    .as_ref()
                    .and_then(|properties| properties.correlation_data.as_deref())
                    .context("downlink correlation data")?
                    .to_vec();
                client.ack(&publish).await?;
                return Ok::<Downlink, anyhow::Error>(Downlink {
                    correlation,
                    payload,
                });
            }
        }
    })
    .await
    .context("device downlink timeout")?
}

async fn wait_command(client: &AsyncClient, events: &mut EventLoop) -> anyhow::Result<Downlink> {
    let command_topic = MqttTopicPolicy::new(vec![mqtt_scope()?])?
        .command_topic(&mqtt_scope()?)
        .context("configured command topic")?;
    wait_downlink(client, events, command_topic.as_str(), None).await
}

async fn wait_receipt(
    client: &AsyncClient,
    events: &mut EventLoop,
    ingress_event_id: &str,
) -> anyhow::Result<Downlink> {
    let receipt_topic = MqttTopicPolicy::new(vec![mqtt_scope()?])?
        .application_receipt_topic(&mqtt_scope()?)
        .context("configured receipt topic")?;
    wait_downlink(
        client,
        events,
        receipt_topic.as_str(),
        Some(ingress_event_id),
    )
    .await
}

fn command_coordinates(downlink: &Downlink) -> anyhow::Result<CommandCoordinates> {
    let payload: serde_json::Value = serde_json::from_slice(&downlink.payload)?;
    let command_id = std::str::from_utf8(&downlink.correlation)?.to_owned();
    anyhow::ensure!(
        payload["deviceId"] == DEVICE,
        "command device scope changed"
    );
    let generation = payload["desiredGeneration"]
        .as_u64()
        .context("command desiredGeneration")?;
    let fence_epoch = payload["fenceEpoch"]
        .as_u64()
        .context("command fenceEpoch")?;
    let artifact_digest = payload["artifactDigest"]
        .as_str()
        .context("command artifactDigest")?
        .to_owned();
    assert_eq!(generation, CREDENTIAL_GENERATION);
    Ok(CommandCoordinates {
        command_id,
        generation,
        fence_epoch,
        artifact_digest,
    })
}

async fn wait_command_published(pool: &sqlx::PgPool, command_id: &str) -> anyhow::Result<()> {
    testkit::await_try(Duration::from_secs(10), async || {
        let evidence = sqlx::query_as::<_, (String, String, i64)>(
            "SELECT command.state,outbox.status, \
               (SELECT count(*) FROM outbox duplicate \
                 WHERE duplicate.tenant_id=command.tenant_id \
                   AND duplicate.event_id=command.command_id) \
             FROM device_commands command \
             JOIN outbox ON outbox.tenant_id=command.tenant_id \
               AND outbox.event_id=command.command_id \
             WHERE command.tenant_id=$1::uuid AND command.command_id=$2",
        )
        .bind(TENANT)
        .bind(command_id)
        .fetch_optional(pool)
        .await?;
        Ok::<_, anyhow::Error>(evidence.filter(|row| row.0 == "published" && row.1 == "published"))
    })
    .await
    .map(|(_, _, count)| assert_eq!(count, 1))
}

async fn artifact_report_evidence(
    pool: &sqlx::PgPool,
    coordinates: &CommandCoordinates,
) -> anyhow::Result<()> {
    let (artifact_digest, eligibility): (String, String) = sqlx::query_as(
        "SELECT encode(artifact_digest,'hex'),artifact_eligibility \
         FROM device_certificate_authorized_artifacts \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND generation=$3",
    )
    .bind(TENANT)
    .bind(DEVICE)
    .bind(i64::try_from(coordinates.generation)?)
    .fetch_one(pool)
    .await?;
    assert_eq!(eligibility, "draft");
    assert_eq!(
        coordinates.artifact_digest,
        format!("sha256:{artifact_digest}")
    );
    Ok(())
}

async fn receipt_evidence(
    pool: &sqlx::PgPool,
    ingress_event_id: &str,
    expected_disposition: &str,
) -> anyhow::Result<String> {
    let (disposition, status, event_id, duplicates): (String, String, String, i64) =
        testkit::await_try(Duration::from_secs(10), async || {
            let evidence = sqlx::query_as(
                "SELECT receipt.disposition,outbox.status,outbox.event_id, \
                   (SELECT count(*) FROM outbox duplicate \
                     WHERE duplicate.tenant_id=outbox.tenant_id \
                       AND duplicate.event_id=outbox.event_id) \
                 FROM device_ingress_receipts receipt \
                 JOIN outbox ON outbox.tenant_id=receipt.tenant_id \
                   AND outbox.contract_id='identity.device-ingress-receipted' \
                   AND convert_from(outbox.payload,'UTF8')::jsonb->>'ingressEnvelopeId'=receipt.event_id \
                 WHERE receipt.tenant_id=$1::uuid AND receipt.event_id=$2 \
                   AND receipt.device_id=$3::uuid",
            )
            .bind(TENANT)
            .bind(ingress_event_id)
            .bind(DEVICE)
            .fetch_optional(pool)
            .await?;
            Ok::<_, anyhow::Error>(evidence.filter(|row: &(String, String, String, i64)| {
                row.1 == "published"
            }))
        })
        .await?;
    assert_eq!(disposition, expected_disposition);
    assert_eq!(status, "published");
    assert_eq!(duplicates, 1);
    Ok(event_id)
}

async fn command_state(pool: &sqlx::PgPool, command_id: &str) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(
        "SELECT state FROM device_commands WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(TENANT)
    .bind(command_id)
    .fetch_one(pool)
    .await?)
}

fn state_is_ready(
    state: &identity::ports::device_certificate::DeviceCertificateStateSnapshot,
) -> bool {
    state.conditions().iter().any(|condition| {
        condition.kind() == deviceloop::DeviceConditionKind::Ready
            && condition.status_label() == "True"
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hermetic_draft_pilot_commits_ack_before_publishing_its_receipt() -> anyhow::Result<()> {
    let postgres_fixture = testkit::env_or_postgres().await?;
    let evidence = migrate_0094_to_0095(postgres_fixture.params()).await?;
    let mqtt_fixture = testkit::mosquitto_mtls().await?;
    let (device, mut device_events) = connect_device(&mqtt_fixture).await?;

    let first = start_pilot(
        postgres_fixture.params(),
        &mqtt_fixture,
        Duration::from_millis(100),
        "draft-pilot-happy-path",
    )
    .await?;
    wait_receipt_relay_ready(&first).await?;
    let command = wait_command(&device, &mut device_events)
        .await
        .context("draft command downlink")?;
    let coordinates = command_coordinates(&command)?;
    wait_command_published(&evidence, &coordinates.command_id).await?;
    artifact_report_evidence(&evidence, &coordinates).await?;
    assert_no_receipt(&mut device_events, Duration::from_millis(500)).await?;

    publish_ack(&device, &coordinates, ACK_EVENT_ID, 1).await?;
    let ack_receipt = wait_receipt(&device, &mut device_events, ACK_EVENT_ID)
        .await
        .context("post-commit ACK receipt downlink")?;
    let ack_receipt_id = receipt_evidence(&evidence, ACK_EVENT_ID, "advanced").await?;
    assert_eq!(ack_receipt.correlation, ack_receipt_id.as_bytes());
    let ack_payload: serde_json::Value = serde_json::from_slice(&ack_receipt.payload)?;
    assert_eq!(ack_payload["outcome"], "committed");
    assert_eq!(
        command_state(&evidence, &coordinates.command_id).await?,
        "received"
    );
    let scope = DeviceCertificateScope::for_test(
        vocab::TenantId::parse(TENANT)?,
        ids::DeviceId::parse(DEVICE)?,
    );
    let after_ack = first
        .repository
        .load_state(scope)
        .await?
        .context("desired certificate state after ACK")?;
    assert!(
        !state_is_ready(&after_ack),
        "ACK alone must not establish certificate Ready"
    );
    first.shutdown().await?;
    evidence.close().await;
    Ok(())
}
