//! #1908 MQTT/backpressure × durable-ingress join hazards.
//!
//! Asserts only join-unique facts: pre-commit receipt/outbox absence under pause, then recovery to
//! exactly one canonical committed receipt/outcome. Does not re-prove TLS/ACL/cert/sequence/
//! redaction or #1906 convergence.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use diport::{Clock, ManagedResource as _};
use eventexec::RelayConfig;
use eventexec::command::{CommandAliasKey, CommandIdempotencyKeyring};
use eventexec::reconcile::{
    DeviceCertificateSystemProducer, ReconcileMaxInFlight, Tenancy, Trigger,
};
use eventexec::retry::BackoffPolicy;
use identity::ports::device_certificate::{
    AcceptDesiredPolicy, DesiredPolicyAcceptOutcome, DeviceCertificateRepository as _,
    DeviceCertificateScope, DevicePolicyIdempotencyKey, DraftEligibility, ExpectedGeneration,
};
use iotdevice::{
    DraftCommand, DraftCommandCoordinate, DraftDeviceSimulator, PendingDraftAck,
    SameEnvelopeReplayAttempts,
};
use mqtt::{MqttReadiness, MqttSession};
use testkit::{MqttMtlsFixture, PgAppRoleSpec, PgConnParams};

#[path = "device_mtls_pg_harness.rs"]
mod device_mtls_pg_harness;
use device_mtls_pg_harness as harness;

const TENANT: &str = "11111111-1111-4111-8111-111111111111";
const DEVICE: &str = "22222222-2222-4222-8222-222222222222";
const RSS_APP_PASSWORD: &str = "mqtt-backpressure-rss-app-test";
const RSS_READ_PASSWORD: &str = "mqtt-backpressure-rss-read-test";
const WAIT: Duration = Duration::from_secs(20);
const MQTT_RECOVERY_WAIT: Duration = Duration::from_secs(20);
const ACK_SEQUENCE: u64 = 1;
const OBSERVED_AT_BASE: i64 = 1_700_000_000_000_000;
const CONTRACT_APPLY_DEVICE_CERTIFICATE: &str = "identity.apply-device-certificate";
const CONTRACT_DEVICE_INGRESS_RECEIPTED: &str = "identity.device-ingress-receipted";
const OUTBOX_STATUS_PUBLISHED: &str = "published";
const COMMAND_STATE_PUBLISHED: &str = "published";

fn coordinate() -> anyhow::Result<harness::DeviceJourneyCoordinate> {
    harness::DeviceJourneyCoordinate::parse(TENANT, DEVICE)
}

struct ProcessClock;

impl Clock for ProcessClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

struct RunningPilot {
    assembly: deviceidentity::DeviceIdentityAssembly,
    sampler: postgres::PgRuntimeMonitor,
    resources: Vec<Box<diport::DynManagedResource<'static>>>,
    /// Closed readiness observer only — never exposed as a raw MQTT client surface.
    mqtt: Arc<MqttSession>,
}

impl RunningPilot {
    fn mqtt_readiness(&self) -> MqttReadiness {
        self.mqtt.readiness()
    }

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

struct JoinHarness {
    mqtt: MqttMtlsFixture,
    _postgres: testkit::OwnedPgFixture,
    evidence: sqlx::PgPool,
    app: testkit::PgAppRole,
    reader: testkit::PgAppRole,
    pilot: Option<RunningPilot>,
    device: Option<DraftDeviceSimulator>,
}

impl JoinHarness {
    fn pilot(&self) -> anyhow::Result<&RunningPilot> {
        self.pilot.as_ref().context("pilot is not running")
    }

    async fn shutdown_pilot(&mut self) -> anyhow::Result<()> {
        let pilot = self.pilot.take().context("pilot is not running")?;
        pilot.shutdown().await
    }

    async fn take_device_offline(&mut self) -> anyhow::Result<iotdevice::OfflineDraftDevice> {
        let device = self.device.take().context("device simulator missing")?;
        device.go_offline().await.map_err(Into::into)
    }
}

#[derive(Debug)]
struct CommandEvidence {
    command_id: String,
    generation: u64,
    fence_epoch: u64,
}

#[derive(Debug, sqlx::FromRow)]
struct CommandPublishedRow {
    command_id: String,
    generation: i64,
    fence_epoch: i64,
    command_state: String,
    outbox_status: String,
    contract_id: String,
}

#[derive(Debug, sqlx::FromRow)]
struct IngressCounts {
    receipt_count: i64,
    outbox_count: i64,
}

async fn migrate_verified_boundary(
    fixture: &testkit::OwnedPgFixture,
) -> anyhow::Result<(sqlx::PgPool, testkit::PgAppRole, testkit::PgAppRole)> {
    let [app, reader] = fixture
        .resolve_app_roles([
            PgAppRoleSpec::new("rss_app", RSS_APP_PASSWORD),
            PgAppRoleSpec::new("rss_app_read", RSS_READ_PASSWORD),
        ])
        .await?;
    let params = fixture.owner_params();
    let pool = harness::admin_pool(
        params,
        harness::PgAdminPoolBudget::new(5, Duration::from_secs(10)),
    )
    .await?;
    let embedded = sqlx::migrate!("../adapters/postgres/migrations");
    harness::migrator_through(&embedded, 94).run(&pool).await?;
    harness::migrator_through(&embedded, 95).run(&pool).await?;
    embedded.run(&pool).await?;
    Ok((pool, app, reader))
}

fn command_keyring() -> anyhow::Result<Arc<CommandIdempotencyKeyring>> {
    Ok(Arc::new(CommandIdempotencyKeyring::new(
        CommandAliasKey::new("mqtt-backpressure-v1", vec![0x43; 32])?,
        Vec::new(),
    )?))
}

fn certificate_scope() -> anyhow::Result<DeviceCertificateScope> {
    Ok(coordinate()?.certificate_scope())
}

async fn accept_generation(
    repository: &postgres::PgDeviceCertificateRepository<DraftEligibility>,
    expected: u64,
    san: &str,
) -> anyhow::Result<()> {
    let policy = deviceloop::CertificatePolicy::restore(
        7_200,
        900,
        vec!["clientAuth".to_owned()],
        vec![san.to_owned()],
    )?;
    let outcome = repository
        .accept_desired_policy(AcceptDesiredPolicy::for_test(
            certificate_scope()?,
            ExpectedGeneration::try_new(expected)?,
            DevicePolicyIdempotencyKey::new(uuid::Uuid::from_u128(expected as u128 + 1)),
            policy,
            httpserve::VerifiedRequestId::for_test(format!("req-mqtt-{expected}")),
            diagctx::CorrelationId::parse(&format!("corr-mqtt-{expected}"))?,
        )?)
        .await?;
    let accepted = match outcome {
        DesiredPolicyAcceptOutcome::Accepted { result, .. } => result.accepted_generation().get(),
        unexpected => anyhow::bail!("unexpected desired-policy outcome: {unexpected:?}"),
    };
    anyhow::ensure!(
        accepted == expected + 1,
        "desired generation did not advance once"
    );
    Ok(())
}

async fn seed_generation_two(
    repository: &postgres::PgDeviceCertificateRepository<DraftEligibility>,
) -> anyhow::Result<()> {
    repository
        .enroll_reconcile_target(certificate_scope()?, SystemTime::now())
        .await?;
    accept_generation(repository, 0, "mqtt-backpressure-one.example").await?;
    accept_generation(repository, 1, "mqtt-backpressure-two.example").await
}

fn pilot_config() -> anyhow::Result<identity_composition::DeviceIdentityPilotConfig> {
    let budget = harness::relay_budget()?;
    Ok(identity_composition::DeviceIdentityPilotConfig::new(
        identity_composition::DeviceIdentitySchedulerConfig::new(
            Arc::new(ProcessClock),
            command_keyring()?,
            DeviceCertificateSystemProducer::install(),
            rss_request_context::TenantId::parse(TENANT)?,
            "mqtt-backpressure-fault-journey",
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
            RelayConfig::new(Duration::from_millis(100), 4)?,
            budget,
        ),
        Duration::from_secs(10),
    ))
}

fn draft_simulator() -> anyhow::Result<identity_composition::DraftArtifactSimulator> {
    let now_seconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let not_after = diport::CertNotAfter::try_from_system_time(
        SystemTime::UNIX_EPOCH + Duration::from_secs(now_seconds + 86_400),
    )?;
    Ok(identity_composition::DraftArtifactSimulator::new(
        [0x19; 32], not_after,
    ))
}

async fn launch_pilot_on_runtime(
    runtime: harness::ConnectedPgRuntime,
    mqtt_fixture: &MqttMtlsFixture,
    expect_session_present: bool,
) -> anyhow::Result<RunningPilot> {
    let (handle, resources, sampler) = runtime.into_parts();
    let assembly_postgres = handle.device_identity_draft_runtime();
    let session = harness::mqtt_session(&coordinate()?, mqtt_fixture).await?;
    let assembly = deviceidentity::DeviceIdentityAssembly::start(
        assembly_postgres,
        draft_simulator()?,
        Arc::clone(&session),
        pilot_config()?,
    )
    .await?;
    let pilot = RunningPilot {
        assembly,
        sampler,
        resources,
        mqtt: session,
    };
    wait_pilot_ready(&pilot).await?;
    wait_mqtt_ready_with_session_present(&pilot, expect_session_present).await?;
    Ok(pilot)
}

/// First bring-up: seed generation 2, then start pilot/session on a cold MQTT client ID.
async fn start_pilot_seeded(
    app: &PgConnParams,
    reader: &PgConnParams,
    mqtt_fixture: &MqttMtlsFixture,
) -> anyhow::Result<RunningPilot> {
    let runtime = harness::ConnectedPgRuntime::connect(app, reader).await?;
    let identity = runtime.handle().for_domain::<postgres::caps::Identity>();
    let repository = identity.device_certificate_repository::<DraftEligibility>();
    seed_generation_two(&repository).await?;
    launch_pilot_on_runtime(runtime, mqtt_fixture, false).await
}

/// Restart-only bring-up: reuse durable DB state and the same Mosquitto endpoint/client ID.
///
/// Closing the previous `MqttSession` leaves unacked QoS1 publishes in the broker persistent
/// session; the replacement session must observe `session_present=true` and an empty local queue.
async fn restart_pilot_runtime(
    app: &PgConnParams,
    reader: &PgConnParams,
    mqtt_fixture: &MqttMtlsFixture,
) -> anyhow::Result<RunningPilot> {
    let runtime = harness::ConnectedPgRuntime::connect(app, reader).await?;
    launch_pilot_on_runtime(runtime, mqtt_fixture, true).await
}

async fn wait_pilot_ready(pilot: &RunningPilot) -> anyhow::Result<()> {
    testkit::await_map(Duration::from_secs(10), async || {
        let readiness = pilot.assembly.readiness();
        (readiness.ingress() == identity_composition::PilotComponentReadiness::Ready
            && readiness.receipt_relay() == identity_composition::PilotComponentReadiness::Ready
            && readiness.mqtt() == identity_composition::PilotComponentReadiness::Ready)
            .then_some(())
    })
    .await
    .with_context(|| {
        format!(
            "pilot readiness deadline; readiness={:?}",
            pilot.assembly.readiness()
        )
    })
}

async fn wait_mqtt_ready_with_session_present(
    pilot: &RunningPilot,
    session_present: bool,
) -> anyhow::Result<()> {
    testkit::await_map(MQTT_RECOVERY_WAIT, async || {
        matches!(
            pilot.mqtt_readiness(),
            MqttReadiness::Ready {
                session_present: present,
                ..
            } if present == session_present
        )
        .then_some(())
    })
    .await
    .with_context(|| {
        format!(
            "mqtt Ready session_present={session_present}; readiness={:?}; mqtt={:?}",
            pilot.assembly.readiness(),
            pilot.mqtt_readiness()
        )
    })
}

async fn wait_command_published(
    pool: &sqlx::PgPool,
    pilot: &RunningPilot,
    generation: u64,
) -> anyhow::Result<CommandEvidence> {
    let row = testkit::await_try(WAIT, async || {
        let evidence = sqlx::query_as::<_, CommandPublishedRow>(
            "SELECT command.command_id AS command_id, \
                   command.generation AS generation, \
                   command.fence_epoch AS fence_epoch, \
                   command.state AS command_state, \
                   outbox.status AS outbox_status, \
                   outbox.contract_id AS contract_id \
                 FROM device_commands command \
                 JOIN outbox ON outbox.tenant_id=command.tenant_id \
                   AND outbox.event_id=command.command_id \
                 WHERE command.tenant_id=$1::uuid AND command.device_id=$2::uuid \
                   AND command.generation=$3",
        )
        .bind(TENANT)
        .bind(DEVICE)
        .bind(i64::try_from(generation)?)
        .fetch_optional(pool)
        .await?;
        Ok::<_, anyhow::Error>(evidence.filter(|row| {
            row.command_state == COMMAND_STATE_PUBLISHED
                && row.outbox_status == OUTBOX_STATUS_PUBLISHED
                && row.contract_id == CONTRACT_APPLY_DEVICE_CERTIFICATE
        }))
    })
    .await
    .with_context(|| {
        format!(
            "generation {generation} command was not published; readiness={:?}",
            pilot.assembly.readiness()
        )
    })?;
    Ok(CommandEvidence {
        command_id: row.command_id,
        generation: u64::try_from(row.generation)?,
        fence_epoch: u64::try_from(row.fence_epoch)?,
    })
}

async fn ingress_counts(pool: &sqlx::PgPool, ingress_id: &str) -> anyhow::Result<IngressCounts> {
    Ok(sqlx::query_as::<_, IngressCounts>(
        "SELECT \
           (SELECT count(*) FROM device_ingress_receipts \
             WHERE tenant_id=$1::uuid AND event_id=$2 AND device_id=$3::uuid) AS receipt_count, \
           (SELECT count(*) FROM outbox \
             WHERE tenant_id=$1::uuid \
               AND contract_id=$4 \
               AND convert_from(payload,'UTF8')::jsonb->>'ingressEnvelopeId'=$2) AS outbox_count",
    )
    .bind(TENANT)
    .bind(ingress_id)
    .bind(DEVICE)
    .bind(CONTRACT_DEVICE_INGRESS_RECEIPTED)
    .fetch_one(pool)
    .await?)
}

fn assert_no_ingress_commit(counts: &IngressCounts, ingress_id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        counts.receipt_count == 0 && counts.outbox_count == 0,
        "join window must not commit application receipt for {ingress_id}; counts={counts:?}"
    );
    Ok(())
}

async fn probe_no_ingress_commit(pool: &sqlx::PgPool, ingress_id: &str) -> anyhow::Result<()> {
    let counts = ingress_counts(pool, ingress_id)
        .await
        .with_context(|| format!("probe ingress counts for {ingress_id}"))?;
    assert_no_ingress_commit(&counts, ingress_id)
}

async fn wait_exactly_one_committed_receipt(
    pool: &sqlx::PgPool,
    pilot: &RunningPilot,
    ingress_id: &str,
) -> anyhow::Result<()> {
    let counts = testkit::await_try(WAIT, async || {
        let observed = ingress_counts(pool, ingress_id).await?;
        Ok::<_, anyhow::Error>(
            (observed.receipt_count == 1 && observed.outbox_count == 1).then_some(observed),
        )
    })
    .await
    .with_context(|| {
        format!(
            "exactly-one committed receipt for {ingress_id}; readiness={:?}",
            pilot.assembly.readiness()
        )
    })?;
    anyhow::ensure!(
        counts.receipt_count == 1 && counts.outbox_count == 1,
        "canonical outcome must be exactly one receipt+outbox; counts={counts:?}"
    );
    Ok(())
}

async fn pause_ingress(
    pilot: &RunningPilot,
) -> anyhow::Result<identity_composition::PilotLoopPauseGuard> {
    tokio::time::timeout(WAIT, pilot.assembly.pause_ingress_for_test())
        .await
        .context("pause and drain ingress deadline")
}

async fn open_harness() -> anyhow::Result<(JoinHarness, DraftCommand)> {
    let mqtt = testkit::mosquitto_mtls().await?;
    let offline =
        DraftDeviceSimulator::prime(harness::draft_device_config(&coordinate()?, &mqtt, WAIT)?)
            .await?
            .go_offline()
            .await?;
    let postgres = testkit::owned_postgres().await?;
    let (evidence, app, reader) = migrate_verified_boundary(&postgres).await?;
    let pilot = start_pilot_seeded(app.params(), reader.params(), &mqtt).await?;
    anyhow::ensure!(
        matches!(
            pilot.mqtt_readiness(),
            MqttReadiness::Ready {
                session_present: false,
                ..
            }
        ),
        "initial MQTT session must be a cold start; mqtt={:?}",
        pilot.mqtt_readiness()
    );
    let published = wait_command_published(&evidence, &pilot, 2).await?;
    let expected = DraftCommandCoordinate::new(published.generation, published.fence_epoch)?;
    let mut device = offline.reconnect().await?;
    let command = device.receive_latest(expected).await.with_context(|| {
        format!(
            "device did not observe published command_id={} generation={} fence_epoch={}; readiness={:?}",
            published.command_id,
            published.generation,
            published.fence_epoch,
            pilot.assembly.readiness()
        )
    })?;
    assert_eq!(command.command_id(), published.command_id);
    Ok((
        JoinHarness {
            mqtt,
            _postgres: postgres,
            evidence,
            app,
            reader,
            pilot: Some(pilot),
            device: Some(device),
        },
        command,
    ))
}

async fn send_ack_under_pause(
    harness: &mut JoinHarness,
    command: DraftCommand,
) -> anyhow::Result<(identity_composition::PilotLoopPauseGuard, PendingDraftAck)> {
    let pause = pause_ingress(harness.pilot()?).await?;
    let device = harness
        .device
        .as_mut()
        .context("device simulator missing")?;
    let pending = device
        .send_ack(
            command,
            ACK_SEQUENCE,
            OBSERVED_AT_BASE + ACK_SEQUENCE as i64,
        )
        .await?;
    Ok((pause, pending))
}

/// Replace the in-process pilot/session while keeping Mosquitto + Postgres fixtures stable.
///
/// The pause guard stays held across old-pilot shutdown so ingress cannot commit from the drained
/// local queue; dropping it afterwards only touches the already-stopped control. The replacement
/// pilot starts admission-open and must restore `session_present=true` for broker replay.
async fn shutdown_old_and_restart_pilot(
    harness: &mut JoinHarness,
    pause: identity_composition::PilotLoopPauseGuard,
    ingress_id: &str,
) -> anyhow::Result<()> {
    probe_no_ingress_commit(&harness.evidence, ingress_id).await?;
    harness.shutdown_pilot().await?;
    probe_no_ingress_commit(&harness.evidence, ingress_id).await?;
    drop(pause);
    let replacement =
        restart_pilot_runtime(harness.app.params(), harness.reader.params(), &harness.mqtt).await?;
    anyhow::ensure!(
        matches!(
            replacement.mqtt_readiness(),
            MqttReadiness::Ready {
                session_present: true,
                ..
            }
        ),
        "replacement MQTT session must restore persistent session; mqtt={:?}",
        replacement.mqtt_readiness()
    );
    harness.pilot = Some(replacement);
    Ok(())
}

async fn finish_join_proof(
    harness: &mut JoinHarness,
    pending: PendingDraftAck,
    ingress_id: &str,
) -> anyhow::Result<()> {
    wait_exactly_one_committed_receipt(&harness.evidence, harness.pilot()?, ingress_id).await?;
    drop(pending);
    harness.shutdown_pilot().await?;
    harness.evidence.close().await;
    Ok(())
}

/// H1: broker accepted uplink, process disconnect before ingress commit, persistent-session replay
/// on the same Mosquitto endpoint → one receipt.
pub async fn broker_delivery_disconnect_before_ingress_commit_replays_to_one_canonical_receipt()
-> anyhow::Result<()> {
    let (mut harness, command) = open_harness().await?;
    let (pause, pending) = send_ack_under_pause(&mut harness, command).await?;
    let ingress_id = pending.ingress_id().to_owned();
    // Keep the device offline across RSS session replacement; join proof is SQL receipt cardinality.
    let _offline = harness.take_device_offline().await?;
    shutdown_old_and_restart_pilot(&mut harness, pause, &ingress_id).await?;
    finish_join_proof(&mut harness, pending, &ingress_id).await
}

/// H2: saturated ingress + persistent-session reconnect on a stable endpoint → one outcome.
pub async fn saturated_ingress_persistent_session_reconnect_reaches_one_canonical_outcome()
-> anyhow::Result<()> {
    let (mut harness, command) = open_harness().await?;
    let (pause, pending) = send_ack_under_pause(&mut harness, command).await?;
    let ingress_id = pending.ingress_id().to_owned();
    {
        let device = harness
            .device
            .as_mut()
            .context("device simulator missing")?;
        device
            .replay_pending_ack(
                &pending,
                SameEnvelopeReplayAttempts::new(SameEnvelopeReplayAttempts::MAX)?,
            )
            .await?;
    }
    // Anti-vacuity: bounded subscriber/receive-window must be full (not a TrySendError claim).
    testkit::await_map(Duration::from_secs(10), async || {
        harness
            .pilot()
            .ok()
            .filter(|pilot| pilot.mqtt.uplink_queue_is_saturated_for_test())
            .map(|_| ())
    })
    .await
    .context("uplink queue did not reach saturation after same-envelope replay")?;
    anyhow::ensure!(
        matches!(
            harness.pilot()?.mqtt_readiness(),
            MqttReadiness::Ready { .. }
        ),
        "saturated ingress queue must keep MQTT transport ready; mqtt={:?}",
        harness.pilot()?.mqtt_readiness()
    );
    probe_no_ingress_commit(&harness.evidence, &ingress_id).await?;
    let _offline = harness.take_device_offline().await?;
    shutdown_old_and_restart_pilot(&mut harness, pause, &ingress_id).await?;
    finish_join_proof(&mut harness, pending, &ingress_id).await
}
