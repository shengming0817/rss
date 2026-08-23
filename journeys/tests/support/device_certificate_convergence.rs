use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use diport::{Clock, ManagedResource as _};
use eventexec::RelayConfig;
use eventexec::command::{CommandAliasKey, CommandIdempotencyKeyring};
use eventexec::reconcile::{
    BackoffPolicy, DeviceCertificateSystemProducer, ReconcileMaxInFlight, Tenancy, Trigger,
};
use identity::ports::device_certificate::{
    AcceptDesiredPolicy, DesiredPolicyAcceptOutcome, DeviceCertificateRepository as _,
    DeviceCertificateScope, DevicePolicyIdempotencyKey, DraftEligibility, ExpectedGeneration,
};
use iotdevice::{DraftAppliedArtifact, DraftCommandCoordinate, DraftDeviceSimulator};
use testkit::{MqttMtlsFixture, PgAppRoleSpec, PgConnParams};

#[path = "device_mtls_pg_harness.rs"]
mod device_mtls_pg_harness;
use device_mtls_pg_harness as harness;

const TENANT: &str = "11111111-1111-4111-8111-111111111111";
const DEVICE: &str = "22222222-2222-4222-8222-222222222222";
const RSS_APP_PASSWORD: &str = "device-convergence-rss-app-test";
const RSS_READ_PASSWORD: &str = "device-convergence-rss-read-test";
const WAIT: Duration = Duration::from_secs(20);
const ACK_SEQUENCE: u64 = 1;
const REPORT_SEQUENCE: u64 = 2;
const OBSERVED_AT_BASE: i64 = 1_700_000_000_000_000;
const SHA256_PREFIX: &str = "sha256:";
const OUTBOX_STATUS_PUBLISHED: &str = "published";
const OUTBOX_STATUS_PENDING: &str = "pending";
const COMMAND_STATE_PUBLISHED: &str = "published";
const CONTRACT_APPLY_DEVICE_CERTIFICATE: &str = "identity.apply-device-certificate";
const CONTRACT_DEVICE_INGRESS_RECEIPTED: &str = "identity.device-ingress-receipted";

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
    repository: postgres::PgDeviceCertificateRepository<DraftEligibility>,
    sampler: postgres::PgRuntimeMonitor,
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

#[derive(Debug)]
struct CommandEvidence {
    command_id: String,
    generation: u64,
    fence_epoch: u64,
}

#[derive(Debug)]
struct ArtifactEvidence {
    eligibility: String,
    artifact_digest: String,
    expected_state_hash: String,
}

#[derive(Debug)]
struct ReceiptEvidence {
    receipt_event_id: String,
}

#[derive(Debug, sqlx::FromRow)]
struct CommandPublishedRow {
    command_id: String,
    generation: i64,
    fence_epoch: i64,
    command_state: String,
    outbox_status: String,
    outbox_count: i64,
    contract_id: String,
}

#[derive(Debug, sqlx::FromRow)]
struct PendingReceiptRow {
    kind: String,
    disposition: String,
    outbox_status: String,
    contract_id: String,
    event_id: String,
    receipt_count: i64,
    outbox_count: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct ConvergedRow {
    command_state: String,
    ready_status: String,
    observed_generation: i64,
    fence_epoch: i64,
    state_hash_hex: String,
    artifact_digest_hex: String,
}

#[derive(Debug, sqlx::FromRow)]
struct ConvergenceSnapshot {
    command_state: String,
    observed_generation: Option<i64>,
    fence_epoch: Option<i64>,
    ready_status: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct ReceiptSetRow {
    receipt_event_id: String,
    outbox_event_id: Option<String>,
    contract_id: Option<String>,
    outbox_status: Option<String>,
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
        harness::PgAdminPoolBudget::new(2, Duration::from_secs(5)),
    )
    .await?;
    let embedded = sqlx::migrate!("../adapters/postgres/migrations");

    harness::migrator_through(&embedded, 94).run(&pool).await?;
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

    harness::migrator_through(&embedded, 95).run(&pool).await?;
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
    let current_version = embedded
        .iter()
        .map(|migration| migration.version)
        .max()
        .context("embedded migrations must not be empty")?;
    let current: (i64, bool) = sqlx::query_as(
        "SELECT max(version), \
           to_regprocedure('public.rss_enroll_device_certificate_reconcile_target(uuid,uuid,bigint)') \
             IS NOT NULL \
         FROM public._sqlx_migrations",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        current,
        (current_version, true),
        "database must reach the exact embedded migration tip beyond 0095"
    );
    Ok((pool, app, reader))
}

fn command_keyring() -> anyhow::Result<Arc<CommandIdempotencyKeyring>> {
    Ok(Arc::new(CommandIdempotencyKeyring::new(
        CommandAliasKey::new("device-convergence-v1", vec![0x42; 32])?,
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
            httpserve::VerifiedRequestId::for_test(format!("req-converge-{expected}")),
            diagctx::CorrelationId::parse(&format!("corr-converge-{expected}"))?,
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
    accept_generation(repository, 0, "device-convergence-one.example").await?;
    accept_generation(repository, 1, "device-convergence-two.example").await
}

async fn start_pilot(
    app: &PgConnParams,
    reader_role: &PgConnParams,
    mqtt_fixture: &MqttMtlsFixture,
) -> anyhow::Result<RunningPilot> {
    let runtime = harness::ConnectedPgRuntime::connect(app, reader_role).await?;
    let identity = runtime.handle().for_domain::<postgres::caps::Identity>();
    let repository = identity.device_certificate_repository::<DraftEligibility>();
    seed_generation_two(&repository).await?;
    let (handle, resources, sampler) = runtime.into_parts();
    let assembly_postgres = handle.device_identity_draft_runtime();
    let session = harness::mqtt_session(&coordinate()?, mqtt_fixture).await?;
    let now_seconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let not_after = diport::CertNotAfter::try_from_system_time(
        SystemTime::UNIX_EPOCH + Duration::from_secs(now_seconds + 86_400),
    )?;
    let budget = harness::relay_budget()?;
    let config = identity_composition::DeviceIdentityPilotConfig::new(
        identity_composition::DeviceIdentitySchedulerConfig::new(
            Arc::new(ProcessClock),
            command_keyring()?,
            DeviceCertificateSystemProducer::install(),
            rss_request_context::TenantId::parse(TENANT)?,
            "device-certificate-convergence-journey",
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

async fn wait_pilot_ready(pilot: &RunningPilot) -> anyhow::Result<()> {
    let result = testkit::await_map(Duration::from_secs(10), async || {
        (pilot.assembly.readiness().receipt_relay()
            == identity_composition::PilotComponentReadiness::Ready)
            .then_some(())
    })
    .await;
    match result {
        Ok(()) => Ok(()),
        Err(error) => anyhow::bail!(
            "receipt relay readiness deadline; readiness={:?}: {error}",
            pilot.assembly.readiness()
        ),
    }
}

async fn wait_command_published(
    pool: &sqlx::PgPool,
    pilot: &RunningPilot,
    generation: u64,
) -> anyhow::Result<CommandEvidence> {
    let observed = testkit::await_try(WAIT, async || {
        let evidence = sqlx::query_as::<_, CommandPublishedRow>(
            "SELECT command.command_id AS command_id, \
                   command.generation AS generation, \
                   command.fence_epoch AS fence_epoch, \
                   command.state AS command_state, \
                   outbox.status AS outbox_status, \
                   (SELECT count(*) FROM outbox duplicate \
                     WHERE duplicate.tenant_id=command.tenant_id \
                       AND duplicate.event_id=command.command_id) AS outbox_count, \
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
        }))
    })
    .await;
    let row = match observed {
        Ok(row) => row,
        Err(error) => {
            let commands: Vec<(i64, i64, String, Option<String>)> = sqlx::query_as(
                "SELECT command.generation,command.fence_epoch,command.state,outbox.status \
                 FROM device_commands command LEFT JOIN outbox \
                   ON outbox.tenant_id=command.tenant_id AND outbox.event_id=command.command_id \
                 WHERE command.tenant_id=$1::uuid AND command.device_id=$2::uuid \
                 ORDER BY command.generation,command.fence_epoch",
            )
            .bind(TENANT)
            .bind(DEVICE)
            .fetch_all(pool)
            .await?;
            anyhow::bail!(
                "generation {generation} command was not published; durable commands={commands:?}; readiness={:?}: {error}",
                pilot.assembly.readiness()
            );
        }
    };
    assert_eq!(
        row.outbox_count, 1,
        "command outbox must be one durable fact"
    );
    assert_eq!(row.contract_id, CONTRACT_APPLY_DEVICE_CERTIFICATE);
    Ok(CommandEvidence {
        command_id: row.command_id,
        generation: u64::try_from(row.generation)?,
        fence_epoch: u64::try_from(row.fence_epoch)?,
    })
}

async fn wait_generation_three_supersedes_two(
    pool: &sqlx::PgPool,
    pilot: &RunningPilot,
) -> anyhow::Result<CommandEvidence> {
    let latest = wait_command_published(pool, pilot, 3).await?;
    let old_state: String = testkit::await_try(WAIT, async || {
        let state = sqlx::query_scalar(
            "SELECT state FROM device_commands \
             WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND generation=2",
        )
        .bind(TENANT)
        .bind(DEVICE)
        .fetch_optional(pool)
        .await?;
        Ok::<_, anyhow::Error>(state.filter(|state| state == "superseded"))
    })
    .await
    .context("generation two command superseded")?;
    assert_eq!(old_state, "superseded");
    Ok(latest)
}

async fn load_artifact(pool: &sqlx::PgPool, generation: u64) -> anyhow::Result<ArtifactEvidence> {
    let (eligibility, artifact_digest, state_hash): (String, String, String) = sqlx::query_as(
        "SELECT artifact_eligibility,encode(artifact_digest,'hex'), \
           encode(expected_state_hash,'hex') \
         FROM device_certificate_authorized_artifacts \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND generation=$3",
    )
    .bind(TENANT)
    .bind(DEVICE)
    .bind(i64::try_from(generation)?)
    .fetch_one(pool)
    .await?;
    Ok(ArtifactEvidence {
        eligibility,
        artifact_digest: format!("{SHA256_PREFIX}{artifact_digest}"),
        expected_state_hash: format!("{SHA256_PREFIX}{state_hash}"),
    })
}

async fn load_command_lease_fences(
    pool: &sqlx::PgPool,
) -> anyhow::Result<Vec<(i64, i64, String, i64)>> {
    Ok(sqlx::query_as(
        "SELECT command.generation,command.fence_epoch,command.state,lease.epoch \
         FROM device_commands command \
         JOIN reconcile_targets target ON target.tenant_id=command.tenant_id \
           AND target.reconciler_id='identity.device-certificate' \
           AND target.resource_id=command.device_id::text \
         JOIN reconcile_leases lease ON lease.tenant_id=target.tenant_id \
           AND lease.target_id=target.target_id \
         WHERE command.tenant_id=$1::uuid AND command.device_id=$2::uuid \
         ORDER BY command.generation,command.fence_epoch",
    )
    .bind(TENANT)
    .bind(DEVICE)
    .fetch_all(pool)
    .await?)
}

async fn wait_pending_receipt(
    pool: &sqlx::PgPool,
    pilot: &RunningPilot,
    ingress_id: &str,
    expected_kind: &str,
) -> anyhow::Result<ReceiptEvidence> {
    let observed = testkit::await_try(WAIT, async || {
        let evidence = sqlx::query_as::<_, PendingReceiptRow>(
            "SELECT receipt.kind AS kind, \
                   receipt.disposition AS disposition, \
                   outbox.status AS outbox_status, \
                   outbox.contract_id AS contract_id, \
                   outbox.event_id AS event_id, \
                   (SELECT count(*) FROM device_ingress_receipts duplicate \
                     WHERE duplicate.tenant_id=receipt.tenant_id \
                       AND duplicate.event_id=receipt.event_id) AS receipt_count, \
                   (SELECT count(*) FROM outbox duplicate \
                     WHERE duplicate.tenant_id=outbox.tenant_id \
                       AND duplicate.event_id=outbox.event_id) AS outbox_count \
                 FROM device_ingress_receipts receipt \
                 JOIN outbox ON outbox.tenant_id=receipt.tenant_id \
                   AND outbox.contract_id=$4 \
                   AND convert_from(outbox.payload,'UTF8')::jsonb->>'ingressEnvelopeId'=receipt.event_id \
                 WHERE receipt.tenant_id=$1::uuid AND receipt.event_id=$2 \
                   AND receipt.device_id=$3::uuid",
        )
        .bind(TENANT)
        .bind(ingress_id)
        .bind(DEVICE)
        .bind(CONTRACT_DEVICE_INGRESS_RECEIPTED)
        .fetch_optional(pool)
        .await?;
        Ok::<_, anyhow::Error>(evidence.filter(|row| row.outbox_status == OUTBOX_STATUS_PENDING))
    })
    .await;
    let row = match observed {
        Ok(row) => row,
        Err(error) => {
            let receipt: Option<(String, String)> = sqlx::query_as(
                "SELECT kind,disposition FROM device_ingress_receipts \
                 WHERE tenant_id=$1::uuid AND event_id=$2 AND device_id=$3::uuid",
            )
            .bind(TENANT)
            .bind(ingress_id)
            .bind(DEVICE)
            .fetch_optional(pool)
            .await?;
            let commands = load_command_lease_fences(pool).await?;
            anyhow::bail!(
                "pending receipt evidence for {ingress_id}; receipt={receipt:?}; \
                 durable command/lease fences={commands:?}; readiness={:?}: {error}",
                pilot.assembly.readiness()
            );
        }
    };
    assert_eq!(row.kind, expected_kind);
    if row.disposition != "advanced" {
        let fences = load_command_lease_fences(pool).await?;
        anyhow::bail!(
            "{expected_kind} ingress disposition was {}, durable command/lease fences={fences:?}",
            row.disposition
        );
    }
    assert_eq!(row.outbox_status, OUTBOX_STATUS_PENDING);
    assert_eq!(row.contract_id, CONTRACT_DEVICE_INGRESS_RECEIPTED);
    assert_eq!(row.receipt_count, 1, "ingress is one durable fact");
    assert_eq!(row.outbox_count, 1, "receipt outbox is one durable fact");
    Ok(ReceiptEvidence {
        receipt_event_id: row.event_id,
    })
}

async fn wait_outbox_published(pool: &sqlx::PgPool, event_id: &str) -> anyhow::Result<()> {
    let count: i64 = testkit::await_try(WAIT, async || {
        let row: Option<(String, i64)> = sqlx::query_as(
            "SELECT status,(SELECT count(*) FROM outbox duplicate \
               WHERE duplicate.tenant_id=outbox.tenant_id \
                 AND duplicate.event_id=outbox.event_id) \
             FROM outbox WHERE tenant_id=$1::uuid AND event_id=$2",
        )
        .bind(TENANT)
        .bind(event_id)
        .fetch_optional(pool)
        .await?;
        Ok::<_, anyhow::Error>(
            row.filter(|row| row.0 == OUTBOX_STATUS_PUBLISHED)
                .map(|row| row.1),
        )
    })
    .await
    .with_context(|| format!("receipt outbox {event_id} published"))?;
    assert_eq!(count, 1);
    Ok(())
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

async fn wait_converged(
    pool: &sqlx::PgPool,
    command: &CommandEvidence,
    artifact: &ArtifactEvidence,
) -> anyhow::Result<()> {
    let observed = testkit::await_try(WAIT, async || {
        let evidence = sqlx::query_as::<_, ConvergedRow>(
            "SELECT command.state AS command_state, \
               condition.status AS ready_status, \
               reported.observed_generation AS observed_generation, \
               reported.fence_epoch AS fence_epoch, \
               encode(reported.state_hash,'hex') AS state_hash_hex, \
               encode(reported.artifact_digest,'hex') AS artifact_digest_hex \
             FROM device_commands command \
             JOIN device_certificate_reported_states reported \
               ON reported.tenant_id=command.tenant_id AND reported.device_id=command.device_id \
             JOIN device_certificate_conditions condition \
               ON condition.tenant_id=command.tenant_id AND condition.device_id=command.device_id \
               AND condition.condition_type='Ready' \
             WHERE command.tenant_id=$1::uuid AND command.command_id=$2",
        )
        .bind(TENANT)
        .bind(&command.command_id)
        .fetch_optional(pool)
        .await?;
        Ok::<_, anyhow::Error>(
            evidence.filter(|row| row.command_state == "applied" && row.ready_status == "True"),
        )
    })
    .await;
    let row = match observed {
        Ok(row) => row,
        Err(error) => {
            let snapshot: Result<Option<ConvergenceSnapshot>, _> = sqlx::query_as(
                "SELECT command.state AS command_state, \
                       reported.observed_generation AS observed_generation, \
                       reported.fence_epoch AS fence_epoch, \
                       (SELECT condition.status FROM device_certificate_conditions condition \
                         WHERE condition.tenant_id=command.tenant_id \
                           AND condition.device_id=command.device_id \
                           AND condition.condition_type='Ready') AS ready_status \
                     FROM device_commands command \
                     LEFT JOIN device_certificate_reported_states reported \
                       ON reported.tenant_id=command.tenant_id \
                       AND reported.device_id=command.device_id \
                     WHERE command.tenant_id=$1::uuid AND command.command_id=$2",
            )
            .bind(TENANT)
            .bind(&command.command_id)
            .fetch_optional(pool)
            .await;
            match snapshot {
                Ok(Some(snapshot)) => anyhow::bail!(
                    "command convergence deadline; command_state={}; \
                     reported_generation={:?}; reported_fence_epoch={:?}; \
                     ready_condition={:?}: {error}",
                    snapshot.command_state,
                    snapshot.observed_generation,
                    snapshot.fence_epoch,
                    snapshot.ready_status
                ),
                Ok(None) => anyhow::bail!(
                    "command convergence deadline; command_state=<missing>; \
                     reported_generation=None; reported_fence_epoch=None; \
                     ready_condition=None: {error}"
                ),
                Err(snapshot_error) => anyhow::bail!(
                    "command convergence deadline; safe readiness snapshot unavailable: \
                     {snapshot_error}: {error}"
                ),
            }
        }
    };
    assert_eq!(u64::try_from(row.observed_generation)?, command.generation);
    assert_eq!(u64::try_from(row.fence_epoch)?, command.fence_epoch);
    assert_eq!(
        format!("{SHA256_PREFIX}{}", row.state_hash_hex),
        artifact.expected_state_hash
    );
    assert_eq!(
        format!("{SHA256_PREFIX}{}", row.artifact_digest_hex),
        artifact.artifact_digest
    );
    Ok(())
}

async fn assert_exact_receipt_set(
    pool: &sqlx::PgPool,
    ack_ingress: &str,
    report_ingress: &str,
) -> anyhow::Result<()> {
    let rows: Vec<ReceiptSetRow> = sqlx::query_as(
        "SELECT receipt.event_id AS receipt_event_id, \
                outbox.event_id AS outbox_event_id, \
                outbox.contract_id AS contract_id, \
                outbox.status AS outbox_status \
         FROM device_ingress_receipts receipt \
         LEFT JOIN outbox ON outbox.tenant_id=receipt.tenant_id \
           AND convert_from(outbox.payload,'UTF8')::jsonb->>'ingressEnvelopeId'=receipt.event_id \
         WHERE receipt.tenant_id=$1::uuid AND receipt.device_id=$2::uuid \
         ORDER BY receipt.event_id",
    )
    .bind(TENANT)
    .bind(DEVICE)
    .fetch_all(pool)
    .await?;
    let actual: BTreeSet<&str> = rows
        .iter()
        .map(|row| row.receipt_event_id.as_str())
        .collect();
    let expected = BTreeSet::from([ack_ingress, report_ingress]);
    assert_eq!(
        actual, expected,
        "ACK/report ingress receipts must be the exact set"
    );
    assert_eq!(rows.len(), 2);
    for row in rows {
        let contract_id = row
            .contract_id
            .as_deref()
            .context("receipt must have linked outbox contract")?;
        let outbox_status = row
            .outbox_status
            .as_deref()
            .context("receipt must have linked outbox status")?;
        let outbox_event_id = row
            .outbox_event_id
            .as_deref()
            .context("receipt outbox identity must be present")?;
        assert_eq!(contract_id, CONTRACT_DEVICE_INGRESS_RECEIPTED);
        assert_eq!(outbox_status, OUTBOX_STATUS_PUBLISHED);
        anyhow::ensure!(
            !outbox_event_id.is_empty(),
            "receipt outbox identity must be present"
        );
    }
    Ok(())
}

#[allow(clippy::cognitive_complexity)] // reason: keep the single linear journey and its evidence order auditable.
pub async fn run() -> anyhow::Result<()> {
    let mqtt_fixture = testkit::mosquitto_mtls().await?;
    let offline = DraftDeviceSimulator::prime(harness::draft_device_config(
        &coordinate()?,
        &mqtt_fixture,
        WAIT,
    )?)
    .await?
    .go_offline()
    .await?;

    let postgres_fixture = testkit::owned_postgres().await?;
    let (evidence, app, reader) = migrate_verified_boundary(&postgres_fixture).await?;
    let pilot = start_pilot(app.params(), reader.params(), &mqtt_fixture).await?;
    wait_pilot_ready(&pilot).await?;

    let generation_two = wait_command_published(&evidence, &pilot, 2).await?;
    accept_generation(&pilot.repository, 2, "device-convergence-three.example").await?;
    let generation_three = wait_generation_three_supersedes_two(&evidence, &pilot).await?;
    assert_ne!(generation_two.command_id, generation_three.command_id);
    assert_eq!(generation_three.generation, 3);

    let expected =
        DraftCommandCoordinate::new(generation_three.generation, generation_three.fence_epoch)?;
    let mut device = offline.reconnect().await?;
    let command = device.receive_latest(expected).await?;
    assert_eq!(command.command_id(), generation_three.command_id);
    assert_eq!(command.coordinate(), expected);
    let command_artifact_digest = command.artifact_digest().to_owned();

    let ack_pause = tokio::time::timeout(WAIT, pilot.assembly.pause_receipt_relay_for_test())
        .await
        .context("pause and drain ACK receipt relay deadline")?;
    let pending_ack = device
        .send_ack(
            command,
            ACK_SEQUENCE,
            OBSERVED_AT_BASE + ACK_SEQUENCE as i64,
        )
        .await?;
    let ack_ingress = pending_ack.ingress_id().to_owned();
    let ack_evidence =
        wait_pending_receipt(&evidence, &pilot, &ack_ingress, "ack_received").await?;
    assert_eq!(
        command_state(&evidence, &generation_three.command_id).await?,
        "received"
    );
    let ready_after_ack: Option<String> = sqlx::query_scalar(
        "SELECT status FROM device_certificate_conditions \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND condition_type='Ready'",
    )
    .bind(TENANT)
    .bind(DEVICE)
    .fetch_optional(&evidence)
    .await?;
    assert_ne!(
        ready_after_ack.as_deref(),
        Some("True"),
        "ACK alone must not establish Ready=True"
    );
    ack_pause.resume();

    let (acknowledged, ack_receipt) = device.wait_ack_receipt(pending_ack).await?;
    assert_eq!(ack_receipt.ingress_id(), ack_ingress);
    assert_eq!(
        ack_receipt.correlation(),
        ack_evidence.receipt_event_id.as_bytes()
    );
    anyhow::ensure!(
        ack_receipt.committed_at() > 0,
        "ACK receipt must carry commit time"
    );
    wait_outbox_published(&evidence, &ack_evidence.receipt_event_id).await?;

    let artifact = load_artifact(&evidence, generation_three.generation).await?;
    assert_eq!(artifact.artifact_digest, command_artifact_digest);
    let applied = DraftAppliedArtifact::from_persisted(
        &artifact.eligibility,
        &artifact.artifact_digest,
        &artifact.expected_state_hash,
    )?;

    let report_pause = tokio::time::timeout(WAIT, pilot.assembly.pause_receipt_relay_for_test())
        .await
        .context("pause and drain report receipt relay deadline")?;
    let pending_report = device
        .send_matching_report(
            acknowledged,
            applied,
            REPORT_SEQUENCE,
            OBSERVED_AT_BASE + REPORT_SEQUENCE as i64,
        )
        .await?;
    let report_ingress = pending_report.ingress_id().to_owned();
    let report_evidence =
        wait_pending_receipt(&evidence, &pilot, &report_ingress, "report").await?;
    wait_converged(&evidence, &generation_three, &artifact).await?;
    report_pause.resume();

    let report_receipt = device.wait_report_receipt(pending_report).await?;
    assert_eq!(report_receipt.ingress_id(), report_ingress);
    assert_eq!(
        report_receipt.correlation(),
        report_evidence.receipt_event_id.as_bytes()
    );
    anyhow::ensure!(
        report_receipt.committed_at() > 0,
        "report receipt must carry commit time"
    );
    wait_outbox_published(&evidence, &report_evidence.receipt_event_id).await?;
    wait_converged(&evidence, &generation_three, &artifact).await?;
    assert_exact_receipt_set(&evidence, &ack_ingress, &report_ingress).await?;

    pilot.shutdown().await?;
    evidence.close().await;
    Ok(())
}

#[cfg(test)]
mod topic_authority {
    use super::*;

    #[tokio::test]
    async fn rss_transport_revision_is_not_topic_generation_authority() -> anyhow::Result<()> {
        let fixture = testkit::mosquitto_mtls().await?;
        let transport = fixture.rss_a();
        let device = fixture.device_current();
        assert_ne!(
            transport.revision(),
            device.revision(),
            "fixture must keep RSS transport revision distinct from device topic generation"
        );

        let config = harness::mqtt_session_config(&coordinate()?, &fixture)?;
        assert_eq!(config.policy().scopes().len(), 1);
        assert_eq!(config.credential_revision().get(), transport.revision());
        assert_eq!(
            config.policy().scopes()[0].generation().get(),
            device.revision()
        );
        assert_ne!(
            config.credential_revision().get(),
            config.policy().scopes()[0].generation().get()
        );
        Ok(())
    }
}
