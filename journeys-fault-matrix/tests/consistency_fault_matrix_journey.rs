//! N-028 consistency fault crash matrix journey.
//!
//! This package intentionally has no `sqlx` dependency. Postgres setup, typed observers, and
//! privileged fixture seeding are only reachable through `postgres::fault_matrix`.

#![cfg(feature = "integration")]

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use amqp::{AmqpPublisher, AmqpSubscriber};
use anyhow::{Context, Result, anyhow, bail};
use consistency::SeenState;
use deadpool_redis::{Config as RedisConfig, Runtime as RedisRuntime};
use diport::{
    AckAction, AckableSubscriber, Acker, DynPublisher, EnvelopeSubjectId, MessageId, OpaqueActorId,
    OutboxActor, PublishRequest, Publisher, Topic,
};
use eventexec::command::{CommandAliasKey, CommandIdempotencyKeyring};
use futures::StreamExt;
use futures::future::LocalBoxFuture;
use postgres::fault_matrix::{
    FaultMatrixDeadLetterEncoding, FaultMatrixDeadLetterSource, FaultMatrixDeadLetterSummary,
    FaultMatrixOutboxStatus, FaultMatrixPublishOutcome, PgFaultMatrixConfig, PgFaultMatrixHarness,
};
use redis::RedisRuntimeDeps;
use testkit::crash_matrix::{CrashCase, CrashFaultSpec, CrashMatrix, CrashRunner, CrashStatus};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const RABBIT_VHOST: &str = "rss_fault_matrix";
const PROJECTION_OWNER: &str = "fault-matrix-projection";

type CaseRunFn = for<'a> fn(
    &'a CrashCase,
    &'a PgHarness,
    &'a RabbitHarness,
    &'a RedisHarness,
    &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>>;

struct ReadyCaseRunner {
    id: &'static str,
    fault_spec: CrashFaultSpec,
    runner: CrashRunner,
    run: CaseRunFn,
}

impl ReadyCaseRunner {
    const fn new(
        id: &'static str,
        fault_spec: CrashFaultSpec,
        runner: CrashRunner,
        run: CaseRunFn,
    ) -> Self {
        Self {
            id,
            fault_spec,
            runner,
            run,
        }
    }

    fn validate_case(&self, case: &CrashCase) -> Result<()> {
        let fault_spec = case.fault_spec()?;
        if fault_spec != self.fault_spec {
            bail!(
                "ready fixture `{}` maps to fault spec {:?}, but journey runner contract is {:?}",
                case.id(),
                fault_spec,
                self.fault_spec
            );
        }
        if case.runner() != self.runner {
            bail!(
                "ready fixture `{}` declares runner {:?}, but journey runner contract is {:?}",
                case.id(),
                case.runner(),
                self.runner
            );
        }
        if self.runner != self.fault_spec.expected_runner() {
            bail!(
                "journey runner `{}` binds {:?}, but fault spec expects {:?}",
                self.id,
                self.runner,
                self.fault_spec.expected_runner()
            );
        }
        if case.domain() != self.fault_spec.expected_domain() {
            bail!(
                "ready fixture `{}` declares domain `{}`, but fault spec expects `{}`",
                case.id(),
                case.domain(),
                self.fault_spec.expected_domain()
            );
        }
        if case.contract_id() != self.fault_spec.expected_contract_id() {
            bail!(
                "ready fixture `{}` declares contract `{}`, but fault spec expects `{}`",
                case.id(),
                case.contract_id(),
                self.fault_spec.expected_contract_id()
            );
        }
        Ok(())
    }
}

const READY_CASE_RUNNERS: &[ReadyCaseRunner] = &[
    ReadyCaseRunner::new(
        "outbox-after-publish-before-settle",
        CrashFaultSpec::OutboxAfterPublishBeforeSettle,
        CrashRunner::PostgresRabbitmq,
        run_outbox_after_publish_before_settle,
    ),
    ReadyCaseRunner::new(
        "outbox-transient-publish-failure",
        CrashFaultSpec::OutboxTransientPublishFailure,
        CrashRunner::Postgres,
        run_outbox_transient_publish_failure,
    ),
    ReadyCaseRunner::new(
        "outbox-permanent-publish-failure",
        CrashFaultSpec::OutboxPermanentPublishFailure,
        CrashRunner::Postgres,
        run_outbox_permanent_publish_failure,
    ),
    ReadyCaseRunner::new(
        "inbox-claim-crash-before-commit",
        CrashFaultSpec::InboxClaimCrashBeforeCommit,
        CrashRunner::Postgres,
        run_inbox_claim_crash_before_commit,
    ),
    ReadyCaseRunner::new(
        "inbox-commit-before-ack-crash",
        CrashFaultSpec::InboxCommitBeforeAckCrash,
        CrashRunner::PostgresRabbitmq,
        run_inbox_commit_before_ack_crash,
    ),
    ReadyCaseRunner::new(
        "inbox-lease-lost-before-commit",
        CrashFaultSpec::InboxLeaseLostBeforeCommit,
        CrashRunner::Postgres,
        run_inbox_lease_lost_before_commit,
    ),
    ReadyCaseRunner::new(
        "saga-forward-completed-before-checkpoint",
        CrashFaultSpec::SagaForwardCompletedBeforeCheckpoint,
        CrashRunner::PostgresRedis,
        run_saga_forward_completed_before_checkpoint,
    ),
    ReadyCaseRunner::new(
        "saga-compensation-interrupted",
        CrashFaultSpec::SagaCompensationInterrupted,
        CrashRunner::PostgresRedis,
        run_saga_compensation_interrupted,
    ),
    ReadyCaseRunner::new(
        "projection-after-apply-before-checkpoint",
        CrashFaultSpec::ProjectionAfterApplyBeforeCheckpoint,
        CrashRunner::Postgres,
        run_projection_after_apply_before_checkpoint,
    ),
    ReadyCaseRunner::new(
        "projection-stale-checkpoint-writer",
        CrashFaultSpec::ProjectionStaleCheckpointWriter,
        CrashRunner::Postgres,
        run_projection_stale_checkpoint_writer,
    ),
    ReadyCaseRunner::new(
        "reconcile-dispatch-before-result-record",
        CrashFaultSpec::ReconcileDispatchBeforeResultRecord,
        CrashRunner::Postgres,
        run_reconcile_dispatch_before_result_record,
    ),
    ReadyCaseRunner::new(
        "reconcile-lease-lost-before-write",
        CrashFaultSpec::ReconcileLeaseLostBeforeWrite,
        CrashRunner::Postgres,
        run_reconcile_lease_lost_before_write,
    ),
];

struct RunScope {
    tenant: vocab::TenantId,
    suffix: String,
}

impl RunScope {
    fn new() -> Result<Self> {
        Ok(Self {
            tenant: vocab::TenantId::parse(&Uuid::new_v4().to_string())?,
            suffix: Uuid::new_v4().simple().to_string(),
        })
    }

    fn event_id(&self, case: &CrashCase) -> String {
        format!("{}-{}", case.id(), self.suffix)
    }

    fn name(&self, prefix: &str) -> String {
        format!("{prefix}-{}", self.suffix)
    }

    fn rabbit_topic(&self, name: &str) -> String {
        let canonical = name.replace('-', ".");
        format!("rss.fm.{canonical}.run{}", self.suffix)
    }
}

struct PgHarness {
    _fixture: testkit::PgFixture,
    harness: PgFaultMatrixHarness,
}

struct RabbitHarness {
    _fixture: testkit::RabbitFixture,
    url: String,
}

struct RedisHarness {
    _fixture: testkit::RedisFixture,
    deps: RedisRuntimeDeps,
}

fn workspace_root() -> Result<std::path::PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("journeys-fault-matrix manifest should have workspace parent"))
}

async fn pg_harness() -> Result<PgHarness> {
    let fixture = testkit::env_or_postgres().await?;
    let p = fixture.params();
    let config = PgFaultMatrixConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        p.password.clone(),
    );
    let harness = PgFaultMatrixHarness::setup(
        config,
        generated::event::PROJECTION_INPUT_GENERATION,
        generated::event::PROJECTION_INPUTS,
    )
    .await?;
    Ok(PgHarness {
        _fixture: fixture,
        harness,
    })
}

async fn rabbit_harness() -> Result<RabbitHarness> {
    let fixture = testkit::env_or_rabbitmq().await?;
    let url = fixture.vhost_url(RABBIT_VHOST).await?;
    Ok(RabbitHarness {
        _fixture: fixture,
        url,
    })
}

async fn redis_harness() -> Result<RedisHarness> {
    let fixture = testkit::env_or_redis().await?;
    let pool = RedisConfig::from_url(fixture.url()).create_pool(Some(RedisRuntime::Tokio1))?;
    Ok(RedisHarness {
        _fixture: fixture,
        deps: RedisRuntimeDeps::setup(pool),
    })
}

fn amqp_endpoint(url: &str) -> Result<secure::AmqpEndpoint> {
    Ok(secure::AmqpEndpoint::parse(
        url,
        secure::PlaintextEndpointPolicy::AllowLoopback,
    )?)
}

async fn connect_publisher(url: &str, name: &str) -> Result<AmqpPublisher> {
    Ok(AmqpPublisher::connect(&amqp_endpoint(url)?, name).await?)
}

async fn connect_subscriber(url: &str, name: &str) -> Result<AmqpSubscriber> {
    Ok(AmqpSubscriber::connect(&amqp_endpoint(url)?, name).await?)
}

async fn rabbit_unsettled_redelivers(
    rabbit: &RabbitHarness,
    scope: &RunScope,
    topic_raw: &str,
    event_id: &str,
) -> Result<()> {
    let topic = Topic::new(topic_raw);
    let sub1 = connect_subscriber(&rabbit.url, &scope.name("fault-matrix-sub1")).await?;
    let token1 = CancellationToken::new();
    let mut stream1 = sub1
        .subscribe_ackable(topic.clone(), token1.clone())
        .await?;
    let publisher = connect_publisher(&rabbit.url, &scope.name("fault-matrix-pub")).await?;

    publisher
        .publish(PublishRequest::new(
            topic.clone(),
            MessageId::new(event_id),
            b"fault-matrix".to_vec(),
        ))
        .await?;

    let delivery = tokio::time::timeout(Duration::from_secs(5), stream1.next())
        .await
        .context("timeout waiting for first delivery")?
        .ok_or_else(|| anyhow!("first stream closed"))?;
    let _unsettled = delivery.acker;
    drop(stream1);
    token1.cancel();
    AckableSubscriber::shutdown(&sub1).await?;

    let sub2 = connect_subscriber(&rabbit.url, &scope.name("fault-matrix-sub2")).await?;
    let token2 = CancellationToken::new();
    let mut stream2 = sub2
        .subscribe_ackable(topic.clone(), token2.clone())
        .await?;
    let redelivery = tokio::time::timeout(Duration::from_secs(5), stream2.next())
        .await
        .context("timeout waiting for redelivery")?
        .ok_or_else(|| anyhow!("redelivery stream closed"))?;
    if redelivery.message.id.as_str() != event_id {
        bail!(
            "redelivery id = {}, expected {event_id}",
            redelivery.message.id.as_str()
        );
    }
    redelivery.acker.settle(AckAction::Ack).await?;
    token2.cancel();
    AckableSubscriber::shutdown(&sub2).await?;
    Publisher::shutdown(&publisher).await?;
    Ok(())
}

#[allow(clippy::cognitive_complexity)]
// reason: fault-matrix journey 顺序表达三次真实 broker 交付/结算状态；拆分会隐藏同一连接生命周期。
async fn outbox_publish_before_settle_redelivers(
    pg: &PgHarness,
    rabbit: &RabbitHarness,
    scope: &RunScope,
    topic_raw: &str,
    event_id: &str,
) -> Result<()> {
    let topic = Topic::new(topic_raw);
    let sub1 = connect_subscriber(&rabbit.url, &scope.name("fault-matrix-outbox-sub1")).await?;
    let token1 = CancellationToken::new();
    let mut stream1 = sub1
        .subscribe_ackable(topic.clone(), token1.clone())
        .await?;
    let publisher = connect_publisher(&rabbit.url, &scope.name("fault-matrix-outbox-pub")).await?;

    pg.harness
        .publish_outbox_before_settle(
            scope.tenant,
            event_id,
            topic_raw,
            DynPublisher::new_box(publisher),
        )
        .await?;

    let delivery = tokio::time::timeout(Duration::from_secs(5), stream1.next())
        .await
        .context("timeout waiting for outbox delivery")?
        .ok_or_else(|| anyhow!("outbox stream closed"))?;
    let _unsettled = delivery.acker;
    drop(stream1);
    token1.cancel();
    AckableSubscriber::shutdown(&sub1).await?;

    let sub2 = connect_subscriber(&rabbit.url, &scope.name("fault-matrix-outbox-sub2")).await?;
    let token2 = CancellationToken::new();
    let mut stream2 = sub2
        .subscribe_ackable(topic.clone(), token2.clone())
        .await?;
    let redelivery = tokio::time::timeout(Duration::from_secs(5), stream2.next())
        .await
        .context("timeout waiting for outbox redelivery")?
        .ok_or_else(|| anyhow!("outbox redelivery stream closed"))?;
    if redelivery.message.id.as_str() != event_id {
        bail!(
            "outbox redelivery id = {}, expected {event_id}",
            redelivery.message.id.as_str()
        );
    }
    redelivery.acker.settle(AckAction::Ack).await?;
    token2.cancel();
    AckableSubscriber::shutdown(&sub2).await?;

    let sub3 = connect_subscriber(&rabbit.url, &scope.name("fault-matrix-outbox-sub3")).await?;
    let token3 = CancellationToken::new();
    let mut stream3 = sub3.subscribe_ackable(topic, token3.clone()).await?;
    let recovery_publisher =
        connect_publisher(&rabbit.url, &scope.name("fault-matrix-outbox-recovery-pub")).await?;
    pg.harness
        .recover_stale_outbox_publish(
            scope.tenant,
            event_id,
            "identity",
            DynPublisher::new_box(recovery_publisher),
        )
        .await?;
    let recovered = tokio::time::timeout(Duration::from_secs(5), stream3.next())
        .await
        .context("timeout waiting for outbox recovery publish")?
        .ok_or_else(|| anyhow!("outbox recovery stream closed"))?;
    if recovered.message.id.as_str() != event_id {
        bail!(
            "outbox recovery id = {}, expected {event_id}",
            recovered.message.id.as_str()
        );
    }
    recovered.acker.settle(AckAction::Ack).await?;
    token3.cancel();
    AckableSubscriber::shutdown(&sub3).await?;
    Ok(())
}

async fn run_case(
    case: &CrashCase,
    pg: &PgHarness,
    rabbit: &RabbitHarness,
    redis: &RedisHarness,
    scope: &RunScope,
) -> Result<()> {
    let runner = ready_case_runner(case.id())
        .ok_or_else(|| anyhow!("ready fixture has no runner function: {}", case.id()))?;
    runner.validate_case(case)?;
    (runner.run)(case, pg, rabbit, redis, scope).await
}

fn ready_case_runner(id: &str) -> Option<&'static ReadyCaseRunner> {
    READY_CASE_RUNNERS.iter().find(|runner| runner.id == id)
}

fn run_outbox_after_publish_before_settle<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let event_id = scope.event_id(case);
        let topic = scope.rabbit_topic("outbox-settle");
        outbox_publish_before_settle_redelivers(pg, rabbit, scope, &topic, &event_id).await?;
        assert_outbox_count(
            pg,
            scope.tenant,
            &event_id,
            FaultMatrixOutboxStatus::Published,
            1,
        )
        .await
    })
}

fn run_outbox_transient_publish_failure<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let event_id = scope.event_id(case);
        pg.harness
            .run_outbox_publish(
                scope.tenant,
                &event_id,
                "settings",
                "settings.config-version-changed",
                "settings.config-version-changed",
                FaultMatrixPublishOutcome::Transient,
            )
            .await?;
        assert_outbox_count(
            pg,
            scope.tenant,
            &event_id,
            FaultMatrixOutboxStatus::Pending,
            1,
        )
        .await
    })
}

fn run_outbox_permanent_publish_failure<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let event_id = scope.event_id(case);
        pg.harness
            .run_outbox_publish(
                scope.tenant,
                &event_id,
                "identity",
                "identity.role-assigned",
                "identity.role-assigned",
                FaultMatrixPublishOutcome::Permanent,
            )
            .await?;
        let dlx = pg
            .harness
            .outbox_dead_letter(scope.tenant, &event_id)
            .await?;
        if dlx.source() != FaultMatrixDeadLetterSource::OutboxRelay {
            bail!(
                "outbox DLX source should be outbox relay, got {:?}",
                dlx.source()
            );
        }
        if dlx.summary() != FaultMatrixDeadLetterSummary::OutboxRelayPublishFailed {
            bail!(
                "outbox DLX summary should be relay publish failure, got {:?}",
                dlx.summary()
            );
        }
        if dlx.encoding() != FaultMatrixDeadLetterEncoding::KeyProviderV1 {
            bail!(
                "outbox DLX payload should use protected encoding, got {:?}",
                dlx.encoding()
            );
        }
        if dlx.original_entry_payload_len() != 1 {
            bail!(
                "outbox DLX should record original payload length 1, got {}",
                dlx.original_entry_payload_len()
            );
        }
        assert_outbox_count(pg, scope.tenant, &event_id, FaultMatrixOutboxStatus::Dlx, 1).await
    })
}

fn run_inbox_claim_crash_before_commit<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let state = pg
            .harness
            .reclaim_stale_inbox_claim(
                scope.tenant,
                &scope.event_id(case),
                &scope.name("audit.session-created"),
            )
            .await?;
        if state != SeenState::Fresh {
            bail!("stale inbox claim should be reclaimable, got {state:?}");
        }
        Ok(())
    })
}

fn run_inbox_commit_before_ack_crash<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let event_id = scope.event_id(case);
        let state = pg
            .harness
            .commit_then_redeliver_inbox(
                scope.tenant,
                &event_id,
                &scope.name("audit.session-created"),
            )
            .await?;
        if state != SeenState::Duplicate {
            bail!("inbox redelivery should dedupe after commit, got {state:?}");
        }
        rabbit_unsettled_redelivers(
            rabbit,
            scope,
            &scope.rabbit_topic("inbox-commit"),
            &event_id,
        )
        .await
    })
}

fn run_inbox_lease_lost_before_commit<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let outcome = pg
            .harness
            .stale_inbox_lease_commit(
                scope.tenant,
                &scope.event_id(case),
                &scope.name("audit.session-created"),
            )
            .await?;
        if !matches!(outcome, consistency::LeaseOutcome::Lost) {
            bail!("stale inbox lease should not commit, got {outcome:?}");
        }
        Ok(())
    })
}

fn run_saga_forward_completed_before_checkpoint<'a>(
    _case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let probe = pg
            .harness
            .saga_forward_resume_skips_completed(
                scope.tenant,
                Uuid::new_v4(),
                generated::saga::billing_v1::SPEC,
                redis.deps.infra().lock_store_handle(),
            )
            .await?;
        if probe.reserve_forward_count() != 0 || probe.charge_forward_count() != 1 {
            bail!(
                "saga forward resume should skip reserve and run charge once, got reserve={} charge={}",
                probe.reserve_forward_count(),
                probe.charge_forward_count()
            );
        }
        if probe.reserve_compensation_count() != 0 || probe.charge_compensation_count() != 0 {
            bail!(
                "saga forward resume should not compensate, got reserve={} charge={}",
                probe.reserve_compensation_count(),
                probe.charge_compensation_count()
            );
        }
        Ok(())
    })
}

fn run_saga_compensation_interrupted<'a>(
    _case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let probe = pg
            .harness
            .saga_compensation_resume_once(
                scope.tenant,
                Uuid::new_v4(),
                generated::saga::billing_v1::SPEC,
                redis.deps.infra().lock_store_handle(),
            )
            .await?;
        if probe.reserve_compensation_count() != 1 || probe.charge_compensation_count() != 1 {
            bail!(
                "saga compensation resume should undo charge and reserve once, got reserve={} charge={}",
                probe.reserve_compensation_count(),
                probe.charge_compensation_count()
            );
        }
        if probe.reserve_forward_count() != 0 || probe.charge_forward_count() != 0 {
            bail!(
                "saga compensation resume should not rerun forward, got reserve={} charge={}",
                probe.reserve_forward_count(),
                probe.charge_forward_count()
            );
        }
        Ok(())
    })
}

fn run_projection_after_apply_before_checkpoint<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let probe = pg
            .harness
            .projection_replay_after_checkpoint_failure(
                PROJECTION_OWNER,
                &scope.name(case.id()),
                scope.tenant,
            )
            .await?;
        if probe.apply_calls() != 2 || probe.unique_applied() != 1 {
            bail!(
                "projection replay should apply twice idempotently to one unique lsn, got calls={} unique={}",
                probe.apply_calls(),
                probe.unique_applied()
            );
        }
        if probe.checkpoint_offset().get() != 10 {
            bail!(
                "projection replay should keep idempotent offset, got {}",
                probe.checkpoint_offset().get()
            );
        }
        Ok(())
    })
}

fn run_projection_stale_checkpoint_writer<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let outcome = pg
            .harness
            .stale_projection_checkpoint_writer(PROJECTION_OWNER, &scope.name(case.id()))
            .await?;
        if !matches!(outcome, diport::SaveOutcome::StaleVersion) {
            bail!("stale checkpoint writer should be fenced, got {outcome:?}");
        }
        Ok(())
    })
}

fn run_reconcile_dispatch_before_result_record<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let event_id = scope.name("reconcile-dispatch-v1");
        let keyring = CommandIdempotencyKeyring::new(
            CommandAliasKey::new("fault-matrix", vec![0x42; 32])?,
            Vec::new(),
        )?;
        let command = || {
            eventexec::ReviewedCommand::from_spec(
                generated::command::_seed_v1::reconcile_command(
                    generated::command::_seed_v1::SeedDoThingRequest {
                        amount: 1,
                        target_id: format!("resource-{event_id}"),
                    },
                    scope.tenant,
                    EnvelopeSubjectId::from_opaque(format!("resource-{event_id}"))?,
                    OutboxActor::service(OpaqueActorId::from_opaque("fault-matrix")?),
                    event_id.clone(),
                ),
                &keyring,
            )
            .map_err(anyhow::Error::from)
        };
        let count = pg
            .harness
            .reconcile_dispatch_key_stable(scope.tenant, &event_id, [command()?, command()?])
            .await
            .with_context(|| format!("{} stable dispatch key invariant failed", case.id()))?;
        if count != 1 {
            bail!("stable dispatch key should create one outbox row, got {count}");
        }
        Ok(())
    })
}

fn run_reconcile_lease_lost_before_write<'a>(
    _case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let outcome = pg
            .harness
            .stale_reconcile_lease_is_rejected(scope.tenant, &scope.name("resource-b"))
            .await?;
        if !matches!(outcome, postgres::ReconcileLeaseOutcome::Lost) {
            bail!("stale reconcile lease should be fenced, got {outcome:?}");
        }
        Ok(())
    })
}

async fn assert_outbox_count(
    pg: &PgHarness,
    tenant: vocab::TenantId,
    event_id: &str,
    status: FaultMatrixOutboxStatus,
    expected: i64,
) -> Result<()> {
    let got = pg.harness.outbox_count(tenant, event_id, status).await?;
    if got != expected {
        bail!("outbox {event_id} status {status:?} count = {got}, expected {expected}",);
    }
    Ok(())
}

fn finish_with_pg_cleanup(body: Result<()>, cleanup: Result<()>) -> Result<()> {
    match (body, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(body), Ok(())) => Err(body),
        (Ok(()), Err(cleanup)) => Err(cleanup).context("shut down fault-matrix postgres"),
        (Err(body), Err(cleanup)) => {
            Err(body).context(format!("postgres cleanup also failed: {cleanup:#}"))
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn consistency_fault_matrix_ready_cases_execute() -> Result<()> {
    let root = workspace_root()?;
    let matrix = CrashMatrix::from_fixture_dir(root.join("fixtures").join("consistency"))?;
    let ready: Vec<&CrashCase> = matrix
        .cases()
        .iter()
        .filter(|case| case.status() == CrashStatus::Ready)
        .collect();
    if ready.len() != READY_CASE_RUNNERS.len() {
        bail!(
            "N-028 expects exactly {} ready cases, got {}",
            READY_CASE_RUNNERS.len(),
            ready.len()
        );
    }

    let mapped: BTreeSet<&str> = ready.iter().map(|case| case.id()).collect();
    let expected: BTreeSet<&str> = READY_CASE_RUNNERS.iter().map(|runner| runner.id).collect();
    if expected.len() != READY_CASE_RUNNERS.len() {
        bail!("READY_CASE_RUNNERS contains duplicate ids");
    }
    if mapped != expected {
        bail!("ready fixture ids drifted: got {mapped:?}, expected {expected:?}");
    }

    let scope = RunScope::new()?;
    let pg = pg_harness().await?;
    let body_result: Result<()> = async {
        let rabbit = rabbit_harness().await?;
        let redis = redis_harness().await?;
        for case in ready {
            run_case(case, &pg, &rabbit, &redis, &scope)
                .await
                .with_context(|| format!("fault matrix case `{}` failed", case.id()))?;
        }
        Ok(())
    }
    .await;

    let PgHarness { _fixture, harness } = pg;
    let cleanup_result = harness.shutdown().await;
    finish_with_pg_cleanup(body_result, cleanup_result)
}

#[test]
fn pg_cleanup_result_preserves_body_error_and_reports_cleanup_failure() -> Result<()> {
    let err = finish_with_pg_cleanup(Err(anyhow!("body failed")), Err(anyhow!("cleanup failed")))
        .err()
        .ok_or_else(|| anyhow!("both failures must remain an error"))?;
    let rendered = format!("{err:#}");
    assert!(rendered.contains("body failed"));
    assert!(rendered.contains("cleanup failed"));
    Ok(())
}

#[test]
fn pg_cleanup_result_returns_cleanup_only_failure() -> Result<()> {
    let err = finish_with_pg_cleanup(Ok(()), Err(anyhow!("cleanup failed")))
        .err()
        .ok_or_else(|| anyhow!("cleanup failure must be returned"))?;
    assert!(format!("{err:#}").contains("cleanup failed"));
    Ok(())
}

#[test]
fn pg_cleanup_result_preserves_success_and_body_only_failure() -> Result<()> {
    finish_with_pg_cleanup(Ok(()), Ok(()))?;
    let err = finish_with_pg_cleanup(Err(anyhow!("body failed")), Ok(()))
        .err()
        .ok_or_else(|| anyhow!("body failure must be returned"))?;
    assert_eq!(format!("{err:#}"), "body failed");
    Ok(())
}
