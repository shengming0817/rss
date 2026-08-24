//! N-028 consistency fault crash matrix journey.
//!
//! This package intentionally has no `sqlx` dependency. Postgres setup, typed observers, and
//! privileged fixture seeding are only reachable through `postgres::fault_matrix`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use amqp::{AmqpPublisher, AmqpSubscriber};
use anyhow::{Context, Result, anyhow, bail};
use consistency::{Disposition, IdemKey, SeenState};
use deadpool_redis::{Config as RedisConfig, Runtime as RedisRuntime};
use diport::{
    AckAction, AckableSubscriber, Acker, DynPublisher, EnvelopeMetadata, ManagedResource,
    MessageId, PublishRequest, Publisher, PublisherError, Topic,
};
use futures::StreamExt;
use futures::future::LocalBoxFuture;
use postgres::fault_matrix::{
    FaultMatrixConsumerDelivery, FaultMatrixDeadLetterEncoding, FaultMatrixDeadLetterSource,
    FaultMatrixDeadLetterSummary, FaultMatrixExpiredSettlementObservation,
    FaultMatrixOutboxRetryObservation, FaultMatrixOutboxStatus, FaultMatrixPublishOutcome,
    FaultMatrixSessionCreatedEffectObservation, FaultMatrixSessionCreatedInput,
    FaultMatrixSessionCreatedRelayObservation, FaultMatrixSettlementOutcome,
    FaultMatrixStaleSettlementObservation, PgFaultMatrixConfig, PgFaultMatrixHarness,
    PgFaultMatrixLoginCredentials, fault_matrix_relay_budget,
};
use redis::RedisRuntimeDeps;
use testkit::crash_matrix::{
    CrashCase, CrashExecutionKind, CrashFaultSpec, CrashMatrix, CrashMechanism, CrashRunner,
    CrashStatus,
};
use testkit::eventing_conformance::{
    ConsumerDuplicateEffectConformancePassed, ConsumerDuplicateEffectObservation, EventingIds,
    SettleAction, assert_consumer_duplicate_effect_conformance,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const RABBIT_VHOST: &str = "rss_fault_matrix";
const PROJECTION_OWNER: &str = "fault-matrix-projection";
const TEST_OCCURRED_AT: i64 = 1_700_000_000;

fn complete_publish_request(
    topic: Topic,
    event_id: MessageId,
    payload: Vec<u8>,
    tenant: rss_request_context::TenantId,
) -> PublishRequest {
    let contract = generated::event::identity_v1::session_created::CONTRACT;
    let mut metadata = EnvelopeMetadata::empty();
    metadata.insert_wire_pair(diport::KEY_TENANT_ID, tenant.to_string());
    metadata.insert_wire_pair(diport::KEY_OCCURRED_AT, TEST_OCCURRED_AT.to_string());
    metadata.insert_wire_pair(diport::KEY_SCHEMA_VERSION, contract.version());
    metadata.insert_wire_pair(diport::KEY_SCHEMA_HASH, contract.schema_hash());
    PublishRequest::new(topic, event_id, payload).with_metadata(metadata)
}

/// INVARIANT: CONSISTENCY-READY-CONTRACT-BINDING-01 { level = "Hard", exec = "native-compile", source = "code", native = "each ready case carries one generated ContractBinding and CrashFaultSpec dispatch is exhaustive" }
struct ReadyCaseRunner {
    id: &'static str,
    fault_spec: CrashFaultSpec,
    runner: CrashRunner,
    contract: vocab::ContractBinding,
    run: CaseRunnerFn,
}

type NormalCaseRunnerFn = for<'a> fn(
    &'a ReadyCaseRunner,
    &'a CrashCase,
    &'a PgHarness,
    &'a RabbitHarness,
    &'a RedisHarness,
    &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>>;

type ConfirmLostCaseRunnerFn =
    for<'a> fn(
        &'a ReadyCaseRunner,
        &'a CrashCase,
        &'a PgHarness,
        &'a RabbitHarness,
        &'a RedisHarness,
        &'a RunScope,
    ) -> LocalBoxFuture<'a, Result<ConfirmLostCriticalEvidence>>;

type StaleContenderCaseRunnerFn =
    for<'a> fn(
        &'a ReadyCaseRunner,
        &'a CrashCase,
        &'a PgHarness,
        &'a RabbitHarness,
        &'a RedisHarness,
        &'a RunScope,
    ) -> LocalBoxFuture<'a, Result<FaultMatrixStaleSettlementObservation>>;

type DeadlineExpiredCaseRunnerFn =
    for<'a> fn(
        &'a ReadyCaseRunner,
        &'a CrashCase,
        &'a PgHarness,
        &'a RabbitHarness,
        &'a RedisHarness,
        &'a RunScope,
    ) -> LocalBoxFuture<'a, Result<FaultMatrixExpiredSettlementObservation>>;

#[derive(Clone, Copy)]
enum CaseRunnerFn {
    Normal(NormalCaseRunnerFn),
    ConfirmLost(ConfirmLostCaseRunnerFn),
    StaleContender(StaleContenderCaseRunnerFn),
    DeadlineExpired(DeadlineExpiredCaseRunnerFn),
}

#[derive(Debug)]
struct ConfirmLostCriticalEvidence {
    _first_relay: FaultMatrixSessionCreatedRelayObservation,
    _retry_relay: FaultMatrixSessionCreatedRelayObservation,
    _effect: FaultMatrixSessionCreatedEffectObservation,
    _duplicate_conformance: ConsumerDuplicateEffectConformancePassed,
}

impl ReadyCaseRunner {
    const fn assert_execution_kind(fault_spec: CrashFaultSpec, expected: CrashExecutionKind) {
        match (fault_spec.execution_kind(), expected) {
            (CrashExecutionKind::Normal, CrashExecutionKind::Normal)
            | (CrashExecutionKind::ConfirmLost, CrashExecutionKind::ConfirmLost)
            | (CrashExecutionKind::StaleContender, CrashExecutionKind::StaleContender)
            | (CrashExecutionKind::DeadlineExpired, CrashExecutionKind::DeadlineExpired) => {}
            _ => panic!("crash fault spec uses the wrong typed journey constructor"),
        }
    }

    const fn new(
        id: &'static str,
        fault_spec: CrashFaultSpec,
        runner: CrashRunner,
        contract: vocab::ContractBinding,
        run: NormalCaseRunnerFn,
    ) -> Self {
        Self::assert_execution_kind(fault_spec, CrashExecutionKind::Normal);
        Self {
            id,
            fault_spec,
            runner,
            contract,
            run: CaseRunnerFn::Normal(run),
        }
    }

    const fn confirm_lost(
        id: &'static str,
        fault_spec: CrashFaultSpec,
        runner: CrashRunner,
        contract: vocab::ContractBinding,
        run: ConfirmLostCaseRunnerFn,
    ) -> Self {
        Self::assert_execution_kind(fault_spec, CrashExecutionKind::ConfirmLost);
        Self {
            id,
            fault_spec,
            runner,
            contract,
            run: CaseRunnerFn::ConfirmLost(run),
        }
    }

    const fn stale_contender(
        id: &'static str,
        fault_spec: CrashFaultSpec,
        runner: CrashRunner,
        contract: vocab::ContractBinding,
        run: StaleContenderCaseRunnerFn,
    ) -> Self {
        Self::assert_execution_kind(fault_spec, CrashExecutionKind::StaleContender);
        Self {
            id,
            fault_spec,
            runner,
            contract,
            run: CaseRunnerFn::StaleContender(run),
        }
    }

    const fn deadline_expired(
        id: &'static str,
        fault_spec: CrashFaultSpec,
        runner: CrashRunner,
        contract: vocab::ContractBinding,
        run: DeadlineExpiredCaseRunnerFn,
    ) -> Self {
        Self::assert_execution_kind(fault_spec, CrashExecutionKind::DeadlineExpired);
        Self {
            id,
            fault_spec,
            runner,
            contract,
            run: CaseRunnerFn::DeadlineExpired(run),
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
        if case.domain() != self.contract.domain() {
            bail!(
                "ready fixture `{}` declares domain `{}`, but generated contract binds `{}`",
                case.id(),
                case.domain(),
                self.contract.domain()
            );
        }
        if case.contract_id() != self.contract.contract_id() {
            bail!(
                "ready fixture `{}` declares contract `{}`, but generated contract binds `{}`",
                case.id(),
                case.contract_id(),
                self.contract.contract_id()
            );
        }
        Ok(())
    }

    fn execute<'a>(
        &'a self,
        case: &'a CrashCase,
        pg: &'a PgHarness,
        rabbit: &'a RabbitHarness,
        redis: &'a RedisHarness,
        scope: &'a RunScope,
    ) -> LocalBoxFuture<'a, Result<()>> {
        match self.run {
            CaseRunnerFn::Normal(run) => run(self, case, pg, rabbit, redis, scope),
            CaseRunnerFn::ConfirmLost(run) => {
                Box::pin(async move { run(self, case, pg, rabbit, redis, scope).await.map(|_| ()) })
            }
            CaseRunnerFn::StaleContender(run) => {
                Box::pin(async move { run(self, case, pg, rabbit, redis, scope).await.map(|_| ()) })
            }
            CaseRunnerFn::DeadlineExpired(run) => {
                Box::pin(async move { run(self, case, pg, rabbit, redis, scope).await.map(|_| ()) })
            }
        }
    }
}

const READY_CASE_RUNNERS: &[ReadyCaseRunner] = &[
    ReadyCaseRunner::new(
        "outbox-after-publish-before-settle",
        CrashFaultSpec::OutboxAfterPublishBeforeSettle,
        CrashRunner::PostgresRabbitmq,
        generated::event::identity_v1::session_created::CONTRACT,
        run_outbox_after_publish_before_settle,
    ),
    ReadyCaseRunner::new(
        "outbox-transient-publish-failure",
        CrashFaultSpec::OutboxTransientPublishFailure,
        CrashRunner::Postgres,
        generated::event::settings_v1::CONTRACT,
        run_outbox_transient_publish_failure,
    ),
    ReadyCaseRunner::confirm_lost(
        "outbox-confirm-lost-channel-close",
        CrashFaultSpec::OutboxConfirmLostChannelClose,
        CrashRunner::PostgresRabbitmq,
        generated::event::identity_v1::session_created::CONTRACT,
        run_outbox_confirm_lost_channel_close,
    ),
    ReadyCaseRunner::stale_contender(
        "outbox-stale-contender-settle",
        CrashFaultSpec::OutboxStaleLeaseContender,
        CrashRunner::Postgres,
        generated::event::identity_v1::session_created::CONTRACT,
        run_outbox_stale_contender_settle,
    ),
    ReadyCaseRunner::deadline_expired(
        "outbox-deadline-expired-settle",
        CrashFaultSpec::OutboxLeaseDeadlineExpired,
        CrashRunner::Postgres,
        generated::event::identity_v1::session_created::CONTRACT,
        run_outbox_deadline_expired_settle,
    ),
    ReadyCaseRunner::new(
        "outbox-permanent-publish-failure",
        CrashFaultSpec::OutboxPermanentPublishFailure,
        CrashRunner::Postgres,
        generated::event::identity_v1::role_assigned::CONTRACT,
        run_outbox_permanent_publish_failure,
    ),
    ReadyCaseRunner::new(
        "outbox-policy-updated-transient-publish-failure",
        CrashFaultSpec::OutboxTransientPublishFailure,
        CrashRunner::Postgres,
        generated::event::identity_v1::policy_updated::CONTRACT,
        run_outbox_transient_publish_failure,
    ),
    ReadyCaseRunner::new(
        "outbox-security-event-transient-publish-failure",
        CrashFaultSpec::OutboxTransientPublishFailure,
        CrashRunner::Postgres,
        generated::event::identity_v1::security_event::CONTRACT,
        run_outbox_transient_publish_failure,
    ),
    ReadyCaseRunner::new(
        "outbox-role-revoked-permanent-publish-failure",
        CrashFaultSpec::OutboxPermanentPublishFailure,
        CrashRunner::Postgres,
        generated::event::identity_v1::role_revoked::CONTRACT,
        run_outbox_permanent_publish_failure,
    ),
    ReadyCaseRunner::new(
        "inbox-claim-crash-before-commit",
        CrashFaultSpec::InboxClaimCrashBeforeCommit,
        CrashRunner::Postgres,
        generated::event::identity_v1::session_created::CONTRACT,
        run_inbox_claim_crash_before_commit,
    ),
    ReadyCaseRunner::new(
        "inbox-commit-before-ack-crash",
        CrashFaultSpec::InboxCommitBeforeAckCrash,
        CrashRunner::PostgresRabbitmq,
        generated::event::identity_v1::session_created::CONTRACT,
        run_inbox_commit_before_ack_crash,
    ),
    ReadyCaseRunner::new(
        "inbox-lease-lost-before-commit",
        CrashFaultSpec::InboxLeaseLostBeforeCommit,
        CrashRunner::Postgres,
        generated::event::identity_v1::session_created::CONTRACT,
        run_inbox_lease_lost_before_commit,
    ),
    ReadyCaseRunner::new(
        "projection-after-apply-before-checkpoint",
        CrashFaultSpec::ProjectionAfterApplyBeforeCheckpoint,
        CrashRunner::Postgres,
        generated::projection::audit_v2::CONTRACT,
        run_projection_after_apply_before_checkpoint,
    ),
    ReadyCaseRunner::new(
        "projection-stale-checkpoint-writer",
        CrashFaultSpec::ProjectionStaleCheckpointWriter,
        CrashRunner::Postgres,
        generated::projection::settings_v3::CONTRACT,
        run_projection_stale_checkpoint_writer,
    ),
];

struct RunScope {
    tenant: rss_request_context::TenantId,
    suffix: String,
    event_ids: BTreeMap<&'static str, String>,
}

impl RunScope {
    fn new() -> Result<Self> {
        Ok(Self {
            tenant: rss_request_context::TenantId::parse(&Uuid::new_v4().to_string())?,
            suffix: Uuid::new_v4().simple().to_string(),
            event_ids: READY_CASE_RUNNERS
                .iter()
                .map(|runner| (runner.id, Uuid::new_v4().to_string()))
                .collect(),
        })
    }

    fn event_id(&self, case: &CrashCase) -> String {
        self.event_ids[case.id()].clone()
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
    _fixture: testkit::OwnedPgFixture,
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
    let fixture = testkit::owned_postgres().await?;
    let owned = &fixture;
    let p = owned.owner_params();
    let config = PgFaultMatrixConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        p.password.clone(),
    );
    let logins = PgFaultMatrixLoginCredentials::generate();
    owned
        .resolve_app_roles([
            testkit::PgAppRoleSpec::new(logins.serving_role(), logins.serving_password()),
            testkit::PgAppRoleSpec::new(logins.reader_role(), logins.reader_password()),
        ])
        .await?;
    let harness = PgFaultMatrixHarness::setup(
        config,
        logins,
        fault_matrix_relay_budget()?,
        eventexec::WorkflowRuntimePlan::disabled_fixture().projection_capture(),
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
        deps: RedisRuntimeDeps::setup_for_test(pool),
    })
}

fn amqp_endpoint(url: &str) -> Result<secure::AmqpEndpoint> {
    Ok(secure::AmqpEndpoint::parse(
        url,
        secure::PlaintextEndpointPolicy::AllowLoopback,
    )?)
}

async fn connect_publisher(url: &str, name: &str) -> Result<AmqpPublisher> {
    Ok(AmqpPublisher::connect_with_webpki_for_test(
        &amqp_endpoint(url)?,
        name,
        fault_matrix_relay_budget()?.publish_timeout(),
    )
    .await?)
}

async fn connect_subscriber(url: &str, name: &str) -> Result<AmqpSubscriber> {
    Ok(AmqpSubscriber::connect_with_webpki_for_test(&amqp_endpoint(url)?, name).await?)
}

#[derive(Clone)]
struct SharedAmqpPublisher(Arc<AmqpPublisher>);

impl Publisher for SharedAmqpPublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
        Publisher::publish(self.0.as_ref(), request).await
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        Publisher::shutdown(self.0.as_ref()).await
    }
}

async fn shutdown_amqp(
    token: &CancellationToken,
    subscriber: Option<&AmqpSubscriber>,
    publisher: &AmqpPublisher,
) -> Result<()> {
    token.cancel();
    let subscriber_result = match subscriber {
        Some(subscriber) => AckableSubscriber::shutdown(subscriber)
            .await
            .map_err(anyhow::Error::new),
        None => Ok(()),
    };
    let publisher_channel_result = Publisher::shutdown(publisher)
        .await
        .map_err(anyhow::Error::new);
    let publisher_resource_result = ManagedResource::shutdown(publisher)
        .await
        .map_err(anyhow::Error::new);

    let result = finish_with_cleanup(
        subscriber_result,
        publisher_channel_result,
        "shut down AMQP publisher channels",
    );
    finish_with_cleanup(
        result,
        publisher_resource_result,
        "shut down AMQP publisher transport",
    )
}

fn session_created_payload(
    tenant: rss_request_context::TenantId,
    session_id: Uuid,
) -> generated::event::identity_v1::session_created::IdentitySessionCreatedPayload {
    generated::event::identity_v1::session_created::IdentitySessionCreatedPayload {
        occurred_at: TEST_OCCURRED_AT,
        session_id,
        subject: Uuid::new_v4(),
        tenant_id: Uuid::from_bytes(tenant.octets()),
    }
}

async fn next_consumer_tx_delivery(
    pg: &PgHarness,
    ids: &EventingIds,
    deliveries: &mut diport::DeliveryStream,
    expected: FaultMatrixConsumerDelivery,
    wait_context: &'static str,
) -> Result<diport::Delivery> {
    let delivery = tokio::time::timeout(Duration::from_secs(5), deliveries.next())
        .await
        .context(wait_context)?
        .ok_or_else(|| anyhow!("session-created delivery stream closed"))?;
    if delivery.message.id().as_str() != ids.event_id {
        bail!(
            "session-created delivery id = {}, expected {}",
            delivery.message.id().as_str(),
            ids.event_id
        );
    }
    let observed = pg
        .harness
        .consume_session_created_delivery(&ids.consumer_group, delivery.message.clone())
        .await?;
    if observed != expected {
        bail!("session-created ConsumerTx delivery = {observed:?}, expected {expected:?}");
    }
    Ok(delivery)
}

async fn rabbit_unsettled_redelivers_through_consumer_tx(
    pg: &PgHarness,
    rabbit: &RabbitHarness,
    scope: &RunScope,
    event_id: &str,
    group: &str,
    session_id: Uuid,
) -> Result<()> {
    let ids = EventingIds::new(event_id, event_id, group, "redelivery-lease");
    let topic = Topic::new(generated::event::identity_v1::session_created::TOPIC);
    let publisher =
        Arc::new(connect_publisher(&rabbit.url, &scope.name("fault-matrix-pub")).await?);
    let mut token = CancellationToken::new();
    let mut subscriber =
        match connect_subscriber(&rabbit.url, &scope.name("fault-matrix-sub1")).await {
            Ok(subscriber) => Some(subscriber),
            Err(error) => {
                let cleanup = shutdown_amqp(&token, None, publisher.as_ref()).await;
                return finish_with_cleanup(
                    Err(error),
                    cleanup,
                    "shut down AMQP after subscriber setup failure",
                );
            }
        };

    let body_result: Result<()> = async {
        subscriber
            .as_ref()
            .ok_or_else(|| anyhow!("first AMQP subscriber missing"))?
            .purge_durable_queue_for_test(&topic)
            .await?;
        let mut stream1 = subscriber
            .as_ref()
            .ok_or_else(|| anyhow!("first AMQP subscriber missing"))?
            .subscribe_ackable(topic.clone(), token.clone())
            .await?;
        pg.harness
            .seed_session_created(FaultMatrixSessionCreatedInput::new(
                session_created_payload(scope.tenant, session_id),
                IdemKey::parse(event_id)?,
            )?)
            .await?;
        let relayed = pg
            .harness
            .relay_session_created_once(
                event_id,
                DynPublisher::new_box(SharedAmqpPublisher(Arc::clone(&publisher))),
            )
            .await?;
        if relayed.disposition() != Disposition::Ack
            || relayed.status() != FaultMatrixOutboxStatus::Published
        {
            bail!("session-created relay did not publish canonical delivery: {relayed:?}");
        }

        let delivery = next_consumer_tx_delivery(
            pg,
            &ids,
            &mut stream1,
            FaultMatrixConsumerDelivery::Committed,
            "timeout waiting for first delivery",
        )
        .await?;
        let _unsettled = delivery.acker;
        drop(stream1);
        token.cancel();
        AckableSubscriber::shutdown(
            subscriber
                .as_ref()
                .ok_or_else(|| anyhow!("first AMQP subscriber missing during shutdown"))?,
        )
        .await?;
        subscriber = None;

        token = CancellationToken::new();
        subscriber = Some(connect_subscriber(&rabbit.url, &scope.name("fault-matrix-sub2")).await?);
        let mut stream2 = subscriber
            .as_ref()
            .ok_or_else(|| anyhow!("redelivery AMQP subscriber missing"))?
            .subscribe_ackable(topic, token.clone())
            .await?;
        let redelivery = next_consumer_tx_delivery(
            pg,
            &ids,
            &mut stream2,
            FaultMatrixConsumerDelivery::Duplicate,
            "timeout waiting for redelivery",
        )
        .await?;
        redelivery.acker.settle(AckAction::Ack).await?;
        let effect = pg
            .harness
            .session_created_effect_observation(scope.tenant, event_id, group)
            .await?;
        assert_consumer_duplicate_effect_conformance(
            &ids,
            &ConsumerDuplicateEffectObservation {
                business_mutations: effect.business_mutations(),
                inbox_done_rows: effect.inbox_done_rows(),
                duplicate_settle: SettleAction::Ack,
            },
        )?;
        Ok(())
    }
    .await;
    let cleanup_result = shutdown_amqp(&token, subscriber.as_ref(), publisher.as_ref()).await;
    finish_with_cleanup(
        body_result,
        cleanup_result,
        "shut down inbox-redelivery AMQP resources",
    )
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
    if redelivery.message.id().as_str() != event_id {
        bail!(
            "outbox redelivery id = {}, expected {event_id}",
            redelivery.message.id().as_str()
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
    if recovered.message.id().as_str() != event_id {
        bail!(
            "outbox recovery id = {}, expected {event_id}",
            recovered.message.id().as_str()
        );
    }
    recovered.acker.settle(AckAction::Ack).await?;
    token3.cancel();
    AckableSubscriber::shutdown(&sub3).await?;
    Ok(())
}

fn ready_case_runner(id: &str) -> Option<&'static ReadyCaseRunner> {
    READY_CASE_RUNNERS.iter().find(|runner| runner.id == id)
}

fn run_outbox_after_publish_before_settle<'a>(
    _runner: &'a ReadyCaseRunner,
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
    runner: &'a ReadyCaseRunner,
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let contract = runner.contract;
        let event_id = scope.event_id(case);
        pg.harness
            .run_outbox_publish(
                scope.tenant,
                &event_id,
                contract.domain(),
                contract.contract_id(),
                contract.contract_id(),
                FaultMatrixPublishOutcome::Transient,
            )
            .await?;
        let observation = pg
            .harness
            .outbox_retry_observation(scope.tenant, &event_id)
            .await?;
        assert_transient_outbox_retry(&event_id, observation)
    })
}

fn assert_transient_outbox_retry(
    event_id: &str,
    observation: FaultMatrixOutboxRetryObservation,
) -> Result<()> {
    if observation.status() != FaultMatrixOutboxStatus::Pending {
        bail!(
            "transient outbox {event_id} status = {:?}, expected Pending",
            observation.status()
        );
    }
    if observation.retry_count() != 1 {
        bail!(
            "transient outbox {event_id} retry_count = {}, expected 1",
            observation.retry_count()
        );
    }
    if !observation.retry_after_scheduled() {
        bail!("transient outbox {event_id} retry_after was not scheduled after updated_at");
    }
    if !observation.lease_cleared() {
        bail!("transient outbox {event_id} retained a lease after requeue");
    }
    Ok(())
}

fn run_outbox_confirm_lost_channel_close<'a>(
    _runner: &'a ReadyCaseRunner,
    case: &'a CrashCase,
    pg: &'a PgHarness,
    rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<ConfirmLostCriticalEvidence>> {
    Box::pin(async move {
        let event_id = scope.event_id(case);
        let group = scope.name("audit.session-created-confirm-lost");
        let session_id = Uuid::new_v4();
        let topic = Topic::new(generated::event::identity_v1::session_created::TOPIC);
        let token = CancellationToken::new();
        let publisher = Arc::new(
            connect_publisher(&rabbit.url, &scope.name("fault-matrix-confirm-lost-pub")).await?,
        );
        let subscriber =
            match connect_subscriber(&rabbit.url, &scope.name("fault-matrix-confirm-lost-sub"))
                .await
            {
                Ok(subscriber) => subscriber,
                Err(error) => {
                    let cleanup = shutdown_amqp(&token, None, publisher.as_ref()).await;
                    return finish_with_cleanup(
                        Err(error),
                        cleanup,
                        "shut down AMQP after confirm-lost subscriber setup failure",
                    );
                }
            };
        let body_result: Result<ConfirmLostCriticalEvidence> = async {
            subscriber.purge_durable_queue_for_test(&topic).await?;
            let mut deliveries = subscriber
                .subscribe_ackable(topic.clone(), token.clone())
                .await?;
            let stale_message_id = Uuid::new_v4().to_string();
            Publisher::publish(
                publisher.as_ref(),
                complete_publish_request(
                    topic,
                    MessageId::new(&stale_message_id),
                    b"stale-prior-run-delivery".to_vec(),
                    scope.tenant,
                ),
            )
            .await?;
            pg.harness
                .seed_session_created(FaultMatrixSessionCreatedInput::new(
                    session_created_payload(scope.tenant, session_id),
                    IdemKey::parse(&event_id)?,
                )?)
                .await?;

            publisher.inject_post_send_connection_close_once();
            let first = pg
                .harness
                .relay_session_created_once(
                    &event_id,
                    DynPublisher::new_box(SharedAmqpPublisher(Arc::clone(&publisher))),
                )
                .await?;
            if first.event_id() != event_id
                || first.disposition() != Disposition::Requeue
                || first.status() != FaultMatrixOutboxStatus::Pending
            {
                bail!("confirm-lost first relay did not requeue the same durable event: {first:?}");
            }
            if !publisher.wait_until_publish_ready_for_test().await {
                bail!("publisher did not become publish-ready after confirm-lost recovery");
            }
            pg.harness
                .make_session_created_retry_due(scope.tenant, &event_id)
                .await?;
            let retry = pg
                .harness
                .relay_session_created_once(
                    &event_id,
                    DynPublisher::new_box(SharedAmqpPublisher(Arc::clone(&publisher))),
                )
                .await?;
            if retry.event_id() != event_id
                || retry.disposition() != Disposition::Ack
                || retry.status() != FaultMatrixOutboxStatus::Published
            {
                bail!("confirm-lost retry did not publish the same durable event: {retry:?}");
            }

            let mut delivered_ids = Vec::with_capacity(2);
            for expected in [
                FaultMatrixConsumerDelivery::Committed,
                FaultMatrixConsumerDelivery::Duplicate,
            ] {
                let delivery = loop {
                    let delivery = tokio::time::timeout(Duration::from_secs(5), deliveries.next())
                        .await
                        .context("timeout waiting for confirm-lost duplicate delivery")?
                        .ok_or_else(|| anyhow!("confirm-lost delivery stream closed"))?;
                    if delivery.message.id().as_str() == event_id {
                        break delivery;
                    }
                    delivery.acker.settle(AckAction::Ack).await?;
                };
                delivered_ids.push(delivery.message.id().as_str().to_string());
                let observed = pg
                    .harness
                    .consume_session_created_delivery(&group, delivery.message)
                    .await?;
                if observed != expected {
                    bail!("confirm-lost ConsumerTx delivery = {observed:?}, expected {expected:?}");
                }
                delivery.acker.settle(AckAction::Ack).await?;
            }
            if delivered_ids.as_slice() != [event_id.as_str(), event_id.as_str()] {
                bail!(
                    "confirm-lost broker deliveries did not preserve the same durable event id: {delivered_ids:?}"
                );
            }
            let ids = EventingIds::new(&event_id, &event_id, &group, "confirm-lost-lease");
            let effect = pg
                .harness
                .session_created_effect_observation(scope.tenant, &event_id, &group)
                .await?;
            let duplicate_conformance = assert_consumer_duplicate_effect_conformance(
                &ids,
                &ConsumerDuplicateEffectObservation {
                    business_mutations: effect.business_mutations(),
                    inbox_done_rows: effect.inbox_done_rows(),
                    duplicate_settle: SettleAction::Ack,
                },
            )?;
            Ok(ConfirmLostCriticalEvidence {
                _first_relay: first,
                _retry_relay: retry,
                _effect: effect,
                _duplicate_conformance: duplicate_conformance,
            })
        }
        .await;
        let cleanup_result = shutdown_amqp(&token, Some(&subscriber), publisher.as_ref()).await;
        finish_with_cleanup(
            body_result,
            cleanup_result,
            "shut down confirm-lost AMQP resources",
        )
    })
}

fn run_outbox_stale_contender_settle<'a>(
    _runner: &'a ReadyCaseRunner,
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<FaultMatrixStaleSettlementObservation>> {
    Box::pin(async move {
        let observed = pg
            .harness
            .stale_outbox_settlement(scope.tenant, &scope.event_id(case))
            .await?;
        if observed.stale() != FaultMatrixSettlementOutcome::LostLease
            || observed.current() != FaultMatrixSettlementOutcome::Settled
            || !observed.intermediate_no_terminal()
            || observed.final_status() != FaultMatrixOutboxStatus::Published
        {
            bail!("stale contender settlement invariant failed: {observed:?}");
        }
        Ok(observed)
    })
}

fn run_outbox_deadline_expired_settle<'a>(
    _runner: &'a ReadyCaseRunner,
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<FaultMatrixExpiredSettlementObservation>> {
    Box::pin(async move {
        let observed = pg
            .harness
            .expired_outbox_settlement(scope.tenant, &scope.event_id(case))
            .await?;
        if observed.outcome() != FaultMatrixSettlementOutcome::Expired
            || !observed.still_publishing()
            || !observed.no_terminal()
        {
            bail!("expired deadline settlement invariant failed: {observed:?}");
        }
        Ok(observed)
    })
}

fn run_outbox_permanent_publish_failure<'a>(
    runner: &'a ReadyCaseRunner,
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let contract = runner.contract;
        let event_id = scope.event_id(case);
        pg.harness
            .run_outbox_publish(
                scope.tenant,
                &event_id,
                contract.domain(),
                contract.contract_id(),
                contract.contract_id(),
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
        if dlx.encoding() != FaultMatrixDeadLetterEncoding::KeyProviderV3 {
            bail!(
                "outbox DLX payload should use protected encoding, got {:?}",
                dlx.encoding()
            );
        }
        if dlx.payload_len() != 1 {
            bail!(
                "outbox DLX should record original payload length 1, got {}",
                dlx.payload_len()
            );
        }
        assert_outbox_count(pg, scope.tenant, &event_id, FaultMatrixOutboxStatus::Dlx, 1).await
    })
}

fn run_inbox_claim_crash_before_commit<'a>(
    _runner: &'a ReadyCaseRunner,
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
    _runner: &'a ReadyCaseRunner,
    case: &'a CrashCase,
    pg: &'a PgHarness,
    rabbit: &'a RabbitHarness,
    _redis: &'a RedisHarness,
    scope: &'a RunScope,
) -> LocalBoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let event_id = scope.event_id(case);
        let group = scope.name("audit.session-created");
        rabbit_unsettled_redelivers_through_consumer_tx(
            pg,
            rabbit,
            scope,
            &event_id,
            &group,
            Uuid::new_v4(),
        )
        .await
    })
}

fn run_inbox_lease_lost_before_commit<'a>(
    _runner: &'a ReadyCaseRunner,
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

fn run_projection_after_apply_before_checkpoint<'a>(
    _runner: &'a ReadyCaseRunner,
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
    _runner: &'a ReadyCaseRunner,
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

async fn assert_outbox_count(
    pg: &PgHarness,
    tenant: rss_request_context::TenantId,
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

fn finish_with_cleanup<T>(
    body: Result<T>,
    cleanup: Result<()>,
    cleanup_context: &str,
) -> Result<T> {
    match (body, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(body), Ok(())) => Err(body),
        (Ok(_), Err(cleanup)) => Err(cleanup).context(cleanup_context.to_string()),
        (Err(body), Err(cleanup)) => {
            Err(body).context(format!("{cleanup_context} also failed: {cleanup:#}"))
        }
    }
}

fn general_target_owns(case: &CrashCase) -> bool {
    case.status() == CrashStatus::Ready && case.mechanism() != CrashMechanism::Saga
}

fn general_target_ready_cases(matrix: &CrashMatrix) -> Result<Vec<&CrashCase>> {
    let ready = matrix
        .cases()
        .iter()
        .filter(|case| general_target_owns(case))
        .collect::<Vec<_>>();
    if ready.len() != READY_CASE_RUNNERS.len() {
        bail!(
            "N-028 expects exactly {} non-Saga ready cases, got {}",
            READY_CASE_RUNNERS.len(),
            ready.len()
        );
    }

    let mapped = ready.iter().map(|case| case.id()).collect::<BTreeSet<_>>();
    let expected = READY_CASE_RUNNERS
        .iter()
        .map(|runner| runner.id)
        .collect::<BTreeSet<_>>();
    if expected.len() != READY_CASE_RUNNERS.len() {
        bail!("READY_CASE_RUNNERS contains duplicate ids");
    }
    if mapped != expected {
        bail!("non-Saga ready fixture ids drifted: got {mapped:?}, expected {expected:?}");
    }
    Ok(ready)
}

#[test]
fn consistency_fault_matrix_target_ownership_is_exact() -> Result<()> {
    let root = workspace_root()?;
    let matrix = CrashMatrix::from_fixture_dir(root.join("fixtures").join("consistency"))?;
    let all_ready = matrix
        .cases()
        .iter()
        .filter(|case| case.status() == CrashStatus::Ready)
        .map(|case| case.id())
        .collect::<BTreeSet<_>>();
    let general = general_target_ready_cases(&matrix)?
        .into_iter()
        .map(CrashCase::id)
        .collect::<BTreeSet<_>>();
    let saga = matrix
        .cases()
        .iter()
        .filter(|case| {
            case.status() == CrashStatus::Ready && case.mechanism() == CrashMechanism::Saga
        })
        .map(|case| case.id())
        .collect::<BTreeSet<_>>();

    if general.is_empty() || saga.is_empty() {
        bail!("fault target ownership must include both general and Saga ready fixtures");
    }
    if let Some(overlap) = general.intersection(&saga).next() {
        bail!("fault target ownership overlaps at stable id `{overlap}`");
    }
    let owned = general.union(&saga).copied().collect::<BTreeSet<_>>();
    if owned != all_ready {
        bail!("fault target ownership drifted: owned {owned:?}, all ready {all_ready:?}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn consistency_fault_matrix_ready_cases_execute() -> Result<()> {
    let root = workspace_root()?;
    let matrix = CrashMatrix::from_fixture_dir(root.join("fixtures").join("consistency"))?;
    let ready = general_target_ready_cases(&matrix)?;

    let scope = RunScope::new()?;
    let pg = pg_harness().await?;
    let body_result: Result<()> = async {
        let rabbit = rabbit_harness().await?;
        let redis = redis_harness().await?;
        for case in ready {
            let runner = ready_case_runner(case.id()).ok_or_else(|| {
                anyhow!(
                    "ready fixture has no ready-case runner mapping: {}",
                    case.id()
                )
            })?;
            runner.validate_case(case)?;
            runner
                .execute(case, &pg, &rabbit, &redis, &scope)
                .await
                .with_context(|| format!("fault matrix case `{}` failed", case.id()))?;
        }
        Ok(())
    }
    .await;

    let PgHarness { _fixture, harness } = pg;
    let cleanup_result = harness.shutdown().await;
    finish_with_cleanup(
        body_result,
        cleanup_result,
        "shut down fault-matrix postgres",
    )
}

#[test]
fn cleanup_result_preserves_body_error_and_reports_cleanup_failure() -> Result<()> {
    let err = finish_with_cleanup::<()>(
        Err(anyhow!("body failed")),
        Err(anyhow!("cleanup failed")),
        "shut down test resource",
    )
    .err()
    .ok_or_else(|| anyhow!("both failures must remain an error"))?;
    let rendered = format!("{err:#}");
    assert!(rendered.contains("body failed"));
    assert!(rendered.contains("cleanup failed"));
    Ok(())
}

#[test]
fn cleanup_result_returns_cleanup_only_failure() -> Result<()> {
    let err = finish_with_cleanup::<()>(
        Ok(()),
        Err(anyhow!("cleanup failed")),
        "shut down test resource",
    )
    .err()
    .ok_or_else(|| anyhow!("cleanup failure must be returned"))?;
    assert!(format!("{err:#}").contains("cleanup failed"));
    Ok(())
}

#[test]
fn cleanup_result_preserves_success_and_body_only_failure() -> Result<()> {
    finish_with_cleanup(Ok(()), Ok(()), "shut down test resource")?;
    let err = finish_with_cleanup::<()>(
        Err(anyhow!("body failed")),
        Ok(()),
        "shut down test resource",
    )
    .err()
    .ok_or_else(|| anyhow!("body failure must be returned"))?;
    assert_eq!(format!("{err:#}"), "body failed");
    Ok(())
}
