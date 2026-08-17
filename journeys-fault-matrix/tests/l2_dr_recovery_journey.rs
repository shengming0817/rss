//! Real PostgreSQL/RabbitMQ L2 DR recovery journey.
//!
//! The restore points below are equivalent-state evidence for the two divergent durable systems;
//! this journey does not claim to perform physical point-in-time restore.

use std::sync::Arc;
use std::time::Duration;

use amqp::{AmqpPublisher, AmqpSubscriber};
use anyhow::{Context, Result, ensure};
use consistency::IdemKey;
use diport::{
    AckAction, AckableSubscriber, Acker, DynPublisher, ManagedResource, MessageId, PublishRequest,
    Publisher, Topic,
};
use eventexec::{
    L2DrRecoveryError, L2DrRecoveryOperatorSubject, L2DrRecoveryOutcome, L2DrRecoveryPlan,
    L2DrRecoveryStore, RecoveryChangeTicket, RecoveryDirection, RecoveryEpochId, RecoveryEventSet,
    UtcEpochMicros,
};
use futures::StreamExt;
use postgres::fault_matrix::{
    FaultMatrixConsumerDelivery, FaultMatrixL2DrOutboxObservation, FaultMatrixOutboxStatus,
    FaultMatrixSameIdDeliveryPhase, FaultMatrixSessionCreatedInput, PgFaultMatrixConfig,
    PgFaultMatrixHarness, PgFaultMatrixLoginCredentials, fault_matrix_relay_budget,
};
use postgres::{
    MaintenanceAuditOutcome, PgConfig, PgL2DrRecoveryAuditConfig, PgL2DrRecoveryDeps,
    PgL2DrRecoveryExecutorConfig, PgPassword, PgSslMode,
};
use testkit::eventing_conformance::{
    ConsumerDuplicateEffectObservation, EventingIds, SettleAction,
    assert_consumer_duplicate_effect_conformance,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const RABBIT_VHOST: &str = "rss_l2_dr_recovery";
const TEST_OCCURRED_AT: i64 = 1_700_000_000;
const TEST_OPERATOR_SUBJECT: &str = "service:l2-dr-journey";

#[derive(Clone)]
struct SharedAmqpPublisher(Arc<AmqpPublisher>);

impl Publisher for SharedAmqpPublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), diport::PublisherError> {
        Publisher::publish(self.0.as_ref(), request).await
    }

    async fn shutdown(&self) -> Result<(), diport::PublisherError> {
        Publisher::shutdown(self.0.as_ref()).await
    }
}

struct JourneyHarness {
    _pg_fixture: testkit::OwnedPgFixture,
    _rabbit_fixture: testkit::RabbitFixture,
    pg: PgFaultMatrixHarness,
    recovery: PgL2DrRecoveryDeps,
    rabbit_url: String,
    tenant: rss_request_context::TenantId,
    suffix: String,
}

impl JourneyHarness {
    async fn setup() -> Result<Self> {
        let pg_fixture = testkit::owned_postgres().await?;
        let owned = &pg_fixture;
        let params = owned.owner_params();
        let pg_config = PgFaultMatrixConfig::new(
            params.host.clone(),
            params.port,
            params.database.clone(),
            params.username.clone(),
            params.password.clone(),
        );
        let logins = PgFaultMatrixLoginCredentials::generate();
        let _serving_roles = owned
            .resolve_app_roles([
                testkit::PgAppRoleSpec::new(logins.serving_role(), logins.serving_password()),
                testkit::PgAppRoleSpec::new(logins.reader_role(), logins.reader_password()),
            ])
            .await?;
        let pg = PgFaultMatrixHarness::setup(
            pg_config,
            logins,
            fault_matrix_relay_budget()?,
            eventexec::WorkflowRuntimePlan::disabled_fixture().projection_capture(),
        )
        .await?;

        // Migration creates this function-only role as NOLOGIN; provision its test-only login only
        // after migration, then connect through the production operator config/deps funnel.
        let logins = PgFaultMatrixLoginCredentials::generate();
        let [auditor_role, executor_role] = owned
            .resolve_app_roles([
                testkit::PgAppRoleSpec::new(
                    logins.l2_dr_recovery_auditor_role(),
                    logins.l2_dr_recovery_auditor_password(),
                ),
                testkit::PgAppRoleSpec::new(
                    logins.l2_dr_recovery_executor_role(),
                    logins.l2_dr_recovery_executor_password(),
                ),
            ])
            .await?;
        let auditor_params = auditor_role.params();
        let auditor = PgConfig::new(
            auditor_params.host.clone(),
            auditor_params.port,
            auditor_params.database.clone(),
            auditor_params.username.clone(),
            PgPassword::new(auditor_params.password.clone()),
        )
        .with_ssl_mode(PgSslMode::Prefer)
        .with_max_connections(2)
        .with_acquire_timeout(Duration::from_secs(5));
        let executor_params = executor_role.params();
        let executor = PgConfig::new(
            executor_params.host.clone(),
            executor_params.port,
            executor_params.database.clone(),
            executor_params.username.clone(),
            PgPassword::new(executor_params.password.clone()),
        )
        .with_ssl_mode(PgSslMode::Prefer)
        .with_max_connections(2)
        .with_acquire_timeout(Duration::from_secs(5));
        let recovery = PgL2DrRecoveryDeps::connect(
            &PgL2DrRecoveryAuditConfig::new(auditor),
            &PgL2DrRecoveryExecutorConfig::new(executor),
        )
        .await?;

        let rabbit_fixture = testkit::env_or_rabbitmq().await?;
        let rabbit_url = rabbit_fixture.vhost_url(RABBIT_VHOST).await?;
        Ok(Self {
            _pg_fixture: pg_fixture,
            _rabbit_fixture: rabbit_fixture,
            pg,
            recovery,
            rabbit_url,
            tenant: rss_request_context::TenantId::parse(&Uuid::new_v4().to_string())?,
            suffix: Uuid::new_v4().simple().to_string(),
        })
    }

    fn name(&self, prefix: &str) -> String {
        format!("{prefix}-{}", self.suffix)
    }

    async fn shutdown(self) -> Result<()> {
        self.recovery.shutdown().await?;
        self.pg.shutdown().await
    }
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

fn recovery_plan(
    tenant: rss_request_context::TenantId,
    epoch: RecoveryEpochId,
    direction: RecoveryDirection,
    event_ids: &[&str],
) -> Result<L2DrRecoveryPlan> {
    let (database_restore_point, broker_restore_point) = match direction {
        RecoveryDirection::DatabaseAheadBrokerEarlier => (200, 100),
        RecoveryDirection::BrokerAheadDatabaseEarlier => (100, 200),
    };
    Ok(L2DrRecoveryPlan::new(
        epoch,
        tenant,
        UtcEpochMicros::new(database_restore_point)?,
        UtcEpochMicros::new(broker_restore_point)?,
        RecoveryEventSet::new(
            event_ids
                .iter()
                .map(|event_id| IdemKey::parse(event_id))
                .collect::<Result<Vec<_>, _>>()?,
        )?,
        RecoveryChangeTicket::parse(format!("CHG-1837-{}", epoch.as_uuid().simple()))?,
    )?)
}

fn test_operator_subject() -> Result<L2DrRecoveryOperatorSubject> {
    Ok(L2DrRecoveryOperatorSubject::parse(TEST_OPERATOR_SUBJECT)?)
}

async fn connect_publisher(url: &str, name: &str) -> Result<AmqpPublisher> {
    Ok(AmqpPublisher::connect_with_webpki_for_test(
        &secure::AmqpEndpoint::parse(url, secure::PlaintextEndpointPolicy::AllowLoopback)?,
        name,
        fault_matrix_relay_budget()?.publish_timeout(),
    )
    .await?)
}

async fn connect_subscriber(url: &str, name: &str) -> Result<AmqpSubscriber> {
    Ok(AmqpSubscriber::connect_with_webpki_for_test(
        &secure::AmqpEndpoint::parse(url, secure::PlaintextEndpointPolicy::AllowLoopback)?,
        name,
    )
    .await?)
}

async fn consume_committed_then_duplicate(
    harness: &JourneyHarness,
    deliveries: &mut diport::DeliveryStream,
    event_id: &str,
    consumer_group: &str,
) -> Result<()> {
    for expected in [
        FaultMatrixConsumerDelivery::Committed,
        FaultMatrixConsumerDelivery::Duplicate,
    ] {
        let delivery = tokio::time::timeout(Duration::from_secs(5), deliveries.next())
            .await
            .context("timeout waiting for L2 DR same-ID delivery")?
            .context("L2 DR same-ID delivery stream closed")?;
        ensure!(delivery.message.id().as_str() == event_id);
        let observed = harness
            .pg
            .consume_session_created_delivery(harness.tenant, consumer_group, delivery.message)
            .await?;
        ensure!(
            observed == expected,
            "delivery = {observed:?}, expected {expected:?}"
        );
        delivery.acker.settle(AckAction::Ack).await?;
    }
    let effect = harness
        .pg
        .session_created_effect_observation(harness.tenant, event_id, consumer_group)
        .await?;
    let ids = EventingIds::new(event_id, event_id, consumer_group, "l2-dr-recovery-lease");
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

fn assert_published_unchanged(
    before: &FaultMatrixL2DrOutboxObservation,
    after: &FaultMatrixL2DrOutboxObservation,
) -> Result<()> {
    ensure!(after.event_id() == before.event_id());
    ensure!(after.status() == FaultMatrixOutboxStatus::Published);
    ensure!(after.phase() == FaultMatrixSameIdDeliveryPhase::Automatic);
    ensure!(after.has_same_fact_fingerprint_as(before));
    ensure!(after.automatic_deadline() == before.automatic_deadline());
    ensure!(after.redrive_deadline().is_none());
    Ok(())
}

async fn publish_duplicate_events(
    publisher: &AmqpPublisher,
    topic: &Topic,
    event_id: &str,
    payload: &[u8],
) -> Result<()> {
    for _ in 0..2 {
        publisher
            .publish(PublishRequest::new(
                topic.clone(),
                MessageId::new(event_id),
                payload.to_vec(),
            ))
            .await?;
    }
    Ok(())
}

async fn broker_ahead_database_earlier(harness: &JourneyHarness) -> Result<()> {
    let event_id = Uuid::new_v4().to_string();
    let group = harness.name("broker-ahead-consumer");
    let session_id = Uuid::new_v4();
    let topic = Topic::new(generated::event::identity_v1::session_created::TOPIC);
    let subscriber =
        connect_subscriber(&harness.rabbit_url, &harness.name("broker-ahead-sub")).await?;
    subscriber.purge_durable_queue_for_test(&topic).await?;
    let publisher =
        connect_publisher(&harness.rabbit_url, &harness.name("broker-ahead-pub")).await?;
    let payload = serde_json::to_vec(&session_created_payload(harness.tenant, session_id))?;
    publish_duplicate_events(&publisher, &topic, &event_id, &payload).await?;

    let epoch = RecoveryEpochId::new(Uuid::new_v4())?;
    let start_audit_id = Uuid::new_v4();
    let operator_subject = test_operator_subject()?;
    let plan = recovery_plan(
        harness.tenant,
        epoch,
        RecoveryDirection::BrokerAheadDatabaseEarlier,
        &[&event_id],
    )?;
    let prepared = harness
        .pg
        .prepare_l2_dr_recovery(&harness.recovery, plan)
        .await?;
    let required = prepared
        .required_fence(&operator_subject, start_audit_id)
        .await?;
    let receipt = harness.recovery.apply_l2_dr_recovery(required).await?;
    harness
        .recovery
        .record_l2_dr_recovery_finish_audit_subject(
            &operator_subject,
            harness.tenant,
            epoch.as_uuid(),
            start_audit_id,
            MaintenanceAuditOutcome::Success,
        )
        .await?;
    ensure!(receipt.outcome() == L2DrRecoveryOutcome::Applied);
    ensure!(
        harness
            .pg
            .l2_dr_recovery_receipt_exists(harness.tenant, epoch)
            .await?
    );
    let token = CancellationToken::new();
    let mut deliveries = subscriber
        .subscribe_ackable(topic.clone(), token.clone())
        .await?;
    consume_committed_then_duplicate(harness, &mut deliveries, &event_id, &group).await?;

    token.cancel();
    AckableSubscriber::shutdown(&subscriber).await?;
    Publisher::shutdown(&publisher).await?;
    ManagedResource::shutdown(&publisher).await?;
    Ok(())
}

async fn database_ahead_broker_earlier(harness: &JourneyHarness) -> Result<()> {
    let fixture = arm_database_ahead_redrive(harness).await?;
    deliver_database_ahead_redrive(harness, fixture).await
}

struct DatabaseAheadFixture {
    event_id: String,
    epoch: RecoveryEpochId,
    group: String,
}

async fn arm_database_ahead_redrive(harness: &JourneyHarness) -> Result<DatabaseAheadFixture> {
    let event_id = Uuid::new_v4().to_string();
    let group = harness.name("database-ahead-consumer");
    let session_id = Uuid::new_v4();
    let before = harness
        .pg
        .seed_and_settle_session_created_published(FaultMatrixSessionCreatedInput::new(
            session_created_payload(harness.tenant, session_id),
            IdemKey::parse(&event_id)?,
        )?)
        .await?;
    ensure!(before.status() == FaultMatrixOutboxStatus::Published);
    ensure!(before.phase() == FaultMatrixSameIdDeliveryPhase::Automatic);
    ensure!(before.redrive_deadline().is_none());

    let epoch = RecoveryEpochId::new(Uuid::new_v4())?;
    let plan = recovery_plan(
        harness.tenant,
        epoch,
        RecoveryDirection::DatabaseAheadBrokerEarlier,
        &[&event_id],
    )?;
    let start_audit_id = Uuid::new_v4();
    let operator_subject = test_operator_subject()?;
    let prepared = harness
        .pg
        .prepare_l2_dr_recovery(&harness.recovery, plan)
        .await?;
    let required = prepared
        .required_fence(&operator_subject, start_audit_id)
        .await?;
    let receipt = harness.recovery.apply_l2_dr_recovery(required).await?;
    ensure!(receipt.outcome() == L2DrRecoveryOutcome::Applied);
    let armed = harness
        .pg
        .l2_dr_outbox_observation(harness.tenant, &event_id)
        .await?;
    ensure!(armed.status() == FaultMatrixOutboxStatus::Pending);
    ensure!(armed.phase() == FaultMatrixSameIdDeliveryPhase::Redrive);
    ensure!(armed.event_id() == before.event_id());
    ensure!(armed.has_same_fact_fingerprint_as(&before));
    ensure!(armed.automatic_deadline() == before.automatic_deadline());
    let first_redrive_deadline = armed
        .redrive_deadline()
        .context("L2 DR did not arm an absolute redrive deadline")?;

    let retry_required = prepared
        .required_fence(&operator_subject, Uuid::new_v4())
        .await?;
    let repeated = harness
        .recovery
        .apply_l2_dr_recovery(retry_required)
        .await?;
    ensure!(repeated.outcome() == L2DrRecoveryOutcome::AlreadyApplied);
    ensure!(repeated.applied_at() == receipt.applied_at());
    ensure!(
        repeated.start_audit_id() == receipt.start_audit_id(),
        "already_applied must retain the first start_audit_id"
    );
    ensure!(
        repeated.start_audit_id() == start_audit_id,
        "already_applied must retain the original start_audit_id, not the retry audit"
    );
    ensure!(
        repeated.operator_subject() == receipt.operator_subject(),
        "already_applied must retain the first operator_subject"
    );
    ensure!(
        repeated.operator_subject() == &operator_subject,
        "already_applied must retain the original operator_subject"
    );
    harness
        .recovery
        .record_l2_dr_recovery_finish_audit_subject(
            &operator_subject,
            harness.tenant,
            epoch.as_uuid(),
            start_audit_id,
            MaintenanceAuditOutcome::Success,
        )
        .await?;
    ensure!(
        harness
            .pg
            .l2_dr_recovery_receipt_exists(harness.tenant, epoch)
            .await?
    );
    let after_repeat = harness
        .pg
        .l2_dr_outbox_observation(harness.tenant, &event_id)
        .await?;
    ensure!(after_repeat.redrive_deadline() == Some(first_redrive_deadline));

    Ok(DatabaseAheadFixture {
        event_id,
        epoch,
        group,
    })
}

async fn deliver_database_ahead_redrive(
    harness: &JourneyHarness,
    fixture: DatabaseAheadFixture,
) -> Result<()> {
    let topic = Topic::new(generated::event::identity_v1::session_created::TOPIC);
    let subscriber =
        connect_subscriber(&harness.rabbit_url, &harness.name("database-ahead-sub")).await?;
    subscriber.purge_durable_queue_for_test(&topic).await?;
    let publisher = Arc::new(
        connect_publisher(&harness.rabbit_url, &harness.name("database-ahead-pub")).await?,
    );
    publisher.inject_post_send_connection_close_once();
    let ambiguous = harness
        .pg
        .relay_session_created_once(
            &fixture.event_id,
            DynPublisher::new_box(SharedAmqpPublisher(Arc::clone(&publisher))),
        )
        .await?;
    ensure!(ambiguous.disposition() == consistency::Disposition::Requeue);
    ensure!(ambiguous.status() == FaultMatrixOutboxStatus::Pending);
    ensure!(publisher.wait_until_publish_ready_for_test().await);
    harness
        .pg
        .make_session_created_retry_due(harness.tenant, &fixture.event_id)
        .await?;
    let settled = harness
        .pg
        .relay_session_created_once(
            &fixture.event_id,
            DynPublisher::new_box(SharedAmqpPublisher(Arc::clone(&publisher))),
        )
        .await?;
    ensure!(settled.disposition() == consistency::Disposition::Ack);
    ensure!(settled.status() == FaultMatrixOutboxStatus::Published);
    ensure!(
        harness
            .pg
            .l2_dr_recovery_receipt_exists(harness.tenant, fixture.epoch)
            .await?
    );
    let token = CancellationToken::new();
    let mut deliveries = subscriber.subscribe_ackable(topic, token.clone()).await?;
    consume_committed_then_duplicate(harness, &mut deliveries, &fixture.event_id, &fixture.group)
        .await?;

    token.cancel();
    AckableSubscriber::shutdown(&subscriber).await?;
    Publisher::shutdown(publisher.as_ref()).await?;
    ManagedResource::shutdown(publisher.as_ref()).await?;
    Ok(())
}

async fn invalid_exact_set_is_atomic(harness: &JourneyHarness) -> Result<()> {
    let event_id = Uuid::new_v4().to_string();
    let missing_event_id = Uuid::new_v4().to_string();
    let before = harness
        .pg
        .seed_and_settle_session_created_published(FaultMatrixSessionCreatedInput::new(
            session_created_payload(harness.tenant, Uuid::new_v4()),
            IdemKey::parse(&event_id)?,
        )?)
        .await?;
    let epoch = RecoveryEpochId::new(Uuid::new_v4())?;
    let start_audit_id = Uuid::new_v4();
    let operator_subject = test_operator_subject()?;
    let plan = recovery_plan(
        harness.tenant,
        epoch,
        RecoveryDirection::DatabaseAheadBrokerEarlier,
        &[&event_id, &missing_event_id],
    )?;
    let prepared = harness
        .pg
        .prepare_l2_dr_recovery(&harness.recovery, plan)
        .await?;
    let required = prepared
        .required_fence(&operator_subject, start_audit_id)
        .await?;
    let error = harness
        .recovery
        .apply_l2_dr_recovery(required)
        .await
        .err()
        .context("missing exact event set must fail atomically")?;
    ensure!(error == L2DrRecoveryError::FactNotFound);
    harness
        .recovery
        .record_l2_dr_recovery_finish_audit_subject(
            &operator_subject,
            harness.tenant,
            epoch.as_uuid(),
            start_audit_id,
            MaintenanceAuditOutcome::Failure {
                reason: "event_missing",
            },
        )
        .await?;
    let after = harness
        .pg
        .l2_dr_outbox_observation(harness.tenant, &event_id)
        .await?;
    assert_published_unchanged(&before, &after)?;
    ensure!(
        !harness
            .pg
            .l2_dr_recovery_receipt_exists(harness.tenant, epoch)
            .await?
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l2_dr_recovery_reconciles_equivalent_divergent_states() -> Result<()> {
    let harness = JourneyHarness::setup().await?;
    let result = async {
        broker_ahead_database_earlier(&harness).await?;
        database_ahead_broker_earlier(&harness).await?;
        invalid_exact_set_is_atomic(&harness).await
    }
    .await;
    let cleanup = harness.shutdown().await;
    result.and(cleanup)
}
