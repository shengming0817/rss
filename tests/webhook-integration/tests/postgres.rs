use super::support::*;
#[path = "../../fixtures/message_fence.rs"]
mod fence_fixture;
use rss_examples::webhook::{Emitter, Timer};
use rss_transactional_messaging::policy::DeliveryBudget;
use rss_transactional_messaging::{message::*, outbox::*, transport::Publisher};
use rss_transactional_messaging_postgres::{
    PgConfig, PgOutboxStore, PgPassword, PgPrivateCa, PgRuntime,
};
use rss_transactional_messaging_runtime::relay::relay_once;
use rss_transactional_messaging_webhook::WebhookPublishReceipt;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
pub struct Database {
    _fixture: testkit::PgTlsFixture,
    _network: testkit::BridgeNetwork,
    pub owner: sqlx::PgPool,
    pub runtime: Arc<PgRuntime>,
    pub store: Arc<PgOutboxStore<WebhookPublishReceipt>>,
    timer: Timer,
}
impl Database {
    pub async fn new() -> anyhow::Result<Self> {
        let network = testkit::bridge_network("webhook-pg").await?;
        let fixture = testkit::postgres_tls(
            testkit::NetworkAttachment {
                network: network.name(),
                dns_name: "webhook-pg",
            },
            testkit::PgTlsServerIdentity::MatchingHost,
        )
        .await?;
        let params = fixture.params();
        let owner = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(
                PgConnectOptions::new()
                    .host(&params.host)
                    .port(params.port)
                    .database(&params.database)
                    .username(&params.username)
                    .options([
                        ("rss.tenant_id", "f47ac10b-58cc-4372-a567-0e02b2c3d479"),
                        ("rss.storage_target", "01010101010101010101010101010101"),
                        ("rss.storage_lineage", "02020202020202020202020202020202"),
                        ("rss.execution_epoch", "1"),
                    ])
                    .password(&params.password)
                    .ssl_mode(PgSslMode::VerifyFull)
                    .ssl_root_cert_from_pem(fixture.ca_pem().as_bytes().to_vec()),
            )
            .await?;
        provision(&owner).await?;
        fence_fixture::provision(&owner).await?;
        let runtime = Arc::new(
            PgRuntime::connect(
                PgConfig::new(
                    &params.host,
                    params.port,
                    &params.database,
                    "webhook_runtime",
                    PgPassword::new("fixture-only"),
                    PgPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?,
                ),
                Timer,
                fence_fixture::binding(),
            )
            .await?,
        );
        let budget = DeliveryBudget::new(
            Duration::from_secs(8),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )?;
        let store = Arc::new(PgOutboxStore::<WebhookPublishReceipt>::new(
            runtime.clone(),
            MessagingDomain::parse("webhook-example")?,
            budget,
        )?);
        Ok(Self {
            _network: network,
            _fixture: fixture,
            owner,
            runtime,
            store,
            timer: Timer,
        })
    }
    pub async fn append(&self, id: &str) -> anyhow::Result<()> {
        let envelope = message(id)?;
        let tenant = envelope.envelope().metadata().tenant_id();
        let append = self.store.clone();
        self.runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move { append.append(tx, envelope).await.map_err(Into::into) })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
        Ok(())
    }
    pub async fn status(&self, id: &str) -> anyhow::Result<String> {
        Ok(sqlx::query_scalar(
            "SELECT status FROM rss_transactional_messaging.outbox WHERE message_id=$1",
        )
        .bind(id)
        .fetch_one(&self.owner)
        .await?)
    }
    pub async fn relay(
        &self,
        publisher: &impl Publisher<Vec<u8>, Receipt = WebhookPublishReceipt>,
    ) -> anyhow::Result<()> {
        let report = relay_once(
            &*self.store,
            publisher,
            &self.timer,
            &Emitter,
            NonZeroUsize::MIN,
        )
        .await?;
        assert_eq!(report.claimed(), 1);
        Ok(())
    }
}
async fn provision(owner: &sqlx::PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; CREATE ROLE webhook_runtime LOGIN PASSWORD 'fixture-only' NOBYPASSRLS;").execute(owner).await?;
    sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
        .execute(owner)
        .await?;
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO webhook_runtime; GRANT SELECT ON rss_transactional_messaging.policy TO webhook_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO webhook_runtime; GRANT SELECT ON rss_transactional_messaging.outbox TO webhook_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(bytea,jsonb) TO webhook_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.next_outbox_wakeup(uuid,text),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) TO webhook_runtime; CREATE TABLE public.webhook_handoff (message_id text PRIMARY KEY, payload bytea NOT NULL);").execute(owner).await?;
    Ok(())
}
impl Database {
    pub fn input(&self, receiver: &Receiver, id: &str) -> serde_json::Value {
        let params = self._fixture.params();
        serde_json::json!({"host":params.host,"port":params.port,"database":params.database,"username":"webhook_runtime","password":"fixture-only","pg_ca":self._fixture.ca_pem(),"tenant":TENANT,"endpoint":{"tenant":TENANT,"url":receiver.endpoint.url,"address":receiver.endpoint.address,"ca":receiver.endpoint.ca,"secret":receiver.endpoint.secret},"id":id})
    }
    async fn ready(&self, id: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE rss_transactional_messaging.outbox SET retry_after=clock_timestamp()-interval '1 second' WHERE message_id=$1").bind(id).execute(&self.owner).await?;
        Ok(())
    }
    pub async fn close(self) {
        self.runtime.close().await;
        self.owner.close().await;
    }
}
#[tokio::test]
async fn pg_atomicity_restart_unknown_and_expiry() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(90), pg_scenario()).await?
}
#[allow(clippy::cognitive_complexity)] // reason: ordered real-PG fault assertions stay adjacent to the state they validate.
async fn pg_scenario() -> anyhow::Result<()> {
    use rss_request_context::TenantId;
    use rss_transactional_messaging::transport::PublishOutcome;
    use rss_transactional_messaging_webhook::WebhookPublisher;
    let database = Database::new().await?;
    let mut receiver = Receiver::new(Mode::DropResponse).await?;
    let writer = database.store.clone();
    let rollback = database
        .runtime
        .local_tx(TenantId::parse(TENANT)?, deadline(), move |tx| {
            Box::pin(async move {
                writer
                    .append(
                        tx,
                        message("rollback").map_err(|_| {
                            rss_transactional_messaging_postgres::PgError::InvalidConnectionConfig
                        })?,
                    )
                    .await?;
                Err::<(), _>(rss_transactional_messaging_postgres::PgError::InvalidConnectionConfig)
            })
        })
        .await
        .fold(
            |_| false,
            |_| false,
            |_| true,
            |_| false,
            |_| false,
            |_| false,
        );
    assert!(rollback);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id='rollback'",
    )
    .fetch_one(&database.owner)
    .await?;
    assert_eq!(count, 0);
    database.append("unknown").await?;
    database.relay(&receiver.publisher()?).await?;
    let first = receiver.received().await?;
    first.verify(&receiver.endpoint.secret)?;
    assert_eq!(database.status("unknown").await?, "pending");
    let original:String=sqlx::query_scalar("SELECT automatic_retry_deadline::text FROM rss_transactional_messaging.outbox WHERE message_id='unknown'").fetch_one(&database.owner).await?;
    // Recreate every publisher/runtime/store owner: retry comes from PG, not memory.
    database.runtime.close().await;
    let input: rss_examples::webhook::Input =
        serde_json::from_value(database.input(&receiver, "unused"))?;
    let restarted = rss_examples::webhook::runtime(&input.pg).await?;
    let store = PgOutboxStore::<WebhookPublishReceipt>::new(
        restarted.clone(),
        MessagingDomain::parse("webhook-example")?,
        rss_examples::webhook::budget()?,
    )?;
    database.ready("unknown").await?;
    *receiver.mode.lock().await = response(204);
    let report = relay_once(
        &store,
        &receiver.publisher()?,
        &Timer,
        &Emitter,
        NonZeroUsize::MIN,
    )
    .await?;
    assert_eq!(report.claimed(), 1);
    let second = receiver.received().await?;
    assert_eq!(first.body, second.body);
    assert_eq!(
        first.headers.get("webhook-id"),
        second.headers.get("webhook-id")
    );
    assert_eq!(database.status("unknown").await?, "published");
    let after:String=sqlx::query_scalar("SELECT automatic_retry_deadline::text FROM rss_transactional_messaging.outbox WHERE message_id='unknown'").fetch_one(&database.owner).await?;
    assert_eq!(original, after);
    // A successful receive with a lost settlement can be delivered again after lease loss.
    let writer = Arc::new(store);
    let append = writer.clone();
    restarted
        .local_tx(TenantId::parse(TENANT)?, deadline(), move |tx| {
            Box::pin(async move {
                append
                    .append(
                        tx,
                        message("settle-loss").map_err(|_| {
                            rss_transactional_messaging_postgres::PgError::InvalidConnectionConfig
                        })?,
                    )
                    .await
                    .map_err(Into::into)
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    let claim = writer
        .claim_partition_heads(NonZeroUsize::MIN, deadline())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("claim"))?;
    let outcome = receiver
        .publisher()?
        .publish(
            PgOutboxStore::<WebhookPublishReceipt>::message(&claim).envelope(),
            deadline(),
        )
        .await;
    assert!(matches!(outcome, PublishOutcome::Confirmed(_)));
    let received = receiver.received().await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE message_id='settle-loss'").execute(&database.owner).await?;
    assert!(
        writer
            .settle(claim, outcome.into_settlement(), deadline())
            .await
            .is_err()
    );
    relay_once(
        &*writer,
        &receiver.publisher()?,
        &Timer,
        &Emitter,
        NonZeroUsize::MIN,
    )
    .await?;
    assert_eq!(received.body, receiver.received().await?.body);
    assert_eq!(database.status("settle-loss").await?, "published");
    // Current authorization is consulted again; denial is known before any send.
    let mut revoked = receiver.endpoint.clone();
    revoked.tenant = "f47ac10b-58cc-4372-a567-0e02b2c3d478".into();
    let revoked = WebhookPublisher::new(revoked, Timer, Timer, rss_examples::webhook::limits()?);
    let before = receiver
        .connections
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        revoked
            .publish(message("revoked")?.envelope(), deadline())
            .await,
        PublishOutcome::DefinitelyNotPublished(_)
    ));
    assert_eq!(
        before,
        receiver
            .connections
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    expiry_and_redrive(&database, &restarted, &writer, &mut receiver).await?;
    restarted.close().await;
    receiver.stop().await?;
    database.close().await;
    Ok(())
}
async fn append_to(
    runtime: &PgRuntime,
    store: Arc<PgOutboxStore<WebhookPublishReceipt>>,
    id: &str,
) -> anyhow::Result<()> {
    let pending = message(id)?;
    runtime
        .local_tx(
            rss_request_context::TenantId::parse(TENANT)?,
            deadline(),
            move |tx| Box::pin(async move { store.append(tx, pending).await.map_err(Into::into) }),
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    Ok(())
}
struct AllowRecovery;
impl rss_transactional_messaging_recovery::Authorizer for AllowRecovery {
    async fn authorize(
        &self,
        c: rss_transactional_messaging_recovery::Challenge<'_>,
        _: rss_transactional_messaging::policy::OperationDeadline,
    ) -> Result<
        rss_transactional_messaging_recovery::Authorization,
        rss_transactional_messaging_recovery::Error,
    > {
        if c.tenant().to_string() != TENANT {
            return Err(rss_transactional_messaging_recovery::Error::Unauthorized);
        }
        Ok(c.authorized())
    }
}
#[allow(clippy::cognitive_complexity)] // reason: ordered real-PG fault assertions stay adjacent to the state they validate.
async fn expiry_and_redrive(
    database: &Database,
    runtime: &PgRuntime,
    store: &Arc<PgOutboxStore<WebhookPublishReceipt>>,
    receiver: &mut Receiver,
) -> anyhow::Result<()> {
    use recovery::RecoveryStore as _;
    use rss_request_context::{Deadline, TenantId};
    use rss_transactional_messaging_recovery as recovery;
    append_to(runtime, store.clone(), "expired").await?;
    let claim = store
        .claim_partition_heads(NonZeroUsize::MIN, deadline())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("expiry claim"))?;
    store
        .settle(claim, OutboxSettlement::Retry, deadline())
        .await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET automatic_retry_deadline=clock_timestamp()-interval '1 second',retry_after=clock_timestamp()-interval '1 second' WHERE message_id='expired'").execute(&database.owner).await?;
    let before = receiver
        .connections
        .load(std::sync::atomic::Ordering::SeqCst);
    relay_once(
        &**store,
        &receiver.publisher()?,
        &Timer,
        &Emitter,
        NonZeroUsize::MIN,
    )
    .await?;
    assert_eq!(database.status("expired").await?, "dead_letter");
    assert_eq!(
        before,
        receiver
            .connections
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    append_to(runtime, store.clone(), "redrive").await?;
    let claim = store
        .claim_partition_heads(NonZeroUsize::MIN, deadline())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("redrive claim"))?;
    let fingerprint =
        MessageFingerprint::of(PgOutboxStore::<WebhookPublishReceipt>::message(&claim).envelope());
    store
        .settle(claim, OutboxSettlement::DeadLetter, deadline())
        .await?;
    let original:String=sqlx::query_scalar("SELECT automatic_retry_deadline::text FROM rss_transactional_messaging.outbox WHERE message_id='redrive'").fetch_one(&database.owner).await?;
    sqlx::raw_sql("CREATE ROLE webhook_operator LOGIN PASSWORD 'fixture-only' NOBYPASSRLS; GRANT webhook_runtime TO webhook_operator; GRANT SELECT,INSERT ON rss_transactional_messaging.consumer_dead_letter TO webhook_operator; GRANT UPDATE(recovery_version) ON rss_transactional_messaging.consumer_dead_letter TO webhook_operator; GRANT SELECT,INSERT ON rss_transactional_messaging.recovery_operations TO webhook_operator; GRANT UPDATE(status,recovery_version,lease_token,lease_until,retry_after) ON rss_transactional_messaging.outbox TO webhook_operator; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution() TO webhook_operator;").execute(&database.owner).await?;
    let params = database._fixture.params();
    let recovery = rss_transactional_messaging_postgres::PgRecoveryStore::connect(
        PgConfig::new(
            &params.host,
            params.port,
            &params.database,
            "webhook_operator",
            PgPassword::new("fixture-only"),
            PgPrivateCa::from_pem(database._fixture.ca_pem().as_bytes().to_vec())?,
        ),
        Timer,
        fence_fixture::binding(),
        Arc::new(rss_examples::ephemeral::EphemeralKey::from_bytes(
            &[1; 32],
            "webhook-fixture",
        )?),
    )
    .await?;
    let tenant = TenantId::parse(TENANT)?;
    let target = recovery::Target::Outbox(MessageId::parse("redrive")?);
    let cutoff = Deadline::from_timeout(&Timer, Duration::from_secs(5))?;
    let query = recovery::authorize_query(
        &AllowRecovery,
        recovery::Query::inspect(tenant, target.clone()),
        &Timer,
        cutoff,
    )
    .await?;
    let entry = recovery
        .query(&query, deadline())
        .await?
        .entries
        .pop()
        .ok_or_else(|| anyhow::anyhow!("recovery entry"))?;
    let request = recovery::authorize_mutation(
        &AllowRecovery,
        recovery::Mutation::new(
            tenant,
            recovery::OperationId::new(),
            target,
            entry.version,
            recovery::Action::Redrive,
        )?,
        &Timer,
        cutoff,
    )
    .await?;
    let receipt = recovery
        .mutate(&request, deadline())
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    assert_eq!(receipt.outcome, recovery::Outcome::Redriven);
    let after:String=sqlx::query_scalar("SELECT automatic_retry_deadline::text FROM rss_transactional_messaging.outbox WHERE message_id='redrive'").fetch_one(&database.owner).await?;
    assert_eq!(original, after);
    let claim = store
        .claim_partition_heads(NonZeroUsize::MIN, deadline())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("redriven claim"))?;
    let envelope = PgOutboxStore::<WebhookPublishReceipt>::message(&claim).envelope();
    assert_eq!(fingerprint, MessageFingerprint::of(envelope));
    let outcome = receiver.publisher()?.publish(envelope, deadline()).await;
    store
        .settle(claim, outcome.into_settlement(), deadline())
        .await?;
    receiver
        .received()
        .await?
        .verify(&receiver.endpoint.secret)?;
    assert_eq!(database.status("redrive").await?, "published");
    recovery.close().await;
    Ok(())
}

struct RecoveringClock(Arc<std::sync::atomic::AtomicI64>);
impl rss_transactional_messaging_webhook::WallClock for RecoveringClock {
    fn unix_seconds(&self) -> i64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}
#[tokio::test]
async fn transient_clock_failure_retries_original_publication_after_recovery() -> anyhow::Result<()>
{
    tokio::time::timeout(Duration::from_secs(30), clock_recovery()).await?
}
#[allow(clippy::cognitive_complexity)] // reason: ordered clock fault and durable retry assertions share one real PG fixture.
async fn clock_recovery() -> anyhow::Result<()> {
    use rss_transactional_messaging::transport::{
        PublishFailureReason, PublishFailureStage, PublishOutcome,
    };
    use rss_transactional_messaging_webhook::WebhookPublisher;
    let database = Database::new().await?;
    let mut receiver = Receiver::new(response(204)).await?;
    let seconds = Arc::new(std::sync::atomic::AtomicI64::new(-1));
    let publisher = WebhookPublisher::new(
        receiver.endpoint.clone(),
        Timer,
        RecoveringClock(seconds.clone()),
        rss_examples::webhook::limits()?,
    );
    let pending = message("clock-recovery")?;
    let outcome = publisher.publish(pending.envelope(), deadline()).await;
    assert!(
        matches!(&outcome,PublishOutcome::DefinitelyNotPublished(f) if f.kind().is_retryable() && f.stage()==PublishFailureStage::Encode && f.reason()==PublishFailureReason::InvalidMessage)
    );
    assert!(matches!(outcome.into_settlement(), OutboxSettlement::Retry));
    receiver.assert_no_request()?;
    database.append("clock-recovery").await?;
    database.relay(&publisher).await?;
    assert_eq!(database.status("clock-recovery").await?, "pending");
    receiver.assert_no_request()?;
    let before:String=sqlx::query_scalar("SELECT automatic_retry_deadline::text FROM rss_transactional_messaging.outbox WHERE message_id='clock-recovery'").fetch_one(&database.owner).await?;
    seconds.store(1700000001, std::sync::atomic::Ordering::SeqCst);
    database.ready("clock-recovery").await?;
    database.relay(&publisher).await?;
    let received = receiver.received().await?;
    received.verify(&receiver.endpoint.secret)?;
    assert_eq!(received.body, pending.envelope().payload().as_slice());
    assert_eq!(
        received.headers.get("webhook-id").map(String::as_str),
        Some("clock-recovery")
    );
    assert_eq!(
        received
            .headers
            .get("webhook-timestamp")
            .map(String::as_str),
        Some("1700000001")
    );
    assert_eq!(database.status("clock-recovery").await?, "published");
    let after:String=sqlx::query_scalar("SELECT automatic_retry_deadline::text FROM rss_transactional_messaging.outbox WHERE message_id='clock-recovery'").fetch_one(&database.owner).await?;
    assert_eq!(before, after);
    receiver.stop().await?;
    database.close().await;
    Ok(())
}
