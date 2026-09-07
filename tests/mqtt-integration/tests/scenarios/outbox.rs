#[path = "../../../fixtures/message_fence.rs"]
mod fence_fixture;
use super::support::{self, FileStore, Timer};
use rss_transactional_messaging::{
    message::*,
    observability::{TransactionalMessagingEmitter, TransactionalMessagingObservation},
    outbox::*,
    policy::DeliveryBudget,
    transport::Publisher,
};
use rss_transactional_messaging_postgres::{
    PgConfig, PgOutboxStore, PgPassword, PgPrivateCa, PgRuntime,
};
use rss_transactional_messaging_runtime::relay::{RelayBatchLimit, relay_once};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};

struct Emitter;
impl TransactionalMessagingEmitter for Emitter {
    fn emit(&self, _: TransactionalMessagingObservation) {}
}
fn message(id: &str) -> anyhow::Result<MessageEnvelope<Vec<u8>>> {
    use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
    Ok(MessageEnvelope::new(
        MessageId::parse(id)?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
                Timepoint::try_from(1_i64)?,
                MessagingDomain::parse("mqtt-integration")?,
                MessageRoute::parse("created")?,
                ContractIdentity::new(
                    ContractId::parse("mqtt.created")?,
                    ContractVersion::from_major(1)?,
                    SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?,
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        b"durable-payload".to_vec(),
    ))
}
fn plan() -> anyhow::Result<rss_mqtt::MqttOutboxPlan> {
    Ok(rss_mqtt::MqttOutboxPlan::new(
        MessagingDomain::parse("mqtt-integration")?,
        [(
            MessageRoute::parse("created")?,
            rss_mqtt::MqttOutboxTopic::new("outbox/events")?,
        )],
    )?)
}
struct Database {
    _fixture: testkit::PgTlsFixture,
    _network: testkit::BridgeNetwork,
    owner: sqlx::PgPool,
    runtime: Arc<PgRuntime>,
    store: Arc<PgOutboxStore<()>>,
    timer: Timer,
}
impl Database {
    async fn new() -> anyhow::Result<Self> {
        let network = testkit::bridge_network("mqtt-pg").await?;
        let fixture = testkit::postgres_tls(
            testkit::NetworkAttachment {
                network: network.name(),
                dns_name: "mqtt-pg",
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
                    "mqtt_runtime",
                    PgPassword::new("fixture-only"),
                    PgPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?,
                ),
                Timer::new(),
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
        let store = Arc::new(PgOutboxStore::<()>::new(
            runtime.clone(),
            MessagingDomain::parse("mqtt-integration")?,
            budget,
        )?);
        Ok(Self {
            _network: network,
            _fixture: fixture,
            owner,
            runtime,
            store,
            timer: Timer::new(),
        })
    }
    async fn append(&self, id: &str) -> anyhow::Result<()> {
        let envelope = message(id)?;
        let tenant = envelope.metadata().tenant_id();
        let append = self.store.clone();
        self.runtime
            .local_tx(tenant, support::deadline(&self.timer), move |tx| {
                Box::pin(async move {
                    append
                        .append(tx, PendingMessage::new(envelope))
                        .await
                        .map_err(Into::into)
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
        Ok(())
    }
    async fn status(&self, id: &str) -> anyhow::Result<String> {
        Ok(sqlx::query_scalar(
            "SELECT status FROM rss_transactional_messaging.outbox WHERE message_id=$1",
        )
        .bind(id)
        .fetch_one(&self.owner)
        .await?)
    }
    async fn relay(&self, publisher: &impl Publisher<Vec<u8>, Receipt = ()>) -> anyhow::Result<()> {
        let report = relay_once(
            &*self.store,
            publisher,
            &self.timer,
            &Emitter,
            RelayBatchLimit::new(NonZeroUsize::MIN)?,
        )
        .await?;
        assert_eq!(report.claimed(), 1);
        Ok(())
    }
}
async fn provision(owner: &sqlx::PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; CREATE ROLE mqtt_runtime LOGIN PASSWORD 'fixture-only' NOBYPASSRLS;").execute(owner).await?;
    sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
        .execute(owner)
        .await?;
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO mqtt_runtime; GRANT SELECT ON rss_transactional_messaging.policy TO mqtt_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO mqtt_runtime; GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO mqtt_runtime; GRANT USAGE ON ALL SEQUENCES IN SCHEMA rss_transactional_messaging TO mqtt_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) TO mqtt_runtime; CREATE TABLE public.mqtt_handoff (message_id text PRIMARY KEY, payload bytea NOT NULL);").execute(owner).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_outbox_relay_to_real_mqtt() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(45), outbox_scenario()).await?
}
async fn outbox_scenario() -> anyhow::Result<()> {
    let database = Database::new().await?;
    let mqtt = testkit::mqtt_tls(true).await?;
    let clock = Arc::new(Timer::new());
    confirmed(&database, &mqtt, clock.clone()).await?;
    ambiguous(&database, &mqtt, clock).await?;
    database.runtime.close().await;
    database.owner.close().await;
    Ok(())
}
async fn confirmed(
    database: &Database,
    mqtt: &testkit::MqttTlsFixture,
    clock: Arc<Timer>,
) -> anyhow::Result<()> {
    database.append("mqtt-outbox-original").await?;
    let (publisher, mut receiver, resource) = rss_mqtt::connect(
        support::config(mqtt, "outbox", vec!["outbox/events".into()])?,
        clock.clone(),
        Arc::new(FileStore::new()?),
    )?;
    publisher.wait_ready(Duration::from_secs(5)).await?;
    database
        .relay(&rss_mqtt::MqttOutboxPublisher::new(publisher, plan()?))
        .await?;
    assert_eq!(database.status("mqtt-outbox-original").await?, "published");
    let delivery = receiver
        .next()
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing broker delivery"))?;
    assert_eq!(delivery.payload(), b"durable-payload");
    assert_eq!(delivery.topic(), b"outbox/events");
    assert!(delivery.properties().is_some_and(|p| {
        p.user_properties
            .contains(&("messageId".into(), "mqtt-outbox-original".into()))
    }));
    // The application's handoff transaction commits before ACK authority is used.
    sqlx::query("INSERT INTO public.mqtt_handoff VALUES($1,$2)")
        .bind("mqtt-outbox-original")
        .bind(delivery.payload())
        .execute(&database.owner)
        .await?;
    delivery
        .into_parts()
        .1
        .ack_after_durable_handoff(support::deadline(&*clock))
        .await?;
    resource.shutdown(Duration::from_secs(3)).await?;
    Ok(())
}
async fn ambiguous(
    database: &Database,
    mqtt: &testkit::MqttTlsFixture,
    clock: Arc<Timer>,
) -> anyhow::Result<()> {
    let (observer, mut receiver, resource) = rss_mqtt::connect(
        support::config(
            mqtt,
            "outbox-observer",
            vec!["outbox/events".into(), "outbox/barrier".into()],
        )?,
        clock.clone(),
        Arc::new(FileStore::new()?),
    )?;
    observer.wait_ready(Duration::from_secs(5)).await?;
    let checkpoint = Arc::new(FileStore::new()?);
    let first = lost_ack(
        database,
        mqtt,
        clock.clone(),
        checkpoint.clone(),
        &mut receiver,
    )
    .await?;
    assert_eq!(first.payload.as_ref(), b"durable-payload");
    assert!(first.properties.as_ref().is_some_and(|p| {
        p.user_properties
            .contains(&("messageId".into(), "mqtt-outbox-ambiguous".into()))
    }));
    retry(database, mqtt, clock, checkpoint, &mut receiver, &first).await?;
    resource.shutdown(Duration::from_secs(3)).await?;
    Ok(())
}
async fn lost_ack(
    database: &Database,
    mqtt: &testkit::MqttTlsFixture,
    clock: Arc<Timer>,
    checkpoint: Arc<FileStore>,
    observer: &mut rss_mqtt::MqttReceiver,
) -> anyhow::Result<rumqttc::mqttbytes::v5::Publish> {
    database.append("mqtt-outbox-ambiguous").await?;
    let proxy =
        support::proxy::AckLossProxy::start(mqtt.port(), support::tls(mqtt, false, true)?).await?;
    let config = rss_mqtt::MqttConfig::new(
        "localhost",
        proxy.port,
        "ambiguous-relay",
        "mqtt-integration",
        proxy.peer_tls.clone(),
        rss_mqtt::Limits::new(32, 32, 32, 65536)?,
    )?
    .credentials("mqtt", b"fixture-only".to_vec())?;
    let (publisher, _receiver, resource) =
        rss_mqtt::connect(config, clock.clone(), checkpoint.clone())?;
    publisher.wait_ready(Duration::from_secs(5)).await?;
    database
        .relay(&rss_mqtt::MqttOutboxPublisher::new(
            publisher.clone(),
            plan()?,
        ))
        .await?;
    assert!(
        proxy.dropped.load(std::sync::atomic::Ordering::Acquire) > 0,
        "withhold a real broker PUBACK"
    );
    assert_eq!(database.status("mqtt-outbox-ambiguous").await?, "pending");
    let mut status = publisher.connection_state();
    drop(resource);
    status
        .wait_for(|v| *v == rss_mqtt::ConnectionState::Closed)
        .await?;
    drop(proxy);
    observe(observer, &clock).await
}
async fn retry(
    database: &Database,
    mqtt: &testkit::MqttTlsFixture,
    clock: Arc<Timer>,
    checkpoint: Arc<FileStore>,
    observer: &mut rss_mqtt::MqttReceiver,
    first: &rumqttc::mqttbytes::v5::Publish,
) -> anyhow::Result<()> {
    let (publisher, _receiver, resource) = rss_mqtt::connect(
        support::config(mqtt, "ambiguous-relay", vec![])?,
        clock.clone(),
        checkpoint,
    )?;
    publisher.wait_ready(Duration::from_secs(5)).await?;
    drain_protocol_replay(&publisher, observer, &clock, first).await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET retry_after=clock_timestamp() WHERE message_id='mqtt-outbox-ambiguous'").execute(&database.owner).await?;
    database
        .relay(&rss_mqtt::MqttOutboxPublisher::new(publisher, plan()?))
        .await?;
    assert_eq!(database.status("mqtt-outbox-ambiguous").await?, "published");
    // This delivery is after the replay barrier: it must come from the canonical Outbox retry.
    assert_same(&observe(observer, &clock).await?, first);
    resource.shutdown(Duration::from_secs(3)).await?;
    Ok(())
}
async fn drain_protocol_replay(
    publisher: &rss_mqtt::MqttPublisher,
    observer: &mut rss_mqtt::MqttReceiver,
    clock: &Timer,
    first: &rumqttc::mqttbytes::v5::Publish,
) -> anyhow::Result<()> {
    use rss_transactional_messaging::transport::PublishOutcome;
    assert!(matches!(
        publisher
            .publish(
                rss_mqtt::PublishRequest::new("outbox/barrier", Vec::new())?,
                support::deadline(clock)
            )
            .await,
        PublishOutcome::Confirmed(())
    ));
    loop {
        let observed = observe(observer, clock).await?;
        if observed.topic.as_ref() == b"outbox/barrier" {
            return Ok(());
        }
        assert_same(&observed, first);
    }
}
async fn observe(
    receiver: &mut rss_mqtt::MqttReceiver,
    clock: &Timer,
) -> anyhow::Result<rumqttc::mqttbytes::v5::Publish> {
    let delivery = tokio::time::timeout(Duration::from_secs(3), receiver.next())
        .await??
        .ok_or_else(|| anyhow::anyhow!("missing observed publication"))?;
    let (publish, settlement) = delivery.into_parts();
    settlement
        .ack_after_durable_handoff(support::deadline(clock))
        .await?;
    Ok(publish)
}
fn assert_same(
    actual: &rumqttc::mqttbytes::v5::Publish,
    expected: &rumqttc::mqttbytes::v5::Publish,
) {
    assert_eq!(actual.topic, expected.topic);
    assert_eq!(actual.payload, expected.payload);
    assert_eq!(actual.properties, expected.properties);
    assert_eq!(actual.retain, expected.retain);
}

#[tokio::test(flavor = "multi_thread")]
async fn unbound_domain_never_enters_the_protocol() -> anyhow::Result<()> {
    use rss_transactional_messaging::transport::{
        PublishFailureKind, PublishFailureStage, PublishOutcome,
    };
    use rumqttc::mqttbytes::v5::Packet;
    let peer = support::wire::Peer::new().await?;
    let config = peer.config("encode-only")?;
    let server = tokio::spawn(async move {
        let mut wire = peer.accept(false).await?;
        anyhow::ensure!(
            matches!(wire.read().await?, Packet::Disconnect(_)),
            "encoding must not enqueue PUBLISH"
        );
        Ok::<_, anyhow::Error>(())
    });
    let clock = Arc::new(Timer::new());
    let (publisher, _receiver, resource) =
        rss_mqtt::connect(config, clock.clone(), Arc::new(FileStore::new()?))?;
    publisher.wait_ready(Duration::from_secs(3)).await?;
    let adapter = rss_mqtt::MqttOutboxPublisher::new(
        publisher,
        rss_mqtt::MqttOutboxPlan::new(
            MessagingDomain::parse("unbound")?,
            [(
                MessageRoute::parse("created")?,
                rss_mqtt::MqttOutboxTopic::new("events")?,
            )],
        )?,
    );
    let result = adapter
        .publish(&message("encode-failure")?, support::deadline(&*clock))
        .await;
    assert!(
        matches!(result, PublishOutcome::DefinitelyNotPublished(f) if f.kind() == PublishFailureKind::Permanent && f.stage() == PublishFailureStage::Encode)
    );
    resource.shutdown(Duration::from_secs(3)).await?;
    server.await??;
    Ok(())
}

#[path = "transactional.rs"]
mod transactional;
