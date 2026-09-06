mod support;
use rss_transactional_messaging::{
    message::MessagingDomain,
    observability::{TransactionalMessagingEmitter, TransactionalMessagingObservation},
    outbox::{OutboxStore, PendingMessage},
    policy::DeliveryBudget,
};
use rss_transactional_messaging_kafka::{KafkaPublishReceipt, KafkaPublisher};
use rss_transactional_messaging_postgres::{
    PgConfig, PgOutboxStore, PgPassword, PgPrivateCa, PgRuntime,
};
use rss_transactional_messaging_runtime::relay::{RelayBatchLimit, relay_once};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::{sync::Arc, time::Duration};
use support::*;
struct Emitter;
impl TransactionalMessagingEmitter for Emitter {
    fn emit(&self, _: TransactionalMessagingObservation) { /* reason: assertions read durable provider state. */
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_outbox_to_kafka_suite() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(110), run()).await??;
    Ok(())
}
async fn run() -> anyhow::Result<()> {
    let kafka = testkit::kafka_tls(testkit::KafkaTlsServerIdentity::MatchingHost).await?;
    let network = testkit::bridge_network("kafka-outbox").await?;
    let pg = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "kafka-outbox-pg",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let params = pg.params();
    let owner = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(
            PgConnectOptions::new()
                .host(&params.host)
                .port(params.port)
                .database(&params.database)
                .username(&params.username)
                .password(&params.password)
                .ssl_mode(PgSslMode::VerifyFull)
                .ssl_root_cert_from_pem(pg.ca_pem().as_bytes().to_vec()),
        )
        .await?;
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; CREATE ROLE kafka_outbox_runtime LOGIN PASSWORD 'fixture-only' NOBYPASSRLS;").execute(&owner).await?;
    sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
        .execute(&owner)
        .await?;
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO kafka_outbox_runtime; GRANT SELECT ON rss_transactional_messaging.policy TO kafka_outbox_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO kafka_outbox_runtime; GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO kafka_outbox_runtime; GRANT USAGE ON ALL SEQUENCES IN SCHEMA rss_transactional_messaging TO kafka_outbox_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_transactional_messaging TO kafka_outbox_runtime;").execute(&owner).await?;
    let runtime = Arc::new(
        PgRuntime::connect(
            PgConfig::new(
                &params.host,
                params.port,
                &params.database,
                "kafka_outbox_runtime",
                PgPassword::new("fixture-only"),
                PgPrivateCa::from_pem(pg.ca_pem().as_bytes().to_vec())?,
            ),
            Timer::new(),
        )
        .await?,
    );
    let store = Arc::new(PgOutboxStore::<KafkaPublishReceipt>::new(
        runtime.clone(),
        MessagingDomain::parse("events")?,
        DeliveryBudget::new(
            Duration::from_secs(10),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )?,
    )?);
    let (publisher, resource) =
        KafkaPublisher::create(config(&kafka)?, Duration::from_secs(5)).await?;
    exercise_outbox(&kafka, &owner, &runtime, &store, &publisher).await?;
    resource.shutdown(Duration::from_secs(5)).await?;
    runtime.close().await;
    owner.close().await;
    Ok(())
}

async fn exercise_outbox(
    kafka: &testkit::KafkaTlsFixture,
    owner: &sqlx::PgPool,
    runtime: &Arc<PgRuntime>,
    store: &Arc<PgOutboxStore<KafkaPublishReceipt>>,
    publisher: &KafkaPublisher,
) -> anyhow::Result<()> {
    for (id, lose_report) in [("pg-confirmed", false), ("pg-ambiguous", true)] {
        append_message(runtime, store, id).await?;
        let (report, release) = first_relay(store, publisher, lose_report).await?;
        let status: String = sqlx::query_scalar(
            "SELECT status FROM rss_transactional_messaging.outbox WHERE message_id=$1",
        )
        .bind(id)
        .fetch_one(owner)
        .await?;
        assert_eq!(status, if lose_report { "pending" } else { "published" });
        assert_record(&read_records(kafka, id, 1).await?[0], id);
        if let Some(release) = release {
            assert_eq!(report.retried(), 1);
            retry_published(kafka, owner, store, publisher, id, release).await?;
        } else {
            assert_eq!(report.published(), 1);
        }
    }
    Ok(())
}

async fn append_message(
    runtime: &Arc<PgRuntime>,
    store: &Arc<PgOutboxStore<KafkaPublishReceipt>>,
    id: &str,
) -> anyhow::Result<()> {
    let envelope = message(id)?;
    let tenant = envelope.metadata().tenant_id();
    let append = store.clone();
    runtime
        .local_tx(tenant, deadline(Duration::from_secs(3))?, move |tx| {
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

async fn retry_published(
    kafka: &testkit::KafkaTlsFixture,
    owner: &sqlx::PgPool,
    store: &Arc<PgOutboxStore<KafkaPublishReceipt>>,
    publisher: &KafkaPublisher,
    id: &str,
    release: tokio::sync::oneshot::Sender<()>,
) -> anyhow::Result<()> {
    let _ = release.send(());
    drained(publisher).await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let report = relay_once(
        &**store,
        publisher,
        &Timer::new(),
        &Emitter,
        RelayBatchLimit::new(std::num::NonZeroUsize::MIN)?,
    )
    .await?;
    assert_eq!(report.published(), 1);
    let status: String = sqlx::query_scalar(
        "SELECT status FROM rss_transactional_messaging.outbox WHERE message_id=$1",
    )
    .bind(id)
    .fetch_one(owner)
    .await?;
    assert_eq!(status, "published");
    for record in read_records(kafka, id, 2).await? {
        assert_record(&record, id);
    }
    Ok(())
}

async fn first_relay(
    store: &Arc<PgOutboxStore<KafkaPublishReceipt>>,
    publisher: &KafkaPublisher,
    lose_report: bool,
) -> anyhow::Result<(
    rss_transactional_messaging_runtime::relay::RelayReport,
    Option<tokio::sync::oneshot::Sender<()>>,
)> {
    let gate = lose_report.then(|| publisher.pause_next_delivery_for_test());
    let store = store.clone();
    let publisher = publisher.clone();
    let task = tokio::spawn(async move {
        Ok::<_, anyhow::Error>(
            relay_once(
                &*store,
                &publisher,
                &Timer::new(),
                &Emitter,
                RelayBatchLimit::new(std::num::NonZeroUsize::MIN)?,
            )
            .await?,
        )
    });
    let release = if let Some((entered, release)) = gate {
        entered.await?;
        Some(release)
    } else {
        None
    };
    Ok((task.await??, release))
}
