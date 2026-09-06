//! Inject one lost settlement result at the provider port; every delivery and transaction is real.
use super::*;
use futures::StreamExt;
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind},
    transaction::SettlementDecision,
    transport::{DeliverySettlement, ManagedDeliveryStream},
};
use rss_transactional_messaging_runtime::consumer::{ConsumerWorker, SubscriptionBackoffPolicy};
use std::{
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
};
use tokio_util::sync::CancellationToken;

struct LoseFirstSettlement {
    source: MqttDeliverySource,
    first: Arc<AtomicBool>,
    done: CancellationToken,
}
struct LostResult {
    inner: MqttTransactionSettlement,
    first: Arc<AtomicBool>,
    done: CancellationToken,
}
impl DeliverySettlement for LostResult {
    async fn settle(
        self,
        decision: SettlementDecision,
        deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        if self.first.swap(false, Ordering::AcqRel) {
            self.inner.abandon(deadline).await?;
            return Err(MessagingError::new(
                MessagingErrorKind::Transient,
                rss_mqtt::MqttError::SettlementUnknown,
            ));
        }
        self.inner.settle(decision, deadline).await?;
        self.done.cancel();
        Ok(())
    }
    async fn abandon(self, deadline: OperationDeadline) -> Result<(), MessagingError> {
        self.inner.abandon(deadline).await
    }
}
type FaultDeliveries =
    Pin<Box<dyn futures::Stream<Item = IncomingDelivery<Vec<u8>, LostResult>> + Send>>;
impl DeliverySource<Vec<u8>> for LoseFirstSettlement {
    type Settlement = LostResult;
    type Deliveries = FaultDeliveries;
    async fn deliveries(
        &self,
        subscription: &SubscriptionIdentity,
    ) -> Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError> {
        let stream = self.source.deliveries(subscription).await?;
        let stream = futures::stream::unfold(stream, |mut stream| async move {
            stream.next().await.map(|item| (item, stream))
        });
        let first = self.first.clone();
        let done = self.done.clone();
        let mapped = stream.map(move |item| match item {
            IncomingDelivery::Valid(delivery) => {
                let (message, inner) = delivery.into_parts();
                IncomingDelivery::Valid(Box::new(Delivery::new(
                    message,
                    LostResult {
                        inner,
                        first: first.clone(),
                        done: done.clone(),
                    },
                )))
            }
            IncomingDelivery::Invalid(invalid) => {
                let (rejection, inner) = invalid.into_parts();
                IncomingDelivery::invalid_from_provider(
                    rejection.reason(),
                    LostResult {
                        inner,
                        first: first.clone(),
                        done: done.clone(),
                    },
                )
            }
        });
        Ok(ManagedDeliveryStream::from_provider(
            Box::pin(mapped) as FaultDeliveries
        ))
    }
}
fn subscription() -> anyhow::Result<SubscriptionIdentity> {
    let message = message("template")?;
    let m = message.metadata();
    Ok(SubscriptionIdentity::new(
        m.domain().clone(),
        m.route().clone(),
        m.contract().clone(),
    ))
}
fn worker<S: DeliverySource<Vec<u8>>>(
    source: Arc<S>,
    database: &Database,
    clock: Arc<Timer>,
    token: CancellationToken,
) -> anyhow::Result<impl Future<Output = Result<(), MessagingError>>> {
    let worker = ConsumerWorker::new(
        source,
        Arc::new(PgInboxStore::new(
            database.runtime.clone(),
            LeaseRenewalPolicy::from_ttl(Duration::from_secs(60))?,
        )?),
        Arc::new(PgConsumerTx::receipt_only(
            database.runtime.clone(),
            Effect(false),
        )),
        ConsumerGroup::parse("mqtt-worker")?,
        Arc::new(Validator(true)),
        subscription()?,
        clock,
        ConsumerExecutionPolicy::new(RetryPolicy::STANDARD, ExecutionBudget::STANDARD),
        Arc::new(Emitter),
        SubscriptionBackoffPolicy::new(Duration::from_millis(10), Duration::from_millis(20))?,
    );
    Ok(async move { worker.run(token).await })
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worker_resubscribes_after_lost_settlement_without_duplicate_effect() -> anyhow::Result<()>
{
    tokio::time::timeout(Duration::from_secs(45), recovery()).await?
}
async fn recovery() -> anyhow::Result<()> {
    let database = Database::new().await?;
    sqlx::raw_sql("GRANT SELECT,INSERT ON public.mqtt_handoff TO mqtt_runtime")
        .execute(&database.owner)
        .await?;
    let mqtt = testkit::mqtt_tls(true).await?;
    let clock = Arc::new(Timer::new());
    let (publisher, receiver, resource) = rss_mqtt::connect(
        support::config(&mqtt, "worker-recovery", vec!["outbox/events".into()])?,
        clock.clone(),
        Arc::new(FileStore::new()?),
    )?;
    publisher.wait_ready(Duration::from_secs(5)).await?;
    let done = CancellationToken::new();
    let source = Arc::new(LoseFirstSettlement {
        source: MqttDeliverySource::new(receiver, subscription()?)?,
        first: Arc::new(AtomicBool::new(true)),
        done: done.clone(),
    });
    let run = worker(source, &database, clock.clone(), done.clone())?;
    database.append("worker-recovery").await?;
    database
        .relay(&rss_mqtt::MqttOutboxPublisher::new(publisher, plan()?))
        .await?;
    run.await?;
    assert!(done.is_cancelled());
    assert_eq!(count(&database, "worker-recovery").await?, 1);
    drop(resource);
    database.runtime.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worker_retains_terminal_protocol_failure_after_stream_end() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), terminal()).await?
}
async fn terminal() -> anyhow::Result<()> {
    use rumqttc::mqttbytes::v5::{Packet, Publish, SubAck, SubscribeReasonCode};
    let database = Database::new().await?;
    let peer = support::wire::Peer::new().await?;
    let config = peer
        .config("worker-terminal")?
        .subscriptions(["outbox/events".into()])?;
    let (send, trigger) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut wire = peer.accept(false).await?;
        let Packet::Subscribe(subscribe) = wire.read().await? else {
            anyhow::bail!("expected subscribe")
        };
        wire.write(Packet::SubAck(SubAck {
            pkid: subscribe.pkid,
            return_codes: vec![SubscribeReasonCode::Success(rumqttc::QoS::AtLeastOnce)],
            properties: None,
        }))
        .await?;
        trigger.await?;
        wire.write(Packet::Publish(Publish::new(
            "outbox/events",
            rumqttc::QoS::AtMostOnce,
            vec![1],
            None,
        )))
        .await?;
        let _closed = wire.read().await;
        Ok::<_, anyhow::Error>(())
    });
    let clock = Arc::new(Timer::new());
    let (publisher, receiver, resource) =
        rss_mqtt::connect(config, clock.clone(), Arc::new(FileStore::new()?))?;
    publisher.wait_ready(Duration::from_secs(5)).await?;
    let source = Arc::new(MqttDeliverySource::new(receiver, subscription()?)?);
    let state = source.connection_state();
    let run = worker(source.clone(), &database, clock, CancellationToken::new())?;
    // Poll worker before releasing the scripted terminal packet, ensuring failure occurs in-stream.
    let result = tokio::join!(run, async {
        tokio::task::yield_now().await;
        send.send(()).map_err(|_| anyhow::anyhow!("server stopped"))
    });
    result.1?;
    assert_eq!(
        result
            .0
            .err()
            .ok_or_else(|| anyhow::anyhow!("worker accepted terminal failure"))?
            .kind(),
        MessagingErrorKind::Permanent
    );
    assert_eq!(
        *state.borrow(),
        rss_mqtt::ConnectionState::Failed(rss_mqtt::MqttError::UnsupportedQos)
    );
    assert!(source.deliveries(&subscription()?).await.is_err());
    server.await??;
    drop(resource);
    database.runtime.close().await;
    Ok(())
}
