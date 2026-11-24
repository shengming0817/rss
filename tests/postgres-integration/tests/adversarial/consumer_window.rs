use super::*;
use crate::Validator;
use rss_transactional_messaging::{
    error::MessagingError,
    message::SubscriptionIdentity,
    observability::{TransactionalMessagingEmitter, TransactionalMessagingObservation},
    transport::{Delivery, DeliverySource, IncomingDelivery, ManagedDeliveryStream, StreamOnStop},
};
use rss_transactional_messaging_runtime::consumer::{ConsumerWorker, SubscriptionBackoffPolicy};
use rss_transactional_messaging_testkit::memory::RecordingSettlement;
use std::{num::NonZeroU16, sync::Mutex};
use tokio_util::sync::CancellationToken;

struct One(Mutex<Option<Delivery<Vec<u8>, RecordingSettlement>>>);
impl DeliverySource<Vec<u8>> for One {
    type Settlement = RecordingSettlement;
    type Deliveries = futures::stream::Iter<
        std::option::IntoIter<IncomingDelivery<Vec<u8>, RecordingSettlement>>,
    >;
    async fn deliveries(
        &self,
        _: &SubscriptionIdentity,
        _: NonZeroU16,
    ) -> Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError> {
        let item = self
            .0
            .lock()
            .expect("fixture delivery")
            .take()
            .map(|d| IncomingDelivery::Valid(Box::new(d)));
        Ok(ManagedDeliveryStream::from_provider(
            StreamOnStop::Release,
            futures::stream::iter(item),
        ))
    }
}
struct Sink(Arc<Notify>);
impl TransactionalMessagingEmitter for Sink {
    fn emit(&self, observation: TransactionalMessagingObservation) {
        if matches!(
            observation,
            TransactionalMessagingObservation::ConsumerClaimCapacityBusy
        ) {
            self.0.notify_one();
        }
    }
}
pub(crate) async fn run(config: PgConfig, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    let runtime = Arc::new(
        PgRuntime::connect(
            config.with_pool_limits(0, 2),
            Timer::new(),
            fence_fixture::storage(),
        )
        .await?,
    );
    let inbox = Arc::new(PgInboxStore::new(
        runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_millis(900))?,
    )?);
    let token = CancellationToken::new();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let busy = Arc::new(Notify::new());
    let mut tasks = Vec::new();
    let mut recorders = Vec::new();
    for id in ["window-held", "window-waiting"] {
        let msg = message(id);
        let metadata = msg.metadata();
        let sub = SubscriptionIdentity::new(
            metadata.domain().clone(),
            metadata.route().clone(),
            metadata.contract().clone(),
        );
        let recorder = RecordingSettlement::new();
        let source = One(Mutex::new(Some(Delivery::new(msg, recorder.clone()))));
        recorders.push(recorder);
        let gate = if id == "window-held" {
            release.clone()
        } else {
            let gate = Arc::new(Notify::new());
            gate.notify_one();
            gate
        };
        let effect = GateEffect {
            entered: entered.clone(),
            release: gate,
        };
        let worker = ConsumerWorker::new(
            NonZeroU16::MIN,
            Arc::new(source),
            inbox.clone(),
            Arc::new(PgConsumerTx::receipt_only(runtime.clone(), effect)),
            ConsumerGroup::parse("window")?,
            Arc::new(Validator),
            sub,
            Arc::new(Timer::new()),
            ConsumerExecutionPolicy::new(RetryPolicy::STANDARD, ExecutionBudget::STANDARD),
            Arc::new(Sink(busy.clone())),
            SubscriptionBackoffPolicy::STANDARD,
        );
        tasks.push(tokio::spawn(worker.run(token.clone())));
        if id == "window-held" {
            entered.notified().await;
        }
    }
    verify_renewal_under_saturation(owner, &busy).await?;
    release.notify_one();
    testkit::await_try(Duration::from_secs(4), async || {
        Ok::<_, anyhow::Error>(
            recorders
                .iter()
                .all(|r| !r.settlements().is_empty())
                .then_some(()),
        )
    })
    .await?;
    token.cancel();
    for task in tasks {
        task.await??;
    }
    verify_settled(owner, &recorders).await?;
    runtime.close().await;
    Ok(())
}

async fn verify_renewal_under_saturation(
    owner: &sqlx::PgPool,
    busy: &Notify,
) -> anyhow::Result<()> {
    let remaining = || {
        sqlx::query_scalar::<_,i64>("SELECT (extract(epoch FROM lease_until)*1000)::bigint FROM rss_transactional_messaging.inbox WHERE message_id='window-held'").fetch_one(owner)
    };
    tokio::time::timeout(Duration::from_secs(3), busy.notified()).await?;
    let initial = remaining().await?;
    testkit::await_try(Duration::from_secs(5), async || {
        Ok::<_, anyhow::Error>((remaining().await? > initial + 900).then_some(()))
    })
    .await?;
    let waiting_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.inbox WHERE message_id='window-waiting'",
    )
    .fetch_one(owner)
    .await?;
    assert_eq!(waiting_rows, 0, "saturation must precede a durable claim");
    Ok(())
}

async fn verify_settled(
    owner: &sqlx::PgPool,
    recorders: &[RecordingSettlement],
) -> anyhow::Result<()> {
    for recorder in recorders {
        assert_eq!(recorder.settlements(), [SettlementKind::Acknowledge]);
        assert_eq!(recorder.abandon_count(), 0);
    }
    for id in ["window-held", "window-waiting"] {
        assert_eq!(count(owner, id).await, 1);
        let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.inbox WHERE message_id=$1 AND disposition='succeeded'").bind(id).fetch_one(owner).await?;
        assert_eq!(receipts, 1);
    }
    Ok(())
}
