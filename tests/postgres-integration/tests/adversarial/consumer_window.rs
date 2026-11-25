mod claim_wait;
use super::*;
use crate::Validator;
use rss_request_context::{Clock, ExecutionTimer};
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

// Let the owner renew in database time while a frozen waiter can only wake by permit transfer.
enum WorkerClock {
    Owner(Timer),
    Waiter(FakeClock),
}
impl Clock for WorkerClock {
    fn now(&self) -> std::time::Instant {
        match self {
            Self::Owner(clock) => clock.now(),
            Self::Waiter(clock) => clock.now(),
        }
    }
}
impl ExecutionTimer for WorkerClock {
    async fn sleep_until(&self, deadline: Deadline) {
        match self {
            Self::Owner(clock) => clock.sleep_until(deadline).await,
            Self::Waiter(clock) => clock.sleep_until(deadline).await,
        }
    }
}

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
struct BeforeEffect {
    tx: PgConsumerTx<GateEffect>,
    claimed: Arc<Notify>,
    start: Arc<Notify>,
}
impl ConsumerTx<Vec<u8>> for BeforeEffect {
    type Claim = PgInboxClaim;
    type CommitProof = <PgConsumerTx<GateEffect> as ConsumerTx<Vec<u8>>>::CommitProof;
    async fn execute(
        &self,
        claim: &PgInboxClaim,
        msg: &MessageEnvelope<Vec<u8>>,
        intent: ReceiptIntent,
        deadline: OperationDeadline,
    ) -> TransactionOutcome<Self::CommitProof> {
        if msg.id().as_str() == "window-held" {
            self.claimed.notify_one();
            self.start.notified().await;
        }
        self.tx.execute(claim, msg, intent, deadline).await
    }
}

pub(crate) async fn run(config: PgConfig, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    claim_wait::install_counter(owner).await?;
    let runtime = Arc::new(
        PgRuntime::connect(
            config.clone().with_pool_limits(0, 2),
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
    let claimed = Arc::new(Notify::new());
    let start = Arc::new(Notify::new());
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
            Arc::new(BeforeEffect {
                tx: PgConsumerTx::receipt_only(runtime.clone(), effect),
                claimed: claimed.clone(),
                start: start.clone(),
            }),
            ConsumerGroup::parse("window")?,
            Arc::new(Validator),
            sub,
            Arc::new(if id == "window-held" {
                WorkerClock::Owner(Timer::new())
            } else {
                WorkerClock::Waiter(FakeClock::new())
            }),
            ConsumerExecutionPolicy::new(RetryPolicy::STANDARD, ExecutionBudget::STANDARD),
            Arc::new(Sink(busy.clone())),
            SubscriptionBackoffPolicy::STANDARD,
        );
        tasks.push(tokio::spawn(worker.run(token.clone())));
        if id == "window-held" {
            claimed.notified().await;
        }
    }
    // The first Worker has a durable claim but has not requested its effect connection.
    tokio::time::timeout(Duration::from_secs(2), busy.notified()).await?;
    claim_wait::cancel_waiter(&inbox, &runtime).await?;
    start.notify_one();
    entered.notified().await;
    verify_renewal_under_saturation(owner).await?;
    assert_eq!(
        claim_wait::claim_count(owner).await?,
        1,
        "only the holder reached claim SQL"
    );
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
    assert_eq!(
        claim_wait::claim_count(owner).await?,
        2,
        "the local waiter claimed exactly once"
    );
    claim_wait::remote_cases(config, runtime.clone(), owner).await?;
    runtime.close().await;
    Ok(())
}

async fn verify_renewal_under_saturation(owner: &sqlx::PgPool) -> anyhow::Result<()> {
    let remaining = || {
        sqlx::query_scalar::<_,i64>("SELECT (extract(epoch FROM lease_until)*1000)::bigint FROM rss_transactional_messaging.inbox WHERE message_id='window-held'").fetch_one(owner)
    };
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
