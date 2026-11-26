use super::*;
use std::num::NonZeroU16;
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;

struct ObserveIngress(mpsc::UnboundedSender<String>);
impl IngressValidator<Vec<u8>> for ObserveIngress {
    fn validate(
        &self,
        c: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        let id = c.message().id().as_str().to_owned();
        let verified = LiveIngress.validate(c)?;
        self.0.send(id).expect("admission observer");
        Ok(verified)
    }
}
struct Gate {
    started: mpsc::UnboundedSender<String>,
    release: Arc<Notify>,
}
impl ConsumerTx<Vec<u8>> for Gate {
    type Claim = ();
    type CommitProof = ();
    async fn execute(
        &self,
        _: &(),
        message: &MessageEnvelope<Vec<u8>>,
        receipt: rss_transactional_messaging::transaction::ReceiptIntent,
        _: OperationDeadline,
    ) -> TransactionOutcome<()> {
        self.started
            .send(message.id().as_str().to_owned())
            .expect("effect observer");
        if message.id().as_str() == "a" {
            self.release.notified().await;
        }
        committed(receipt)
    }
}

struct Broker {
    url: String,
    route: MessageRoute,
    sub: AmqpSubscriber,
    resource: AmqpSubscriberResource,
    publisher: AmqpPublisher,
    publisher_resource: AmqpPublisherResource,
}

impl Broker {
    async fn open(rabbit: &testkit::RabbitFixture) -> anyhow::Result<Self> {
        let url = isolated_url(rabbit, "rss_window").await?;
        let route = MessageRoute::parse("rss.window")?;
        let (sub, resource) = prepared_subscriber(&url, &route, "window", true).await?;
        let (publisher, publisher_resource) = connected_publisher(&url, "window-pub").await?;
        Ok(Self {
            url,
            route,
            sub,
            resource,
            publisher,
            publisher_resource,
        })
    }
}

pub(super) async fn run(rabbit: &testkit::RabbitFixture) -> anyhow::Result<()> {
    for window in [NonZeroU16::MIN, NonZeroU16::new(2).expect("two")] {
        drain_window(rabbit, window).await?;
    }
    for head in [Head::Retry, Head::Reject, Head::Unknown, Head::Fenced] {
        drain_after_failed_head(rabbit, head).await?;
    }
    busy_redelivery(rabbit).await
}

#[expect(
    clippy::cognitive_complexity,
    reason = "Keep broker registration, cancellation, and post-drain redelivery in their observed order."
)]
async fn drain_window(rabbit: &testkit::RabbitFixture, window: NonZeroU16) -> anyhow::Result<()> {
    let Broker {
        url,
        route,
        sub,
        resource,
        publisher,
        publisher_resource,
    } = Broker::open(rabbit).await?;
    let subscription = subscription_for(&envelope(&route, "template"), &route);
    let (starts, mut started) = mpsc::unbounded_channel();
    let (sees, mut admitted) = mpsc::unbounded_channel();
    let release = Arc::new(Notify::new());
    let token = CancellationToken::new();
    let sub = Arc::new(sub);
    let worker = ConsumerWorker::new(
        window,
        sub.clone(),
        Arc::new(LiveInbox),
        Arc::new(Gate {
            started: starts,
            release: release.clone(),
        }),
        ConsumerGroup::parse("window")?,
        Arc::new(ObserveIngress(sees)),
        subscription.clone(),
        Arc::new(TokioClock::new()),
        ConsumerExecutionPolicy::new(
            RetryPolicy::STANDARD,
            ExecutionBudget::new(TIMEOUT, Duration::from_secs(3))?,
        ),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::STANDARD,
    );
    let task = tokio::spawn(worker.run(token.clone()));
    for (id, key) in [
        ("a", "ordered"),
        ("b", "other"),
        ("c", "other"),
        ("d", "ordered"),
        ("e", "other"),
    ] {
        assert!(matches!(
            publisher
                .publish(
                    &envelope_in_partition(&route, id, vec![1], key),
                    provider_deadline()
                )
                .await,
            PublishOutcome::Confirmed(())
        ));
    }
    let vhost = url.rsplit('/').next().expect("vhost");
    assert_eq!(
        rabbit
            .broker_consumer_prefetch(vhost, route.as_str())
            .await?,
        [window.get()]
    );
    assert_active_window(window, &mut started, &mut admitted).await;
    token.cancel();
    await_cancelled(rabbit, vhost, &route).await?;
    release.notify_one();
    task.await??;
    if window.get() == 2 {
        assert_eq!(started.recv().await.as_deref(), Some("d"));
    }
    assert!(started.recv().await.is_none());
    let mut fresh = sub.deliveries(&subscription, NonZeroU16::MIN).await?;
    let delivery = next_valid_delivery(&mut fresh).await?;
    let expected = if window.get() == 2 { "e" } else { "b" };
    assert_eq!(delivery.into_parts().0.id().as_str(), expected);
    drop(fresh);
    shutdown_bounded(resource.shutdown(Duration::from_secs(5))).await?;
    shutdown_bounded(publisher_resource.shutdown(Duration::from_secs(5))).await?;
    Ok(())
}

async fn await_cancelled(
    rabbit: &testkit::RabbitFixture,
    vhost: &str,
    route: &MessageRoute,
) -> anyhow::Result<()> {
    testkit::await_try(TIMEOUT, async || {
        Ok::<_, anyhow::Error>(
            (rabbit.broker_consumer_count(vhost, route.as_str()).await? == 0).then_some(()),
        )
    })
    .await
}

async fn assert_active_window(
    window: NonZeroU16,
    started: &mut mpsc::UnboundedReceiver<String>,
    admitted: &mut mpsc::UnboundedReceiver<String>,
) {
    assert_eq!(started.recv().await.as_deref(), Some("a"));
    assert_eq!(admitted.recv().await.as_deref(), Some("a"));
    if window.get() == 2 {
        for id in ["b", "c"] {
            assert_eq!(started.recv().await.as_deref(), Some(id));
            assert_eq!(admitted.recv().await.as_deref(), Some(id));
        }
        assert_eq!(admitted.recv().await.as_deref(), Some("d"));
    }
    assert!(started.try_recv().is_err());
    assert!(admitted.try_recv().is_err());
}

#[expect(
    clippy::cognitive_complexity,
    reason = "The timed pause, negative settlement and redelivery assertions observe one physical delivery lifecycle."
)]
async fn busy_redelivery(rabbit: &testkit::RabbitFixture) -> anyhow::Result<()> {
    let Broker {
        route,
        sub: subscriber,
        resource,
        publisher,
        publisher_resource,
        ..
    } = Broker::open(rabbit).await?;
    let message = envelope(&route, "live-owner");
    let subscription = subscription_for(&message, &route);
    let mut stream = subscriber
        .deliveries(&subscription, NonZeroU16::MIN)
        .await?;
    let store = MemoryInboxStore::new(TokioClock::new());
    let group = ConsumerGroup::parse("busy")?;
    let holder = claim_original(&store, &group, &subscription, &message).await?;
    assert!(matches!(
        publisher.publish(&message, provider_deadline()).await,
        PublishOutcome::Confirmed(())
    ));
    let timer = TokioClock::new();
    let exec = ConsumerExecution::new(
        group,
        &LiveIngress,
        &subscription,
        &timer,
        ConsumerExecutionPolicy::new(
            RetryPolicy::STANDARD,
            ExecutionBudget::new(Duration::from_secs(2), Duration::from_secs(1))?,
        ),
        &NoopEmitter,
    );
    let transaction = RecordingInboxTx {
        store: store.clone(),
        effects: Arc::new(AtomicUsize::new(0)),
    };
    let attempt = consume_once(
        &store,
        &transaction,
        &exec,
        *next_valid_delivery(&mut stream).await?,
    );
    tokio::pin!(attempt);
    assert!(
        tokio::time::timeout(Duration::from_millis(400), &mut attempt)
            .await
            .is_err()
    );
    assert_eq!(attempt.await?, ProcessingDisposition::InProgress);
    assert_eq!(transaction.effects.load(Ordering::SeqCst), 0);
    store.release(holder, provider_deadline()).await?;
    let (redelivered, settlement) = next_valid_delivery(&mut stream).await?.into_parts();
    assert_eq!(redelivered.id(), message.id());
    assert!(matches!(
        consume_once(
            &store,
            &transaction,
            &exec,
            Delivery::new(redelivered, settlement)
        )
        .await?,
        ProcessingDisposition::Committed(_)
    ));
    assert_eq!(transaction.effects.load(Ordering::SeqCst), 1);
    drop(stream);
    shutdown_bounded(resource.shutdown(Duration::from_secs(5))).await?;
    shutdown_bounded(publisher_resource.shutdown(Duration::from_secs(5))).await?;
    Ok(())
}

async fn claim_original(
    store: &MemoryInboxStore,
    group: &ConsumerGroup,
    subscription: &SubscriptionIdentity,
    message: &MessageEnvelope<Vec<u8>>,
) -> anyhow::Result<<MemoryInboxStore as InboxStore>::Claim> {
    let verified = rss_transactional_messaging::transaction::verify_ingress(
        &LiveIngress,
        group.clone(),
        subscription,
        message,
    )
    .map_err(|_| anyhow::anyhow!("fixture binding"))?;
    let IdempotencyDisposition::Acquired(holder) = store
        .claim(
            store
                .reserve_claim(
                    verified.execution(),
                    verified.identity(),
                    provider_deadline(),
                )?
                .acquire()
                .await?,
        )
        .await?
    else {
        anyhow::bail!("original claim");
    };
    Ok(holder)
}

#[derive(Clone, Copy)]
enum Head {
    Retry,
    Reject,
    Unknown,
    Fenced,
}

struct DuringRetirement {
    head: Head,
    requeue: Arc<Notify>,
    finish: Arc<Notify>,
}
impl ConsumerTx<Vec<u8>> for DuringRetirement {
    type Claim = ();
    type CommitProof = ();
    async fn execute(
        &self,
        _: &(),
        msg: &MessageEnvelope<Vec<u8>>,
        receipt: rss_transactional_messaging::transaction::ReceiptIntent,
        _: OperationDeadline,
    ) -> TransactionOutcome<()> {
        match msg.id().as_str() {
            "retry-head" => {
                self.requeue.notified().await;
                match self.head {
                    Head::Retry => TransactionOutcome::rolled_back(
                        rss_transactional_messaging::transaction::FailureClass::Infrastructure,
                    ),
                    Head::Reject => rejected(receipt),
                    Head::Unknown => TransactionOutcome::commit_unknown(),
                    Head::Fenced => TransactionOutcome::fenced(),
                }
            }
            id => {
                assert_eq!(
                    id, "independent",
                    "partition successor unexpectedly started"
                );
                self.finish.notified().await;
                committed(receipt)
            }
        }
    }
}
async fn drain_after_failed_head(
    rabbit: &testkit::RabbitFixture,
    head: Head,
) -> anyhow::Result<()> {
    let Broker {
        url,
        route,
        sub,
        resource,
        publisher,
        publisher_resource,
    } = Broker::open(rabbit).await?;
    let subscription = subscription_for(&envelope(&route, "template"), &route);
    let requeue = Arc::new(Notify::new());
    let finish = Arc::new(Notify::new());
    let (observed, mut admitted) = mpsc::unbounded_channel();
    let stop = CancellationToken::new();
    let worker = ConsumerWorker::new(
        NonZeroU16::new(3).expect("three"),
        Arc::new(sub),
        Arc::new(LiveInbox),
        Arc::new(DuringRetirement {
            head,
            requeue: requeue.clone(),
            finish: finish.clone(),
        }),
        ConsumerGroup::parse("retire")?,
        Arc::new(ObserveIngress(observed)),
        subscription,
        Arc::new(TokioClock::new()),
        consumer_policy(),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::STANDARD,
    );
    let task = tokio::spawn(worker.run(stop.clone()));
    for (id, key) in [("retry-head", "k"), ("next", "k"), ("independent", "other")] {
        assert!(matches!(
            publisher
                .publish(
                    &envelope_in_partition(&route, id, vec![1], key),
                    provider_deadline()
                )
                .await,
            PublishOutcome::Confirmed(())
        ));
        assert_eq!(admitted.recv().await.as_deref(), Some(id));
    }
    requeue.notify_one();
    let vhost = url.rsplit('/').next().expect("vhost");
    await_cancelled(rabbit, vhost, &route).await?;
    stop.cancel();
    finish.notify_one();
    task.await??;
    shutdown_bounded(resource.shutdown(Duration::from_secs(5))).await?;
    verify_redelivered_head(&url, &route, head).await?;
    shutdown_bounded(publisher_resource.shutdown(Duration::from_secs(5))).await?;
    Ok(())
}

async fn verify_redelivered_head(
    url: &str,
    route: &MessageRoute,
    head: Head,
) -> anyhow::Result<()> {
    let expected: &[&str] = match head {
        Head::Reject => &["next"],
        Head::Retry | Head::Unknown | Head::Fenced => &["next", "retry-head"],
    };
    assert_eq!(
        topology::ready_depth(url, route.as_str()).await? as usize,
        expected.len()
    );
    let (replacement, resource) = prepared_subscriber(url, route, "recovery", false).await?;
    let sub = subscription_for(&envelope(route, "template"), route);
    let mut stream = replacement.deliveries(&sub, NonZeroU16::MIN).await?;
    let mut recovered = Vec::new();
    for _ in expected {
        let item = next_valid_delivery(&mut stream).await?;
        recovered.push(item.message().id().as_str().to_owned());
        consume_live_delivery(item, "window-recovery", &sub, committed, &NoopEmitter).await?;
    }
    recovered.sort();
    assert_eq!(
        recovered, expected,
        "independently committed delivery must stay acknowledged"
    );
    drop(stream);
    shutdown_bounded(resource.shutdown(Duration::from_secs(5))).await?;
    Ok(())
}
