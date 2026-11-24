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

pub(super) async fn run(rabbit: &testkit::RabbitFixture) -> anyhow::Result<()> {
    for window in [NonZeroU16::MIN, NonZeroU16::new(2).expect("two")] {
        let url = isolated_url(rabbit, "rss_window").await?;
        let route = MessageRoute::parse("rss.window")?;
        let (sub, resource) = prepared_subscriber(&url, &route, "window", true).await?;
        let (publisher, publisher_resource) = connected_publisher(&url, "window-pub").await?;
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
        assert_eq!(started.recv().await.as_deref(), Some("a"));
        assert_eq!(admitted.recv().await.as_deref(), Some("a"));
        let vhost = url.rsplit('/').next().expect("vhost");
        assert_eq!(
            rabbit
                .broker_consumer_prefetch(vhost, route.as_str())
                .await?,
            [window.get()]
        );
        if window.get() == 2 {
            for id in ["b", "c"] {
                assert_eq!(started.recv().await.as_deref(), Some(id));
                assert_eq!(admitted.recv().await.as_deref(), Some(id));
            }
            assert_eq!(admitted.recv().await.as_deref(), Some("d"));
        }
        assert!(started.try_recv().is_err());
        assert!(admitted.try_recv().is_err());
        token.cancel();
        testkit::await_try(TIMEOUT, async || {
            Ok::<_, anyhow::Error>(
                (rabbit.broker_consumer_count(vhost, route.as_str()).await? == 0).then_some(()),
            )
        })
        .await?;
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
    }
    busy_redelivery(rabbit).await
}

async fn busy_redelivery(rabbit: &testkit::RabbitFixture) -> anyhow::Result<()> {
    let url = isolated_url(rabbit, "rss_busy_delivery").await?;
    let route = MessageRoute::parse("rss.busy")?;
    let (subscriber, resource) = prepared_subscriber(&url, &route, "busy", true).await?;
    let (publisher, publisher_resource) = connected_publisher(&url, "busy-pub").await?;
    let message = envelope(&route, "live-owner");
    let subscription = subscription_for(&message, &route);
    let mut stream = subscriber
        .deliveries(&subscription, NonZeroU16::MIN)
        .await?;
    let store = MemoryInboxStore::new();
    let group = ConsumerGroup::parse("busy")?;
    let verified = rss_transactional_messaging::transaction::verify_ingress(
        &LiveIngress,
        group.clone(),
        &subscription,
        &message,
    )
    .map_err(|_| anyhow::anyhow!("fixture binding"))?;
    let IdempotencyDisposition::Acquired(holder) = store
        .claim(
            verified.execution(),
            verified.identity(),
            provider_deadline(),
        )
        .await?
    else {
        anyhow::bail!("original claim");
    };
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
