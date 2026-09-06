mod support;
use rss_transactional_messaging::{
    error::MessagingErrorKind, policy::ExecutionBudget, transport::*,
};
use rss_transactional_messaging_kafka::*;
use rss_transactional_messaging_testkit::{ConformanceError, transport::*};
use std::time::Duration;
use support::*;
struct Driver<'a>(&'a KafkaPublisher, &'a testkit::KafkaTlsFixture);
fn error(_: impl std::fmt::Debug) -> ConformanceError {
    ConformanceError::publish(MessagingErrorKind::Invariant)
}
fn attempt(
    id: &str,
    outcome: PublishOutcome<KafkaPublishReceipt>,
) -> Result<PublishAttempt, ConformanceError> {
    Ok(PublishAttempt {
        message_id: rss_transactional_messaging::message::MessageId::parse(id).map_err(error)?,
        outcome: match outcome {
            PublishOutcome::Confirmed(receipt) => {
                assert_eq!(receipt.topic(), TOPIC);
                assert!(receipt.partition() >= 0);
                assert!(receipt.offset() >= 0);
                PublishOutcome::Confirmed(())
            }
            PublishOutcome::DefinitelyNotPublished(f) => PublishOutcome::DefinitelyNotPublished(f),
            PublishOutcome::Ambiguous(f) => PublishOutcome::Ambiguous(f),
        },
    })
}
impl PublisherTransportDriver for Driver<'_> {
    async fn confirmed(&self) -> Result<PublishAttempt, ConformanceError> {
        let outcome = self
            .0
            .publish(
                &message("confirmed").map_err(error)?,
                deadline(Duration::from_secs(5)).map_err(error)?,
            )
            .await;
        assert!(
            matches!(&outcome, PublishOutcome::Confirmed(_)),
            "first publication failed: {:?}",
            outcome.failure()
        );
        compare_receipt(self.1, "confirmed", &outcome, 1)
            .await
            .map_err(error)?;
        attempt("confirmed", outcome)
    }
    async fn permanent(&self) -> Result<PublishAttempt, ConformanceError> {
        let mut m = message("oversize").map_err(error)?;
        // Authored oversized content cannot fit this adapter's bounded record representation.
        m = rss_transactional_messaging::message::MessageEnvelope::new(
            m.id().clone(),
            m.metadata().clone(),
            vec![0; 4097],
        );
        attempt(
            "oversize",
            self.0
                .publish(&m, deadline(Duration::from_secs(1)).map_err(error)?)
                .await,
        )
    }
    async fn transient(&self) -> Result<PublishAttempt, ConformanceError> {
        let (first, release) = lose_report(self.0, "capacity-first").await.map_err(error)?;
        assert!(first.is_ambiguous());
        let queued = self
            .0
            .publish(
                &message("capacity-queued").map_err(error)?,
                deadline(Duration::from_millis(50)).map_err(error)?,
            )
            .await;
        assert!(queued.is_ambiguous());
        let outcome = self
            .0
            .publish(
                &message("capacity-refusal").map_err(error)?,
                deadline(Duration::from_secs(1)).map_err(error)?,
            )
            .await;
        let _ = release.send(());
        drained(self.0).await.map_err(error)?;
        attempt("capacity-refusal", outcome)
    }
    async fn ambiguous_retry(&self) -> Result<Vec<PublishAttempt>, ConformanceError> {
        let m = message("same-id-retry").map_err(error)?;
        let (first, release) = lose_report(self.0, "same-id-retry").await.map_err(error)?;
        assert!(first.is_ambiguous());
        assert_eq!(self.0.pending_for_test(), 1);
        let _ = release.send(());
        drained(self.0).await.map_err(error)?;
        let second = self
            .0
            .publish(&m, deadline(Duration::from_secs(5)).map_err(error)?)
            .await;
        compare_receipt(self.1, "same-id-retry", &second, 2)
            .await
            .map_err(error)?;
        Ok(vec![
            attempt("same-id-retry", first)?,
            attempt("same-id-retry", second)?,
        ])
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kafka_transport_suite() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(110), async {
        let fixture = testkit::kafka_tls(testkit::KafkaTlsServerIdentity::MatchingHost).await?;
        let (publisher, resource) =
            KafkaPublisher::create(config(&fixture)?, Duration::from_secs(5)).await?;
        run_publisher_transport_conformance(
            &Driver(&publisher, &fixture),
            &Timer::new(),
            ExecutionBudget::new(Duration::from_secs(45), Duration::from_secs(1))?,
        )
        .await?;
        for record in read_records(&fixture, "same-id-retry", 2).await? {
            assert_record(&record, "same-id-retry");
        }
        let (entered, release) = publisher.pause_next_delivery_for_test();
        let cloned = publisher.clone();
        let task = tokio::spawn(async move {
            cloned
                .publish(&message("cancelled")?, deadline(Duration::from_secs(5))?)
                .await;
            Ok::<_, anyhow::Error>(())
        });
        entered.await?;
        task.abort();
        let cancelled = task.await;
        assert!(cancelled.is_err_and(|error| error.is_cancelled()));
        assert_eq!(publisher.pending_for_test(), 1);
        assert_record(
            &read_records(&fixture, "cancelled", 1).await?[0],
            "cancelled",
        );
        let _ = release.send(());
        drained(&publisher).await?;
        resource.shutdown(Duration::from_secs(5)).await?;
        assert!(matches!(
            publisher
                .publish(&message("closed")?, deadline(Duration::from_secs(1))?)
                .await,
            PublishOutcome::DefinitelyNotPublished(_)
        ));
        forced_shutdown(&fixture).await?;
        close_before_native_send(&fixture).await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

async fn forced_shutdown(fixture: &testkit::KafkaTlsFixture) -> anyhow::Result<()> {
    let (publisher, resource) =
        KafkaPublisher::create(config(fixture)?, Duration::from_secs(5)).await?;
    let (entered, _release) = publisher.pause_next_delivery_for_test();
    let clone = publisher.clone();
    let task = tokio::spawn(async move {
        Ok::<_, anyhow::Error>(
            clone
                .publish(&message("forced-close")?, deadline(Duration::from_secs(5))?)
                .await,
        )
    });
    entered.await?;
    assert!(resource.shutdown(Duration::ZERO).await.is_err());
    let outcome = task.await??;
    assert!(matches!(
        outcome,
        PublishOutcome::Confirmed(_) | PublishOutcome::Ambiguous(_)
    ));
    drained(&publisher).await?;
    assert!(matches!(
        publisher
            .publish(
                &message("after-forced-close")?,
                deadline(Duration::from_secs(1))?
            )
            .await,
        PublishOutcome::DefinitelyNotPublished(_)
    ));
    Ok(())
}

async fn lose_report(
    publisher: &KafkaPublisher,
    id: &str,
) -> anyhow::Result<(
    PublishOutcome<KafkaPublishReceipt>,
    tokio::sync::oneshot::Sender<()>,
)> {
    let (entered, release) = publisher.pause_next_delivery_for_test();
    let clone = publisher.clone();
    let m = message(id)?;
    let task = tokio::spawn(async move {
        Ok::<_, anyhow::Error>(
            clone
                .publish(&m, deadline(Duration::from_millis(500))?)
                .await,
        )
    });
    entered.await?;
    Ok((task.await??, release))
}

async fn close_before_native_send(fixture: &testkit::KafkaTlsFixture) -> anyhow::Result<()> {
    let (publisher, resource) =
        KafkaPublisher::create(config(fixture)?, Duration::from_secs(5)).await?;
    let (entered, release) = publisher.pause_before_send_for_test();
    let clone = publisher.clone();
    let task = tokio::spawn(async move {
        Ok::<_, anyhow::Error>(
            clone
                .publish(
                    &message("closed-before-send")?,
                    deadline(Duration::from_secs(5))?,
                )
                .await,
        )
    });
    entered.await?;
    assert!(resource.shutdown(Duration::ZERO).await.is_err());
    let _ = release.send(());
    let outcome = task.await??;
    assert!(
        matches!(outcome, PublishOutcome::DefinitelyNotPublished(f) if f.stage() == PublishFailureStage::Admission)
    );
    assert_eq!(publisher.pending_for_test(), 0);
    assert!(
        read_records(fixture, "closed-before-send", 0)
            .await?
            .is_empty()
    );
    Ok(())
}

async fn compare_receipt(
    fixture: &testkit::KafkaTlsFixture,
    id: &str,
    outcome: &PublishOutcome<KafkaPublishReceipt>,
    count: usize,
) -> anyhow::Result<()> {
    use rdkafka::Message as _;
    let PublishOutcome::Confirmed(receipt) = outcome else {
        anyhow::bail!("missing confirmed receipt");
    };
    let records = read_records(fixture, id, count).await?;
    let record = records
        .last()
        .ok_or_else(|| anyhow::anyhow!("missing broker record"))?;
    assert_eq!(receipt.topic(), record.topic());
    assert_eq!(receipt.partition(), record.partition());
    assert_eq!(receipt.offset(), record.offset());
    Ok(())
}
