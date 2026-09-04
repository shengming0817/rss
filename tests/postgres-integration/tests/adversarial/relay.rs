use super::*;
use rss_transactional_messaging::{
    message::*,
    observability::{TransactionalMessagingEmitter, TransactionalMessagingObservation},
    outbox::*,
    transport::PublishOutcome,
};
use rss_transactional_messaging_runtime::relay::{RelayBatchLimit, relay_once};
use rss_transactional_messaging_testkit::memory::MemoryPublisher;
struct Emitter;
impl TransactionalMessagingEmitter for Emitter {
    fn emit(&self, _: TransactionalMessagingObservation) {}
}

pub(super) async fn run(runtime: Arc<PgRuntime>, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    let budget = DeliveryBudget::new(
        Duration::from_secs(8),
        Duration::from_secs(2),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )?;
    assert!(
        DeliveryBudget::new(
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .is_err(),
        "short configured lease is rejected before a provider can be composed"
    );
    for (case, window, expected, broker_calls) in [
        ("normal", None, "published", 1),
        ("short-window", Some(2_i64), "pending", 0),
        ("expired-window", Some(-1_i64), "dead_letter", 0),
    ] {
        let id = format!("real-relay-{case}");
        let template = message(&id);
        let m = template.metadata();
        let domain = MessagingDomain::parse(&id)?;
        let envelope = MessageEnvelope::new(
            template.id().clone(),
            MessageMetadata::new(
                AuthoredMessageMetadata::new(
                    m.tenant_id(),
                    m.occurred_at(),
                    domain.clone(),
                    m.route().clone(),
                    m.contract().clone(),
                ),
                MessageMetadataExtensions::default(),
            ),
            vec![1],
        );
        let store = Arc::new(PgOutboxStore::<()>::new(runtime.clone(), domain, budget)?);
        let append_store = store.clone();
        let tenant = envelope.metadata().tenant_id();
        runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move {
                    append_store
                        .append(tx, PendingMessage::new(envelope))
                        .await
                        .map_err(Into::into)
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
        if let Some(seconds) = window {
            sqlx::query("UPDATE rss_transactional_messaging.outbox SET automatic_retry_deadline=clock_timestamp()+$2*interval '1 second' WHERE message_id=$1")
                .bind(&id).bind(seconds).execute(owner).await?;
        }
        let publisher = MemoryPublisher::new([PublishOutcome::Confirmed(())]);
        let report = relay_once(
            &*store,
            &publisher,
            &Timer::new(),
            &Emitter,
            RelayBatchLimit::new(std::num::NonZeroUsize::MIN)?,
        )
        .await?;
        assert_eq!(report.claimed(), 1);
        assert_eq!(publisher.message_ids().len(), broker_calls);
        let actual: String = sqlx::query_scalar(
            "SELECT status FROM rss_transactional_messaging.outbox WHERE message_id=$1",
        )
        .bind(&id)
        .fetch_one(owner)
        .await?;
        assert_eq!(actual, expected);
    }
    Ok(())
}
