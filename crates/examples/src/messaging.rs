//! Non-durable custom-provider example. Durability is verified separately with PostgreSQL.
use rss_request_context::Clock;
#[cfg(feature = "consumer")]
use rss_request_context::Deadline;
#[cfg(feature = "consumer")]
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_testkit::memory::FakeClock;
use std::time::Duration;

pub(super) async fn run() -> anyhow::Result<()> {
    let clock = FakeClock::new();
    let start = clock.now();
    clock.advance(Duration::from_secs(1))?;
    assert_eq!(
        clock.now().checked_duration_since(start),
        Some(Duration::from_secs(1))
    );
    #[cfg(feature = "producer")]
    producer(&clock).await?;
    #[cfg(feature = "consumer")]
    consumer(&clock).await?;
    Ok(())
}

#[cfg(any(feature = "producer", feature = "consumer"))]
fn envelope() -> anyhow::Result<rss_transactional_messaging::message::MessageEnvelope<Vec<u8>>> {
    use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
    use rss_request_context::TenantId;
    use rss_transactional_messaging::message::*;
    Ok(MessageEnvelope::new(
        MessageId::parse("example-message")?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
                Timepoint::try_from(1_i64)?,
                MessagingDomain::parse("example")?,
                MessageRoute::parse("example.created")?,
                ContractIdentity::new(
                    ContractId::parse("example.created")?,
                    ContractVersion::from_major(1)?,
                    SchemaDigest::parse(
                        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    )?,
                ),
            ),
            MessageMetadataExtensions::new(None, None, None, std::collections::BTreeMap::new()),
        ),
        b"payload".to_vec(),
    ))
}

#[cfg(feature = "producer")]
async fn producer(clock: &FakeClock) -> anyhow::Result<()> {
    use rss_transactional_messaging::{
        message::MessageEnvelope,
        observability::{TransactionalMessagingEmitter, TransactionalMessagingObservation},
        outbox::{OutboxDisposition, OutboxWriter, PendingMessage},
        policy::OperationDeadline,
        transport::{PublishOutcome, Publisher},
    };
    use rss_transactional_messaging_runtime::relay::{RelayBatchLimit, relay_once};
    use rss_transactional_messaging_testkit::memory::MemoryOutboxStore;
    use std::{
        num::NonZeroUsize,
        sync::atomic::{AtomicUsize, Ordering},
    };
    struct CustomPublisher(AtomicUsize, tokio::sync::Notify);
    impl Publisher<Vec<u8>> for CustomPublisher {
        type Receipt = ();
        async fn publish(
            &self,
            message: &MessageEnvelope<Vec<u8>>,
            _deadline: OperationDeadline,
        ) -> PublishOutcome<()> {
            assert_eq!(message.id().as_str(), "example-message");
            self.0.fetch_add(1, Ordering::SeqCst);
            self.1.notify_one();
            PublishOutcome::Confirmed(())
        }
    }
    struct Observations(AtomicUsize);
    impl TransactionalMessagingEmitter for Observations {
        fn emit(&self, _observation: TransactionalMessagingObservation) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let store = MemoryOutboxStore::new();
    store
        .append(&mut (), PendingMessage::new(envelope()?))
        .await?;
    let publisher = CustomPublisher(AtomicUsize::new(0), tokio::sync::Notify::new());
    let observations = Observations(AtomicUsize::new(0));
    let report = relay_once(
        &store,
        &publisher,
        clock,
        &observations,
        RelayBatchLimit::new(NonZeroUsize::MIN)?,
    )
    .await?;
    assert_eq!(report.published(), 1);
    assert_eq!(publisher.0.load(Ordering::SeqCst), 1);
    assert_eq!(store.settlements(), [OutboxDisposition::Published]);
    assert!(observations.0.load(Ordering::SeqCst) > 0);
    #[cfg(feature = "managed-worker")]
    {
        use rss_runtime::{ShutdownStack, TotalDrainBudget};
        use rss_transactional_messaging::policy::ShutdownBudget;
        use rss_transactional_messaging_runtime::relay::{RelayConfig, RelayWorker};
        use std::sync::Arc;
        let store = Arc::new(MemoryOutboxStore::new());
        store
            .append(&mut (), PendingMessage::new(envelope()?))
            .await?;
        let publisher = Arc::new(CustomPublisher(
            AtomicUsize::new(0),
            tokio::sync::Notify::new(),
        ));
        let worker = RelayWorker::new(
            store.clone(),
            publisher.clone(),
            Arc::new(clock.clone()),
            Arc::new(observations),
            RelayConfig::new(Duration::from_millis(100), NonZeroUsize::MIN)?,
        );
        let (registration, _) = worker.into_registration(
            "example-relay",
            ShutdownBudget::new(Duration::from_secs(2))?,
        );
        let mut stack = ShutdownStack::try_new(TotalDrainBudget::new(Duration::from_secs(5))?)?;
        let mut startup = stack.startup()?;
        let _status = startup.stage_task_with_token(registration);
        startup.commit().finish();
        tokio::time::timeout(Duration::from_secs(5), publisher.1.notified()).await?;
        assert!(stack.shutdown().join().await?.is_clean());
        assert_eq!(store.settlements(), [OutboxDisposition::Published]);
        assert_eq!(publisher.0.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[cfg(feature = "consumer")]
async fn consumer(clock: &FakeClock) -> anyhow::Result<()> {
    use rss_transactional_messaging::inbox::{
        ConsumerGroup, ConsumerIdentity, IdempotencyDisposition, InboxStore, LeaseStatus,
    };
    use rss_transactional_messaging_testkit::memory::MemoryInboxStore;
    let message = envelope()?;
    let identity = ConsumerIdentity::new(
        message.metadata().tenant_id(),
        ConsumerGroup::parse("example-handler")?,
        message.id().clone(),
        message.metadata().contract().clone(),
    );
    let store = MemoryInboxStore::new();
    let deadline = OperationDeadline::from_cutoff(
        Deadline::from_timeout(clock, Duration::from_secs(5))?,
        clock,
    );
    let IdempotencyDisposition::Acquired(claim) = store.claim(&identity, deadline).await? else {
        anyhow::bail!("initial claim was not acquired")
    };
    assert!(matches!(
        store.claim(&identity, deadline).await?,
        IdempotencyDisposition::InProgress
    ));
    store.expire(&identity);
    assert_eq!(store.extend(&claim, deadline).await?, LeaseStatus::Lost);
    uncertain_consumer(clock, message).await?;
    Ok(())
}

#[cfg(feature = "consumer")]
async fn uncertain_consumer(
    clock: &FakeClock,
    message: rss_transactional_messaging::message::MessageEnvelope<Vec<u8>>,
) -> anyhow::Result<()> {
    use rss_transactional_messaging::{
        inbox::{ConsumerGroup, ConsumerIdentity},
        message::{MessageEnvelope, SubscriptionIdentity},
        observability::{TransactionalMessagingEmitter, TransactionalMessagingObservation},
        policy::{ConsumerExecutionPolicy, ExecutionBudget, OperationDeadline, RetryPolicy},
        transaction::{
            ConsumerTx, EnvelopeValidationFailure, IngressChallenge, IngressValidator,
            ReceiptIntent, TransactionOutcome, VerifiedIngress,
        },
        transport::Delivery,
    };
    use rss_transactional_messaging_runtime::consumer::{
        ConsumerExecution, ProcessingDisposition, consume_once,
    };
    use rss_transactional_messaging_testkit::memory::{MemoryInboxStore, RecordingSettlement};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct UncertainTx(AtomicUsize);
    impl ConsumerTx<Vec<u8>> for UncertainTx {
        type Claim = (ConsumerIdentity, u64);
        type CommitProof = ();
        async fn execute(
            &self,
            _claim: &Self::Claim,
            _message: &MessageEnvelope<Vec<u8>>,
            _receipt: ReceiptIntent,
            _deadline: OperationDeadline,
        ) -> TransactionOutcome<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            // This custom port has no durable commit evidence and must not manufacture ACK authority.
            TransactionOutcome::commit_unknown()
        }
    }
    struct Validator(rss_request_context::TenantId);
    impl IngressValidator<Vec<u8>> for Validator {
        fn validate(
            &self,
            challenge: IngressChallenge<'_, Vec<u8>>,
        ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
            if challenge.message().metadata().tenant_id() != self.0 {
                return Err(EnvelopeValidationFailure::MalformedIdentity);
            }
            if !challenge.subscription().accepts(challenge.message()) {
                return Err(EnvelopeValidationFailure::UnsupportedContract);
            }
            Ok(challenge.verified())
        }
    }
    struct Observations;
    impl TransactionalMessagingEmitter for Observations {
        fn emit(&self, _observation: TransactionalMessagingObservation) {
            // reason: this bounded example observes settlement directly instead of installing telemetry.
        }
    }
    let validator = Validator(rss_request_context::TenantId::parse(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    )?);
    let metadata = message.metadata();
    let subscription = SubscriptionIdentity::new(
        metadata.domain().clone(),
        metadata.route().clone(),
        metadata.contract().clone(),
    );
    let execution = ConsumerExecution::new(
        ConsumerGroup::parse("example-handler")?,
        &validator,
        &subscription,
        clock,
        ConsumerExecutionPolicy::new(RetryPolicy::STANDARD, ExecutionBudget::STANDARD),
        &Observations,
    );
    let settlement = RecordingSettlement::new();
    let transaction = UncertainTx(AtomicUsize::new(0));
    assert_eq!(
        consume_once(
            &MemoryInboxStore::new(),
            &transaction,
            &execution,
            Delivery::new(message, settlement.clone())
        )
        .await?,
        ProcessingDisposition::Deferred
    );
    assert_eq!(transaction.0.load(Ordering::SeqCst), 1);
    assert!(settlement.settlements().is_empty());
    assert_eq!(settlement.abandon_count(), 1);
    Ok(())
}
