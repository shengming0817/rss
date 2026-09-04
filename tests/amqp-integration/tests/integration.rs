//! Live AMQP proof for the canonical publisher/delivery/settlement ports.

#![allow(clippy::expect_used)]
// reason: canonical live-provider fixtures must fail loudly when typed identities drift.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use amqp::{
    AmqpPrivateCa, AmqpPublisher, AmqpPublisherEndpoint, AmqpRuntimeDeps, AmqpSubscriber,
    AmqpSubscriberEndpoint,
};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_runtime::{ManagedResource, ShutdownFailureKind, ShutdownStack, TotalDrainBudget};
use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
use rss_transactional_messaging::inbox::{
    ConsumerGroup, ConsumerIdentity, IdempotencyDisposition, InboxStore, LeaseStatus,
};
use rss_transactional_messaging::message::{
    AuthoredMessageMetadata, ContractIdentity, MessageEnvelope, MessageFingerprint, MessageId,
    MessageMetadata, MessageMetadataExtensions, MessageRoute, MessagingDomain, PartitionKey,
    SubscriptionIdentity,
};
use rss_transactional_messaging::observability::{
    TransactionalMessagingEmitter, TransactionalMessagingObservation,
};
use rss_transactional_messaging::outbox::{
    AppendOutcome, OutboxDisposition, OutboxLeaseStatus, OutboxSettlement, OutboxStore,
    PendingMessage,
};
use rss_transactional_messaging::policy::{
    AbsoluteDeadline, Clock, ConsumerExecutionPolicy, ExecutionBudget, ExecutionTimer,
    LeaseRenewalPolicy, MonotonicInstant, OperationDeadline, RetryPolicy, ShutdownBudget,
};
use rss_transactional_messaging::transaction::{
    ConsumerTx, EnvelopeValidationFailure, IngressChallenge, IngressValidator, SettlementDecision,
    TerminalDisposition, TransactionOutcome, VerifiedIngress,
};
use rss_transactional_messaging::transport::{
    Delivery, DeliverySettlement, DeliverySource, IncomingDelivery, ManagedDeliveryStream,
    PublishFailure, PublishFailureKind, PublishFailureReason, PublishFailureStage, PublishOutcome,
    Publisher,
};
use rss_transactional_messaging_runtime::consumer::{
    ConsumerExecution, ConsumerWorker, ProcessingDisposition, SubscriptionBackoffPolicy,
    consume_once,
};
use rss_transactional_messaging_testkit::ConformanceError;
use rss_transactional_messaging_testkit::consumer::{ConsumerTxDriver, run_consumer_conformance};
use rss_transactional_messaging_testkit::memory::{
    FakeClock, MemoryInboxStore, MemoryOutboxStore, MemoryPublisher, RecordingSettlement,
};
use rss_transactional_messaging_testkit::outbox::{OutboxDriver, run_outbox_conformance};

const TIMEOUT: Duration = Duration::from_secs(40);
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const SCHEMA: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static FIXTURE_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

fn isolated_vhost(prefix: &str) -> String {
    format!(
        "{prefix}_{}",
        FIXTURE_SEQUENCE.fetch_add(1, Ordering::SeqCst)
    )
}

fn provider_deadline() -> OperationDeadline {
    let clock = FakeClock::new();
    AbsoluteDeadline::from_timeout(&clock, TIMEOUT)
        .expect("bounded integration deadline")
        .operation(&clock)
}

fn consumer_policy() -> ConsumerExecutionPolicy {
    ConsumerExecutionPolicy::new(
        RetryPolicy::STANDARD,
        ExecutionBudget::STANDARD,
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30)).expect("lease policy"),
    )
}

fn envelope(route: &MessageRoute, id: &str) -> MessageEnvelope<Vec<u8>> {
    envelope_with_payload(route, id, b"payload".to_vec())
}

fn envelope_with_payload(
    route: &MessageRoute,
    id: &str,
    payload: Vec<u8>,
) -> MessageEnvelope<Vec<u8>> {
    let tenant = TenantId::parse(TENANT).expect("tenant");
    MessageEnvelope::new(
        MessageId::parse(id).expect("message id"),
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                Timepoint::try_from(1_700_000_000_i64).expect("time"),
                MessagingDomain::parse("integration").expect("domain"),
                route.clone(),
                ContractIdentity::new(
                    ContractId::parse("integration.message").expect("contract"),
                    ContractVersion::from_major(1).expect("version"),
                    SchemaDigest::parse(SCHEMA).expect("schema"),
                ),
            ),
            MessageMetadataExtensions::new(
                None,
                Some(PartitionKey::parse("integration-partition").expect("partition")),
                None,
                BTreeMap::new(),
            ),
        ),
        payload,
    )
}

struct TokioClock {
    origin: tokio::time::Instant,
}

impl TokioClock {
    #[allow(clippy::disallowed_methods)]
    // reason: this integration adapter is the injected Clock owner for real Tokio I/O.
    fn new() -> Self {
        Self {
            origin: tokio::time::Instant::now(),
        }
    }
}

impl Clock for TokioClock {
    #[allow(clippy::disallowed_methods)]
    // reason: the injected adapter projects its single Tokio monotonic origin into core time.
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_elapsed(tokio::time::Instant::now() - self.origin)
    }
}

impl ExecutionTimer for TokioClock {
    async fn sleep_until(&self, deadline: AbsoluteDeadline) {
        tokio::time::sleep_until(self.origin + deadline.instant().elapsed()).await;
    }
}

struct BlockingLiveTx(Arc<AtomicUsize>);

impl ConsumerTx<Vec<u8>> for BlockingLiveTx {
    type Claim = ();
    type CommitProof = ();

    async fn execute(
        &self,
        _claim: &Self::Claim,
        _message: &MessageEnvelope<Vec<u8>>,
        _receipt: rss_transactional_messaging::transaction::ReceiptIntent,
        _deadline: OperationDeadline,
    ) -> TransactionOutcome<Self::CommitProof> {
        self.0.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }
}

struct LiveInbox;

impl InboxStore for LiveInbox {
    type Claim = ();

    async fn claim(
        &self,
        _identity: &rss_transactional_messaging::inbox::ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        Ok(IdempotencyDisposition::Acquired(()))
    }

    async fn read_terminal(
        &self,
        _identity: &rss_transactional_messaging::inbox::ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<Option<rss_transactional_messaging::transaction::TerminalReceipt>, MessagingError>
    {
        Ok(None)
    }

    async fn extend(
        &self,
        _claim: &Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<LeaseStatus, MessagingError> {
        Ok(LeaseStatus::Held {
            remaining: Duration::from_secs(30),
        })
    }

    async fn release(
        &self,
        _claim: Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        Ok(())
    }
}

struct LostInbox;

impl InboxStore for LostInbox {
    type Claim = ();

    async fn claim(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        Ok(IdempotencyDisposition::Acquired(()))
    }

    async fn read_terminal(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<Option<rss_transactional_messaging::transaction::TerminalReceipt>, MessagingError>
    {
        Ok(None)
    }

    async fn extend(
        &self,
        _claim: &Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<LeaseStatus, MessagingError> {
        Ok(LeaseStatus::Lost)
    }

    async fn release(
        &self,
        _claim: Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        Ok(())
    }
}

type LiveTxFactory =
    fn(rss_transactional_messaging::transaction::ReceiptIntent) -> TransactionOutcome<()>;

fn committed(
    receipt: rss_transactional_messaging::transaction::ReceiptIntent,
) -> TransactionOutcome<()> {
    receipt.committed((), TerminalDisposition::Succeeded)
}

fn rejected(
    receipt: rss_transactional_messaging::transaction::ReceiptIntent,
) -> TransactionOutcome<()> {
    receipt.committed(
        (),
        TerminalDisposition::Rejected(
            rss_transactional_messaging::transaction::RejectKind::Permanent,
        ),
    )
}

fn commit_unknown(
    _receipt: rss_transactional_messaging::transaction::ReceiptIntent,
) -> TransactionOutcome<()> {
    TransactionOutcome::commit_unknown()
}

struct LiveTx(LiveTxFactory);

impl ConsumerTx<Vec<u8>> for LiveTx {
    type Claim = ();
    type CommitProof = ();

    async fn execute(
        &self,
        _claim: &Self::Claim,
        _message: &MessageEnvelope<Vec<u8>>,
        receipt: rss_transactional_messaging::transaction::ReceiptIntent,
        _deadline: OperationDeadline,
    ) -> TransactionOutcome<Self::CommitProof> {
        (self.0)(receipt)
    }
}

struct MemoryInboxTx;

impl ConsumerTx<Vec<u8>> for MemoryInboxTx {
    type Claim = (ConsumerIdentity, u64);
    type CommitProof = ();

    async fn execute(
        &self,
        _claim: &Self::Claim,
        _message: &MessageEnvelope<Vec<u8>>,
        receipt: rss_transactional_messaging::transaction::ReceiptIntent,
        _deadline: OperationDeadline,
    ) -> TransactionOutcome<Self::CommitProof> {
        receipt.committed((), TerminalDisposition::Succeeded)
    }
}

struct RecordingInboxTx {
    store: MemoryInboxStore,
    effects: Arc<AtomicUsize>,
}

impl ConsumerTx<Vec<u8>> for RecordingInboxTx {
    type Claim = (ConsumerIdentity, u64);
    type CommitProof = ();

    async fn execute(
        &self,
        claim: &Self::Claim,
        message: &MessageEnvelope<Vec<u8>>,
        receipt: rss_transactional_messaging::transaction::ReceiptIntent,
        _deadline: OperationDeadline,
    ) -> TransactionOutcome<Self::CommitProof> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        self.store.store_terminal(
            claim.0.clone(),
            MessageFingerprint::of(message),
            TerminalDisposition::Succeeded,
        );
        receipt.committed((), TerminalDisposition::Succeeded)
    }
}

struct LiveIngress;

impl IngressValidator<Vec<u8>> for LiveIngress {
    fn validate(
        &self,
        challenge: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        challenge
            .subscription()
            .accepts(challenge.message())
            .then(|| challenge.verified())
            .ok_or(EnvelopeValidationFailure::UnsupportedContract)
    }
}

struct NoopEmitter;

impl TransactionalMessagingEmitter for NoopEmitter {
    fn emit(&self, _observation: TransactionalMessagingObservation) {}
}

struct RecordingEmitter(Arc<Mutex<Vec<TransactionalMessagingObservation>>>);

impl TransactionalMessagingEmitter for RecordingEmitter {
    fn emit(&self, observation: TransactionalMessagingObservation) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(observation);
    }
}

struct ObservingSettlement<S> {
    inner: S,
    abandons: Arc<AtomicUsize>,
}

impl<S> ObservingSettlement<S> {
    fn new(inner: S, abandons: Arc<AtomicUsize>) -> Self {
        Self { inner, abandons }
    }
}

impl<S: DeliverySettlement> DeliverySettlement for ObservingSettlement<S> {
    async fn settle(
        self,
        decision: SettlementDecision,
        deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        self.inner.settle(decision, deadline).await
    }

    async fn abandon(self, deadline: OperationDeadline) -> Result<(), MessagingError> {
        self.abandons.fetch_add(1, Ordering::SeqCst);
        self.inner.abandon(deadline).await
    }
}

fn endpoint(url: &str) -> anyhow::Result<secure::AmqpEndpoint> {
    Ok(secure::AmqpEndpoint::parse(
        url,
        secure::PlaintextEndpointPolicy::AllowLoopback,
    )?)
}

async fn shutdown_bounded(resource: &impl ManagedResource) -> Result<(), LiveConformanceFailure> {
    match tokio::time::timeout(Duration::from_secs(5), ManagedResource::shutdown(resource)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(live_failure(
            LivePhase::Shutdown,
            MessagingErrorKind::Transient,
        )),
        Err(_) => Err(live_failure(
            LivePhase::Shutdown,
            MessagingErrorKind::DeadlineElapsed,
        )),
    }
}

type AmqpDeliveries = <AmqpSubscriber as DeliverySource<Vec<u8>>>::Deliveries;
type AmqpDelivery = Delivery<Vec<u8>, <AmqpSubscriber as DeliverySource<Vec<u8>>>::Settlement>;

async fn next_valid_delivery(
    deliveries: &mut ManagedDeliveryStream<AmqpDeliveries>,
    missing: &'static str,
    invalid: &'static str,
) -> Result<Box<AmqpDelivery>, LiveConformanceFailure> {
    match tokio::time::timeout(TIMEOUT, deliveries.next())
        .await
        .map_err(|_| live_failure(LivePhase::Delivery, MessagingErrorKind::DeadlineElapsed))?
        .ok_or_else(|| live_failure(LivePhase::Delivery, MessagingErrorKind::Transient))?
    {
        IncomingDelivery::Valid(delivery) => Ok(delivery),
        IncomingDelivery::Invalid(_) => {
            let _ = (missing, invalid);
            Err(live_failure(
                LivePhase::Delivery,
                MessagingErrorKind::Permanent,
            ))
        }
    }
}

async fn isolated_rabbit(
    prefix: &str,
) -> Result<(testkit::RabbitFixture, String), LiveConformanceFailure> {
    let rabbit = testkit::env_or_rabbitmq()
        .await
        .map_err(|_| live_failure(LivePhase::Fixture, MessagingErrorKind::Transient))?;
    let url = rabbit
        .vhost_url(&isolated_vhost(prefix))
        .await
        .map_err(|_| live_failure(LivePhase::Fixture, MessagingErrorKind::Transient))?;
    Ok((rabbit, url))
}

async fn prepared_subscriber(
    url: &str,
    route: &MessageRoute,
    name: &'static str,
    purge: bool,
) -> Result<AmqpSubscriber, LiveConformanceFailure> {
    let endpoint = endpoint(url)
        .map_err(|_| live_failure(LivePhase::Connect, MessagingErrorKind::Permanent))?;
    let subscriber = AmqpSubscriber::connect_with_webpki_for_test(&endpoint, name)
        .await
        .map_err(|_| live_failure(LivePhase::Connect, MessagingErrorKind::Transient))?;
    subscriber
        .prepare_delivery_route(route)
        .await
        .map_err(|error| live_failure(LivePhase::Fixture, error.kind()))?;
    if purge {
        subscriber
            .purge_durable_queue_for_test(route)
            .await
            .map_err(|_| live_failure(LivePhase::Fixture, MessagingErrorKind::Transient))?;
    }
    Ok(subscriber)
}

async fn connected_publisher(
    url: &str,
    name: &'static str,
) -> Result<AmqpPublisher, LiveConformanceFailure> {
    let endpoint = endpoint(url)
        .map_err(|_| live_failure(LivePhase::Connect, MessagingErrorKind::Permanent))?;
    AmqpPublisher::connect_with_webpki_for_test(&endpoint, name, TIMEOUT)
        .await
        .map_err(|_| live_failure(LivePhase::Connect, MessagingErrorKind::Transient))
}

fn subscription_for(
    message: &MessageEnvelope<Vec<u8>>,
    route: &MessageRoute,
) -> SubscriptionIdentity {
    SubscriptionIdentity::new(
        message.metadata().domain().clone(),
        route.clone(),
        message.metadata().contract().clone(),
    )
}

async fn consume_live_delivery<S: DeliverySettlement>(
    delivery: Box<Delivery<Vec<u8>, S>>,
    group: &'static str,
    subscription: &SubscriptionIdentity,
    transaction: LiveTxFactory,
    emitter: &impl TransactionalMessagingEmitter,
) -> Result<ProcessingDisposition, LiveConformanceFailure> {
    let timer = FakeClock::new();
    let execution = ConsumerExecution::new(
        ConsumerGroup::parse(group).expect("group"),
        &LiveIngress,
        subscription,
        &timer,
        consumer_policy(),
        emitter,
    );
    consume_once(&LiveInbox, &LiveTx(transaction), &execution, *delivery)
        .await
        .map_err(|error| live_failure(LivePhase::Settlement, error.kind()))
}

async fn duplicate_delivery_evidence()
-> Result<(TerminalDisposition, Vec<TransactionalMessagingObservation>), MessagingError> {
    let route = MessageRoute::parse("rss.integration.duplicate")
        .map_err(|error| MessagingError::new(MessagingErrorKind::Invariant, error))?;
    let message = envelope(&route, "duplicate-delivery");
    let group = ConsumerGroup::parse("duplicate-consumer")
        .map_err(|error| MessagingError::new(MessagingErrorKind::Invariant, error))?;
    let subscription = subscription_for(&message, &route);
    let store = MemoryInboxStore::new();
    store.store_terminal(
        ConsumerIdentity::new(
            message.metadata().tenant_id(),
            group.clone(),
            message.id().clone(),
            message.metadata().contract().clone(),
        ),
        MessageFingerprint::of(&message),
        TerminalDisposition::Succeeded,
    );
    let observations = Arc::new(Mutex::new(Vec::new()));
    let outcome = consume_once(
        &store,
        &MemoryInboxTx,
        &ConsumerExecution::new(
            group,
            &LiveIngress,
            &subscription,
            &FakeClock::new(),
            consumer_policy(),
            &RecordingEmitter(Arc::clone(&observations)),
        ),
        Delivery::new(message, RecordingSettlement::new()),
    )
    .await?;
    let ProcessingDisposition::Duplicate(disposition) = outcome else {
        return Err(
            live_failure(LivePhase::Settlement, MessagingErrorKind::Invariant).into_messaging(),
        );
    };
    let observations = observations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Ok((disposition, observations))
}

async fn lease_lost_evidence()
-> Result<(Vec<TransactionalMessagingObservation>, usize), MessagingError> {
    let route = MessageRoute::parse("rss.integration.lease-lost")
        .map_err(|error| MessagingError::new(MessagingErrorKind::Invariant, error))?;
    let message = envelope(&route, "lease-lost-delivery");
    let subscription = subscription_for(&message, &route);
    let observations = Arc::new(Mutex::new(Vec::new()));
    let settlements = Arc::new(Mutex::new(Vec::new()));
    let abandons = Arc::new(AtomicUsize::new(0));
    let outcome = consume_once(
        &LostInbox,
        &LiveTx(committed),
        &ConsumerExecution::new(
            ConsumerGroup::parse("lease-lost-consumer")
                .map_err(|error| MessagingError::new(MessagingErrorKind::Invariant, error))?,
            &LiveIngress,
            &subscription,
            &FakeClock::new(),
            consumer_policy(),
            &RecordingEmitter(Arc::clone(&observations)),
        ),
        Delivery::new(
            message,
            RecordingSettlement::observing(settlements, Arc::clone(&abandons)),
        ),
    )
    .await?;
    if !matches!(outcome, ProcessingDisposition::Fenced) {
        return Err(
            live_failure(LivePhase::Settlement, MessagingErrorKind::Invariant).into_messaging(),
        );
    }
    let observations = observations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Ok((observations, abandons.load(Ordering::SeqCst)))
}

async fn assert_committed_redelivery(
    url: &str,
    route: &MessageRoute,
    subscription: &SubscriptionIdentity,
    subscriber_name: &'static str,
    missing: &'static str,
    invalid: &'static str,
) -> Result<(), LiveConformanceFailure> {
    let subscriber = prepared_subscriber(url, route, subscriber_name, false).await?;
    let mut deliveries = DeliverySource::deliveries(&subscriber, subscription)
        .await
        .map_err(|error| live_failure(LivePhase::Delivery, error.kind()))?;
    let delivery = next_valid_delivery(&mut deliveries, missing, invalid).await?;
    let disposition = consume_live_delivery(
        delivery,
        "unknown-consumer",
        subscription,
        committed,
        &NoopEmitter,
    )
    .await?;
    if disposition != ProcessingDisposition::Committed(TerminalDisposition::Succeeded) {
        return Err(live_failure(
            LivePhase::Settlement,
            MessagingErrorKind::Invariant,
        ));
    }
    shutdown_bounded(&subscriber).await
}

async fn assert_same_id_redelivery(
    url: &str,
    route: &MessageRoute,
    subscription: &SubscriptionIdentity,
    expected_id: &MessageId,
) -> Result<(), LiveConformanceFailure> {
    let subscriber = prepared_subscriber(url, route, "managed-cancel-sub-2", false).await?;
    let mut deliveries = DeliverySource::deliveries(&subscriber, subscription)
        .await
        .map_err(|error| live_failure(LivePhase::Delivery, error.kind()))?;
    let delivery = next_valid_delivery(
        &mut deliveries,
        "forced cancellation was not redelivered",
        "redelivery was invalid",
    )
    .await?;
    let (message, settlement) = delivery.into_parts();
    if message.id() != expected_id {
        return Err(live_failure(
            LivePhase::Delivery,
            MessagingErrorKind::Invariant,
        ));
    }
    let disposition = consume_live_delivery(
        Box::new(Delivery::new(message, settlement)),
        "managed-cancel-consumer",
        subscription,
        committed,
        &NoopEmitter,
    )
    .await?;
    if disposition != ProcessingDisposition::Committed(TerminalDisposition::Succeeded) {
        return Err(live_failure(
            LivePhase::Settlement,
            MessagingErrorKind::Invariant,
        ));
    }
    shutdown_bounded(&subscriber).await
}

async fn run_publish_delivery_and_settle_once() -> Result<
    (
        PublishOutcome<()>,
        OutboxSettlement<()>,
        Vec<TransactionalMessagingObservation>,
    ),
    LiveConformanceFailure,
> {
    let (_rabbit, url) = isolated_rabbit("rss_transactional_core").await?;
    let route = MessageRoute::parse("rss.integration.message").expect("route");
    let subscriber = prepared_subscriber(&url, &route, "core-sub", true).await?;
    let message = envelope(&route, "integration-message-1");
    let subscription = subscription_for(&message, &route);
    let mut deliveries = DeliverySource::deliveries(&subscriber, &subscription)
        .await
        .map_err(|error| live_failure(LivePhase::Delivery, error.kind()))?;
    let publisher = connected_publisher(&url, "core-pub").await?;

    let outcome = Publisher::publish(&publisher, &message, provider_deadline()).await;
    if !matches!(outcome, PublishOutcome::Confirmed(())) {
        return Err(live_failure(
            LivePhase::Publish,
            MessagingErrorKind::Invariant,
        ));
    }
    let delivery = next_valid_delivery(
        &mut deliveries,
        "delivery stream ended",
        "valid envelope was rejected",
    )
    .await?;
    let observations = Arc::new(Mutex::new(Vec::new()));
    let emitter = RecordingEmitter(Arc::clone(&observations));
    let disposition = consume_live_delivery(
        delivery,
        "integration-consumer",
        &subscription,
        committed,
        &emitter,
    )
    .await?;
    if disposition != ProcessingDisposition::Committed(TerminalDisposition::Succeeded) {
        return Err(live_failure(
            LivePhase::Settlement,
            MessagingErrorKind::Invariant,
        ));
    }

    shutdown_bounded(&publisher).await?;
    shutdown_bounded(&subscriber).await?;
    let observations = observations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Ok((outcome, OutboxSettlement::Published(()), observations))
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_publish_delivery_and_settle_once() -> anyhow::Result<()> {
    run_publish_delivery_and_settle_once().await?;
    Ok(())
}

async fn consume_ambiguous_retries(
    deliveries: &mut ManagedDeliveryStream<AmqpDeliveries>,
    subscription: &SubscriptionIdentity,
) -> Result<usize, LiveConformanceFailure> {
    let store = MemoryInboxStore::new();
    let effects = Arc::new(AtomicUsize::new(0));
    let transaction = RecordingInboxTx {
        store: store.clone(),
        effects: Arc::clone(&effects),
    };
    let timer = FakeClock::new();
    let emitter = NoopEmitter;
    let execution = ConsumerExecution::new(
        ConsumerGroup::parse("ambiguous-consumer").expect("group"),
        &LiveIngress,
        subscription,
        &timer,
        consumer_policy(),
        &emitter,
    );
    let first = next_valid_delivery(
        deliveries,
        "ambiguous first delivery was not observed",
        "ambiguous first delivery was invalid",
    )
    .await?;
    let first = consume_once(&store, &transaction, &execution, *first)
        .await
        .map_err(|error| live_failure(LivePhase::Settlement, error.kind()))?;
    if first != ProcessingDisposition::Committed(TerminalDisposition::Succeeded) {
        return Err(live_failure(
            LivePhase::Settlement,
            MessagingErrorKind::Invariant,
        ));
    }
    let duplicate = next_valid_delivery(
        deliveries,
        "ambiguous retry delivery was not observed",
        "ambiguous retry delivery was invalid",
    )
    .await?;
    let duplicate = consume_once(&store, &transaction, &execution, *duplicate)
        .await
        .map_err(|error| live_failure(LivePhase::Settlement, error.kind()))?;
    if duplicate != ProcessingDisposition::Duplicate(TerminalDisposition::Succeeded) {
        return Err(live_failure(
            LivePhase::Settlement,
            MessagingErrorKind::Invariant,
        ));
    }
    Ok(effects.load(Ordering::SeqCst))
}

async fn run_ambiguous_publish_retries_the_same_message_identity()
-> Result<(Vec<MessageId>, Vec<PublishOutcome<()>>, usize), LiveConformanceFailure> {
    let (_rabbit, url) = isolated_rabbit("rss_transactional_ambiguity").await?;
    let route = MessageRoute::parse("rss.integration.ambiguity").expect("route");
    let subscriber = prepared_subscriber(&url, &route, "ambiguous-sub", false).await?;
    let publisher = connected_publisher(&url, "ambiguous-pub").await?;
    let message = envelope(&route, "stable-message-id");
    let subscription = subscription_for(&message, &route);
    let mut deliveries = DeliverySource::deliveries(&subscriber, &subscription)
        .await
        .map_err(|error| live_failure(LivePhase::Delivery, error.kind()))?;

    publisher.inject_post_send_connection_close_once();
    let first = Publisher::publish(&publisher, &message, provider_deadline()).await;
    if !matches!(first, PublishOutcome::Ambiguous(_)) {
        return Err(live_failure(
            LivePhase::Publish,
            MessagingErrorKind::Invariant,
        ));
    }
    let ready = tokio::time::timeout(TIMEOUT, publisher.wait_until_publish_ready_for_test())
        .await
        .map_err(|_| live_failure(LivePhase::Publish, MessagingErrorKind::DeadlineElapsed))?;
    if !ready {
        return Err(live_failure(
            LivePhase::Publish,
            MessagingErrorKind::Transient,
        ));
    }
    let second = Publisher::publish(&publisher, &message, provider_deadline()).await;
    if !matches!(second, PublishOutcome::Confirmed(())) {
        return Err(live_failure(
            LivePhase::Publish,
            MessagingErrorKind::Invariant,
        ));
    }

    let effects = consume_ambiguous_retries(&mut deliveries, &subscription).await?;

    shutdown_bounded(&publisher).await?;
    shutdown_bounded(&subscriber).await?;
    Ok((
        vec![message.id().clone(), message.id().clone()],
        vec![first, second],
        effects,
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_ambiguous_publish_retries_the_same_message_identity() -> anyhow::Result<()> {
    run_ambiguous_publish_retries_the_same_message_identity().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_rejected_commit_enters_broker_dead_letter_queue() -> anyhow::Result<()> {
    let rabbit = testkit::env_or_rabbitmq().await?;
    let url = rabbit.vhost_url("rss_transactional_reject").await?;
    let route = MessageRoute::parse("rss.integration.reject").expect("route");
    let subscriber =
        AmqpSubscriber::connect_with_webpki_for_test(&endpoint(&url)?, "reject-sub").await?;
    subscriber.prepare_delivery_route(&route).await?;
    subscriber.purge_durable_queue_for_test(&route).await?;
    let publisher =
        AmqpPublisher::connect_with_webpki_for_test(&endpoint(&url)?, "reject-pub", TIMEOUT)
            .await?;
    let message = envelope(&route, "integration-reject-1");
    let subscription = SubscriptionIdentity::new(
        message.metadata().domain().clone(),
        route.clone(),
        message.metadata().contract().clone(),
    );
    let mut deliveries = DeliverySource::deliveries(&subscriber, &subscription).await?;
    assert!(matches!(
        Publisher::publish(&publisher, &message, provider_deadline()).await,
        PublishOutcome::Confirmed(())
    ));
    let delivery = next_valid_delivery(
        &mut deliveries,
        "reject delivery stream ended",
        "reject fixture envelope was invalid",
    )
    .await?;
    assert_eq!(
        consume_live_delivery(
            delivery,
            "reject-consumer",
            &subscription,
            rejected,
            &NoopEmitter
        )
        .await?,
        ProcessingDisposition::Committed(TerminalDisposition::Rejected(
            rss_transactional_messaging::transaction::RejectKind::Permanent,
        ))
    );
    testkit::await_try(TIMEOUT, async || {
        let depth = subscriber.dead_letter_depth_for_test(&route).await?;
        Ok::<_, anyhow::Error>((depth == 1).then_some(()))
    })
    .await?;
    shutdown_bounded(&publisher).await?;
    shutdown_bounded(&subscriber).await?;
    Ok(())
}

async fn run_commit_unknown_abandons_and_redelivers_same_message()
-> Result<(Vec<TransactionalMessagingObservation>, usize), LiveConformanceFailure> {
    let (_rabbit, url) = isolated_rabbit("rss_transactional_unknown").await?;
    let route = MessageRoute::parse("rss.integration.unknown").expect("route");
    let first = prepared_subscriber(&url, &route, "unknown-sub-1", true).await?;
    let publisher = connected_publisher(&url, "unknown-pub").await?;
    let message = envelope(&route, "integration-unknown-1");
    let subscription = subscription_for(&message, &route);
    let mut deliveries = DeliverySource::deliveries(&first, &subscription)
        .await
        .map_err(|error| live_failure(LivePhase::Delivery, error.kind()))?;
    let publish = Publisher::publish(&publisher, &message, provider_deadline()).await;
    if !matches!(publish, PublishOutcome::Confirmed(())) {
        return Err(live_failure(
            LivePhase::Publish,
            MessagingErrorKind::Invariant,
        ));
    }
    let delivery = next_valid_delivery(
        &mut deliveries,
        "unknown delivery stream ended",
        "unknown fixture envelope was invalid",
    )
    .await?;
    let observations = Arc::new(Mutex::new(Vec::new()));
    let abandons = Arc::new(AtomicUsize::new(0));
    let (message, settlement) = (*delivery).into_parts();
    let outcome = consume_live_delivery(
        Box::new(Delivery::new(
            message,
            ObservingSettlement::new(settlement, Arc::clone(&abandons)),
        )),
        "unknown-consumer",
        &subscription,
        commit_unknown,
        &RecordingEmitter(Arc::clone(&observations)),
    )
    .await?;
    if outcome != ProcessingDisposition::Deferred {
        return Err(live_failure(
            LivePhase::Settlement,
            MessagingErrorKind::Invariant,
        ));
    }
    assert_committed_redelivery(
        &url,
        &route,
        &subscription,
        "unknown-sub-2",
        "abandoned delivery was not redelivered",
        "redelivered envelope was invalid",
    )
    .await?;
    shutdown_bounded(&publisher).await?;
    shutdown_bounded(&first).await?;
    let observations = observations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Ok((observations, abandons.load(Ordering::SeqCst)))
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_commit_unknown_abandons_and_redelivers_same_message() -> anyhow::Result<()> {
    run_commit_unknown_abandons_and_redelivers_same_message().await?;
    Ok(())
}

async fn run_managed_forced_cancel_redelivers_the_same_message_id()
-> Result<(), LiveConformanceFailure> {
    let (_rabbit, url) = isolated_rabbit("rss_transactional_managed_cancel").await?;
    let route = MessageRoute::parse("rss.integration.managed-cancel").expect("route");
    let first = Arc::new(prepared_subscriber(&url, &route, "managed-cancel-sub-1", true).await?);
    let publisher = connected_publisher(&url, "managed-cancel-pub").await?;
    let message = envelope(&route, "integration-managed-cancel-1");
    let subscription = subscription_for(&message, &route);
    let publish = Publisher::publish(&publisher, &message, provider_deadline()).await;
    if !matches!(publish, PublishOutcome::Confirmed(())) {
        return Err(live_failure(
            LivePhase::Publish,
            MessagingErrorKind::Invariant,
        ));
    }

    let started = Arc::new(AtomicUsize::new(0));
    let worker = ConsumerWorker::new(
        Arc::clone(&first),
        Arc::new(LiveInbox),
        Arc::new(BlockingLiveTx(Arc::clone(&started))),
        ConsumerGroup::parse("managed-cancel-consumer").expect("group"),
        Arc::new(LiveIngress),
        subscription.clone(),
        Arc::new(TokioClock::new()),
        consumer_policy(),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::STANDARD,
    );
    let (registration, _status) = worker.into_registration(
        "managed-cancel-consumer",
        ShutdownBudget::new(Duration::from_millis(50)).expect("budget"),
    );
    let mut stack = ShutdownStack::try_new(
        TotalDrainBudget::new(Duration::from_secs(2)).expect("total budget"),
    )
    .map_err(|_| live_failure(LivePhase::Shutdown, MessagingErrorKind::Invariant))?;
    let mut startup = stack
        .startup()
        .map_err(|_| live_failure(LivePhase::Shutdown, MessagingErrorKind::Invariant))?;
    startup.stage_task_with_token(registration);
    startup.commit().finish();
    tokio::time::timeout(TIMEOUT, async {
        while started.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| live_failure(LivePhase::Shutdown, MessagingErrorKind::DeadlineElapsed))?;

    let receipt = stack
        .shutdown()
        .await
        .map_err(|_| live_failure(LivePhase::Shutdown, MessagingErrorKind::Transient))?;
    if !matches!(
        receipt.failures().first().map(|failure| &failure.kind),
        Some(ShutdownFailureKind::TimedOut(_))
    ) {
        return Err(live_failure(
            LivePhase::Shutdown,
            MessagingErrorKind::Invariant,
        ));
    }
    shutdown_bounded(first.as_ref()).await?;

    assert_same_id_redelivery(&url, &route, &subscription, message.id()).await?;

    shutdown_bounded(&publisher).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_managed_forced_cancel_redelivers_the_same_message_id() -> anyhow::Result<()> {
    run_managed_forced_cancel_redelivers_the_same_message_id().await?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum LivePhase {
    Fixture,
    Connect,
    Publish,
    Delivery,
    Settlement,
    Shutdown,
}

impl LivePhase {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Connect => "connect",
            Self::Publish => "publish",
            Self::Delivery => "delivery",
            Self::Settlement => "settlement",
            Self::Shutdown => "shutdown",
        }
    }
}

#[derive(Debug)]
struct LiveConformanceFailure {
    phase: LivePhase,
    kind: MessagingErrorKind,
}

impl LiveConformanceFailure {
    const fn new(phase: LivePhase, kind: MessagingErrorKind) -> Self {
        Self { phase, kind }
    }

    fn into_messaging(self) -> MessagingError {
        MessagingError::new(self.kind, self)
    }

    const fn into_conformance(self) -> ConformanceError {
        match self.phase {
            LivePhase::Fixture => ConformanceError::fixture(self.kind),
            LivePhase::Connect => ConformanceError::connect(self.kind),
            LivePhase::Publish => ConformanceError::publish(self.kind),
            LivePhase::Delivery => ConformanceError::delivery(self.kind),
            LivePhase::Settlement => ConformanceError::settlement(self.kind),
            LivePhase::Shutdown => ConformanceError::shutdown(self.kind),
        }
    }
}

impl std::fmt::Display for LiveConformanceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "live AMQP {} phase failed",
            self.phase.as_label()
        )
    }
}

impl std::error::Error for LiveConformanceFailure {}

fn live_failure(phase: LivePhase, kind: MessagingErrorKind) -> LiveConformanceFailure {
    LiveConformanceFailure::new(phase, kind)
}

struct AmqpOutboxDriver {
    append_store: Mutex<MemoryOutboxStore<Vec<u8>>>,
    recovery_store: Mutex<MemoryOutboxStore<Vec<u8>>>,
    published_ids: Mutex<Vec<MessageId>>,
    consumer_effects: AtomicUsize,
}

impl Default for AmqpOutboxDriver {
    fn default() -> Self {
        Self {
            append_store: Mutex::new(MemoryOutboxStore::new()),
            recovery_store: Mutex::new(MemoryOutboxStore::new()),
            published_ids: Mutex::new(Vec::new()),
            consumer_effects: AtomicUsize::new(0),
        }
    }
}

impl OutboxDriver for AmqpOutboxDriver {
    fn reset(&self) {
        *self
            .append_store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = MemoryOutboxStore::new();
        *self
            .recovery_store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = MemoryOutboxStore::new();
        self.published_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.consumer_effects.store(0, Ordering::SeqCst);
    }

    async fn append_first(&self) -> Result<AppendOutcome, MessagingError> {
        let store = self
            .append_store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        store
            .append(
                &mut (),
                PendingMessage::new(envelope(
                    &MessageRoute::parse("rss.integration.outbox").expect("route"),
                    "shared-outbox-append",
                )),
            )
            .await
    }

    async fn append_same(&self) -> Result<AppendOutcome, MessagingError> {
        self.append_first().await
    }

    async fn append_conflict(&self) -> Result<AppendOutcome, MessagingError> {
        let store = self
            .append_store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let route = MessageRoute::parse("rss.integration.outbox").expect("route");
        let changed = envelope_with_payload(
            &route,
            "shared-outbox-append",
            b"conflicting-payload".to_vec(),
        );
        store.append(&mut (), PendingMessage::new(changed)).await
    }

    async fn partition_head_claims(&self) -> Result<usize, MessagingError> {
        let store = memory_partition_store().await?;
        Ok(store
            .claim_partition_heads(NonZeroUsize::new(8).expect("positive"), provider_deadline())
            .await?
            .len())
    }

    async fn blocked_partition_claims(&self) -> Result<usize, MessagingError> {
        let store = memory_partition_store().await?;
        let claims = store
            .claim_partition_heads(NonZeroUsize::new(8).expect("positive"), provider_deadline())
            .await?;
        let claim = claims.into_iter().next().expect("partition head");
        store
            .settle(claim, OutboxSettlement::DeadLetter, provider_deadline())
            .await?;
        Ok(store
            .claim_partition_heads(NonZeroUsize::new(8).expect("positive"), provider_deadline())
            .await?
            .len())
    }

    async fn confirmed_publish(
        &self,
    ) -> Result<(PublishOutcome<()>, OutboxSettlement<()>), ConformanceError> {
        let (outcome, settlement, _) = run_publish_delivery_and_settle_once()
            .await
            .map_err(LiveConformanceFailure::into_conformance)?;
        Ok((outcome, settlement))
    }

    async fn transient_publish(&self) -> Result<PublishOutcome<()>, MessagingError> {
        let outcome = PublishOutcome::DefinitelyNotPublished(PublishFailure::new(
            PublishFailureKind::Transient,
            PublishFailureStage::Admission,
            PublishFailureReason::TransportUnavailable,
        ));
        let publisher = MemoryPublisher::new([outcome]);
        Ok(publisher
            .publish(
                &envelope(
                    &MessageRoute::parse("rss.integration.transient").expect("route"),
                    "transient-publish",
                ),
                provider_deadline(),
            )
            .await)
    }

    async fn ambiguous_publish(&self) -> Result<Vec<PublishOutcome<()>>, ConformanceError> {
        let (ids, outcomes, effects) = run_ambiguous_publish_retries_the_same_message_identity()
            .await
            .map_err(LiveConformanceFailure::into_conformance)?;
        *self
            .published_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = ids;
        self.consumer_effects.store(effects, Ordering::SeqCst);
        Ok(outcomes)
    }

    async fn stale_lease(&self) -> Result<OutboxLeaseStatus, MessagingError> {
        let store = memory_partition_store().await?;
        let claim = store
            .claim_partition_heads(NonZeroUsize::new(1).expect("positive"), provider_deadline())
            .await?
            .into_iter()
            .next()
            .expect("partition head");
        store.fence_claims();
        store.lease_status(&claim, provider_deadline()).await
    }

    async fn expired_lease(&self) -> Result<OutboxLeaseStatus, MessagingError> {
        let store = memory_partition_store().await?;
        let claim = store
            .claim_partition_heads(NonZeroUsize::new(1).expect("positive"), provider_deadline())
            .await?
            .into_iter()
            .next()
            .expect("partition head");
        let clock = FakeClock::new();
        let expired = AbsoluteDeadline::from_timeout(&clock, Duration::ZERO)
            .expect("representable")
            .operation(&clock);
        store.lease_status(&claim, expired).await
    }

    async fn permanent_publish(&self) -> Result<PublishOutcome<()>, MessagingError> {
        let outcome = PublishOutcome::DefinitelyNotPublished(PublishFailure::new(
            PublishFailureKind::Permanent,
            PublishFailureStage::Admission,
            PublishFailureReason::ProviderRejected,
        ));
        let publisher = MemoryPublisher::new([outcome]);
        Ok(publisher
            .publish(
                &envelope(
                    &MessageRoute::parse("rss.integration.permanent").expect("route"),
                    "permanent-publish",
                ),
                provider_deadline(),
            )
            .await)
    }

    async fn publish_before_settle_recovery(
        &self,
    ) -> Result<Vec<PublishOutcome<()>>, ConformanceError> {
        let (ids, outcomes, effects) = run_ambiguous_publish_retries_the_same_message_identity()
            .await
            .map_err(LiveConformanceFailure::into_conformance)?;
        *self
            .published_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = ids;
        self.consumer_effects.store(effects, Ordering::SeqCst);
        let store = self
            .recovery_store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let route = MessageRoute::parse("rss.integration.recovery")
            .map_err(|_| ConformanceError::fixture(MessagingErrorKind::Invariant))?;
        store
            .append(
                &mut (),
                PendingMessage::new(envelope(&route, "recovery-message")),
            )
            .await
            .map_err(|error| ConformanceError::settlement(error.kind()))?;
        let claim = store
            .claim_partition_heads(NonZeroUsize::new(1).expect("positive"), provider_deadline())
            .await
            .map_err(|error| ConformanceError::settlement(error.kind()))?
            .into_iter()
            .next()
            .expect("recovery claim");
        store
            .settle(claim, OutboxSettlement::Published(()), provider_deadline())
            .await
            .map_err(|error| ConformanceError::settlement(error.kind()))?;
        Ok(outcomes)
    }

    fn published_message_ids(&self) -> Vec<MessageId> {
        self.published_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn settlement_dispositions(&self) -> Vec<OutboxDisposition> {
        self.recovery_store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .settlements()
    }

    fn consumer_effects(&self) -> usize {
        self.consumer_effects.load(Ordering::SeqCst)
    }
}

async fn memory_partition_store() -> Result<MemoryOutboxStore<Vec<u8>>, MessagingError> {
    let store = MemoryOutboxStore::new();
    let route = MessageRoute::parse("rss.integration.partition")
        .map_err(|error| MessagingError::new(MessagingErrorKind::Invariant, error))?;
    store
        .append(
            &mut (),
            PendingMessage::new(envelope(&route, "partition-head")),
        )
        .await?;
    store
        .append(
            &mut (),
            PendingMessage::new(envelope(&route, "partition-successor")),
        )
        .await?;
    Ok(store)
}

#[derive(Default)]
struct AmqpConsumerDriver;

impl ConsumerTxDriver for AmqpConsumerDriver {
    fn reset(&self) {}

    async fn committed_delivery(
        &self,
    ) -> Result<Vec<TransactionalMessagingObservation>, ConformanceError> {
        let (_, _, observations) = run_publish_delivery_and_settle_once()
            .await
            .map_err(LiveConformanceFailure::into_conformance)?;
        Ok(observations)
    }

    async fn duplicate_delivery(
        &self,
    ) -> Result<(TerminalDisposition, Vec<TransactionalMessagingObservation>), ConformanceError>
    {
        duplicate_delivery_evidence()
            .await
            .map_err(|error| ConformanceError::settlement(error.kind()))
    }

    async fn commit_unknown_delivery(
        &self,
    ) -> Result<(Vec<TransactionalMessagingObservation>, usize), ConformanceError> {
        run_commit_unknown_abandons_and_redelivers_same_message()
            .await
            .map_err(LiveConformanceFailure::into_conformance)
    }

    async fn lease_lost_delivery(
        &self,
    ) -> Result<(Vec<TransactionalMessagingObservation>, usize), ConformanceError> {
        run_managed_forced_cancel_redelivers_the_same_message_id()
            .await
            .map_err(LiveConformanceFailure::into_conformance)?;
        lease_lost_evidence()
            .await
            .map_err(|error| ConformanceError::settlement(error.kind()))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_shared_outbox_conformance_runner() -> anyhow::Result<()> {
    run_outbox_conformance(
        &AmqpOutboxDriver::default(),
        &TokioClock::new(),
        ExecutionBudget::new(Duration::from_secs(90), Duration::from_secs(5))?,
    )
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_shared_consumer_conformance_runner() -> anyhow::Result<()> {
    run_consumer_conformance(
        &AmqpConsumerDriver,
        &TokioClock::new(),
        ExecutionBudget::new(Duration::from_secs(90), Duration::from_secs(5))?,
    )
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_private_ca_and_split_roles_fail_closed() -> anyhow::Result<()> {
    let network = testkit::bridge_network("rss-transactional-amqp-tls").await?;
    let dns_name = format!("{}-node", network.name());
    let route = "rss.integration.private-ca";
    let fixture = testkit::rabbitmq_tls(
        route,
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: &dns_name,
        },
    )
    .await?;
    let publisher_endpoint = AmqpPublisherEndpoint::new(secure::AmqpEndpoint::parse(
        fixture.publisher_url(),
        secure::PlaintextEndpointPolicy::Deny,
    )?);
    let subscriber_endpoint = AmqpSubscriberEndpoint::new(secure::AmqpEndpoint::parse(
        fixture.subscriber_url(),
        secure::PlaintextEndpointPolicy::Deny,
    )?);
    let deps = AmqpRuntimeDeps::connect_with_private_ca(
        &publisher_endpoint,
        &subscriber_endpoint,
        AmqpPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?,
        "private-ca",
        TIMEOUT,
    )
    .await?;
    assert_eq!(deps.runtime_resources().len(), 2);
    assert!(fixture.publisher_permissions_are_exact().await?);
    assert!(fixture.subscriber_permissions_are_exact().await?);
    assert!(
        AmqpRuntimeDeps::connect_with_private_ca(
            &publisher_endpoint,
            &subscriber_endpoint,
            AmqpPrivateCa::from_pem(fixture.wrong_ca_pem().as_bytes().to_vec())?,
            "wrong-private-ca",
            TIMEOUT,
        )
        .await
        .is_err()
    );
    ManagedResource::shutdown(deps.publisher_for_integration_test()).await?;
    ManagedResource::shutdown(deps.subscriber_for_integration_test()).await?;
    Ok(())
}
