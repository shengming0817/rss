//! Live AMQP proof for the canonical publisher/delivery/settlement ports.

#![allow(clippy::expect_used)]
// reason: canonical live-provider fixtures must fail loudly when typed identities drift.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

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
use rss_transactional_messaging::policy::{
    AbsoluteDeadline, Clock, ConsumerExecutionPolicy, ExecutionBudget, ExecutionTimer,
    MonotonicInstant, OperationDeadline, RetryPolicy, ShutdownBudget,
};
use rss_transactional_messaging::transaction::{
    ConsumerTx, EnvelopeValidationFailure, IngressChallenge, IngressValidator, SettlementDecision,
    TerminalDisposition, TransactionOutcome, VerifiedIngress,
};
use rss_transactional_messaging::transport::{
    Delivery, DeliverySettlement, DeliverySource, IncomingDelivery, ManagedDeliveryStream,
    PublishFailureKind, PublishOutcome, Publisher,
};
use rss_transactional_messaging_amqp::{
    AmqpPrivateCa, AmqpPublisher, AmqpPublisherEndpoint, AmqpPublisherResource, AmqpSubscriber,
    AmqpSubscriberEndpoint, AmqpSubscriberResource,
};
use rss_transactional_messaging_runtime::consumer::{
    ConsumerExecution, ConsumerWorker, ProcessingDisposition, SubscriptionBackoffPolicy,
    consume_once,
};
use rss_transactional_messaging_testkit::ConformanceError;
use rss_transactional_messaging_testkit::memory::{FakeClock, MemoryInboxStore};

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
    ConsumerExecutionPolicy::new(RetryPolicy::STANDARD, ExecutionBudget::STANDARD)
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
    fn lease_policy(&self) -> rss_transactional_messaging::policy::LeaseRenewalPolicy {
        rss_transactional_messaging::policy::LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))
            .expect("test lease")
    }
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
) -> Result<Box<AmqpDelivery>, LiveConformanceFailure> {
    match tokio::time::timeout(TIMEOUT, deliveries.next())
        .await
        .map_err(|_| live_failure(LivePhase::Delivery, MessagingErrorKind::DeadlineElapsed))?
        .ok_or_else(|| live_failure(LivePhase::Delivery, MessagingErrorKind::Transient))?
    {
        IncomingDelivery::Valid(delivery) => Ok(delivery),
        IncomingDelivery::Invalid(_) => Err(live_failure(
            LivePhase::Delivery,
            MessagingErrorKind::Permanent,
        )),
    }
}

async fn isolated_url(
    rabbit: &testkit::RabbitFixture,
    prefix: &str,
) -> Result<String, LiveConformanceFailure> {
    rabbit
        .vhost_url(&isolated_vhost(prefix))
        .await
        .map_err(|_| live_failure(LivePhase::Fixture, MessagingErrorKind::Transient))
}

async fn prepared_subscriber(
    url: &str,
    route: &MessageRoute,
    name: &'static str,
    purge: bool,
) -> Result<(AmqpSubscriber, AmqpSubscriberResource), LiveConformanceFailure> {
    let endpoint = AmqpSubscriberEndpoint::for_test(url)
        .map_err(|_| live_failure(LivePhase::Connect, MessagingErrorKind::Permanent))?;
    let (subscriber, resource) = AmqpSubscriber::connect_for_test(&endpoint, name, TIMEOUT)
        .await
        .map_err(|_| live_failure(LivePhase::Connect, MessagingErrorKind::Transient))?;
    topology::provision(url, route, purge)
        .await
        .map_err(|_| live_failure(LivePhase::Fixture, MessagingErrorKind::Transient))?;
    Ok((subscriber, resource))
}

async fn connected_publisher(
    url: &str,
    name: &'static str,
) -> Result<(AmqpPublisher, AmqpPublisherResource), LiveConformanceFailure> {
    let endpoint = AmqpPublisherEndpoint::for_test(url)
        .map_err(|_| live_failure(LivePhase::Connect, MessagingErrorKind::Permanent))?;
    AmqpPublisher::connect_for_test(&endpoint, name, TIMEOUT)
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

async fn assert_same_id_redelivery(
    url: &str,
    route: &MessageRoute,
    subscription: &SubscriptionIdentity,
    expected_id: &MessageId,
) -> Result<(), LiveConformanceFailure> {
    let (subscriber, subscriber_resource) =
        prepared_subscriber(url, route, "managed-cancel-sub-2", false).await?;
    let mut deliveries = DeliverySource::deliveries(&subscriber, subscription)
        .await
        .map_err(|error| live_failure(LivePhase::Delivery, error.kind()))?;
    let delivery = next_valid_delivery(&mut deliveries).await?;
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
    shutdown_bounded(&subscriber_resource).await
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
    let first = next_valid_delivery(deliveries).await?;
    let first = consume_once(&store, &transaction, &execution, *first)
        .await
        .map_err(|error| live_failure(LivePhase::Settlement, error.kind()))?;
    if first != ProcessingDisposition::Committed(TerminalDisposition::Succeeded) {
        return Err(live_failure(
            LivePhase::Settlement,
            MessagingErrorKind::Invariant,
        ));
    }
    let duplicate = next_valid_delivery(deliveries).await?;
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

async fn run_ambiguous_publish_retries_the_same_message_identity(
    rabbit: &testkit::RabbitFixture,
) -> Result<(Vec<MessageId>, Vec<PublishOutcome<()>>, usize), LiveConformanceFailure> {
    let url = isolated_url(rabbit, "rss_transactional_ambiguity").await?;
    let route = MessageRoute::parse("rss.integration.ambiguity").expect("route");
    let (subscriber, subscriber_resource) =
        prepared_subscriber(&url, &route, "ambiguous-sub", false).await?;
    let (publisher, publisher_resource) = connected_publisher(&url, "ambiguous-pub").await?;
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

    shutdown_bounded(&publisher_resource).await?;
    shutdown_bounded(&subscriber_resource).await?;
    Ok((
        vec![message.id().clone(), message.id().clone()],
        vec![first, second],
        effects,
    ))
}

async fn rejected_commit_enters_broker_dead_letter_queue(
    rabbit: &testkit::RabbitFixture,
) -> anyhow::Result<()> {
    let url = rabbit.vhost_url("rss_transactional_reject").await?;
    let route = MessageRoute::parse("rss.integration.reject").expect("route");
    let (subscriber, subscriber_resource) = AmqpSubscriber::connect_for_test(
        &AmqpSubscriberEndpoint::for_test(&url)?,
        "reject-sub",
        TIMEOUT,
    )
    .await?;
    topology::provision(&url, &route, true).await?;
    let (publisher, publisher_resource) = AmqpPublisher::connect_for_test(
        &AmqpPublisherEndpoint::for_test(&url)?,
        "reject-pub",
        TIMEOUT,
    )
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
    let delivery = next_valid_delivery(&mut deliveries).await?;
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
        let depth = topology::dead_letter_depth(&url, &route).await?;
        Ok::<_, anyhow::Error>((depth == 1).then_some(()))
    })
    .await?;
    shutdown_bounded(&publisher_resource).await?;
    shutdown_bounded(&subscriber_resource).await?;
    Ok(())
}

async fn run_managed_forced_cancel_redelivers_the_same_message_id(
    rabbit: &testkit::RabbitFixture,
) -> Result<(), LiveConformanceFailure> {
    let url = isolated_url(rabbit, "rss_transactional_managed_cancel").await?;
    let route = MessageRoute::parse("rss.integration.managed-cancel").expect("route");
    let (first, first_resource) =
        prepared_subscriber(&url, &route, "managed-cancel-sub-1", true).await?;
    let first = Arc::new(first);
    let (publisher, publisher_resource) = connected_publisher(&url, "managed-cancel-pub").await?;
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
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(first_resource));
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

    assert_same_id_redelivery(&url, &route, &subscription, message.id()).await?;

    shutdown_bounded(&publisher_resource).await?;
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

async fn private_ca_and_split_roles_fail_closed(
    fixture: &testkit::RabbitTlsFixture,
) -> anyhow::Result<()> {
    let route = TLS_ROUTE;
    let publisher_endpoint = AmqpPublisherEndpoint::parse(fixture.publisher_url())?;
    let subscriber_endpoint = AmqpSubscriberEndpoint::parse(fixture.subscriber_url())?;
    let ca = AmqpPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?;
    let wrong_ca = AmqpPrivateCa::from_pem(fixture.wrong_ca_pem().as_bytes().to_vec())?;
    let (publisher, publisher_resource) =
        AmqpPublisher::connect(&publisher_endpoint, "private-ca-publisher", &ca, TIMEOUT).await?;
    let (subscriber, subscriber_resource) =
        AmqpSubscriber::connect(&subscriber_endpoint, "private-ca-subscriber", &ca, TIMEOUT)
            .await?;
    assert!(fixture.publisher_permissions_are_exact().await?);
    assert!(fixture.subscriber_permissions_are_exact().await?);
    assert!(
        AmqpPublisher::connect(&publisher_endpoint, "wrong-private-ca", &wrong_ca, TIMEOUT)
            .await
            .is_err()
    );
    assert!(
        AmqpSubscriber::connect(&subscriber_endpoint, "wrong-private-ca", &wrong_ca, TIMEOUT)
            .await
            .is_err()
    );
    assert_tls_startup_rollback(&publisher_endpoint, &subscriber_endpoint, &ca, &wrong_ca).await?;

    let route = MessageRoute::parse(route)?;

    assert_tls_roundtrip(&publisher, &subscriber, &route).await?;
    shutdown_bounded(&publisher_resource).await?;
    shutdown_bounded(&subscriber_resource).await?;
    Ok(())
}

const TLS_ROUTE: &str = "rss.integration.private-ca";

// One inherited deadline includes fixture startup and all phases, leaving nextest 10s for cleanup.
const SUITE_BUDGET: Duration = Duration::from_secs(110);
#[allow(clippy::disallowed_methods)]
// reason: this fixture orchestration owns the wall-clock deadline for real Docker and broker I/O.
fn suite_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + SUITE_BUDGET
}

async fn suite_phase<T, E: Into<anyhow::Error>>(
    deadline: tokio::time::Instant,
    phase: &'static str,
    operation: impl Future<Output = Result<T, E>>,
) -> anyhow::Result<T> {
    use anyhow::Context as _;
    tokio::time::timeout_at(deadline, operation)
        .await
        .with_context(|| format!("{phase}: 110s suite deadline elapsed"))?
        .map_err(Into::into)
        .with_context(|| phase)
}

#[tokio::test(flavor = "multi_thread")]
async fn publisher_and_security_suite() -> anyhow::Result<()> {
    let deadline = suite_deadline();
    let rabbit = suite_phase(
        deadline,
        "publisher broker startup",
        testkit::managed_rabbitmq(),
    )
    .await?;
    let network = suite_phase(
        deadline,
        "TLS network",
        testkit::bridge_network("rss-amqp-security"),
    )
    .await?;
    let dns = format!("{}-node", network.name());
    let tls = suite_phase(
        deadline,
        "TLS broker startup",
        testkit::rabbitmq_tls(
            TLS_ROUTE,
            testkit::NetworkAttachment {
                network: network.name(),
                dns_name: &dns,
            },
        ),
    )
    .await?;
    suite_phase(
        deadline,
        "publisher conformance",
        transport::publisher_conformance(&rabbit, &tls),
    )
    .await?;
    suite_phase(
        deadline,
        "cancelled publish",
        transport::cancelled_publish_retires_generation_and_owner_cannot_revive(&rabbit),
    )
    .await?;
    suite_phase(
        deadline,
        "confirm deadline",
        transport::confirmation_deadline_retires_generation_and_preserves_retry_identity(&rabbit),
    )
    .await?;
    suite_phase(
        deadline,
        "private CA and split roles",
        private_ca_and_split_roles_fail_closed(&tls),
    )
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settlement_and_runtime_suite() -> anyhow::Result<()> {
    let deadline = suite_deadline();
    let rabbit = suite_phase(
        deadline,
        "settlement broker startup",
        testkit::managed_rabbitmq(),
    )
    .await?;
    suite_phase(
        deadline,
        "delivery conformance",
        transport::delivery_conformance(&rabbit),
    )
    .await?;
    suite_phase(
        deadline,
        "zero-deadline settlement",
        transport::expired_settlement_never_acks_and_redelivers(&rabbit),
    )
    .await?;
    suite_phase(
        deadline,
        "rejected commit / DLQ",
        rejected_commit_enters_broker_dead_letter_queue(&rabbit),
    )
    .await?;
    suite_phase(
        deadline,
        "forced runtime cancellation",
        run_managed_forced_cancel_redelivers_the_same_message_id(&rabbit),
    )
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn subscriber_lifecycle_suite() -> anyhow::Result<()> {
    let deadline = suite_deadline();
    let rabbit = suite_phase(
        deadline,
        "subscriber broker startup",
        testkit::managed_rabbitmq(),
    )
    .await?;
    suite_phase(
        deadline,
        "headers / route isolation",
        transport::headers_roundtrip_and_subscription_cancel_is_isolated(&rabbit),
    )
    .await?;
    suite_phase(
        deadline,
        "registration / shutdown",
        transport::subscription_cannot_register_after_resource_shutdown(&rabbit),
    )
    .await?;
    suite_phase(
        deadline,
        "subscriber recovery",
        transport::subscriber_recovers_after_broker_connection_loss(&rabbit),
    )
    .await?;
    suite_phase(
        deadline,
        "recovery installation fencing",
        transport::subscriber_recovery_cancellation_and_shutdown_fence_installation(&rabbit),
    )
    .await?;
    suite_phase(
        deadline,
        "missing queue",
        transport::subscriber_never_provisions_a_missing_queue(&rabbit),
    )
    .await?;
    Ok(())
}

mod topology;
mod transport;

async fn assert_tls_startup_rollback(
    publisher_endpoint: &AmqpPublisherEndpoint,
    subscriber_endpoint: &AmqpSubscriberEndpoint,
    ca: &AmqpPrivateCa,
    wrong_ca: &AmqpPrivateCa,
) -> anyhow::Result<()> {
    let mut rollback_stack =
        ShutdownStack::try_new(TotalDrainBudget::new(Duration::from_secs(10))?)?;
    let mut startup = rollback_stack.startup()?;
    let (rollback_handle, rollback_resource) =
        AmqpPublisher::connect(publisher_endpoint, "rollback-publisher", ca, TIMEOUT).await?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(rollback_resource));
    assert!(
        AmqpSubscriber::connect(
            subscriber_endpoint,
            "rollback-subscriber",
            wrong_ca,
            TIMEOUT
        )
        .await
        .is_err()
    );
    drop(startup);
    let rollback = rollback_stack.shutdown().await?;
    assert!(rollback.failures().is_empty());
    assert!(rollback_handle.transport_generation_for_test().is_none());

    Ok(())
}

async fn assert_tls_roundtrip(
    publisher: &AmqpPublisher,
    subscriber: &AmqpSubscriber,
    route: &MessageRoute,
) -> anyhow::Result<()> {
    assert!(matches!(
        publisher
            .publish(&envelope(route, "private-ca-valid"), provider_deadline())
            .await,
        PublishOutcome::Confirmed(())
    ));
    let message = envelope(route, "private-ca-valid");
    let subscription = subscription_for(&message, route);
    let mut stream = subscriber.deliveries(&subscription).await?;
    let delivery = next_valid_delivery(&mut stream).await?;
    let (received, settlement) = (*delivery).into_parts();
    transport::acknowledge(settlement, &received, &subscription).await?;
    let forbidden = MessageRoute::parse("rss.integration.forbidden")?;
    assert!(
        matches!(publisher.publish(&envelope(&forbidden, "private-ca-forbidden"), provider_deadline()).await, PublishOutcome::DefinitelyNotPublished(failure) if failure.kind() == PublishFailureKind::Permanent)
    );
    Ok(())
}
