//! Live AMQP proof for the canonical publisher/delivery/settlement ports.

#![allow(clippy::expect_used)]
// reason: canonical live-provider fixtures must fail loudly when typed identities drift.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use amqp::{
    AmqpPrivateCa, AmqpPublisher, AmqpPublisherEndpoint, AmqpRuntimeDeps, AmqpSubscriber,
    AmqpSubscriberEndpoint,
};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_runtime::{ManagedResource, ShutdownFailureKind, ShutdownStack, TotalDrainBudget};
use rss_transactional_messaging::error::MessagingError;
use rss_transactional_messaging::inbox::{
    ConsumerGroup, IdempotencyDisposition, InboxStore, LeaseStatus,
};
use rss_transactional_messaging::message::{
    AuthoredMessageMetadata, ContractIdentity, MessageEnvelope, MessageId, MessageMetadata,
    MessageMetadataExtensions, MessageRoute, MessagingDomain, SubscriptionIdentity,
};
use rss_transactional_messaging::observability::{
    TransactionalMessagingEmitter, TransactionalMessagingObservation,
};
use rss_transactional_messaging::policy::{
    AbsoluteDeadline, Clock, ConsumerExecutionPolicy, ExecutionBudget, ExecutionTimer,
    LeaseRenewalPolicy, MonotonicInstant, OperationDeadline, RetryPolicy, ShutdownBudget,
};
use rss_transactional_messaging::transaction::{
    ConsumerTx, EnvelopeValidationFailure, IngressChallenge, IngressValidator, TerminalDisposition,
    TransactionOutcome, VerifiedIngress,
};
use rss_transactional_messaging::transport::{
    Delivery, DeliverySource, IncomingDelivery, PublishOutcome, Publisher,
};
use rss_transactional_messaging_runtime::consumer::{
    ConsumerExecution, ConsumerWorker, ProcessingDisposition, SubscriptionBackoffPolicy,
    consume_once,
};

const TIMEOUT: Duration = Duration::from_secs(40);
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const SCHEMA: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct TestClock;

impl Clock for TestClock {
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_elapsed(Duration::ZERO)
    }
}

fn provider_deadline() -> OperationDeadline {
    AbsoluteDeadline::from_timeout(&TestClock, TIMEOUT)
        .expect("bounded integration deadline")
        .operation(&TestClock)
}

fn consumer_policy() -> ConsumerExecutionPolicy {
    ConsumerExecutionPolicy::new(
        RetryPolicy::STANDARD,
        ExecutionBudget::STANDARD,
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30)).expect("lease policy"),
    )
}

fn envelope(route: &MessageRoute, id: &str) -> MessageEnvelope<Vec<u8>> {
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
            MessageMetadataExtensions::new(None, None, None, BTreeMap::new()),
        ),
        b"payload".to_vec(),
    )
}

impl ExecutionTimer for TestClock {
    async fn sleep_until(&self, _deadline: AbsoluteDeadline) {
        std::future::pending().await
    }
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

#[derive(Clone, Copy)]
enum LiveTxOutcome {
    Succeeded,
    Rejected,
    CommitUnknown,
}

struct LiveTx(LiveTxOutcome);

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
        match self.0 {
            LiveTxOutcome::Succeeded => receipt.committed((), TerminalDisposition::Succeeded),
            LiveTxOutcome::Rejected => receipt.committed(
                (),
                TerminalDisposition::Rejected(
                    rss_transactional_messaging::transaction::RejectKind::Permanent,
                ),
            ),
            LiveTxOutcome::CommitUnknown => TransactionOutcome::commit_unknown(),
        }
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

fn endpoint(url: &str) -> anyhow::Result<secure::AmqpEndpoint> {
    Ok(secure::AmqpEndpoint::parse(
        url,
        secure::PlaintextEndpointPolicy::AllowLoopback,
    )?)
}

async fn shutdown_bounded(resource: &impl ManagedResource) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), ManagedResource::shutdown(resource)).await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_publish_delivery_and_settle_once() -> anyhow::Result<()> {
    let rabbit = testkit::env_or_rabbitmq().await?;
    let url = rabbit.vhost_url("rss_transactional_core").await?;
    let route = MessageRoute::parse("rss.integration.message").expect("route");
    let subscriber =
        AmqpSubscriber::connect_with_webpki_for_test(&endpoint(&url)?, "core-sub").await?;
    subscriber.prepare_delivery_route(&route).await?;
    subscriber.purge_durable_queue_for_test(&route).await?;
    let message = envelope(&route, "integration-message-1");
    let subscription = SubscriptionIdentity::new(
        message.metadata().domain().clone(),
        route.clone(),
        message.metadata().contract().clone(),
    );
    let mut deliveries = DeliverySource::deliveries(&subscriber, &subscription).await?;
    let publisher =
        AmqpPublisher::connect_with_webpki_for_test(&endpoint(&url)?, "core-pub", TIMEOUT).await?;

    assert!(matches!(
        Publisher::publish(&publisher, &message, provider_deadline()).await,
        PublishOutcome::Confirmed(())
    ));
    let incoming = tokio::time::timeout(TIMEOUT, deliveries.next())
        .await?
        .ok_or_else(|| anyhow::anyhow!("delivery stream ended"))?;
    let delivery = match incoming {
        IncomingDelivery::Valid(delivery) => delivery,
        IncomingDelivery::Invalid(_) => {
            return Err(anyhow::anyhow!("valid envelope was rejected"));
        }
    };
    let timer = TestClock;
    let emitter = NoopEmitter;
    let execution = ConsumerExecution::new(
        ConsumerGroup::parse("integration-consumer").expect("group"),
        &LiveIngress,
        &subscription,
        &timer,
        consumer_policy(),
        &emitter,
    );
    assert_eq!(
        consume_once(
            &LiveInbox,
            &LiveTx(LiveTxOutcome::Succeeded),
            &execution,
            *delivery,
        )
        .await?,
        ProcessingDisposition::Committed(TerminalDisposition::Succeeded)
    );

    ManagedResource::shutdown(&publisher).await?;
    ManagedResource::shutdown(&subscriber).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_ambiguous_publish_retries_the_same_message_identity() -> anyhow::Result<()> {
    let rabbit = testkit::env_or_rabbitmq().await?;
    let url = rabbit.vhost_url("rss_transactional_ambiguity").await?;
    let route = MessageRoute::parse("rss.integration.ambiguity").expect("route");
    let subscriber =
        AmqpSubscriber::connect_with_webpki_for_test(&endpoint(&url)?, "ambiguous-sub").await?;
    subscriber.prepare_delivery_route(&route).await?;
    let publisher =
        AmqpPublisher::connect_with_webpki_for_test(&endpoint(&url)?, "ambiguous-pub", TIMEOUT)
            .await?;
    let message = envelope(&route, "stable-message-id");

    publisher.inject_post_send_connection_close_once();
    assert!(matches!(
        Publisher::publish(&publisher, &message, provider_deadline()).await,
        PublishOutcome::Ambiguous(_)
    ));
    assert!(publisher.wait_until_publish_ready_for_test().await);
    assert!(matches!(
        Publisher::publish(&publisher, &message, provider_deadline()).await,
        PublishOutcome::Confirmed(())
    ));
    assert_eq!(message.id().as_str(), "stable-message-id");

    ManagedResource::shutdown(&publisher).await?;
    ManagedResource::shutdown(&subscriber).await?;
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
    let delivery = match tokio::time::timeout(TIMEOUT, deliveries.next())
        .await?
        .ok_or_else(|| anyhow::anyhow!("reject delivery stream ended"))?
    {
        IncomingDelivery::Valid(delivery) => delivery,
        IncomingDelivery::Invalid(_) => {
            return Err(anyhow::anyhow!("reject fixture envelope was invalid"));
        }
    };
    let timer = TestClock;
    let emitter = NoopEmitter;
    let execution = ConsumerExecution::new(
        ConsumerGroup::parse("reject-consumer").expect("group"),
        &LiveIngress,
        &subscription,
        &timer,
        consumer_policy(),
        &emitter,
    );
    assert_eq!(
        consume_once(
            &LiveInbox,
            &LiveTx(LiveTxOutcome::Rejected),
            &execution,
            *delivery,
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
    ManagedResource::shutdown(&publisher).await?;
    ManagedResource::shutdown(&subscriber).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_commit_unknown_abandons_and_redelivers_same_message() -> anyhow::Result<()> {
    let rabbit = testkit::env_or_rabbitmq().await?;
    let url = rabbit.vhost_url("rss_transactional_unknown").await?;
    let route = MessageRoute::parse("rss.integration.unknown").expect("route");
    let first =
        AmqpSubscriber::connect_with_webpki_for_test(&endpoint(&url)?, "unknown-sub-1").await?;
    first.prepare_delivery_route(&route).await?;
    first.purge_durable_queue_for_test(&route).await?;
    let publisher =
        AmqpPublisher::connect_with_webpki_for_test(&endpoint(&url)?, "unknown-pub", TIMEOUT)
            .await?;
    let message = envelope(&route, "integration-unknown-1");
    let subscription = SubscriptionIdentity::new(
        message.metadata().domain().clone(),
        route.clone(),
        message.metadata().contract().clone(),
    );
    let mut deliveries = DeliverySource::deliveries(&first, &subscription).await?;
    assert!(matches!(
        Publisher::publish(&publisher, &message, provider_deadline()).await,
        PublishOutcome::Confirmed(())
    ));
    let delivery = match tokio::time::timeout(TIMEOUT, deliveries.next())
        .await?
        .ok_or_else(|| anyhow::anyhow!("unknown delivery stream ended"))?
    {
        IncomingDelivery::Valid(delivery) => delivery,
        IncomingDelivery::Invalid(_) => {
            return Err(anyhow::anyhow!("unknown fixture envelope was invalid"));
        }
    };
    let timer = TestClock;
    let emitter = NoopEmitter;
    let execution = ConsumerExecution::new(
        ConsumerGroup::parse("unknown-consumer").expect("group"),
        &LiveIngress,
        &subscription,
        &timer,
        consumer_policy(),
        &emitter,
    );
    assert_eq!(
        consume_once(
            &LiveInbox,
            &LiveTx(LiveTxOutcome::CommitUnknown),
            &execution,
            *delivery,
        )
        .await?,
        ProcessingDisposition::Deferred
    );
    let second =
        AmqpSubscriber::connect_with_webpki_for_test(&endpoint(&url)?, "unknown-sub-2").await?;
    let mut redeliveries = DeliverySource::deliveries(&second, &subscription).await?;
    let redelivery = tokio::time::timeout(TIMEOUT, redeliveries.next())
        .await?
        .ok_or_else(|| anyhow::anyhow!("abandoned delivery was not redelivered"))?;
    let redelivery = match redelivery {
        IncomingDelivery::Valid(delivery) => delivery,
        IncomingDelivery::Invalid(_) => {
            return Err(anyhow::anyhow!("redelivered envelope was invalid"));
        }
    };
    let execution = ConsumerExecution::new(
        ConsumerGroup::parse("unknown-consumer").expect("group"),
        &LiveIngress,
        &subscription,
        &timer,
        consumer_policy(),
        &emitter,
    );
    assert_eq!(
        consume_once(
            &LiveInbox,
            &LiveTx(LiveTxOutcome::Succeeded),
            &execution,
            *redelivery,
        )
        .await?,
        ProcessingDisposition::Committed(TerminalDisposition::Succeeded)
    );
    ManagedResource::shutdown(&publisher).await?;
    ManagedResource::shutdown(&first).await?;
    ManagedResource::shutdown(&second).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_managed_forced_cancel_redelivers_the_same_message_id() -> anyhow::Result<()> {
    let rabbit = testkit::env_or_rabbitmq().await?;
    let url = rabbit.vhost_url("rss_transactional_managed_cancel").await?;
    let route = MessageRoute::parse("rss.integration.managed-cancel").expect("route");
    let first = Arc::new(
        AmqpSubscriber::connect_with_webpki_for_test(&endpoint(&url)?, "managed-cancel-sub-1")
            .await?,
    );
    first.prepare_delivery_route(&route).await?;
    first.purge_durable_queue_for_test(&route).await?;
    let publisher = AmqpPublisher::connect_with_webpki_for_test(
        &endpoint(&url)?,
        "managed-cancel-pub",
        TIMEOUT,
    )
    .await?;
    let message = envelope(&route, "integration-managed-cancel-1");
    let subscription = SubscriptionIdentity::new(
        message.metadata().domain().clone(),
        route.clone(),
        message.metadata().contract().clone(),
    );
    assert!(matches!(
        Publisher::publish(&publisher, &message, provider_deadline()).await,
        PublishOutcome::Confirmed(())
    ));

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
    )?;
    let mut startup = stack.startup()?;
    startup.stage_task_with_token(registration);
    startup.commit().finish();
    tokio::time::timeout(TIMEOUT, async {
        while started.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;

    let receipt = stack.shutdown().await?;
    assert!(matches!(
        receipt.failures()[0].kind,
        ShutdownFailureKind::TimedOut(_)
    ));
    shutdown_bounded(first.as_ref()).await?;

    let second =
        AmqpSubscriber::connect_with_webpki_for_test(&endpoint(&url)?, "managed-cancel-sub-2")
            .await?;
    let mut redeliveries = DeliverySource::deliveries(&second, &subscription).await?;
    let redelivery = tokio::time::timeout(TIMEOUT, redeliveries.next())
        .await?
        .ok_or_else(|| anyhow::anyhow!("forced cancellation was not redelivered"))?;
    let delivery = match redelivery {
        IncomingDelivery::Valid(delivery) => delivery,
        IncomingDelivery::Invalid(_) => return Err(anyhow::anyhow!("redelivery was invalid")),
    };
    let (redelivered_message, settlement) = delivery.into_parts();
    assert_eq!(redelivered_message.id().as_str(), message.id().as_str());
    let execution = ConsumerExecution::new(
        ConsumerGroup::parse("managed-cancel-consumer").expect("group"),
        &LiveIngress,
        &subscription,
        &TestClock,
        consumer_policy(),
        &NoopEmitter,
    );
    assert_eq!(
        consume_once(
            &LiveInbox,
            &LiveTx(LiveTxOutcome::Succeeded),
            &execution,
            Delivery::new(redelivered_message, settlement),
        )
        .await?,
        ProcessingDisposition::Committed(TerminalDisposition::Succeeded)
    );

    shutdown_bounded(&publisher).await?;
    shutdown_bounded(&second).await?;
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
