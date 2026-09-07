//! Real PG outbox → AMQP → PG effect/receipt → ACK, with caller-owned resource shutdown.
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    inbox::ConsumerGroup,
    message::*,
    observability::{TransactionalMessagingEmitter, TransactionalMessagingObservation},
    outbox::{AppendOutcome, OutboxStore, PendingMessage},
    policy::*,
    transaction::{
        EnvelopeValidationFailure, IngressChallenge, IngressValidator, TerminalDisposition,
        VerifiedIngress,
    },
    transport::{DeliverySource, IncomingDelivery},
};
use rss_transactional_messaging_amqp::{
    AmqpPrivateCa, AmqpPublisher, AmqpPublisherEndpoint, AmqpSubscriber, AmqpSubscriberEndpoint,
};
use rss_transactional_messaging_postgres::{
    PgConfig, PgConsumerEffect, PgConsumerEffectFailure, PgConsumerTx, PgInboxStore, PgOutboxStore,
    PgPassword, PgPrivateCa, PgRuntime, PgTransaction,
};
use rss_transactional_messaging_runtime::{
    consumer::{ConsumerExecution, ProcessingDisposition, consume_once},
    relay::{RelayBatchLimit, relay_once},
};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};

/// Ephemeral fixture configuration supplied by the integration harness, never a product format.
#[derive(serde::Deserialize)]
pub struct FixtureInput {
    /// PG TLS hostname.
    pub host: String,
    /// PG TLS port.
    pub port: u16,
    /// Pre-provisioned fixture database.
    pub database: String,
    /// Non-owner, non-bypass runtime role.
    pub username: String,
    /// Private fixture credential; not Debug or serialized to logs.
    pub password: String,
    /// Exclusive PG trust root.
    pub pg_ca: String,
    /// Explicitly authorized fixture tenant.
    pub tenant: String,
    /// Storage authority from fixture provisioning, not restored data discovery.
    pub target: [u8; 16],
    /// Independently supplied storage lineage.
    pub lineage: [u8; 16],
    /// Independently supplied execution epoch.
    pub epoch: i64,
    /// Per-run message identity.
    pub id: String,
    /// Pre-provisioned broker route.
    pub route: String,
    /// Separate publisher authority.
    pub publisher_url: String,
    /// Separate subscriber authority.
    pub subscriber_url: String,
    /// Exclusive broker trust root.
    pub amqp_ca: String,
}

#[derive(Clone)]
struct Timer(tokio::time::Instant);
impl Timer {
    #[allow(clippy::disallowed_methods)] // reason: this consumer owns the injected monotonic clock.
    fn new() -> Self {
        Self(tokio::time::Instant::now())
    }
    fn deadline(&self) -> anyhow::Result<OperationDeadline> {
        Ok(AbsoluteDeadline::from_timeout(self, Duration::from_secs(10))?.operation(self))
    }
}
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)] // reason: the concrete clock reads its own monotonic origin.
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_elapsed(self.0.elapsed())
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, deadline: AbsoluteDeadline) {
        tokio::time::sleep(deadline.remaining(self)).await;
    }
}

struct Effect;
impl PgConsumerEffect<Vec<u8>> for Effect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        _deadline: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        let id = message.id().as_str().to_owned();
        let tenant = tx.tenant_id().to_string();
        tx.with_connection(move |connection| {
            Box::pin(async move {
                sqlx::query(
                    "INSERT INTO public.business_effects(tenant_id,id) VALUES($1::uuid,$2)",
                )
                .bind(tenant)
                .bind(id)
                .execute(connection)
                .await?;
                Ok(())
            })
        })
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
        Ok(TerminalDisposition::Succeeded)
    }
}
struct Validator(TenantId);
impl IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        challenge: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        // Fixture authority is supplied independently; envelope coordinates are not authentication.
        if challenge.message().metadata().tenant_id() != self.0 {
            return Err(EnvelopeValidationFailure::MalformedIdentity);
        }
        let metadata = challenge.message().metadata();
        let subscription = challenge.subscription();
        if metadata.domain() != subscription.domain()
            || metadata.route() != subscription.route()
            || metadata.contract() != subscription.contract()
        {
            return Err(EnvelopeValidationFailure::UnsupportedContract);
        }
        Ok(challenge.verified())
    }
}
struct Observations;
impl TransactionalMessagingEmitter for Observations {
    fn emit(&self, _observation: TransactionalMessagingObservation) {
        // The executable asserts durable outcomes directly; it installs no telemetry backend.
    }
}

/// Run a bounded real-provider flow and close every resource through its selected public owner.
///
/// # Errors
/// Returns fixture connection, transaction, delivery or shutdown failures.
pub async fn run(input: FixtureInput) -> anyhow::Result<()> {
    run_inner(input).await
}

#[tokio::test]
async fn failed_operation_still_awaits_cleanup_and_preserves_both_errors() {
    let completed = std::sync::atomic::AtomicBool::new(false);
    let result = finish::<()>(Err(anyhow::anyhow!("operation failed")), async {
        tokio::task::yield_now().await;
        completed.store(true, std::sync::atomic::Ordering::SeqCst);
        Err(anyhow::anyhow!("cleanup failed"))
    })
    .await;
    assert!(completed.load(std::sync::atomic::Ordering::SeqCst));
    let text = format!(
        "{:#}",
        result
            .err()
            .unwrap_or_else(|| anyhow::anyhow!("missing failure"))
    );
    assert!(text.contains("operation failed"));
    assert!(text.contains("cleanup failed"));
}

async fn finish<T>(
    operation: anyhow::Result<T>,
    cleanup: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<T> {
    let cleanup = tokio::time::timeout(Duration::from_secs(10), cleanup)
        .await
        .map_err(anyhow::Error::from)
        .and_then(std::convert::identity);
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(operation), Ok(())) => Err(operation),
        (Ok(_), Err(cleanup)) => Err(cleanup.context("provider cleanup failed")),
        (Err(operation), Err(cleanup)) => {
            Err(operation.context(format!("provider cleanup also failed: {cleanup:#}")))
        }
    }
}

async fn run_inner(input: FixtureInput) -> anyhow::Result<()> {
    // Validate parameters before owning connections. Startup/operation cancellation must retain
    // every already-connected resource outside the cancelled future.
    let tenant = TenantId::parse(&input.tenant)?;
    let authority = ExecutionBinding::new(
        StorageIdentity::new(input.target, input.lineage)?,
        vec![(tenant, Epoch::new(input.epoch)?)],
    )?;
    let ca = AmqpPrivateCa::from_pem(input.amqp_ca.into_bytes())?;
    let publisher_endpoint = AmqpPublisherEndpoint::parse(input.publisher_url)?;
    let subscriber_endpoint = AmqpSubscriberEndpoint::parse(input.subscriber_url)?;
    let subscription = subscription(&input.route)?;
    let config = PgConfig::new(
        input.host,
        input.port,
        input.database,
        input.username,
        PgPassword::new(input.password),
        PgPrivateCa::from_pem(input.pg_ca.into_bytes())?,
    );
    #[cfg(feature = "managed")]
    let mut stack = rss_runtime::ShutdownStack::try_new(rss_runtime::TotalDrainBudget::new(
        Duration::from_secs(8),
    )?)?;
    #[cfg(feature = "managed")]
    let mut startup = stack.startup()?;
    let timer = Timer::new();
    let runtime = Arc::new(
        tokio::time::timeout(
            Duration::from_secs(10),
            PgRuntime::connect(config, timer.clone(), authority),
        )
        .await??,
    );
    #[cfg(not(feature = "managed"))]
    let (mut publisher_owner, mut subscriber_owner) = (None, None);
    let operation = tokio::time::timeout(Duration::from_secs(30), async {
        let (publisher, resource) = AmqpPublisher::connect(
            &publisher_endpoint,
            "example-publisher",
            &ca,
            Duration::from_secs(5),
        )
        .await?;
        #[cfg(not(feature = "managed"))]
        {
            publisher_owner = Some(resource);
        }
        #[cfg(feature = "managed")]
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(resource));
        let (subscriber, resource) = AmqpSubscriber::connect(
            &subscriber_endpoint,
            "example-subscriber",
            &ca,
            Duration::from_secs(5),
        )
        .await?;
        #[cfg(not(feature = "managed"))]
        {
            subscriber_owner = Some(resource);
        }
        #[cfg(feature = "managed")]
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(resource));
        transfer(
            &runtime,
            &publisher,
            &subscriber,
            &timer,
            tenant,
            &input.id,
            &input.route,
        )
        .await?;
        Ok::<_, anyhow::Error>(subscriber)
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(std::convert::identity);
    #[cfg(not(feature = "managed"))]
    let cleanup = async {
        // Await all owners before inspecting errors. None means that connection never completed.
        let (publisher, subscriber, ()) = tokio::join!(
            async {
                match publisher_owner {
                    Some(owner) => owner.shutdown(Duration::from_secs(5)).await,
                    None => Ok(()),
                }
            },
            async {
                match subscriber_owner {
                    Some(owner) => owner.shutdown(Duration::from_secs(5)).await,
                    None => Ok(()),
                }
            },
            runtime.close(),
        );
        match (publisher, subscriber) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(publisher), Ok(())) => Err(publisher.into()),
            (Ok(()), Err(subscriber)) => Err(subscriber.into()),
            (Err(publisher), Err(subscriber)) => Err(anyhow::anyhow!(
                "publisher cleanup: {publisher}; subscriber cleanup: {subscriber}"
            )),
        }
    };
    #[cfg(feature = "managed")]
    startup.commit().finish();
    #[cfg(feature = "managed")]
    let cleanup = async {
        let (receipt, postgres) = tokio::join!(
            stack.shutdown().join(),
            rss_runtime::ManagedResource::shutdown(runtime.as_ref())
        );
        let receipt = receipt?;
        postgres?;
        anyhow::ensure!(
            receipt.is_clean(),
            "managed provider cleanup failed: {:?}",
            receipt.failures()
        );
        Ok(())
    };
    let subscriber = finish(operation, cleanup).await?;
    assert!(runtime.is_closed());
    assert!(
        DeliverySource::deliveries(&subscriber, &subscription)
            .await
            .is_err()
    );
    Ok(())
}

fn subscription(route: &str) -> anyhow::Result<SubscriptionIdentity> {
    Ok(SubscriptionIdentity::new(
        MessagingDomain::parse("example")?,
        MessageRoute::parse(route)?,
        ContractIdentity::new(
            ContractId::parse("example.created")?,
            ContractVersion::from_major(1)?,
            SchemaDigest::parse(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )?,
        ),
    ))
}

async fn transfer(
    runtime: &Arc<PgRuntime>,
    publisher: &AmqpPublisher,
    subscriber: &AmqpSubscriber,
    timer: &Timer,
    tenant: TenantId,
    id: &str,
    route: &str,
) -> anyhow::Result<()> {
    let subscription = subscription(route)?;
    let message = MessageEnvelope::new(
        MessageId::parse(id)?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                Timepoint::try_from(1_i64)?,
                subscription.domain().clone(),
                subscription.route().clone(),
                subscription.contract().clone(),
            ),
            MessageMetadataExtensions::default(),
        ),
        b"payload".to_vec(),
    );
    let store = Arc::new(PgOutboxStore::<()>::new(
        runtime.clone(),
        subscription.domain().clone(),
        DeliveryBudget::new(
            Duration::from_secs(30),
            Duration::from_secs(5),
            Duration::from_secs(2),
            Duration::from_secs(2),
        )?,
    )?);
    let append = store.clone();
    runtime
        .local_tx(tenant, timer.deadline()?, move |tx| {
            Box::pin(async move {
                append
                    .append(tx, PendingMessage::new(message))
                    .await
                    .map_err(Into::into)
            })
        })
        .await
        .fold(
            |outcome| {
                assert_eq!(outcome, AppendOutcome::Inserted);
                Ok(())
            },
            Err,
            Err,
            Err,
            Err,
            Err,
        )?;
    let mut deliveries = DeliverySource::deliveries(subscriber, &subscription).await?;
    let report = relay_once(
        store.as_ref(),
        publisher,
        timer,
        &Observations,
        RelayBatchLimit::new(NonZeroUsize::MIN)?,
    )
    .await?;
    assert_eq!(report.published(), 1);
    let Some(IncomingDelivery::Valid(delivery)) =
        tokio::time::timeout(Duration::from_secs(10), deliveries.next()).await?
    else {
        anyhow::bail!("expected valid broker delivery")
    };
    let (received, settlement) = delivery.into_parts();
    assert_eq!(received.id().as_str(), id);
    let delivery = rss_transactional_messaging::transport::Delivery::new(received, settlement);
    let inbox = PgInboxStore::new(
        runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))?,
    )?;
    let tx = PgConsumerTx::receipt_only(runtime.clone(), Effect);
    let validator = Validator(tenant);
    let execution = ConsumerExecution::new(
        ConsumerGroup::parse("example-handler")?,
        &validator,
        &subscription,
        timer,
        ConsumerExecutionPolicy::new(RetryPolicy::STANDARD, ExecutionBudget::STANDARD),
        &Observations,
    );
    assert_eq!(
        consume_once(&inbox, &tx, &execution, delivery).await?,
        ProcessingDisposition::Committed(TerminalDisposition::Succeeded)
    );
    // Cancelling admission owns no ACK authority. Dropping this stream stops its subscription.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), deliveries.next())
            .await
            .is_err()
    );
    drop(deliveries);
    assert_eq!(
        relay_once(
            store.as_ref(),
            publisher,
            timer,
            &Observations,
            RelayBatchLimit::new(NonZeroUsize::MIN)?
        )
        .await?
        .claimed(),
        0
    );
    Ok(())
}
