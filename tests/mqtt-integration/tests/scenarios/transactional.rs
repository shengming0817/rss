//! Real MQTT → canonical ingress/Inbox/ConsumerTx → MQTT settlement.
use super::*;
use rss_mqtt::{MqttDeliverySource, MqttTransactionSettlement};
use rss_transactional_messaging::{
    inbox::ConsumerGroup,
    policy::{
        ConsumerExecutionPolicy, ExecutionBudget, LeaseRenewalPolicy, OperationDeadline,
        RetryPolicy,
    },
    transaction::{
        ConsumerTx, EnvelopeValidationFailure, IngressChallenge, IngressValidator, ReceiptIntent,
        TerminalDisposition, TransactionOutcome, VerifiedIngress,
    },
    transport::{Delivery, DeliverySource, IncomingDelivery, PublishOutcome},
};
use rss_transactional_messaging_postgres::{
    PgConsumerEffect, PgConsumerEffectFailure, PgConsumerTx, PgInboxClaim, PgInboxStore,
    PgTransaction, PgTransactionFault,
};
use rss_transactional_messaging_runtime::consumer::{
    ConsumerExecution, ProcessingDisposition, consume_once,
};

struct Validator(bool);
impl IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        challenge: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        if !self.0 {
            return Err(EnvelopeValidationFailure::MalformedIdentity);
        }
        // Trusted test verifier: exact fixture tenant and subscription, never a production authenticator.
        if challenge.message().metadata().tenant_id().to_string()
            != "f47ac10b-58cc-4372-a567-0e02b2c3d479"
            || !challenge.subscription().accepts(challenge.message())
        {
            return Err(EnvelopeValidationFailure::MalformedIdentity);
        }
        Ok(challenge.verified())
    }
}
struct Effect(bool);
impl PgConsumerEffect<Vec<u8>> for Effect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        let id = message.id().as_str().to_owned();
        let payload = message.payload().clone();
        tx.with_connection(move |connection| {
            Box::pin(async move {
                sqlx::query("INSERT INTO public.mqtt_handoff VALUES($1,$2)")
                    .bind(id)
                    .bind(payload)
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
        if self.0 {
            return Err(PgConsumerEffectFailure::infrastructure(
                std::io::Error::other("fixture infrastructure failure"),
            ));
        }
        Ok(TerminalDisposition::Succeeded)
    }
}
struct FaultTransaction<'a> {
    inner: PgConsumerTx<Effect>,
    runtime: &'a PgRuntime,
    fault: Option<PgTransactionFault>,
}
impl ConsumerTx<Vec<u8>> for FaultTransaction<'_> {
    type Claim = PgInboxClaim;
    type CommitProof = <PgConsumerTx<Effect> as ConsumerTx<Vec<u8>>>::CommitProof;
    async fn execute(
        &self,
        claim: &Self::Claim,
        message: &MessageEnvelope<Vec<u8>>,
        intent: ReceiptIntent,
        deadline: OperationDeadline,
    ) -> TransactionOutcome<Self::CommitProof> {
        if let Some(fault) = self.fault {
            self.runtime.inject_next_transaction_fault(fault);
        }
        self.inner.execute(claim, message, intent, deadline).await
    }
}
async fn next(
    stream: &mut rss_transactional_messaging::transport::ManagedDeliveryStream<
        rss_mqtt::MqttDeliveries,
    >,
) -> anyhow::Result<Delivery<Vec<u8>, MqttTransactionSettlement>> {
    match tokio::time::timeout(Duration::from_secs(8), stream.next())
        .await?
        .ok_or_else(|| anyhow::anyhow!("stream ended"))?
    {
        IncomingDelivery::Valid(delivery) => Ok(*delivery),
        IncomingDelivery::Invalid(_) => anyhow::bail!("unexpected decode rejection"),
    }
}
async fn count(database: &Database, id: &str) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM public.mqtt_handoff WHERE message_id=$1")
            .bind(id)
            .fetch_one(&database.owner)
            .await?,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_mqtt_postgres_commit_evidence_controls_real_mqtt_ack_and_redelivery()
-> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(90), scenario()).await?
}
async fn scenario() -> anyhow::Result<()> {
    let database = Database::new().await?;
    sqlx::raw_sql("GRANT SELECT,INSERT ON public.mqtt_handoff TO mqtt_runtime")
        .execute(&database.owner)
        .await?;
    let mqtt = testkit::shared_mqtt_tls().await?;
    let clock = Arc::new(Timer::new());
    let (publisher, receiver, resource) = rss_mqtt::connect(
        support::config(&mqtt, "transactional", vec!["outbox/+".into()])?,
        clock.clone(),
        Arc::new(FileStore::new()?),
    )?;
    publisher.wait_ready(Duration::from_secs(5)).await?;
    let template = message("template")?;
    let m = template.metadata();
    let subscription =
        SubscriptionIdentity::new(m.domain().clone(), m.route().clone(), m.contract().clone());
    let source = MqttDeliverySource::new(receiver, subscription.clone())?;
    let mut stream = start_stream(&source, &subscription).await?;
    let adapter = rss_mqtt::MqttOutboxPublisher::new(publisher.clone(), plan()?);
    let inbox = PgInboxStore::new(
        database.runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(60))?,
    )?;
    let case = TransactionCase {
        connection: source.connection_state(),
        database,
        clock,
        adapter,
        inbox,
        subscription,
    };
    case.committed(&mut stream).await?;
    case.uncertain(&mut stream, false).await?;
    case.uncertain(&mut stream, true).await?;
    case.invalid(&mut stream).await?;
    case.expired_retirement(&mut stream).await?;
    drop(stream);
    let recovered = tokio::time::timeout(
        Duration::from_secs(5),
        source.deliveries(&case.subscription),
    )
    .await??;
    drop(recovered);
    drop(resource);
    case.database.runtime.close().await;
    case.database.owner.close().await;
    Ok(())
}
struct TransactionCase {
    connection: tokio::sync::watch::Receiver<rss_mqtt::ConnectionState>,
    database: Database,
    clock: Arc<Timer>,
    adapter: rss_mqtt::MqttOutboxPublisher,
    inbox: PgInboxStore,
    subscription: SubscriptionIdentity,
}
type Stream =
    rss_transactional_messaging::transport::ManagedDeliveryStream<rss_mqtt::MqttDeliveries>;
impl TransactionCase {
    async fn publish(&self, id: &str) -> anyhow::Result<()> {
        let outcome = self
            .adapter
            .publish(&message(id)?, support::deadline(&*self.clock))
            .await;
        assert!(
            matches!(outcome, PublishOutcome::Confirmed(())),
            "fixture publication {id}: ambiguous={} failure={:?}",
            outcome.is_ambiguous(),
            outcome.failure()
        );
        Ok(())
    }
    async fn process(
        &self,
        delivery: Delivery<Vec<u8>, MqttTransactionSettlement>,
        fault: Option<PgTransactionFault>,
        rollback: bool,
        valid: bool,
    ) -> anyhow::Result<ProcessingDisposition> {
        let validator = Validator(valid);
        let execution = ConsumerExecution::new(
            ConsumerGroup::parse("mqtt-transactional")?,
            &validator,
            &self.subscription,
            &*self.clock,
            ConsumerExecutionPolicy::new(RetryPolicy::STANDARD, ExecutionBudget::STANDARD),
            &Emitter,
        );
        let transaction = FaultTransaction {
            inner: PgConsumerTx::receipt_only(self.database.runtime.clone(), Effect(rollback)),
            runtime: &self.database.runtime,
            fault,
        };
        Ok(consume_once(&self.inbox, &transaction, &execution, delivery).await?)
    }
    async fn committed(&self, stream: &mut Stream) -> anyhow::Result<()> {
        self.database.append("committed").await?;
        self.database.relay(&self.adapter).await?;
        assert_committed(self.process(next(stream).await?, None, false, true).await?);
        assert_eq!(count(&self.database, "committed").await?, 1);
        self.publish("committed").await?;
        assert!(matches!(
            self.process(next(stream).await?, None, false, true).await?,
            ProcessingDisposition::Duplicate(_)
        ));
        assert_eq!(
            count(&self.database, "committed").await?,
            1,
            "duplicate never reexecutes INSERT"
        );
        Ok(())
    }
    async fn uncertain(&self, stream: &mut Stream, rollback: bool) -> anyhow::Result<()> {
        let (id, fault) = if rollback {
            ("rollback", PgTransactionFault::RollbackFailedAfterAck)
        } else {
            ("unknown", PgTransactionFault::CommitUnknownAfterAck)
        };
        self.publish(id).await?;
        let before = support::ready_generation(&self.connection)?;
        assert_deferred(
            self.process(next(stream).await?, Some(fault), rollback, true)
                .await?,
        );
        assert_eq!(count(&self.database, id).await?, i64::from(!rollback));
        support::wait_reconnected(&self.connection, before).await?;
        self.settle_replay(stream, id, rollback).await
    }
    async fn settle_replay(
        &self,
        stream: &mut Stream,
        id: &str,
        rollback: bool,
    ) -> anyhow::Result<()> {
        // No application republish: broker must return the original after session retirement.
        let (envelope, settlement) = next(stream).await?.into_parts();
        assert_eq!(envelope.id().as_str(), id);
        assert_eq!(envelope.payload(), message(id)?.payload());
        if rollback {
            self.expire_claim(id).await?;
        }
        let outcome = self
            .process(Delivery::new(envelope, settlement), None, false, true)
            .await?;
        if rollback {
            assert_committed(outcome);
        } else {
            assert!(matches!(outcome, ProcessingDisposition::Duplicate(_)));
        }
        assert_eq!(count(&self.database, id).await?, 1);
        Ok(())
    }
    async fn expire_claim(&self, id: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE rss_transactional_messaging.inbox SET lease_until=clock_timestamp()-interval '1 second' WHERE message_id=$1")
            .bind(id).execute(&self.database.owner).await?;
        Ok(())
    }
    async fn invalid(&self, stream: &mut Stream) -> anyhow::Result<()> {
        self.publish("invalid-ingress").await?;
        assert!(matches!(
            self.process(next(stream).await?, None, false, false)
                .await?,
            ProcessingDisposition::Rejected(_)
        ));
        let claims: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.inbox WHERE message_id='invalid-ingress'")
            .fetch_one(&self.database.owner).await?;
        assert_eq!(claims, 0);
        Ok(())
    }
}

async fn start_stream(
    source: &MqttDeliverySource,
    subscription: &SubscriptionIdentity,
) -> anyhow::Result<Stream> {
    let wrong = SubscriptionIdentity::new(
        subscription.domain().clone(),
        MessageRoute::parse("wrong")?,
        subscription.contract().clone(),
    );
    assert!(source.deliveries(&wrong).await.is_err());
    let mut stream = source.deliveries(subscription).await?;
    assert!(
        source.deliveries(subscription).await.is_err(),
        "no second admission owner"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), stream.next())
            .await
            .is_err(),
        "cancelling admission must preserve future deliveries"
    );
    Ok(stream)
}

fn assert_committed(result: ProcessingDisposition) {
    assert!(matches!(result, ProcessingDisposition::Committed(_)));
}
fn assert_deferred(result: ProcessingDisposition) {
    assert!(matches!(result, ProcessingDisposition::Deferred));
}

impl TransactionCase {
    async fn expired_retirement(&self, stream: &mut Stream) -> anyhow::Result<()> {
        use rss_transactional_messaging::{
            error::MessagingErrorKind, policy::AbsoluteDeadline, transport::DeliverySettlement,
        };
        self.publish("expired-retirement").await?;
        let (_, settlement) = next(stream).await?.into_parts();
        let before = support::ready_generation(&self.connection)?;
        let deadline =
            AbsoluteDeadline::from_timeout(&*self.clock, Duration::ZERO)?.operation(&*self.clock);
        assert_eq!(
            settlement
                .abandon(deadline)
                .await
                .err()
                .ok_or_else(|| anyhow::anyhow!("expired retirement succeeded"))?
                .kind(),
            MessagingErrorKind::DeadlineElapsed
        );
        support::wait_reconnected(&self.connection, before).await?;
        let delivery = next(stream).await?;
        let (message, settlement) = delivery.into_parts();
        assert_eq!(message.id().as_str(), "expired-retirement");
        self.process(Delivery::new(message, settlement), None, false, true)
            .await?;
        Ok(())
    }
}
#[path = "transactional_worker.rs"]
mod worker;
