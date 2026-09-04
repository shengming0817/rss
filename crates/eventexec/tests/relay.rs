#![allow(clippy::expect_used)]
// reason: deterministic in-memory fixtures must fail loudly on poisoned locks or script drift.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_transactional_messaging::error::MessagingError;
use rss_transactional_messaging::message::{
    AuthoredMessageMetadata, ContractIdentity, MessageEnvelope, MessageId, MessageMetadata,
    MessageMetadataExtensions, MessageRoute, MessagingDomain,
};
use rss_transactional_messaging::observability::{
    TransactionalMessagingEmitter, TransactionalMessagingObservation,
};
use rss_transactional_messaging::outbox::{
    AppendOutcome, OutboxDisposition, OutboxLeaseStatus, OutboxSettlement, OutboxStore,
    PendingMessage,
};
use rss_transactional_messaging::policy::{
    Clock, DeliveryBudget, MonotonicInstant, OperationDeadline,
};
use rss_transactional_messaging::relay::relay_once;
use rss_transactional_messaging::transport::{
    PublishFailure, PublishFailureKind, PublishFailureReason, PublishFailureStage, PublishOutcome,
    Publisher,
};

struct Claim(PendingMessage<Vec<u8>>);

struct Store {
    claims: Mutex<Vec<Claim>>,
    lease: OutboxLeaseStatus,
}

impl Store {
    fn new(lease: OutboxLeaseStatus) -> Self {
        Self {
            claims: Mutex::new(vec![Claim(message())]),
            lease,
        }
    }
}

impl OutboxStore<Vec<u8>> for Store {
    type Transaction = ();
    type Claim = Claim;
    type PublishReceipt = ();

    async fn append(
        &self,
        _transaction: &mut Self::Transaction,
        _message: PendingMessage<Vec<u8>>,
    ) -> Result<AppendOutcome, MessagingError> {
        Ok(AppendOutcome::Inserted)
    }

    async fn claim_partition_heads(
        &self,
        limit: usize,
        _deadline: OperationDeadline,
    ) -> Result<Vec<Self::Claim>, MessagingError> {
        let mut claims = self.claims.lock().expect("claim mutex");
        let count = limit.min(claims.len());
        Ok(claims.drain(..count).collect())
    }

    async fn lease_status(
        &self,
        _claim: &Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<OutboxLeaseStatus, MessagingError> {
        Ok(self.lease)
    }

    async fn extend(
        &self,
        _claim: &Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<OutboxLeaseStatus, MessagingError> {
        Ok(self.lease)
    }

    fn message(claim: &Self::Claim) -> &PendingMessage<Vec<u8>> {
        &claim.0
    }

    async fn settle(
        &self,
        claim: Self::Claim,
        settlement: OutboxSettlement<Self::PublishReceipt>,
        _deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        let disposition = settlement.disposition();
        if disposition == OutboxDisposition::Retry {
            self.claims.lock().expect("claim mutex").push(claim);
        }
        Ok(())
    }
}

struct ScriptedPublisher {
    outcomes: Mutex<VecDeque<PublishOutcome<()>>>,
    message_ids: Mutex<Vec<String>>,
}

impl ScriptedPublisher {
    fn new(outcomes: impl IntoIterator<Item = PublishOutcome<()>>) -> Self {
        Self {
            outcomes: Mutex::new(outcomes.into_iter().collect()),
            message_ids: Mutex::new(Vec::new()),
        }
    }
}

impl Publisher<Vec<u8>> for ScriptedPublisher {
    type Receipt = ();

    async fn publish(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        _deadline: OperationDeadline,
    ) -> PublishOutcome<Self::Receipt> {
        self.message_ids
            .lock()
            .expect("ids mutex")
            .push(message.id().as_str().to_owned());
        self.outcomes
            .lock()
            .expect("outcome mutex")
            .pop_front()
            .expect("scripted outcome")
    }
}

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_elapsed(Duration::ZERO)
    }
}

struct NoopEmitter;

impl TransactionalMessagingEmitter for NoopEmitter {
    fn emit(&self, _observation: TransactionalMessagingObservation) {}
}

fn budget() -> DeliveryBudget {
    DeliveryBudget::new(
        Duration::from_secs(10),
        Duration::from_secs(2),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .expect("budget")
}

fn message() -> PendingMessage<Vec<u8>> {
    let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
    let metadata = MessageMetadata::new(
        AuthoredMessageMetadata::new(
            tenant,
            Timepoint::try_from(1_700_000_000_i64).expect("time"),
            MessagingDomain::parse("orders").expect("domain"),
            MessageRoute::parse("orders.created").expect("route"),
            ContractIdentity::new(
                ContractId::parse("orders.created").expect("contract"),
                ContractVersion::from_major(1).expect("version"),
                SchemaDigest::parse(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .expect("schema"),
            ),
        ),
        MessageMetadataExtensions::new(None, None, None, BTreeMap::new()),
    );
    PendingMessage::new(MessageEnvelope::new(
        MessageId::parse("message-1").expect("id"),
        metadata,
        b"payload".to_vec(),
    ))
}

#[tokio::test]
async fn ambiguous_retry_reuses_the_persisted_message_id() {
    let store = Store::new(OutboxLeaseStatus::Held {
        remaining: Duration::from_secs(10),
    });
    let publisher = ScriptedPublisher::new([
        PublishOutcome::Ambiguous(PublishFailure::new(
            PublishFailureKind::Transient,
            PublishFailureStage::Confirm,
            PublishFailureReason::DeadlineElapsed,
        )),
        PublishOutcome::Confirmed(()),
    ]);

    let first = relay_once(&store, &publisher, &FixedClock, budget(), &NoopEmitter, 1)
        .await
        .expect("first relay");
    let second = relay_once(&store, &publisher, &FixedClock, budget(), &NoopEmitter, 1)
        .await
        .expect("second relay");

    assert_eq!(first.retried(), 1);
    assert_eq!(second.published(), 1);
    assert_eq!(
        publisher.message_ids.lock().expect("ids mutex").as_slice(),
        ["message-1", "message-1"]
    );
}

#[tokio::test]
async fn lost_lease_fences_before_publication() {
    let store = Store::new(OutboxLeaseStatus::Lost);
    let publisher = ScriptedPublisher::new([PublishOutcome::Confirmed(())]);

    let report = relay_once(&store, &publisher, &FixedClock, budget(), &NoopEmitter, 1)
        .await
        .expect("relay");

    assert_eq!(report.fenced(), 1);
    assert!(publisher.message_ids.lock().expect("ids mutex").is_empty());
}

#[tokio::test]
async fn insufficient_authoritative_lease_budget_retries_without_publish() {
    let store = Store::new(OutboxLeaseStatus::Held {
        remaining: budget().required_budget(),
    });
    let publisher = ScriptedPublisher::new([]);

    let report = relay_once(&store, &publisher, &FixedClock, budget(), &NoopEmitter, 1)
        .await
        .expect("relay");

    assert_eq!(report.retried(), 1);
    assert!(publisher.message_ids.lock().expect("ids mutex").is_empty());
}
