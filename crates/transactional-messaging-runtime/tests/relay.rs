#![allow(clippy::expect_used)]
// reason: deterministic in-memory fixtures must fail loudly on poisoned locks or script drift.

use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
use rss_transactional_messaging::message::{
    AuthoredMessageMetadata, ContractIdentity, MessageEnvelope, MessageId, MessageMetadata,
    MessageMetadataExtensions, MessageRoute, MessagingDomain,
};
use rss_transactional_messaging::observability::{
    TransactionalMessagingEmitter, TransactionalMessagingObservation,
    TransactionalMessagingRuntimePhase,
};
use rss_transactional_messaging::outbox::{
    AppendOutcome, OutboxClaimBatch, OutboxDisposition, OutboxLeaseStatus, OutboxSettlement,
    OutboxStore, PendingMessage,
};
use rss_transactional_messaging::policy::{
    Clock, DeliveryBudget, MonotonicInstant, OperationDeadline, ShutdownBudget,
};
use rss_transactional_messaging::transport::{
    PublishFailure, PublishFailureKind, PublishFailureReason, PublishFailureStage, PublishOutcome,
    Publisher,
};
use rss_transactional_messaging_runtime::relay::{
    RelayBatchLimit, RelayConfig, RelayConfigError, RelayWorker, relay_once,
};

struct Claim(PendingMessage<Vec<u8>>);

struct Store {
    claims: Mutex<Vec<Claim>>,
    lease: OutboxLeaseStatus,
    respect_limit: bool,
}

impl Store {
    fn new(lease: OutboxLeaseStatus) -> Self {
        Self {
            claims: Mutex::new(vec![Claim(message())]),
            lease,
            respect_limit: true,
        }
    }

    fn with_count(lease: OutboxLeaseStatus, count: usize) -> Self {
        Self {
            claims: Mutex::new(
                (0..count)
                    .map(|index| Claim(message_with_id(&format!("message-{index}"))))
                    .collect(),
            ),
            lease,
            respect_limit: true,
        }
    }

    fn over_returning(lease: OutboxLeaseStatus, count: usize) -> Self {
        let mut store = Self::with_count(lease, count);
        store.respect_limit = false;
        store
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
        limit: NonZeroUsize,
        _deadline: OperationDeadline,
    ) -> Result<OutboxClaimBatch<Self::Claim>, MessagingError> {
        let mut claims = self.claims.lock().expect("claim mutex");
        let count = if self.respect_limit {
            limit.get().min(claims.len())
        } else {
            claims.len()
        };
        OutboxClaimBatch::try_from_provider(claims.drain(..count).collect(), limit)
            .map_err(|error| MessagingError::new(MessagingErrorKind::Invariant, error))
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

struct RecordingEmitter(Arc<Mutex<Vec<TransactionalMessagingObservation>>>);

impl TransactionalMessagingEmitter for RecordingEmitter {
    fn emit(&self, observation: TransactionalMessagingObservation) {
        self.0.lock().expect("observations").push(observation);
    }
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

fn limit() -> RelayBatchLimit {
    RelayBatchLimit::new(NonZeroUsize::MIN).expect("limit")
}

fn message() -> PendingMessage<Vec<u8>> {
    message_with_id("message-1")
}

fn message_with_id(id: &str) -> PendingMessage<Vec<u8>> {
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
        MessageId::parse(id).expect("id"),
        metadata,
        b"payload".to_vec(),
    ))
}

struct ConcurrentPublisher {
    active: AtomicUsize,
    peak: AtomicUsize,
    started: AtomicUsize,
    permits: tokio::sync::Semaphore,
}

impl ConcurrentPublisher {
    fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            started: AtomicUsize::new(0),
            permits: tokio::sync::Semaphore::new(0),
        }
    }
}

impl Publisher<Vec<u8>> for ConcurrentPublisher {
    type Receipt = ();

    async fn publish(
        &self,
        _message: &MessageEnvelope<Vec<u8>>,
        _deadline: OperationDeadline,
    ) -> PublishOutcome<Self::Receipt> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        self.started.fetch_add(1, Ordering::SeqCst);
        let permit = self.permits.acquire().await.expect("semaphore open");
        permit.forget();
        self.active.fetch_sub(1, Ordering::SeqCst);
        PublishOutcome::Confirmed(())
    }
}

#[tokio::test]
async fn relay_once_dispatches_claimed_batch_concurrently_with_hard_limit() {
    let store = Arc::new(Store::with_count(
        OutboxLeaseStatus::Held {
            remaining: Duration::from_secs(10),
        },
        2,
    ));
    let publisher = Arc::new(ConcurrentPublisher::new());
    let task = tokio::spawn({
        let store = Arc::clone(&store);
        let publisher = Arc::clone(&publisher);
        async move {
            relay_once(
                store.as_ref(),
                publisher.as_ref(),
                &FixedClock,
                budget(),
                &NoopEmitter,
                RelayBatchLimit::new(NonZeroUsize::new(2).expect("limit")).expect("bounded"),
            )
            .await
        }
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        while publisher.started.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first window starts");
    assert_eq!(publisher.peak.load(Ordering::SeqCst), 2);
    assert_eq!(publisher.started.load(Ordering::SeqCst), 2);

    publisher.permits.add_permits(2);

    let report = task.await.expect("relay task").expect("relay batch");
    assert_eq!(report.claimed(), 2);
    assert_eq!(report.published(), 2);
    assert_eq!(publisher.peak.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn provider_cannot_return_more_claims_than_the_admitted_bound() {
    let store = Store::over_returning(
        OutboxLeaseStatus::Held {
            remaining: Duration::from_secs(10),
        },
        3,
    );
    let publisher = ScriptedPublisher::new([]);

    let error = relay_once(
        &store,
        &publisher,
        &FixedClock,
        budget(),
        &NoopEmitter,
        RelayBatchLimit::new(NonZeroUsize::new(2).expect("limit")).expect("bounded"),
    )
    .await
    .expect_err("provider over-return must fail closed");

    assert_eq!(error.kind(), MessagingErrorKind::Invariant);
    assert!(publisher.message_ids.lock().expect("ids mutex").is_empty());
}

#[tokio::test]
async fn relay_deadline_overflow_emits_a_closed_failure_phase() {
    struct OverflowClock;
    impl Clock for OverflowClock {
        fn now(&self) -> MonotonicInstant {
            MonotonicInstant::from_elapsed(Duration::MAX)
        }
    }

    let observations = Arc::new(Mutex::new(Vec::new()));
    let error = relay_once(
        &Store::new(OutboxLeaseStatus::Held {
            remaining: Duration::from_secs(10),
        }),
        &ScriptedPublisher::new([]),
        &OverflowClock,
        budget(),
        &RecordingEmitter(Arc::clone(&observations)),
        limit(),
    )
    .await
    .expect_err("deadline must overflow");

    assert_eq!(error.kind(), MessagingErrorKind::Invariant);
    assert!(observations.lock().expect("observations").contains(
        &TransactionalMessagingObservation::RuntimeFailure {
            phase: TransactionalMessagingRuntimePhase::RelayDeadline,
            kind: MessagingErrorKind::Invariant,
        }
    ));
}

#[test]
fn relay_limit_cannot_exceed_the_public_hard_bound() {
    assert_eq!(
        RelayBatchLimit::new(NonZeroUsize::new(65).expect("non-zero")),
        Err(RelayConfigError::MaxInFlightExceeded)
    );
}

struct AuditedStore {
    claims: Mutex<Vec<Claim>>,
    events: Arc<Mutex<Vec<String>>>,
}

impl OutboxStore<Vec<u8>> for AuditedStore {
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
        limit: NonZeroUsize,
        _deadline: OperationDeadline,
    ) -> Result<OutboxClaimBatch<Self::Claim>, MessagingError> {
        let mut claims = self.claims.lock().expect("claims");
        let count = limit.get().min(claims.len());
        OutboxClaimBatch::try_from_provider(claims.drain(..count).collect(), limit)
            .map_err(|error| MessagingError::new(MessagingErrorKind::Invariant, error))
    }

    async fn lease_status(
        &self,
        _claim: &Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<OutboxLeaseStatus, MessagingError> {
        Ok(OutboxLeaseStatus::Held {
            remaining: Duration::from_secs(10),
        })
    }

    async fn extend(
        &self,
        _claim: &Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<OutboxLeaseStatus, MessagingError> {
        Ok(OutboxLeaseStatus::Held {
            remaining: Duration::from_secs(10),
        })
    }

    fn message(claim: &Self::Claim) -> &PendingMessage<Vec<u8>> {
        &claim.0
    }

    async fn settle(
        &self,
        claim: Self::Claim,
        _settlement: OutboxSettlement<Self::PublishReceipt>,
        _deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        let id = claim.0.message_id().as_str().to_owned();
        self.events
            .lock()
            .expect("events")
            .push(format!("settle:{id}"));
        match id.as_str() {
            "message-0" => Err(MessagingError::new(
                MessagingErrorKind::Invariant,
                std::io::Error::other("first claim settlement failed"),
            )),
            "message-1" => Err(MessagingError::new(
                MessagingErrorKind::Transient,
                std::io::Error::other("second claim settlement failed"),
            )),
            _ => Ok(()),
        }
    }
}

struct AuditedPublisher(Arc<Mutex<Vec<String>>>);

impl Publisher<Vec<u8>> for AuditedPublisher {
    type Receipt = ();

    async fn publish(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        _deadline: OperationDeadline,
    ) -> PublishOutcome<Self::Receipt> {
        self.0
            .lock()
            .expect("events")
            .push(format!("publish:{}", message.id().as_str()));
        tokio::task::yield_now().await;
        PublishOutcome::Confirmed(())
    }
}

#[tokio::test]
async fn relay_drains_partial_failures_and_returns_first_error_in_claim_order() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let observations = Arc::new(Mutex::new(Vec::new()));
    let store = AuditedStore {
        claims: Mutex::new(
            (0..3)
                .map(|index| Claim(message_with_id(&format!("message-{index}"))))
                .collect(),
        ),
        events: Arc::clone(&events),
    };
    let error = relay_once(
        &store,
        &AuditedPublisher(Arc::clone(&events)),
        &FixedClock,
        budget(),
        &RecordingEmitter(Arc::clone(&observations)),
        RelayBatchLimit::new(NonZeroUsize::new(3).expect("non-zero")).expect("limit"),
    )
    .await
    .expect_err("two settlements fail");

    assert_eq!(error.kind(), MessagingErrorKind::Invariant);
    let events = events.lock().expect("events");
    for index in 0..3 {
        let publish = format!("publish:message-{index}");
        let settle = format!("settle:message-{index}");
        let publish_index = events
            .iter()
            .position(|event| event == &publish)
            .expect("publish");
        let settle_index = events
            .iter()
            .position(|event| event == &settle)
            .expect("settle");
        assert!(publish_index < settle_index, "{events:?}");
    }
    assert_eq!(
        events
            .iter()
            .filter(|event| event.starts_with("settle:"))
            .count(),
        3,
        "all admitted claims must drain"
    );
    let observations = observations.lock().expect("observations");
    assert!(
        observations.contains(&TransactionalMessagingObservation::RuntimeFailure {
            phase: TransactionalMessagingRuntimePhase::RelaySettlement,
            kind: MessagingErrorKind::Invariant,
        })
    );
    assert!(
        observations.contains(&TransactionalMessagingObservation::RuntimeFailure {
            phase: TransactionalMessagingRuntimePhase::RelaySettlement,
            kind: MessagingErrorKind::Transient,
        })
    );
}

#[tokio::test]
async fn relay_shutdown_drains_the_active_batch_within_budget() {
    let publisher = Arc::new(ConcurrentPublisher::new());
    let worker = RelayWorker::<Vec<u8>, _, _, _, _>::new(
        Arc::new(Store::new(OutboxLeaseStatus::Held {
            remaining: Duration::from_secs(10),
        })),
        Arc::clone(&publisher),
        Arc::new(FixedClock),
        Arc::new(NoopEmitter),
        RelayConfig::new(Duration::from_millis(100), NonZeroUsize::MIN).expect("config"),
        budget(),
    );
    let (registration, status) = worker.into_registration(
        "relay-drain",
        ShutdownBudget::new(Duration::from_secs(1)).expect("shutdown budget"),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(2)).expect("total budget"),
    )
    .expect("stack");
    let mut startup = stack.startup().expect("startup");
    startup.stage_task_with_token(registration);
    startup.commit().finish();
    tokio::time::timeout(Duration::from_secs(1), async {
        while publisher.started.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("publish starts");

    let release = async {
        tokio::task::yield_now().await;
        publisher.permits.add_permits(1);
    };
    let (receipt, ()) = tokio::join!(stack.shutdown(), release);
    assert!(receipt.expect("shutdown").is_clean());
    assert_eq!(
        status.wait_stopped().await,
        rss_runtime::TaskExit::Cancelled
    );
}

#[tokio::test]
async fn relay_worker_uses_runtime_token_and_reports_cancelled_status() {
    let worker = RelayWorker::<Vec<u8>, _, _, _, _>::new(
        Arc::new(Store::with_count(
            OutboxLeaseStatus::Held {
                remaining: Duration::from_secs(10),
            },
            0,
        )),
        Arc::new(ScriptedPublisher::new([])),
        Arc::new(FixedClock),
        Arc::new(NoopEmitter),
        RelayConfig::new(Duration::from_millis(100), NonZeroUsize::MIN).expect("config"),
        budget(),
    );
    let (registration, status) = worker.into_registration(
        "relay-test",
        ShutdownBudget::new(Duration::from_secs(1)).expect("shutdown budget"),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(2)).expect("total budget"),
    )
    .expect("stack");
    let mut startup = stack.startup().expect("startup");
    let same_status = startup.stage_task_with_token(registration);
    assert_eq!(same_status.name(), status.name());
    startup.commit().finish();
    tokio::task::yield_now().await;
    assert!(status.is_running());

    let receipt = stack.shutdown().await.expect("shutdown");
    assert!(receipt.is_clean());
    assert_eq!(
        status.wait_stopped().await,
        rss_runtime::TaskExit::Cancelled
    );
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

    let first = relay_once(
        &store,
        &publisher,
        &FixedClock,
        budget(),
        &NoopEmitter,
        limit(),
    )
    .await
    .expect("first relay");
    let second = relay_once(
        &store,
        &publisher,
        &FixedClock,
        budget(),
        &NoopEmitter,
        limit(),
    )
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
    let observations = Arc::new(Mutex::new(Vec::new()));

    let report = relay_once(
        &store,
        &publisher,
        &FixedClock,
        budget(),
        &RecordingEmitter(Arc::clone(&observations)),
        limit(),
    )
    .await
    .expect("relay");

    assert_eq!(report.fenced(), 1);
    assert!(publisher.message_ids.lock().expect("ids mutex").is_empty());
    assert!(
        observations
            .lock()
            .expect("observations")
            .contains(&TransactionalMessagingObservation::RelayLeaseLost)
    );
}

#[tokio::test]
async fn publication_evidence_maps_to_the_complete_settlement_matrix() {
    let cases = [
        (PublishOutcome::Confirmed(()), (1, 0, 0)),
        (
            PublishOutcome::DefinitelyNotPublished(PublishFailure::new(
                PublishFailureKind::Transient,
                PublishFailureStage::Send,
                PublishFailureReason::TransportUnavailable,
            )),
            (0, 1, 0),
        ),
        (
            PublishOutcome::DefinitelyNotPublished(PublishFailure::new(
                PublishFailureKind::Permanent,
                PublishFailureStage::Encode,
                PublishFailureReason::InvalidMessage,
            )),
            (0, 0, 1),
        ),
        (
            PublishOutcome::Ambiguous(PublishFailure::new(
                PublishFailureKind::Transient,
                PublishFailureStage::Confirm,
                PublishFailureReason::DeadlineElapsed,
            )),
            (0, 1, 0),
        ),
    ];

    for (outcome, expected) in cases {
        let report = relay_once(
            &Store::new(OutboxLeaseStatus::Held {
                remaining: Duration::from_secs(10),
            }),
            &ScriptedPublisher::new([outcome]),
            &FixedClock,
            budget(),
            &NoopEmitter,
            limit(),
        )
        .await
        .expect("matrix case");
        assert_eq!(
            (report.published(), report.retried(), report.dead_lettered()),
            expected
        );
    }
}

#[tokio::test]
async fn insufficient_authoritative_lease_budget_retries_without_publish() {
    let store = Store::new(OutboxLeaseStatus::Held {
        remaining: budget().required_budget(),
    });
    let publisher = ScriptedPublisher::new([]);

    let report = relay_once(
        &store,
        &publisher,
        &FixedClock,
        budget(),
        &NoopEmitter,
        limit(),
    )
    .await
    .expect("relay");

    assert_eq!(report.retried(), 1);
    assert!(publisher.message_ids.lock().expect("ids mutex").is_empty());
}
