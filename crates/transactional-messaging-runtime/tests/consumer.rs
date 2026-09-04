#![allow(clippy::expect_used)]
// reason: fixed canonical fixtures must fail loudly if their identity or protocol invariants drift.

mod support;

use std::collections::{BTreeMap, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_diag_context::CorrelationId;
use rss_request_context::TenantId;
use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
use rss_transactional_messaging::inbox::{
    ConsumerGroup, ConsumerIdentity, IdempotencyDisposition, InboxStore, LeaseStatus,
};
#[cfg(feature = "producer")]
use rss_transactional_messaging::message::PartitionIdentity;
use rss_transactional_messaging::message::{
    AuthoredMessageMetadata, ContractIdentity, MessageEnvelope, MessageFingerprint, MessageId,
    MessageMetadata, MessageMetadataExtensions, MessageRoute, MessagingDomain, PartitionKey,
    TransportContext,
};
use rss_transactional_messaging::observability::{
    TransactionalMessagingEmitter, TransactionalMessagingObservation,
    TransactionalMessagingRuntimePhase,
};
#[cfg(feature = "producer")]
use rss_transactional_messaging::outbox::{OutboxDisposition, PartitionHead, PartitionHeadState};
use rss_transactional_messaging::policy::{
    AbsoluteDeadline, Clock, ConsumerExecutionPolicy, DeliveryBudget, DeliveryBudgetError,
    ExecutionBudget, ExecutionBudgetError, ExecutionDeadlines, ExecutionTimer, LeaseRenewalPolicy,
    MonotonicInstant, OperationDeadline, RetryPolicy,
};
use rss_transactional_messaging::transaction::{
    ConsumerTx, FailureClass, LocalTxAttempt, RejectKind, SettlementKind, TerminalDisposition,
    TerminalReceipt, TransactionOutcome,
};
use rss_transactional_messaging::transport::{
    Delivery, DeliverySettlement, DeliverySource, IncomingDelivery, ManagedDeliveryStream,
};
use rss_transactional_messaging_runtime::consumer::{
    ConsumerExecution, ConsumerWorker, ProcessingDisposition, SubscriptionBackoffPolicy,
    consume_once,
};
use support::{AdvancingTimer as ManualTimer, ScriptedTimer};

const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const TENANT_B: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d480";
const SCHEMA_A: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SCHEMA_B: &str = "sha256:1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Fixture {
    id: &'static str,
    tenant: &'static str,
    occurred_at: i64,
    correlation: Option<&'static str>,
    domain: &'static str,
    route: &'static str,
    contract: &'static str,
    version: u32,
    schema: &'static str,
    partition: Option<(&'static str, &'static str, &'static str)>,
    causation: Option<&'static str>,
    attributes: BTreeMap<String, String>,
    payload: Vec<u8>,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            id: "message-1",
            tenant: TENANT_A,
            occurred_at: 1_700_000_000,
            correlation: Some("correlation-1"),
            domain: "orders",
            route: "orders.created",
            contract: "orders.created",
            version: 1,
            schema: SCHEMA_A,
            partition: Some((TENANT_A, "orders", "customer-7")),
            causation: Some("message-root"),
            attributes: BTreeMap::from([("contentType".to_owned(), "application/json".to_owned())]),
            payload: br#"{"orderId":7}"#.to_vec(),
        }
    }
}

fn tenant(raw: &str) -> TenantId {
    TenantId::parse(raw).expect("tenant fixture")
}

fn envelope(change: impl FnOnce(&mut Fixture)) -> MessageEnvelope<Vec<u8>> {
    let mut fixture = Fixture::default();
    change(&mut fixture);
    let domain = MessagingDomain::parse(fixture.domain).expect("domain fixture");
    let partition = fixture
        .partition
        .map(|(_, _, key)| PartitionKey::parse(key).expect("partition fixture"));
    let contract = ContractIdentity::new(
        ContractId::parse(fixture.contract).expect("contract fixture"),
        ContractVersion::from_major(fixture.version).expect("contract version fixture"),
        SchemaDigest::parse(fixture.schema).expect("schema fixture"),
    );
    let metadata = MessageMetadata::new(
        AuthoredMessageMetadata::new(
            tenant(fixture.tenant),
            Timepoint::try_from(fixture.occurred_at).expect("time fixture"),
            domain,
            MessageRoute::parse(fixture.route).expect("route fixture"),
            contract,
        ),
        MessageMetadataExtensions::new(
            fixture
                .correlation
                .map(|value| CorrelationId::parse(value).expect("correlation fixture")),
            partition,
            fixture
                .causation
                .map(|value| MessageId::parse(value).expect("causation fixture")),
            fixture.attributes,
        ),
    );
    MessageEnvelope::new(
        MessageId::parse(fixture.id).expect("message id fixture"),
        metadata,
        fixture.payload,
    )
}

fn fingerprint(change: impl FnOnce(&mut Fixture)) -> MessageFingerprint {
    MessageFingerprint::of(&envelope(change))
}

fn fingerprint_hex(value: MessageFingerprint) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct FixedClock(MonotonicInstant);

impl Clock for FixedClock {
    fn now(&self) -> MonotonicInstant {
        self.0
    }
}

impl ExecutionTimer for FixedClock {
    async fn sleep_until(&self, _deadline: AbsoluteDeadline) {
        std::future::pending().await
    }
}

struct RealtimeClock {
    origin: tokio::time::Instant,
}

impl RealtimeClock {
    #[allow(clippy::disallowed_methods)]
    // reason: this test adapter is the injected Clock owner; Tokio time also supports pause/advance.
    fn new() -> Self {
        Self {
            origin: tokio::time::Instant::now(),
        }
    }
}

impl Clock for RealtimeClock {
    #[allow(clippy::disallowed_methods)]
    // reason: the injected adapter projects its single Tokio monotonic origin into core time.
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_elapsed(tokio::time::Instant::now() - self.origin)
    }
}

impl ExecutionTimer for RealtimeClock {
    async fn sleep_until(&self, deadline: AbsoluteDeadline) {
        tokio::time::sleep_until(self.origin + deadline.instant().elapsed()).await;
    }
}

#[tokio::test(start_paused = true)]
async fn realtime_clock_sleep_and_now_share_one_monotonic_domain() {
    let timer = RealtimeClock::new();
    let deadline =
        AbsoluteDeadline::from_timeout(&timer, Duration::from_secs(1)).expect("deadline");

    let sleeping = timer.sleep_until(deadline);
    tokio::pin!(sleeping);
    tokio::time::advance(Duration::from_secs(1)).await;
    sleeping.await;

    assert_eq!(deadline.remaining(&timer), Duration::ZERO);
}

struct NoopEmitter;

impl TransactionalMessagingEmitter for NoopEmitter {
    fn emit(&self, _observation: TransactionalMessagingObservation) {}
}

fn consumer_policy() -> ConsumerExecutionPolicy {
    ConsumerExecutionPolicy::new(
        RetryPolicy::STANDARD,
        ExecutionBudget::STANDARD,
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30)).expect("lease policy"),
    )
}

#[test]
fn policy_budgets_are_strict_and_monotonic() {
    assert_eq!(
        DeliveryBudget::new(
            Duration::from_secs(3),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        ),
        Err(DeliveryBudgetError::RequiredBudgetNotBelowLease)
    );
    let budget = DeliveryBudget::new(
        Duration::from_secs(4),
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .expect("valid delivery budget");
    assert!(!budget.can_start_attempt(Duration::from_secs(3)));
    assert!(budget.can_start_attempt(Duration::from_secs(3) + Duration::from_millis(1)));

    let retry = RetryPolicy::new(
        std::num::NonZeroU32::new(3).expect("nonzero"),
        Duration::from_millis(100),
        Duration::from_millis(250),
    )
    .expect("retry policy");
    assert_eq!(
        retry.delay_after(std::num::NonZeroU32::new(3).expect("nonzero")),
        Duration::from_millis(250)
    );

    let execution = ExecutionBudget::new(Duration::from_secs(5), Duration::from_secs(1))
        .expect("execution budget");
    let clock = FixedClock(MonotonicInstant::from_elapsed(Duration::from_secs(10)));
    let deadlines = ExecutionDeadlines::from_budget(&clock, execution).expect("deadlines");
    assert_eq!(
        deadlines.operation().remaining(&clock),
        Duration::from_secs(4)
    );
    assert_eq!(
        deadlines.settlement().remaining(&clock),
        Duration::from_secs(5)
    );
    let overflow_clock = FixedClock(MonotonicInstant::from_elapsed(Duration::MAX));
    assert_eq!(
        ExecutionDeadlines::from_budget(&overflow_clock, execution),
        Err(ExecutionBudgetError::DeadlineOverflow)
    );
}

#[test]
fn message_id_enforces_every_boundary() {
    assert!(MessageId::parse("").is_err());
    assert!(MessageId::parse("a").is_ok());
    assert!(MessageId::parse(&"x".repeat(255)).is_ok());
    assert!(MessageId::parse(&"x".repeat(256)).is_err());
    for invalid in ["contains space", "slash/value", "ümlaut", "line\nbreak"] {
        assert!(MessageId::parse(invalid).is_err(), "accepted {invalid:?}");
    }
    assert_eq!(
        MessageId::parse("a:b.c_d-1").map(|id| id.as_str().to_owned()),
        Ok("a:b.c_d-1".to_owned())
    );
}

#[test]
fn fingerprint_known_answer_and_every_authored_field_mutation() {
    let original = fingerprint(|_| {});
    assert_eq!(
        fingerprint_hex(original),
        "1a71f18b237b7f2eb456ad006194fdefa890cdaa9f76d6cc05ab3acd54e329b2"
    );

    let mutations = [
        fingerprint(|value| value.id = "message-2"),
        fingerprint(|value| value.tenant = TENANT_B),
        fingerprint(|value| value.occurred_at += 1),
        fingerprint(|value| value.correlation = Some("correlation-2")),
        fingerprint(|value| value.domain = "billing"),
        fingerprint(|value| value.route = "orders.updated"),
        fingerprint(|value| value.contract = "orders.updated"),
        fingerprint(|value| value.version = 2),
        fingerprint(|value| value.schema = SCHEMA_B),
        fingerprint(|value| value.partition = Some((TENANT_A, "orders", "customer-8"))),
        fingerprint(|value| value.partition = None),
        fingerprint(|value| value.causation = Some("message-parent")),
        fingerprint(|value| {
            value
                .attributes
                .insert("contentType".to_owned(), "text/plain".to_owned());
        }),
        fingerprint(|value| value.payload = br#"{"orderId":8}"#.to_vec()),
    ];
    for mutation in mutations {
        assert_ne!(original, mutation);
    }

    let id = MessageId::parse("message-1").expect("fixture");
    assert!(original.verify(&id, mutations[1]).is_err());
}

#[test]
fn transport_context_has_no_fingerprint_authority() {
    let original = envelope(|_| {});
    let with_transport = envelope(|_| {}).with_transport_context(TransportContext::new(
        Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_owned()),
        Some("opaque-authority".to_owned()),
    ));
    assert_eq!(
        MessageFingerprint::of(&original),
        MessageFingerprint::of(&with_transport)
    );
}

#[test]
fn only_confirmed_transient_non_commits_are_retryable_or_acknowledgeable() {
    assert!(TransactionOutcome::<()>::not_started(FailureClass::Transient).may_retry());
    assert!(TransactionOutcome::<()>::rolled_back(FailureClass::Transient).may_retry());
    for outcome in [
        TransactionOutcome::<()>::not_started(FailureClass::Permanent),
        TransactionOutcome::<()>::rollback_failed(),
        TransactionOutcome::<()>::commit_unknown(),
        TransactionOutcome::<()>::fenced(),
    ] {
        assert!(!outcome.may_retry());
    }
}

#[test]
fn local_transaction_fold_preserves_all_fault_semantics() {
    assert_eq!(
        LocalTxAttempt::<u8, &str>::committed(7).fold(|v| v, |_| 1, |_| 2, |_| 3, |_| 4, |_| 5),
        7
    );
    assert_eq!(
        LocalTxAttempt::<(), _>::not_started("x").fold(|_| 0, |_| 1, |_| 2, |_| 3, |_| 4, |_| 5),
        1
    );
    assert_eq!(
        LocalTxAttempt::<(), _>::rolled_back("x").fold(|_| 0, |_| 1, |_| 2, |_| 3, |_| 4, |_| 5),
        2
    );
    assert_eq!(
        LocalTxAttempt::<(), _>::rollback_failed("x").fold(
            |_| 0,
            |_| 1,
            |_| 2,
            |_| 3,
            |_| 4,
            |_| 5
        ),
        3
    );
    assert_eq!(
        LocalTxAttempt::<(), _>::commit_unknown("x").fold(|_| 0, |_| 1, |_| 2, |_| 3, |_| 4, |_| 5),
        4
    );
    assert_eq!(
        LocalTxAttempt::<(), _>::fenced("x").fold(|_| 0, |_| 1, |_| 2, |_| 3, |_| 4, |_| 5),
        5
    );
}

#[cfg(feature = "producer")]
#[test]
fn partition_head_gates_successors_and_dead_letter_requires_resolution() {
    let partition_a = PartitionIdentity::new(
        tenant(TENANT_A),
        MessagingDomain::parse("orders").expect("domain"),
        PartitionKey::parse("customer-7").expect("partition"),
    );
    let partition_b = PartitionIdentity::new(
        tenant(TENANT_B),
        MessagingDomain::parse("orders").expect("domain"),
        PartitionKey::parse("customer-7").expect("partition"),
    );
    assert_ne!(
        partition_a, partition_b,
        "tenant must isolate equal partition keys"
    );

    let mut head = PartitionHead::new(partition_a, MessageId::parse("message-1").expect("message"));
    assert!(!head.allows_successor());
    head.claim().expect("head claim");
    assert_eq!(head.state(), PartitionHeadState::InFlight);
    assert!(head.claim().is_err(), "only one head claim may exist");
    head.settle(OutboxDisposition::DeadLetter)
        .expect("dead letter");
    assert!(
        !head.allows_successor(),
        "unresolved dead letter blocks successor"
    );
    head.resolve_dead_letter().expect("operator resolution");
    assert!(head.allows_successor());
}

struct Proof;
struct Claim;

struct FakeInbox {
    disposition: Mutex<Option<IdempotencyDisposition<Claim>>>,
    lease: LeaseStatus,
}

struct ExtendErrorInbox;

struct ClaimErrorInbox;

impl InboxStore for ClaimErrorInbox {
    type Claim = Claim;

    async fn claim(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        Err(MessagingError::new(
            MessagingErrorKind::Invariant,
            std::io::Error::other("primary claim failure"),
        ))
    }

    async fn read_terminal(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<Option<TerminalReceipt>, MessagingError> {
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

impl InboxStore for ExtendErrorInbox {
    type Claim = Claim;

    async fn claim(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        Ok(IdempotencyDisposition::Acquired(Claim))
    }

    async fn read_terminal(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<Option<TerminalReceipt>, MessagingError> {
        Ok(None)
    }

    async fn extend(
        &self,
        _claim: &Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<LeaseStatus, MessagingError> {
        Err(MessagingError::new(
            MessagingErrorKind::Transient,
            std::io::Error::other("provider time unavailable"),
        ))
    }

    async fn release(
        &self,
        _claim: Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        Err(MessagingError::new(
            MessagingErrorKind::Invariant,
            std::io::Error::other("an unverified claim must not be released"),
        ))
    }
}

impl InboxStore for FakeInbox {
    type Claim = Claim;

    async fn claim(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        self.disposition
            .lock()
            .expect("lock")
            .take()
            .ok_or_else(|| {
                MessagingError::new(
                    MessagingErrorKind::Invariant,
                    std::io::Error::other("claim reused"),
                )
            })
    }

    async fn read_terminal(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<Option<TerminalReceipt>, MessagingError> {
        Ok(None)
    }

    async fn extend(
        &self,
        _claim: &Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<LeaseStatus, MessagingError> {
        Ok(self.lease)
    }

    async fn release(
        &self,
        _claim: Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        Ok(())
    }
}

struct FakeTx {
    calls: Arc<AtomicUsize>,
    disposition: TerminalDisposition,
}

struct RetryThenCommitTx {
    calls: Arc<AtomicUsize>,
}

impl ConsumerTx<Vec<u8>> for RetryThenCommitTx {
    type Claim = Claim;
    type CommitProof = Proof;

    async fn execute(
        &self,
        _claim: &Self::Claim,
        _message: &MessageEnvelope<Vec<u8>>,
        receipt: rss_transactional_messaging::transaction::ReceiptIntent,
        _deadline: OperationDeadline,
    ) -> TransactionOutcome<Self::CommitProof> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            TransactionOutcome::rolled_back(FailureClass::Transient)
        } else {
            receipt.committed(Proof, TerminalDisposition::Succeeded)
        }
    }
}

impl ConsumerTx<Vec<u8>> for FakeTx {
    type Claim = Claim;
    type CommitProof = Proof;

    async fn execute(
        &self,
        _claim: &Self::Claim,
        _message: &MessageEnvelope<Vec<u8>>,
        receipt: rss_transactional_messaging::transaction::ReceiptIntent,
        _deadline: OperationDeadline,
    ) -> TransactionOutcome<Self::CommitProof> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        receipt.committed(Proof, self.disposition)
    }
}

struct FakeSettlement {
    actions: Arc<Mutex<Vec<SettlementKind>>>,
    fail: bool,
    abandoned: Arc<AtomicUsize>,
}

struct FailingAbandonSettlement {
    abandoned: Arc<AtomicUsize>,
}

impl DeliverySettlement for FailingAbandonSettlement {
    async fn settle(
        self,
        _decision: rss_transactional_messaging::transaction::SettlementDecision,
        _deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        Err(MessagingError::new(
            MessagingErrorKind::Invariant,
            std::io::Error::other("must not settle"),
        ))
    }

    async fn abandon(self, _deadline: OperationDeadline) -> Result<(), MessagingError> {
        self.abandoned.fetch_add(1, Ordering::SeqCst);
        Err(MessagingError::new(
            MessagingErrorKind::Transient,
            std::io::Error::other("cleanup failure"),
        ))
    }
}

impl DeliverySettlement for FakeSettlement {
    async fn settle(
        self,
        decision: rss_transactional_messaging::transaction::SettlementDecision,
        _deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        self.actions.lock().expect("lock").push(decision.kind());
        if self.fail {
            Err(MessagingError::new(
                MessagingErrorKind::Transient,
                std::io::Error::other("settlement unavailable"),
            ))
        } else {
            Ok(())
        }
    }

    async fn abandon(self, _deadline: OperationDeadline) -> Result<(), MessagingError> {
        self.abandoned.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct TrustedIngress;

impl rss_transactional_messaging::transaction::IngressValidator<Vec<u8>> for TrustedIngress {
    fn validate(
        &self,
        challenge: rss_transactional_messaging::transaction::IngressChallenge<'_, Vec<u8>>,
    ) -> Result<
        rss_transactional_messaging::transaction::VerifiedIngress,
        rss_transactional_messaging::transaction::EnvelopeValidationFailure,
    > {
        challenge
            .subscription()
            .accepts(challenge.message())
            .then(|| challenge.verified())
            .ok_or(rss_transactional_messaging::transaction::EnvelopeValidationFailure::UnsupportedContract)
    }
}

fn subscription(
    message: &MessageEnvelope<Vec<u8>>,
) -> rss_transactional_messaging::message::SubscriptionIdentity {
    rss_transactional_messaging::message::SubscriptionIdentity::new(
        message.metadata().domain().clone(),
        message.metadata().route().clone(),
        message.metadata().contract().clone(),
    )
}

fn consumer_identity(group: ConsumerGroup, message: &MessageEnvelope<Vec<u8>>) -> ConsumerIdentity {
    ConsumerIdentity::new(
        message.metadata().tenant_id(),
        group,
        message.id().clone(),
        message.metadata().contract().clone(),
    )
}

#[tokio::test]
async fn duplicate_returns_original_terminal_receipt_without_handler_call() {
    let message = envelope(|_| {});
    let group = ConsumerGroup::parse("orders-projection").expect("group");
    let receipt = TerminalReceipt::from_durable(
        consumer_identity(group.clone(), &message),
        MessageFingerprint::of(&message),
        TerminalDisposition::Succeeded,
    );
    let inbox = FakeInbox {
        disposition: Mutex::new(Some(IdempotencyDisposition::Terminal(receipt))),
        lease: LeaseStatus::Held {
            remaining: Duration::from_secs(30),
        },
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let transaction = FakeTx {
        calls: Arc::clone(&calls),
        disposition: TerminalDisposition::Succeeded,
    };
    let actions = Arc::new(Mutex::new(Vec::new()));
    let expected = subscription(&message);
    let delivery = Delivery::new(
        message,
        FakeSettlement {
            actions: Arc::clone(&actions),
            fail: false,
            abandoned: Arc::new(AtomicUsize::new(0)),
        },
    );

    let outcome = consume_once(
        &inbox,
        &transaction,
        &ConsumerExecution::new(
            group,
            &TrustedIngress,
            &expected,
            &FixedClock(MonotonicInstant::from_elapsed(Duration::ZERO)),
            consumer_policy(),
            &NoopEmitter,
        ),
        delivery,
    )
    .await;

    assert_eq!(
        outcome.expect("duplicate settles"),
        ProcessingDisposition::Duplicate(TerminalDisposition::Succeeded)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        *actions.lock().expect("lock"),
        [SettlementKind::Acknowledge]
    );
}

#[tokio::test]
async fn duplicate_authored_drift_rejects_without_handler_call() {
    let message = envelope(|_| {});
    let group = ConsumerGroup::parse("orders-projection").expect("group");
    let receipt = TerminalReceipt::from_durable(
        consumer_identity(group.clone(), &message),
        fingerprint(|fixture| fixture.payload = b"different".to_vec()),
        TerminalDisposition::Succeeded,
    );
    let inbox = FakeInbox {
        disposition: Mutex::new(Some(IdempotencyDisposition::Terminal(receipt))),
        lease: LeaseStatus::Held {
            remaining: Duration::from_secs(30),
        },
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let transaction = FakeTx {
        calls: Arc::clone(&calls),
        disposition: TerminalDisposition::Succeeded,
    };
    let expected = subscription(&message);
    let actions = Arc::new(Mutex::new(Vec::new()));
    let observations = Arc::new(Mutex::new(Vec::new()));
    let emitter = RecordingEmitter(Arc::clone(&observations));

    let outcome = consume_once(
        &inbox,
        &transaction,
        &ConsumerExecution::new(
            group,
            &TrustedIngress,
            &expected,
            &FixedClock(MonotonicInstant::from_elapsed(Duration::ZERO)),
            consumer_policy(),
            &emitter,
        ),
        Delivery::new(
            message,
            FakeSettlement {
                actions: Arc::clone(&actions),
                fail: false,
                abandoned: Arc::new(AtomicUsize::new(0)),
            },
        ),
    )
    .await
    .expect("conflict settles");

    assert!(observations.lock().expect("observations").contains(
        &TransactionalMessagingObservation::ConsumerIngressRejected {
            reason: rss_transactional_messaging::transaction::EnvelopeValidationFailure::FingerprintConflict,
        }
    ));

    assert_eq!(
        outcome,
        ProcessingDisposition::Rejected(
            rss_transactional_messaging::transaction::EnvelopeValidationFailure::FingerprintConflict
        )
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(*actions.lock().expect("lock"), [SettlementKind::Reject]);
}

#[tokio::test]
async fn stale_claim_abandons_without_effect_or_broker_settlement() {
    let message = envelope(|_| {});
    let group = ConsumerGroup::parse("orders-projection").expect("group");
    let inbox = FakeInbox {
        disposition: Mutex::new(Some(IdempotencyDisposition::Acquired(Claim))),
        lease: LeaseStatus::Lost,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let transaction = FakeTx {
        calls: Arc::clone(&calls),
        disposition: TerminalDisposition::Succeeded,
    };
    let expected = subscription(&message);
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));

    let outcome = consume_once(
        &inbox,
        &transaction,
        &ConsumerExecution::new(
            group,
            &TrustedIngress,
            &expected,
            &FixedClock(MonotonicInstant::from_elapsed(Duration::ZERO)),
            consumer_policy(),
            &NoopEmitter,
        ),
        Delivery::new(
            message,
            FakeSettlement {
                actions: Arc::clone(&actions),
                fail: false,
                abandoned: Arc::clone(&abandoned),
            },
        ),
    )
    .await
    .expect("fenced delivery abandons");

    assert_eq!(outcome, ProcessingDisposition::Fenced);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(actions.lock().expect("lock").is_empty());
    assert_eq!(abandoned.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn lease_check_failure_abandons_without_effect_or_broker_settlement() {
    let message = envelope(|_| {});
    let group = ConsumerGroup::parse("orders-projection").expect("group");
    let calls = Arc::new(AtomicUsize::new(0));
    let transaction = FakeTx {
        calls: Arc::clone(&calls),
        disposition: TerminalDisposition::Succeeded,
    };
    let expected = subscription(&message);
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));

    let outcome = consume_once(
        &ExtendErrorInbox,
        &transaction,
        &ConsumerExecution::new(
            group,
            &TrustedIngress,
            &expected,
            &FixedClock(MonotonicInstant::from_elapsed(Duration::ZERO)),
            consumer_policy(),
            &NoopEmitter,
        ),
        Delivery::new(
            message,
            FakeSettlement {
                actions: Arc::clone(&actions),
                fail: false,
                abandoned: Arc::clone(&abandoned),
            },
        ),
    )
    .await;

    assert!(outcome.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(actions.lock().expect("lock").is_empty());
    assert_eq!(abandoned.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn provider_lease_shorter_than_the_renewal_schedule_is_a_hard_fence() {
    let message = envelope(|_| {});
    let expected = subscription(&message);
    let calls = Arc::new(AtomicUsize::new(0));
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let error = consume_once(
        &FakeInbox {
            disposition: Mutex::new(Some(IdempotencyDisposition::Acquired(Claim))),
            lease: LeaseStatus::Held {
                remaining: Duration::from_secs(1),
            },
        },
        &FakeTx {
            calls: Arc::clone(&calls),
            disposition: TerminalDisposition::Succeeded,
        },
        &ConsumerExecution::new(
            ConsumerGroup::parse("authoritative-short-lease").expect("group"),
            &TrustedIngress,
            &expected,
            &FixedClock(MonotonicInstant::from_elapsed(Duration::ZERO)),
            consumer_policy(),
            &NoopEmitter,
        ),
        Delivery::new(
            message,
            FakeSettlement {
                actions: Arc::clone(&actions),
                fail: false,
                abandoned: Arc::clone(&abandoned),
            },
        ),
    )
    .await
    .expect_err("provider evidence must fence an unsafe renewal schedule");

    assert_eq!(error.kind(), MessagingErrorKind::Invariant);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(actions.lock().expect("actions").is_empty());
    assert_eq!(abandoned.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cleanup_failure_does_not_replace_the_primary_claim_error() {
    let message = envelope(|_| {});
    let expected = subscription(&message);
    let abandoned = Arc::new(AtomicUsize::new(0));
    let observations = Arc::new(Mutex::new(Vec::new()));
    let emitter = RecordingEmitter(Arc::clone(&observations));
    let error = consume_once(
        &ClaimErrorInbox,
        &FakeTx {
            calls: Arc::new(AtomicUsize::new(0)),
            disposition: TerminalDisposition::Succeeded,
        },
        &ConsumerExecution::new(
            ConsumerGroup::parse("primary-error").expect("group"),
            &TrustedIngress,
            &expected,
            &FixedClock(MonotonicInstant::from_elapsed(Duration::ZERO)),
            consumer_policy(),
            &emitter,
        ),
        Delivery::new(
            message,
            FailingAbandonSettlement {
                abandoned: Arc::clone(&abandoned),
            },
        ),
    )
    .await
    .expect_err("claim remains primary");

    assert_eq!(error.kind(), MessagingErrorKind::Invariant);
    assert_eq!(abandoned.load(Ordering::SeqCst), 1);
    assert!(observations.lock().expect("observations").contains(
        &TransactionalMessagingObservation::RuntimeFailure {
            phase: TransactionalMessagingRuntimePhase::ConsumerClaim,
            kind: MessagingErrorKind::Invariant,
        }
    ));
    assert!(observations.lock().expect("observations").contains(
        &TransactionalMessagingObservation::RuntimeFailure {
            phase: TransactionalMessagingRuntimePhase::ConsumerAbandon,
            kind: MessagingErrorKind::Transient,
        }
    ));
}

#[tokio::test]
async fn deadline_overflow_emits_a_closed_failure_phase() {
    let message = envelope(|_| {});
    let expected = subscription(&message);
    let observations = Arc::new(Mutex::new(Vec::new()));
    let emitter = RecordingEmitter(Arc::clone(&observations));
    let error = consume_once(
        &ClaimErrorInbox,
        &FakeTx {
            calls: Arc::new(AtomicUsize::new(0)),
            disposition: TerminalDisposition::Succeeded,
        },
        &ConsumerExecution::new(
            ConsumerGroup::parse("deadline-overflow").expect("group"),
            &TrustedIngress,
            &expected,
            &FixedClock(MonotonicInstant::from_elapsed(Duration::MAX)),
            consumer_policy(),
            &emitter,
        ),
        Delivery::new(
            message,
            FakeSettlement {
                actions: Arc::new(Mutex::new(Vec::new())),
                fail: false,
                abandoned: Arc::new(AtomicUsize::new(0)),
            },
        ),
    )
    .await
    .expect_err("deadline must overflow");

    assert_eq!(error.kind(), MessagingErrorKind::Invariant);
    assert!(observations.lock().expect("observations").contains(
        &TransactionalMessagingObservation::RuntimeFailure {
            phase: TransactionalMessagingRuntimePhase::ConsumerDeadline,
            kind: MessagingErrorKind::Invariant,
        }
    ));
}

#[tokio::test]
async fn only_confirmed_transient_rollback_retries_locally() {
    let message = envelope(|_| {});
    let group = ConsumerGroup::parse("orders-projection").expect("group");
    let inbox = FakeInbox {
        disposition: Mutex::new(Some(IdempotencyDisposition::Acquired(Claim))),
        lease: LeaseStatus::Held {
            remaining: Duration::from_secs(30),
        },
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let transaction = RetryThenCommitTx {
        calls: Arc::clone(&calls),
    };
    let expected = subscription(&message);
    let actions = Arc::new(Mutex::new(Vec::new()));
    let timer = Arc::new(ManualTimer::new());
    let task = tokio::spawn({
        let timer = Arc::clone(&timer);
        let actions = Arc::clone(&actions);
        async move {
            consume_once(
                &inbox,
                &transaction,
                &ConsumerExecution::new(
                    group,
                    &TrustedIngress,
                    &expected,
                    timer.as_ref(),
                    consumer_policy(),
                    &NoopEmitter,
                ),
                Delivery::new(
                    message,
                    FakeSettlement {
                        actions,
                        fail: false,
                        abandoned: Arc::new(AtomicUsize::new(0)),
                    },
                ),
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        support::wait_for_count(calls.as_ref(), 1).await;
        timer.wait_registered(Duration::from_secs(1)).await;
    })
    .await
    .expect("retry backoff starts");
    timer.advance(Duration::from_secs(1));
    let outcome = task.await.expect("consumer task").expect("retry commits");

    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        outcome,
        ProcessingDisposition::Committed(TerminalDisposition::Succeeded)
    );
    assert_eq!(
        *actions.lock().expect("lock"),
        [SettlementKind::Acknowledge]
    );
}

#[tokio::test]
async fn rejected_effect_commits_receipt_before_reject_settlement() {
    let group = ConsumerGroup::parse("orders-projection").expect("group");
    let inbox = FakeInbox {
        disposition: Mutex::new(Some(IdempotencyDisposition::Acquired(Claim))),
        lease: LeaseStatus::Held {
            remaining: Duration::from_secs(30),
        },
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let transaction = FakeTx {
        calls: Arc::clone(&calls),
        disposition: TerminalDisposition::Rejected(RejectKind::Permanent),
    };
    let actions = Arc::new(Mutex::new(Vec::new()));

    let message = envelope(|_| {});
    let expected = subscription(&message);
    let outcome = consume_once(
        &inbox,
        &transaction,
        &ConsumerExecution::new(
            group,
            &TrustedIngress,
            &expected,
            &FixedClock(MonotonicInstant::from_elapsed(Duration::ZERO)),
            consumer_policy(),
            &NoopEmitter,
        ),
        Delivery::new(
            message,
            FakeSettlement {
                actions: Arc::clone(&actions),
                fail: false,
                abandoned: Arc::new(AtomicUsize::new(0)),
            },
        ),
    )
    .await
    .expect("settled");

    assert_eq!(
        outcome,
        ProcessingDisposition::Committed(TerminalDisposition::Rejected(RejectKind::Permanent))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(*actions.lock().expect("lock"), [SettlementKind::Reject]);
}

#[tokio::test]
async fn settlement_io_failure_does_not_reexecute_or_change_durable_outcome() {
    let group = ConsumerGroup::parse("orders-projection").expect("group");
    let inbox = FakeInbox {
        disposition: Mutex::new(Some(IdempotencyDisposition::Acquired(Claim))),
        lease: LeaseStatus::Held {
            remaining: Duration::from_secs(30),
        },
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let transaction = FakeTx {
        calls: Arc::clone(&calls),
        disposition: TerminalDisposition::Succeeded,
    };
    let actions = Arc::new(Mutex::new(Vec::new()));

    let message = envelope(|_| {});
    let expected = subscription(&message);
    let outcome = consume_once(
        &inbox,
        &transaction,
        &ConsumerExecution::new(
            group,
            &TrustedIngress,
            &expected,
            &FixedClock(MonotonicInstant::from_elapsed(Duration::ZERO)),
            consumer_policy(),
            &NoopEmitter,
        ),
        Delivery::new(
            message,
            FakeSettlement {
                actions: Arc::clone(&actions),
                fail: true,
                abandoned: Arc::new(AtomicUsize::new(0)),
            },
        ),
    )
    .await;

    assert!(outcome.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *actions.lock().expect("lock"),
        [SettlementKind::Acknowledge]
    );
}

#[derive(Clone, Copy)]
enum MatrixOutcome {
    HandlerTransient,
    Permanent,
    Infrastructure,
    RollbackFailed,
    CommitUnknown,
    Fenced,
}

struct MatrixTx {
    outcome: MatrixOutcome,
    calls: Arc<AtomicUsize>,
}

impl ConsumerTx<Vec<u8>> for MatrixTx {
    type Claim = Claim;
    type CommitProof = Proof;

    async fn execute(
        &self,
        _claim: &Self::Claim,
        _message: &MessageEnvelope<Vec<u8>>,
        _receipt: rss_transactional_messaging::transaction::ReceiptIntent,
        _deadline: OperationDeadline,
    ) -> TransactionOutcome<Self::CommitProof> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.outcome {
            MatrixOutcome::HandlerTransient => {
                TransactionOutcome::rolled_back(FailureClass::Transient)
            }
            MatrixOutcome::Permanent => TransactionOutcome::not_started(FailureClass::Permanent),
            MatrixOutcome::Infrastructure => {
                TransactionOutcome::not_started(FailureClass::Infrastructure)
            }
            MatrixOutcome::RollbackFailed => TransactionOutcome::rollback_failed(),
            MatrixOutcome::CommitUnknown => TransactionOutcome::commit_unknown(),
            MatrixOutcome::Fenced => TransactionOutcome::fenced(),
        }
    }
}

struct RecordingEmitter(Arc<Mutex<Vec<TransactionalMessagingObservation>>>);

impl TransactionalMessagingEmitter for RecordingEmitter {
    fn emit(&self, observation: TransactionalMessagingObservation) {
        self.0.lock().expect("observation lock").push(observation);
    }
}

#[tokio::test]
async fn consume_once_fault_matrix_is_bounded_and_never_acks_uncertain_outcomes() {
    use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus;

    let cases = [
        (
            MatrixOutcome::HandlerTransient,
            3,
            TransactionalMessagingTransactionStatus::HandlerTransient,
            0,
            vec![SettlementKind::Requeue],
        ),
        (
            MatrixOutcome::Permanent,
            1,
            TransactionalMessagingTransactionStatus::RejectedPermanent,
            0,
            vec![SettlementKind::Requeue],
        ),
        (
            MatrixOutcome::Infrastructure,
            1,
            TransactionalMessagingTransactionStatus::InfrastructureTransient,
            0,
            vec![SettlementKind::Requeue],
        ),
        (
            MatrixOutcome::RollbackFailed,
            1,
            TransactionalMessagingTransactionStatus::RollbackFailed,
            1,
            vec![],
        ),
        (
            MatrixOutcome::CommitUnknown,
            1,
            TransactionalMessagingTransactionStatus::CommitUnknown,
            1,
            vec![],
        ),
        (
            MatrixOutcome::Fenced,
            1,
            TransactionalMessagingTransactionStatus::Fenced,
            1,
            vec![],
        ),
    ];

    for (kind, expected_calls, expected_status, expected_abandon, expected_actions) in cases {
        let inbox = FakeInbox {
            disposition: Mutex::new(Some(IdempotencyDisposition::Acquired(Claim))),
            lease: LeaseStatus::Held {
                remaining: Duration::from_secs(30),
            },
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let actions = Arc::new(Mutex::new(Vec::new()));
        let abandoned = Arc::new(AtomicUsize::new(0));
        let observations = Arc::new(Mutex::new(Vec::new()));
        let timer = Arc::new(ManualTimer::new());
        let message = envelope(|_| {});
        let expected = subscription(&message);
        let task = tokio::spawn({
            let calls = Arc::clone(&calls);
            let actions = Arc::clone(&actions);
            let abandoned = Arc::clone(&abandoned);
            let observations = Arc::clone(&observations);
            let timer = Arc::clone(&timer);
            async move {
                consume_once(
                    &inbox,
                    &MatrixTx {
                        outcome: kind,
                        calls,
                    },
                    &ConsumerExecution::new(
                        ConsumerGroup::parse("matrix").expect("group"),
                        &TrustedIngress,
                        &expected,
                        timer.as_ref(),
                        consumer_policy(),
                        &RecordingEmitter(observations),
                    ),
                    Delivery::new(
                        message,
                        FakeSettlement {
                            actions,
                            fail: false,
                            abandoned,
                        },
                    ),
                )
                .await
            }
        });
        if matches!(kind, MatrixOutcome::HandlerTransient) {
            tokio::time::timeout(Duration::from_secs(1), async {
                support::wait_for_count(calls.as_ref(), 1).await;
                timer.wait_registered(Duration::from_secs(1)).await;
            })
            .await
            .expect("first backoff");
            timer.advance(Duration::from_secs(1));
            tokio::time::timeout(Duration::from_secs(1), async {
                support::wait_for_count(calls.as_ref(), 2).await;
                timer.wait_registered(Duration::from_secs(3)).await;
            })
            .await
            .expect("second backoff");
            timer.advance(Duration::from_secs(2));
        }
        task.await.expect("consumer task").expect("matrix outcome");
        assert_eq!(calls.load(Ordering::SeqCst), expected_calls);
        assert_eq!(abandoned.load(Ordering::SeqCst), expected_abandon);
        assert_eq!(*actions.lock().expect("actions"), expected_actions);
        assert!(
            observations
                .lock()
                .expect("observations")
                .iter()
                .any(|entry| {
                    matches!(
                        entry,
                        TransactionalMessagingObservation::ConsumerTransaction { status }
                            if *status == expected_status
                    )
                })
        );
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PendingInboxStage {
    None,
    Claim,
    Extend,
    Renewal,
    Release,
}

struct PendingInbox {
    stage: PendingInboxStage,
    started: Arc<AtomicUsize>,
}

impl InboxStore for PendingInbox {
    type Claim = Claim;

    async fn claim(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        if self.stage == PendingInboxStage::Claim {
            self.started.fetch_add(1, Ordering::SeqCst);
            return std::future::pending().await;
        }
        Ok(IdempotencyDisposition::Acquired(Claim))
    }

    async fn read_terminal(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<Option<TerminalReceipt>, MessagingError> {
        Ok(None)
    }

    async fn extend(
        &self,
        _claim: &Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<LeaseStatus, MessagingError> {
        if self.stage == PendingInboxStage::Extend {
            self.started.fetch_add(1, Ordering::SeqCst);
            return std::future::pending().await;
        }
        if self.stage == PendingInboxStage::Renewal {
            let call = self.started.fetch_add(1, Ordering::SeqCst);
            if call > 0 {
                return std::future::pending().await;
            }
        }
        Ok(LeaseStatus::Held {
            remaining: Duration::from_secs(30),
        })
    }

    async fn release(
        &self,
        _claim: Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        if self.stage == PendingInboxStage::Release {
            self.started.fetch_add(1, Ordering::SeqCst);
            return std::future::pending().await;
        }
        Ok(())
    }
}

struct NeverReadyTx(Arc<AtomicUsize>);

impl ConsumerTx<Vec<u8>> for NeverReadyTx {
    type Claim = Claim;
    type CommitProof = Proof;

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

struct PendingSettlement {
    actions: Arc<Mutex<Vec<SettlementKind>>>,
    settle_started: Arc<AtomicUsize>,
    abandon_started: Arc<AtomicUsize>,
}

impl DeliverySettlement for PendingSettlement {
    async fn settle(
        self,
        decision: rss_transactional_messaging::transaction::SettlementDecision,
        _deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        self.actions.lock().expect("actions").push(decision.kind());
        self.settle_started.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }

    async fn abandon(self, _deadline: OperationDeadline) -> Result<(), MessagingError> {
        self.abandon_started.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }
}

fn deadline_policy(total: Duration, reserve: Duration) -> ConsumerExecutionPolicy {
    ConsumerExecutionPolicy::new(
        RetryPolicy::STANDARD,
        ExecutionBudget::new(total, reserve).expect("execution budget"),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30)).expect("lease policy"),
    )
}

#[tokio::test]
async fn never_ready_claim_and_extend_stop_before_handler_and_ack() {
    for stage in [PendingInboxStage::Claim, PendingInboxStage::Extend] {
        let timer = Arc::new(ManualTimer::new());
        let started = Arc::new(AtomicUsize::new(0));
        let tx_calls = Arc::new(AtomicUsize::new(0));
        let actions = Arc::new(Mutex::new(Vec::new()));
        let abandoned = Arc::new(AtomicUsize::new(0));
        let message = envelope(|_| {});
        let expected = subscription(&message);
        let task = tokio::spawn({
            let timer = Arc::clone(&timer);
            let started = Arc::clone(&started);
            let tx_calls = Arc::clone(&tx_calls);
            let actions = Arc::clone(&actions);
            let abandoned = Arc::clone(&abandoned);
            async move {
                consume_once(
                    &PendingInbox { stage, started },
                    &NeverReadyTx(tx_calls),
                    &ConsumerExecution::new(
                        ConsumerGroup::parse("deadline-stage").expect("group"),
                        &TrustedIngress,
                        &expected,
                        timer.as_ref(),
                        deadline_policy(Duration::from_millis(100), Duration::from_millis(20)),
                        &NoopEmitter,
                    ),
                    Delivery::new(
                        message,
                        FakeSettlement {
                            actions,
                            fail: false,
                            abandoned,
                        },
                    ),
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            support::wait_for_count(started.as_ref(), 1).await;
            timer.wait_registered(Duration::from_millis(80)).await;
        })
        .await
        .expect("provider stage starts");
        timer.advance(Duration::from_millis(80));

        let error = task
            .await
            .expect("consumer task")
            .expect_err("deadline elapsed");
        assert_eq!(error.kind(), MessagingErrorKind::DeadlineElapsed);
        assert_eq!(tx_calls.load(Ordering::SeqCst), 0);
        assert!(actions.lock().expect("actions").is_empty());
        assert_eq!(abandoned.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn never_ready_execute_maps_to_commit_unknown_and_uses_settlement_reserve() {
    let timer = Arc::new(ManualTimer::new());
    let tx_calls = Arc::new(AtomicUsize::new(0));
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let observations = Arc::new(Mutex::new(Vec::new()));
    let message = envelope(|_| {});
    let expected = subscription(&message);
    let task = tokio::spawn({
        let timer = Arc::clone(&timer);
        let tx_calls = Arc::clone(&tx_calls);
        let actions = Arc::clone(&actions);
        let abandoned = Arc::clone(&abandoned);
        let observations = Arc::clone(&observations);
        async move {
            consume_once(
                &PendingInbox {
                    stage: PendingInboxStage::None,
                    started: Arc::new(AtomicUsize::new(0)),
                },
                &NeverReadyTx(tx_calls),
                &ConsumerExecution::new(
                    ConsumerGroup::parse("execute-deadline").expect("group"),
                    &TrustedIngress,
                    &expected,
                    timer.as_ref(),
                    deadline_policy(Duration::from_millis(100), Duration::from_millis(20)),
                    &RecordingEmitter(observations),
                ),
                Delivery::new(
                    message,
                    FakeSettlement {
                        actions,
                        fail: false,
                        abandoned,
                    },
                ),
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        support::wait_for_count(tx_calls.as_ref(), 1).await;
        timer.wait_registered(Duration::from_millis(80)).await;
    })
    .await
    .expect("transaction starts");
    timer.advance(Duration::from_millis(80));

    assert_eq!(
        task.await.expect("consumer task").expect("deferred"),
        ProcessingDisposition::Deferred
    );
    assert!(actions.lock().expect("actions").is_empty());
    assert_eq!(abandoned.load(Ordering::SeqCst), 1);
    assert!(observations.lock().expect("observations").iter().any(|entry| {
        matches!(
            entry,
            TransactionalMessagingObservation::ConsumerTransaction {
                status: rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::CommitUnknown
            }
        )
    }));
    assert!(observations.lock().expect("observations").contains(
        &TransactionalMessagingObservation::RuntimeFailure {
            phase: TransactionalMessagingRuntimePhase::ConsumerTransaction,
            kind: MessagingErrorKind::DeadlineElapsed,
        }
    ));
}

#[tokio::test]
async fn never_ready_periodic_extend_fences_execute_at_the_operation_cutoff() {
    let timer = Arc::new(ManualTimer::new());
    let extend_calls = Arc::new(AtomicUsize::new(0));
    let tx_calls = Arc::new(AtomicUsize::new(0));
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let message = envelope(|_| {});
    let expected = subscription(&message);
    let task = tokio::spawn({
        let timer = Arc::clone(&timer);
        let extend_calls = Arc::clone(&extend_calls);
        let tx_calls = Arc::clone(&tx_calls);
        let actions = Arc::clone(&actions);
        let abandoned = Arc::clone(&abandoned);
        async move {
            consume_once(
                &PendingInbox {
                    stage: PendingInboxStage::Renewal,
                    started: extend_calls,
                },
                &NeverReadyTx(tx_calls),
                &ConsumerExecution::new(
                    ConsumerGroup::parse("renewal-deadline").expect("group"),
                    &TrustedIngress,
                    &expected,
                    timer.as_ref(),
                    renewing_consumer_policy(),
                    &NoopEmitter,
                ),
                Delivery::new(
                    message,
                    FakeSettlement {
                        actions,
                        fail: false,
                        abandoned,
                    },
                ),
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        support::wait_for_count(tx_calls.as_ref(), 1).await;
        timer.wait_registered(Duration::from_secs(10)).await;
    })
    .await
    .expect("transaction and renewal start");
    timer.advance(Duration::from_secs(10));
    tokio::time::timeout(Duration::from_secs(1), async {
        support::wait_for_count(extend_calls.as_ref(), 2).await;
    })
    .await
    .expect("periodic extend starts");
    timer.advance(Duration::from_secs(28));

    assert_eq!(
        task.await.expect("consumer task").expect("deferred"),
        ProcessingDisposition::Deferred
    );
    assert!(actions.lock().expect("actions").is_empty());
    assert_eq!(abandoned.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn never_ready_release_settle_and_abandon_are_bounded_without_second_action() {
    let cases = [PendingInboxStage::Release];
    for stage in cases {
        let timer = Arc::new(ManualTimer::new());
        let started = Arc::new(AtomicUsize::new(0));
        let actions = Arc::new(Mutex::new(Vec::new()));
        let abandoned = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let message = envelope(|_| {});
        let expected = subscription(&message);
        let task = tokio::spawn({
            let timer = Arc::clone(&timer);
            let started = Arc::clone(&started);
            let actions = Arc::clone(&actions);
            let abandoned = Arc::clone(&abandoned);
            let calls = Arc::clone(&calls);
            async move {
                consume_once(
                    &PendingInbox { stage, started },
                    &MatrixTx {
                        outcome: MatrixOutcome::Infrastructure,
                        calls,
                    },
                    &ConsumerExecution::new(
                        ConsumerGroup::parse("release-deadline").expect("group"),
                        &TrustedIngress,
                        &expected,
                        timer.as_ref(),
                        deadline_policy(Duration::from_millis(100), Duration::from_millis(20)),
                        &NoopEmitter,
                    ),
                    Delivery::new(
                        message,
                        FakeSettlement {
                            actions,
                            fail: false,
                            abandoned,
                        },
                    ),
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            support::wait_for_count(started.as_ref(), 1).await;
            timer.wait_registered(Duration::from_millis(100)).await;
        })
        .await
        .expect("release starts");
        timer.advance(Duration::from_millis(100));
        let error = task
            .await
            .expect("consumer task")
            .expect_err("release deadline");
        assert_eq!(error.kind(), MessagingErrorKind::DeadlineElapsed);
        assert!(actions.lock().expect("actions").is_empty());
        assert_eq!(abandoned.load(Ordering::SeqCst), 0);
    }

    for commit_unknown in [false, true] {
        let timer = Arc::new(ManualTimer::new());
        let actions = Arc::new(Mutex::new(Vec::new()));
        let settle_started = Arc::new(AtomicUsize::new(0));
        let abandon_started = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let message = envelope(|_| {});
        let expected = subscription(&message);
        let task = tokio::spawn({
            let timer = Arc::clone(&timer);
            let actions = Arc::clone(&actions);
            let settle_started = Arc::clone(&settle_started);
            let abandon_started = Arc::clone(&abandon_started);
            let calls = Arc::clone(&calls);
            async move {
                consume_once(
                    &PendingInbox {
                        stage: PendingInboxStage::None,
                        started: Arc::new(AtomicUsize::new(0)),
                    },
                    &MatrixTx {
                        outcome: if commit_unknown {
                            MatrixOutcome::CommitUnknown
                        } else {
                            MatrixOutcome::Permanent
                        },
                        calls,
                    },
                    &ConsumerExecution::new(
                        ConsumerGroup::parse("settlement-deadline").expect("group"),
                        &TrustedIngress,
                        &expected,
                        timer.as_ref(),
                        deadline_policy(Duration::from_millis(100), Duration::from_millis(20)),
                        &NoopEmitter,
                    ),
                    Delivery::new(
                        message,
                        PendingSettlement {
                            actions,
                            settle_started,
                            abandon_started,
                        },
                    ),
                )
                .await
            }
        });
        let active = if commit_unknown {
            Arc::clone(&abandon_started)
        } else {
            Arc::clone(&settle_started)
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            support::wait_for_count(active.as_ref(), 1).await;
            timer.wait_registered(Duration::from_millis(100)).await;
        })
        .await
        .expect("settlement action starts");
        timer.advance(Duration::from_millis(100));
        let error = task
            .await
            .expect("consumer task")
            .expect_err("settlement deadline");
        assert_eq!(error.kind(), MessagingErrorKind::DeadlineElapsed);
        assert_eq!(
            settle_started.load(Ordering::SeqCst),
            usize::from(!commit_unknown)
        );
        assert_eq!(
            abandon_started.load(Ordering::SeqCst),
            usize::from(commit_unknown)
        );
        let recorded = actions.lock().expect("actions");
        if commit_unknown {
            assert!(recorded.is_empty());
        } else {
            assert_eq!(recorded.as_slice(), &[SettlementKind::Requeue]);
        }
    }
}

#[tokio::test]
async fn duplicate_ack_timeout_attempts_exactly_one_settlement_without_handler() {
    let timer = Arc::new(ManualTimer::new());
    let actions = Arc::new(Mutex::new(Vec::new()));
    let settle_started = Arc::new(AtomicUsize::new(0));
    let abandon_started = Arc::new(AtomicUsize::new(0));
    let tx_calls = Arc::new(AtomicUsize::new(0));
    let message = envelope(|_| {});
    let group = ConsumerGroup::parse("duplicate-deadline").expect("group");
    let receipt = TerminalReceipt::from_durable(
        consumer_identity(group.clone(), &message),
        MessageFingerprint::of(&message),
        TerminalDisposition::Succeeded,
    );
    let expected = subscription(&message);
    let task = tokio::spawn({
        let timer = Arc::clone(&timer);
        let actions = Arc::clone(&actions);
        let settle_started = Arc::clone(&settle_started);
        let abandon_started = Arc::clone(&abandon_started);
        let tx_calls = Arc::clone(&tx_calls);
        async move {
            consume_once(
                &FakeInbox {
                    disposition: Mutex::new(Some(IdempotencyDisposition::Terminal(receipt))),
                    lease: LeaseStatus::Lost,
                },
                &FakeTx {
                    calls: tx_calls,
                    disposition: TerminalDisposition::Succeeded,
                },
                &ConsumerExecution::new(
                    group,
                    &TrustedIngress,
                    &expected,
                    timer.as_ref(),
                    deadline_policy(Duration::from_millis(100), Duration::from_millis(20)),
                    &NoopEmitter,
                ),
                Delivery::new(
                    message,
                    PendingSettlement {
                        actions,
                        settle_started,
                        abandon_started,
                    },
                ),
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        support::wait_for_count(settle_started.as_ref(), 1).await;
        timer.wait_registered(Duration::from_millis(100)).await;
    })
    .await
    .expect("duplicate ack starts");
    timer.advance(Duration::from_millis(100));
    let error = task
        .await
        .expect("consumer task")
        .expect_err("settlement deadline");

    assert_eq!(error.kind(), MessagingErrorKind::DeadlineElapsed);
    assert_eq!(tx_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        actions.lock().expect("actions").as_slice(),
        &[SettlementKind::Acknowledge]
    );
    assert_eq!(settle_started.load(Ordering::SeqCst), 1);
    assert_eq!(abandon_started.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn backoff_equal_to_operation_budget_does_not_start_another_attempt() {
    let calls = Arc::new(AtomicUsize::new(0));
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let message = envelope(|_| {});
    let expected = subscription(&message);

    let disposition = consume_once(
        &PendingInbox {
            stage: PendingInboxStage::None,
            started: Arc::new(AtomicUsize::new(0)),
        },
        &MatrixTx {
            outcome: MatrixOutcome::HandlerTransient,
            calls: Arc::clone(&calls),
        },
        &ConsumerExecution::new(
            ConsumerGroup::parse("backoff-cutoff").expect("group"),
            &TrustedIngress,
            &expected,
            &FixedClock(MonotonicInstant::from_elapsed(Duration::ZERO)),
            deadline_policy(Duration::from_millis(1_200), Duration::from_millis(200)),
            &NoopEmitter,
        ),
        Delivery::new(
            message,
            FakeSettlement {
                actions: Arc::clone(&actions),
                fail: false,
                abandoned: Arc::clone(&abandoned),
            },
        ),
    )
    .await
    .expect("deferred");

    assert_eq!(disposition, ProcessingDisposition::Deferred);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        actions.lock().expect("actions").as_slice(),
        &[SettlementKind::Requeue]
    );
    assert_eq!(abandoned.load(Ordering::SeqCst), 0);
}

struct RenewingInbox {
    claim: Mutex<Option<IdempotencyDisposition<Claim>>>,
    extends: AtomicUsize,
    lose_at: Option<usize>,
}

impl InboxStore for RenewingInbox {
    type Claim = Claim;

    async fn claim(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        self.claim
            .lock()
            .expect("claim lock")
            .take()
            .ok_or_else(|| {
                MessagingError::new(
                    MessagingErrorKind::Invariant,
                    std::io::Error::other("claim reused"),
                )
            })
    }

    async fn read_terminal(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<Option<TerminalReceipt>, MessagingError> {
        Ok(None)
    }

    async fn extend(
        &self,
        _claim: &Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<LeaseStatus, MessagingError> {
        let attempt = self.extends.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(if self.lose_at.is_some_and(|limit| attempt >= limit) {
            LeaseStatus::Lost
        } else {
            LeaseStatus::Held {
                remaining: Duration::from_secs(30),
            }
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

fn renewing_consumer_policy() -> ConsumerExecutionPolicy {
    ConsumerExecutionPolicy::new(
        RetryPolicy::STANDARD,
        ExecutionBudget::new(Duration::from_secs(40), Duration::from_secs(2))
            .expect("execution budget"),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30)).expect("lease policy"),
    )
}

struct BlockingCommitTx {
    started: Arc<AtomicUsize>,
    complete: Arc<tokio::sync::Notify>,
}

impl ConsumerTx<Vec<u8>> for BlockingCommitTx {
    type Claim = Claim;
    type CommitProof = Proof;

    async fn execute(
        &self,
        _claim: &Self::Claim,
        _message: &MessageEnvelope<Vec<u8>>,
        receipt: rss_transactional_messaging::transaction::ReceiptIntent,
        _deadline: OperationDeadline,
    ) -> TransactionOutcome<Self::CommitProof> {
        self.started.fetch_add(1, Ordering::SeqCst);
        self.complete.notified().await;
        receipt.committed(Proof, TerminalDisposition::Succeeded)
    }
}

#[tokio::test]
async fn long_handler_is_periodically_renewed_then_commits_before_ack() {
    let inbox = Arc::new(RenewingInbox {
        claim: Mutex::new(Some(IdempotencyDisposition::Acquired(Claim))),
        extends: AtomicUsize::new(0),
        lose_at: None,
    });
    let timer = Arc::new(ManualTimer::new());
    let started = Arc::new(AtomicUsize::new(0));
    let complete = Arc::new(tokio::sync::Notify::new());
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let message = envelope(|_| {});
    let expected = subscription(&message);

    let task = tokio::spawn({
        let inbox = Arc::clone(&inbox);
        let timer = Arc::clone(&timer);
        let started = Arc::clone(&started);
        let complete = Arc::clone(&complete);
        let actions = Arc::clone(&actions);
        let abandoned = Arc::clone(&abandoned);
        async move {
            consume_once(
                inbox.as_ref(),
                &BlockingCommitTx { started, complete },
                &ConsumerExecution::new(
                    ConsumerGroup::parse("renewing-consumer").expect("group"),
                    &TrustedIngress,
                    &expected,
                    timer.as_ref(),
                    renewing_consumer_policy(),
                    &NoopEmitter,
                ),
                Delivery::new(
                    message,
                    FakeSettlement {
                        actions,
                        fail: false,
                        abandoned,
                    },
                ),
            )
            .await
        }
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        while started.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("handler starts");
    assert_eq!(inbox.extends.load(Ordering::SeqCst), 1);

    for expected_extends in [2, 3] {
        let wake = Duration::from_secs(10 * (expected_extends - 1) as u64);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !timer.registered(wake) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("renewal sleep registers");
        timer.advance(Duration::from_secs(10));
        tokio::time::timeout(Duration::from_secs(1), async {
            while inbox.extends.load(Ordering::SeqCst) < expected_extends {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("periodic renewal");
    }
    complete.notify_one();

    assert_eq!(
        task.await.expect("consumer task").expect("consume once"),
        ProcessingDisposition::Committed(TerminalDisposition::Succeeded)
    );
    assert_eq!(
        *actions.lock().expect("actions"),
        [SettlementKind::Acknowledge]
    );
}

#[tokio::test]
async fn lease_lost_during_handler_cancels_effect_and_abandons_without_settlement() {
    let inbox = Arc::new(RenewingInbox {
        claim: Mutex::new(Some(IdempotencyDisposition::Acquired(Claim))),
        extends: AtomicUsize::new(0),
        lose_at: Some(2),
    });
    let timer = Arc::new(ManualTimer::new());
    let started = Arc::new(AtomicUsize::new(0));
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let message = envelope(|_| {});
    let expected = subscription(&message);
    let task = tokio::spawn({
        let inbox = Arc::clone(&inbox);
        let timer = Arc::clone(&timer);
        let started = Arc::clone(&started);
        let actions = Arc::clone(&actions);
        let abandoned = Arc::clone(&abandoned);
        async move {
            consume_once(
                inbox.as_ref(),
                &BlockingCommitTx {
                    started,
                    complete: Arc::new(tokio::sync::Notify::new()),
                },
                &ConsumerExecution::new(
                    ConsumerGroup::parse("fenced-consumer").expect("group"),
                    &TrustedIngress,
                    &expected,
                    timer.as_ref(),
                    renewing_consumer_policy(),
                    &NoopEmitter,
                ),
                Delivery::new(
                    message,
                    FakeSettlement {
                        actions,
                        fail: false,
                        abandoned,
                    },
                ),
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while started.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("handler starts");
    tokio::time::timeout(Duration::from_secs(1), async {
        while !timer.registered(Duration::from_secs(10)) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("renewal sleep registers");
    timer.advance(Duration::from_secs(10));

    assert_eq!(
        task.await.expect("consumer task").expect("fenced result"),
        ProcessingDisposition::Fenced
    );
    assert!(actions.lock().expect("actions").is_empty());
    assert_eq!(abandoned.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn lease_loss_wins_when_a_terminal_transaction_is_also_ready() {
    let inbox = Arc::new(RenewingInbox {
        claim: Mutex::new(Some(IdempotencyDisposition::Acquired(Claim))),
        extends: AtomicUsize::new(0),
        lose_at: Some(2),
    });
    let timer = Arc::new(ManualTimer::new());
    let started = Arc::new(AtomicUsize::new(0));
    let complete = Arc::new(tokio::sync::Notify::new());
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let message = envelope(|_| {});
    let expected = subscription(&message);

    let task = tokio::spawn({
        let inbox = Arc::clone(&inbox);
        let timer = Arc::clone(&timer);
        let started = Arc::clone(&started);
        let complete = Arc::clone(&complete);
        let actions = Arc::clone(&actions);
        let abandoned = Arc::clone(&abandoned);
        async move {
            consume_once(
                inbox.as_ref(),
                &BlockingCommitTx { started, complete },
                &ConsumerExecution::new(
                    ConsumerGroup::parse("simultaneous-fence").expect("group"),
                    &TrustedIngress,
                    &expected,
                    timer.as_ref(),
                    renewing_consumer_policy(),
                    &NoopEmitter,
                ),
                Delivery::new(
                    message,
                    FakeSettlement {
                        actions,
                        fail: false,
                        abandoned,
                    },
                ),
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while started.load(Ordering::SeqCst) == 0 || !timer.registered(Duration::from_secs(10)) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both branches pending");
    complete.notify_one();
    timer.advance(Duration::from_secs(10));
    let disposition = task.await.expect("consumer task").expect("fenced outcome");

    assert_eq!(disposition, ProcessingDisposition::Fenced);
    assert_eq!(started.load(Ordering::SeqCst), 1);
    assert!(actions.lock().expect("actions").is_empty());
    assert_eq!(abandoned.load(Ordering::SeqCst), 1);
}

struct RenewalErrorAfterInitialInbox {
    extends: AtomicUsize,
}

impl InboxStore for RenewalErrorAfterInitialInbox {
    type Claim = Claim;

    async fn claim(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        Ok(IdempotencyDisposition::Acquired(Claim))
    }

    async fn read_terminal(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<Option<TerminalReceipt>, MessagingError> {
        Ok(None)
    }

    async fn extend(
        &self,
        _claim: &Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<LeaseStatus, MessagingError> {
        if self.extends.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(LeaseStatus::Held {
                remaining: Duration::from_secs(30),
            })
        } else {
            Err(MessagingError::new(
                MessagingErrorKind::Transient,
                std::io::Error::other("renewal failed"),
            ))
        }
    }

    async fn release(
        &self,
        _claim: Self::Claim,
        _deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        Err(MessagingError::new(
            MessagingErrorKind::Invariant,
            std::io::Error::other("renewal failure must not release"),
        ))
    }
}

#[tokio::test]
async fn renewal_error_wins_when_a_terminal_transaction_is_also_ready() {
    let inbox = Arc::new(RenewalErrorAfterInitialInbox {
        extends: AtomicUsize::new(0),
    });
    let timer = Arc::new(ManualTimer::new());
    let started = Arc::new(AtomicUsize::new(0));
    let complete = Arc::new(tokio::sync::Notify::new());
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let message = envelope(|_| {});
    let expected = subscription(&message);

    let task = tokio::spawn({
        let inbox = Arc::clone(&inbox);
        let timer = Arc::clone(&timer);
        let started = Arc::clone(&started);
        let complete = Arc::clone(&complete);
        let actions = Arc::clone(&actions);
        let abandoned = Arc::clone(&abandoned);
        async move {
            consume_once(
                inbox.as_ref(),
                &BlockingCommitTx { started, complete },
                &ConsumerExecution::new(
                    ConsumerGroup::parse("simultaneous-renewal-error").expect("group"),
                    &TrustedIngress,
                    &expected,
                    timer.as_ref(),
                    renewing_consumer_policy(),
                    &NoopEmitter,
                ),
                Delivery::new(
                    message,
                    FakeSettlement {
                        actions,
                        fail: false,
                        abandoned,
                    },
                ),
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while started.load(Ordering::SeqCst) == 0 || !timer.registered(Duration::from_secs(10)) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both branches pending");
    complete.notify_one();
    timer.advance(Duration::from_secs(10));
    let error = task
        .await
        .expect("consumer task")
        .expect_err("renewal error must fence settlement");

    assert_eq!(error.kind(), MessagingErrorKind::Transient);
    assert_eq!(started.load(Ordering::SeqCst), 1);
    assert!(actions.lock().expect("actions").is_empty());
    assert_eq!(abandoned.load(Ordering::SeqCst), 1);
}

struct OneDeliverySource {
    delivery: Mutex<Option<IncomingDelivery<Vec<u8>, FakeSettlement>>>,
}

struct RedeliverySource {
    deliveries: Mutex<VecDeque<IncomingDelivery<Vec<u8>, FakeSettlement>>>,
    subscriptions: AtomicUsize,
}

impl DeliverySource<Vec<u8>> for RedeliverySource {
    type Settlement = FakeSettlement;
    type Deliveries =
        futures::stream::Iter<std::vec::IntoIter<IncomingDelivery<Vec<u8>, Self::Settlement>>>;

    async fn deliveries(
        &self,
        _subscription: &rss_transactional_messaging::message::SubscriptionIdentity,
    ) -> Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError> {
        self.subscriptions.fetch_add(1, Ordering::SeqCst);
        let delivery = self.deliveries.lock().expect("deliveries").pop_front();
        Ok(ManagedDeliveryStream::from_provider(futures::stream::iter(
            delivery.into_iter().collect::<Vec<_>>(),
        )))
    }
}

struct TransientThenAcquiredInbox(AtomicUsize);

impl InboxStore for TransientThenAcquiredInbox {
    type Claim = Claim;

    async fn claim(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(MessagingError::new(
                MessagingErrorKind::Transient,
                std::io::Error::other("replace provider session"),
            ))
        } else {
            Ok(IdempotencyDisposition::Acquired(Claim))
        }
    }

    async fn read_terminal(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<Option<TerminalReceipt>, MessagingError> {
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

impl DeliverySource<Vec<u8>> for OneDeliverySource {
    type Settlement = FakeSettlement;
    type Deliveries =
        futures::stream::Iter<std::vec::IntoIter<IncomingDelivery<Vec<u8>, Self::Settlement>>>;

    async fn deliveries(
        &self,
        _subscription: &rss_transactional_messaging::message::SubscriptionIdentity,
    ) -> Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError> {
        let delivery = self.delivery.lock().expect("delivery lock").take();
        Ok(ManagedDeliveryStream::from_provider(futures::stream::iter(
            delivery.into_iter().collect::<Vec<_>>(),
        )))
    }
}

struct BlockingClaimInbox {
    started: Arc<AtomicUsize>,
    gate: Arc<tokio::sync::Notify>,
}

#[tokio::test]
async fn transient_delivery_failure_replaces_stream_and_resubscribes() {
    let first = envelope(|_| {});
    let expected = subscription(&first);
    let second = envelope(|_| {});
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let settlement = || FakeSettlement {
        actions: Arc::clone(&actions),
        fail: false,
        abandoned: Arc::clone(&abandoned),
    };
    let source = Arc::new(RedeliverySource {
        deliveries: Mutex::new(VecDeque::from([
            IncomingDelivery::Valid(Box::new(Delivery::new(first, settlement()))),
            IncomingDelivery::Valid(Box::new(Delivery::new(second, settlement()))),
        ])),
        subscriptions: AtomicUsize::new(0),
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let worker = ConsumerWorker::new(
        Arc::clone(&source),
        Arc::new(TransientThenAcquiredInbox(AtomicUsize::new(0))),
        Arc::new(FakeTx {
            calls: Arc::clone(&calls),
            disposition: TerminalDisposition::Succeeded,
        }),
        ConsumerGroup::parse("transient-redelivery").expect("group"),
        Arc::new(TrustedIngress),
        expected,
        Arc::new(RealtimeClock::new()),
        consumer_policy(),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::new(Duration::from_millis(1), Duration::from_millis(1))
            .expect("backoff"),
    );
    let (registration, status) = worker.into_registration(
        "transient-redelivery",
        rss_transactional_messaging::policy::ShutdownBudget::new(Duration::from_secs(1))
            .expect("budget"),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(2)).expect("total"),
    )
    .expect("stack");
    let mut startup = stack.startup().expect("startup");
    startup.stage_task_with_token(registration);
    startup.commit().finish();

    tokio::time::timeout(Duration::from_secs(1), async {
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("redelivery committed");

    assert!(source.subscriptions.load(Ordering::SeqCst) >= 2);
    assert_eq!(abandoned.load(Ordering::SeqCst), 1);
    assert_eq!(
        actions.lock().expect("actions").as_slice(),
        &[SettlementKind::Acknowledge]
    );
    assert!(stack.shutdown().await.expect("shutdown").is_clean());
    assert_eq!(
        status.wait_stopped().await,
        rss_runtime::TaskExit::Cancelled
    );
}

#[tokio::test]
async fn claim_deadline_replaces_stream_and_mints_a_fresh_delivery_budget() {
    let first = envelope(|_| {});
    let expected = subscription(&first);
    let second = envelope(|fixture| fixture.id = "message-2");
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let settlement = || FakeSettlement {
        actions: Arc::clone(&actions),
        fail: false,
        abandoned: Arc::clone(&abandoned),
    };
    let source = Arc::new(RedeliverySource {
        deliveries: Mutex::new(VecDeque::from([
            IncomingDelivery::Valid(Box::new(Delivery::new(first, settlement()))),
            IncomingDelivery::Valid(Box::new(Delivery::new(second, settlement()))),
        ])),
        subscriptions: AtomicUsize::new(0),
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let worker = ConsumerWorker::new(
        Arc::clone(&source),
        Arc::new(FakeInbox {
            disposition: Mutex::new(Some(IdempotencyDisposition::Acquired(Claim))),
            lease: LeaseStatus::Held {
                remaining: Duration::from_secs(30),
            },
        }),
        Arc::new(FakeTx {
            calls: Arc::clone(&calls),
            disposition: TerminalDisposition::Succeeded,
        }),
        ConsumerGroup::parse("deadline-redelivery").expect("group"),
        Arc::new(TrustedIngress),
        expected,
        Arc::new(ScriptedTimer::new([1, 3])),
        consumer_policy(),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::new(Duration::from_millis(1), Duration::from_millis(1))
            .expect("backoff"),
    );
    let (registration, status) = worker.into_registration(
        "deadline-redelivery",
        rss_transactional_messaging::policy::ShutdownBudget::new(Duration::from_secs(1))
            .expect("budget"),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(2)).expect("total"),
    )
    .expect("stack");
    let mut startup = stack.startup().expect("startup");
    startup.stage_task_with_token(registration);
    startup.commit().finish();

    tokio::time::timeout(Duration::from_secs(1), async {
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("redelivery committed under a fresh budget");

    assert!(source.subscriptions.load(Ordering::SeqCst) >= 2);
    assert_eq!(abandoned.load(Ordering::SeqCst), 1);
    assert_eq!(
        actions.lock().expect("actions").as_slice(),
        &[SettlementKind::Acknowledge]
    );
    assert!(stack.shutdown().await.expect("shutdown").is_clean());
    assert_eq!(
        status.wait_stopped().await,
        rss_runtime::TaskExit::Cancelled
    );
}

impl InboxStore for BlockingClaimInbox {
    type Claim = Claim;

    async fn claim(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        self.started.fetch_add(1, Ordering::SeqCst);
        self.gate.notified().await;
        Ok(IdempotencyDisposition::Acquired(Claim))
    }

    async fn read_terminal(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<Option<TerminalReceipt>, MessagingError> {
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

#[tokio::test]
async fn forced_shutdown_during_claim_drops_without_settlement_or_cleanup() {
    let message = envelope(|_| {});
    let expected = subscription(&message);
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let source = Arc::new(OneDeliverySource {
        delivery: Mutex::new(Some(IncomingDelivery::Valid(Box::new(Delivery::new(
            message,
            FakeSettlement {
                actions: Arc::clone(&actions),
                fail: false,
                abandoned: Arc::clone(&abandoned),
            },
        ))))),
    });
    let claim_started = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let worker = ConsumerWorker::new(
        source,
        Arc::new(BlockingClaimInbox {
            started: Arc::clone(&claim_started),
            gate: Arc::new(tokio::sync::Notify::new()),
        }),
        Arc::new(FakeTx {
            calls: Arc::clone(&calls),
            disposition: TerminalDisposition::Succeeded,
        }),
        ConsumerGroup::parse("claim-cancel").expect("group"),
        Arc::new(TrustedIngress),
        expected,
        Arc::new(FixedClock(MonotonicInstant::from_elapsed(Duration::ZERO))),
        consumer_policy(),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::STANDARD,
    );
    let (registration, _status) = worker.into_registration(
        "claim-cancel",
        rss_transactional_messaging::policy::ShutdownBudget::new(Duration::from_millis(20))
            .expect("budget"),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(1)).expect("total"),
    )
    .expect("stack");
    let mut startup = stack.startup().expect("startup");
    startup.stage_task_with_token(registration);
    startup.commit().finish();
    tokio::time::timeout(Duration::from_secs(1), async {
        while claim_started.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("claim starts");

    let receipt = stack.shutdown().await.expect("shutdown");
    assert!(matches!(
        receipt.failures()[0].kind,
        rss_runtime::ShutdownFailureKind::TimedOut(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(actions.lock().expect("actions").is_empty());
    assert_eq!(abandoned.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn provider_decoding_failure_uses_core_minted_reject() {
    let message = envelope(|_| {});
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let worker = ConsumerWorker::new(
        Arc::new(OneDeliverySource {
            delivery: Mutex::new(Some(IncomingDelivery::invalid_from_provider(
                rss_transactional_messaging::transaction::EnvelopeValidationFailure::MalformedMetadata,
                FakeSettlement {
                    actions: Arc::clone(&actions),
                    fail: false,
                    abandoned: Arc::clone(&abandoned),
                },
            ))),
        }),
        idle_inbox(),
        Arc::new(FakeTx {
            calls: Arc::clone(&calls),
            disposition: TerminalDisposition::Succeeded,
        }),
        ConsumerGroup::parse("invalid-provider-delivery").expect("group"),
        Arc::new(TrustedIngress),
        subscription(&message),
        Arc::new(ManualTimer::new()),
        consumer_policy(),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::STANDARD,
    );
    let (registration, status) = worker.into_registration(
        "invalid-provider-delivery",
        rss_transactional_messaging::policy::ShutdownBudget::new(Duration::from_secs(1))
            .expect("budget"),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(2)).expect("total"),
    )
    .expect("stack");
    let mut startup = stack.startup().expect("startup");
    startup.stage_task_with_token(registration);
    startup.commit().finish();
    tokio::time::timeout(Duration::from_secs(1), async {
        while actions.lock().expect("actions").is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("invalid delivery rejected");

    assert!(stack.shutdown().await.expect("shutdown").is_clean());
    assert_eq!(
        status.wait_stopped().await,
        rss_runtime::TaskExit::Cancelled
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        actions.lock().expect("actions").as_slice(),
        &[SettlementKind::Reject]
    );
    assert_eq!(abandoned.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn forced_worker_shutdown_drops_handler_without_settlement() {
    let message = envelope(|_| {});
    let expected = subscription(&message);
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let source = Arc::new(OneDeliverySource {
        delivery: Mutex::new(Some(IncomingDelivery::Valid(Box::new(Delivery::new(
            message,
            FakeSettlement {
                actions: Arc::clone(&actions),
                fail: false,
                abandoned: Arc::clone(&abandoned),
            },
        ))))),
    });
    let inbox = Arc::new(RenewingInbox {
        claim: Mutex::new(Some(IdempotencyDisposition::Acquired(Claim))),
        extends: AtomicUsize::new(0),
        lose_at: None,
    });
    let timer = Arc::new(ManualTimer::new());
    let started = Arc::new(AtomicUsize::new(0));
    let worker = ConsumerWorker::new(
        source,
        inbox,
        Arc::new(BlockingCommitTx {
            started: Arc::clone(&started),
            complete: Arc::new(tokio::sync::Notify::new()),
        }),
        ConsumerGroup::parse("shutdown-consumer").expect("group"),
        Arc::new(TrustedIngress),
        expected,
        timer,
        consumer_policy(),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::STANDARD,
    );
    let (registration, _status) = worker.into_registration(
        "consumer-shutdown",
        rss_transactional_messaging::policy::ShutdownBudget::new(Duration::from_millis(20))
            .expect("shutdown budget"),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(1)).expect("total budget"),
    )
    .expect("stack");
    let mut startup = stack.startup().expect("startup");
    startup.stage_task_with_token(registration);
    startup.commit().finish();
    tokio::time::timeout(Duration::from_secs(1), async {
        while started.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("handler starts");

    let receipt = stack.shutdown().await.expect("bounded shutdown");
    assert!(!receipt.is_clean());
    assert!(matches!(
        receipt.failures()[0].kind,
        rss_runtime::ShutdownFailureKind::TimedOut(_)
    ));
    assert!(actions.lock().expect("actions").is_empty());
    assert_eq!(abandoned.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn terminal_outcome_completing_during_cancellation_is_settled() {
    let message = envelope(|_| {});
    let expected = subscription(&message);
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let source = Arc::new(OneDeliverySource {
        delivery: Mutex::new(Some(IncomingDelivery::Valid(Box::new(Delivery::new(
            message,
            FakeSettlement {
                actions: Arc::clone(&actions),
                fail: false,
                abandoned: Arc::clone(&abandoned),
            },
        ))))),
    });
    let started = Arc::new(AtomicUsize::new(0));
    let complete = Arc::new(tokio::sync::Notify::new());
    let worker = ConsumerWorker::new(
        source,
        idle_inbox(),
        Arc::new(BlockingCommitTx {
            started: Arc::clone(&started),
            complete: Arc::clone(&complete),
        }),
        ConsumerGroup::parse("terminal-cancel").expect("group"),
        Arc::new(TrustedIngress),
        expected,
        Arc::new(ManualTimer::new()),
        consumer_policy(),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::STANDARD,
    );
    let (registration, status) = worker.into_registration(
        "terminal-cancel",
        rss_transactional_messaging::policy::ShutdownBudget::new(Duration::from_secs(1))
            .expect("budget"),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(2)).expect("total"),
    )
    .expect("stack");
    let mut startup = stack.startup().expect("startup");
    startup.stage_task_with_token(registration);
    startup.commit().finish();
    tokio::time::timeout(Duration::from_secs(1), async {
        while started.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("handler starts");

    let finish = async {
        tokio::task::yield_now().await;
        complete.notify_one();
    };
    let (receipt, ()) = tokio::join!(stack.shutdown(), finish);
    assert!(receipt.expect("shutdown").is_clean());
    assert_eq!(
        status.wait_stopped().await,
        rss_runtime::TaskExit::Cancelled
    );
    assert_eq!(
        *actions.lock().expect("actions"),
        [SettlementKind::Acknowledge]
    );
    assert_eq!(abandoned.load(Ordering::SeqCst), 0);
}

type BoxDeliveries =
    Pin<Box<dyn futures::Stream<Item = IncomingDelivery<Vec<u8>, FakeSettlement>> + Send>>;

struct BlockingSubscribeSource {
    started: Arc<AtomicUsize>,
    gate: Arc<tokio::sync::Notify>,
}

impl DeliverySource<Vec<u8>> for BlockingSubscribeSource {
    type Settlement = FakeSettlement;
    type Deliveries = BoxDeliveries;

    async fn deliveries(
        &self,
        _subscription: &rss_transactional_messaging::message::SubscriptionIdentity,
    ) -> Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError> {
        self.started.fetch_add(1, Ordering::SeqCst);
        self.gate.notified().await;
        Ok(ManagedDeliveryStream::from_provider(Box::pin(
            futures::stream::empty(),
        )))
    }
}

struct GatedDeliverySource {
    subscribed: Arc<AtomicUsize>,
    gate: Arc<tokio::sync::Notify>,
    delivery: Mutex<Option<IncomingDelivery<Vec<u8>, FakeSettlement>>>,
}

impl DeliverySource<Vec<u8>> for GatedDeliverySource {
    type Settlement = FakeSettlement;
    type Deliveries = BoxDeliveries;

    async fn deliveries(
        &self,
        _subscription: &rss_transactional_messaging::message::SubscriptionIdentity,
    ) -> Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError> {
        self.subscribed.fetch_add(1, Ordering::SeqCst);
        let gate = Arc::clone(&self.gate);
        let delivery = self.delivery.lock().expect("delivery").take();
        Ok(ManagedDeliveryStream::from_provider(Box::pin(
            futures::stream::once(async move {
                gate.notified().await;
                delivery.expect("one delivery")
            }),
        )))
    }
}

struct FailingSubscribeSource {
    calls: Arc<AtomicUsize>,
    kind: MessagingErrorKind,
}

impl DeliverySource<Vec<u8>> for FailingSubscribeSource {
    type Settlement = FakeSettlement;
    type Deliveries = BoxDeliveries;

    async fn deliveries(
        &self,
        _subscription: &rss_transactional_messaging::message::SubscriptionIdentity,
    ) -> Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(MessagingError::new(
            self.kind,
            std::io::Error::other("scripted subscribe failure"),
        ))
    }
}

struct PanickingSubscribeSource;

impl DeliverySource<Vec<u8>> for PanickingSubscribeSource {
    type Settlement = FakeSettlement;
    type Deliveries = BoxDeliveries;

    #[allow(clippy::panic)]
    // reason: panic isolation is the lifecycle behavior under test.
    async fn deliveries(
        &self,
        _subscription: &rss_transactional_messaging::message::SubscriptionIdentity,
    ) -> Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError> {
        panic!("private provider panic")
    }
}

fn idle_inbox() -> Arc<RenewingInbox> {
    Arc::new(RenewingInbox {
        claim: Mutex::new(Some(IdempotencyDisposition::Acquired(Claim))),
        extends: AtomicUsize::new(0),
        lose_at: None,
    })
}

#[tokio::test]
async fn cancellation_during_subscribe_stops_without_admitting_work() {
    let message = envelope(|_| {});
    let started = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let worker = ConsumerWorker::new(
        Arc::new(BlockingSubscribeSource {
            started: Arc::clone(&started),
            gate: Arc::new(tokio::sync::Notify::new()),
        }),
        idle_inbox(),
        Arc::new(FakeTx {
            calls: Arc::clone(&calls),
            disposition: TerminalDisposition::Succeeded,
        }),
        ConsumerGroup::parse("cancel-subscribe").expect("group"),
        Arc::new(TrustedIngress),
        subscription(&message),
        Arc::new(FixedClock(MonotonicInstant::from_elapsed(Duration::ZERO))),
        consumer_policy(),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::STANDARD,
    );
    let (registration, status) = worker.into_registration(
        "cancel-subscribe",
        rss_transactional_messaging::policy::ShutdownBudget::new(Duration::from_secs(1))
            .expect("budget"),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(2)).expect("total"),
    )
    .expect("stack");
    let mut startup = stack.startup().expect("startup");
    startup.stage_task_with_token(registration);
    startup.commit().finish();
    tokio::time::timeout(Duration::from_secs(1), async {
        while started.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("subscribe starts");

    assert!(stack.shutdown().await.expect("shutdown").is_clean());
    assert_eq!(
        status.wait_stopped().await,
        rss_runtime::TaskExit::Cancelled
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancellation_wins_over_a_simultaneously_ready_new_delivery() {
    let message = envelope(|_| {});
    let expected = subscription(&message);
    let calls = Arc::new(AtomicUsize::new(0));
    let actions = Arc::new(Mutex::new(Vec::new()));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let subscribed = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(tokio::sync::Notify::new());
    let worker = ConsumerWorker::new(
        Arc::new(GatedDeliverySource {
            subscribed: Arc::clone(&subscribed),
            gate: Arc::clone(&gate),
            delivery: Mutex::new(Some(IncomingDelivery::Valid(Box::new(Delivery::new(
                message,
                FakeSettlement {
                    actions: Arc::clone(&actions),
                    fail: false,
                    abandoned: Arc::clone(&abandoned),
                },
            ))))),
        }),
        idle_inbox(),
        Arc::new(FakeTx {
            calls: Arc::clone(&calls),
            disposition: TerminalDisposition::Succeeded,
        }),
        ConsumerGroup::parse("cancel-admission").expect("group"),
        Arc::new(TrustedIngress),
        expected,
        Arc::new(FixedClock(MonotonicInstant::from_elapsed(Duration::ZERO))),
        consumer_policy(),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::STANDARD,
    );
    let (registration, status) = worker.into_registration(
        "cancel-admission",
        rss_transactional_messaging::policy::ShutdownBudget::new(Duration::from_secs(1))
            .expect("budget"),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(2)).expect("total"),
    )
    .expect("stack");
    let mut startup = stack.startup().expect("startup");
    startup.stage_task_with_token(registration);
    startup.commit().finish();
    tokio::time::timeout(Duration::from_secs(1), async {
        while subscribed.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("subscribed");

    let release = async {
        tokio::task::yield_now().await;
        gate.notify_one();
    };
    let (receipt, ()) = tokio::join!(stack.shutdown(), release);
    assert!(receipt.expect("shutdown").is_clean());
    assert_eq!(
        status.wait_stopped().await,
        rss_runtime::TaskExit::Cancelled
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(actions.lock().expect("actions").is_empty());
    assert_eq!(abandoned.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancellation_interrupts_subscription_backoff() {
    let message = envelope(|_| {});
    let subscribe_calls = Arc::new(AtomicUsize::new(0));
    let worker = ConsumerWorker::new(
        Arc::new(FailingSubscribeSource {
            calls: Arc::clone(&subscribe_calls),
            kind: MessagingErrorKind::Transient,
        }),
        idle_inbox(),
        Arc::new(FakeTx {
            calls: Arc::new(AtomicUsize::new(0)),
            disposition: TerminalDisposition::Succeeded,
        }),
        ConsumerGroup::parse("cancel-backoff").expect("group"),
        Arc::new(TrustedIngress),
        subscription(&message),
        Arc::new(ManualTimer::new()),
        consumer_policy(),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::STANDARD,
    );
    let (registration, status) = worker.into_registration(
        "cancel-backoff",
        rss_transactional_messaging::policy::ShutdownBudget::new(Duration::from_secs(1))
            .expect("budget"),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(2)).expect("total"),
    )
    .expect("stack");
    let mut startup = stack.startup().expect("startup");
    startup.stage_task_with_token(registration);
    startup.commit().finish();
    tokio::time::timeout(Duration::from_secs(1), async {
        while subscribe_calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("subscribe fails");

    assert!(stack.shutdown().await.expect("shutdown").is_clean());
    assert_eq!(
        status.wait_stopped().await,
        rss_runtime::TaskExit::Cancelled
    );
    assert_eq!(subscribe_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn non_transient_subscribe_failure_is_fail_loud() {
    let message = envelope(|_| {});
    let worker = ConsumerWorker::new(
        Arc::new(FailingSubscribeSource {
            calls: Arc::new(AtomicUsize::new(0)),
            kind: MessagingErrorKind::Invariant,
        }),
        idle_inbox(),
        Arc::new(FakeTx {
            calls: Arc::new(AtomicUsize::new(0)),
            disposition: TerminalDisposition::Succeeded,
        }),
        ConsumerGroup::parse("failed-subscribe").expect("group"),
        Arc::new(TrustedIngress),
        subscription(&message),
        Arc::new(FixedClock(MonotonicInstant::from_elapsed(Duration::ZERO))),
        consumer_policy(),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::STANDARD,
    );
    let (registration, status) = worker.into_registration(
        "failed-subscribe",
        rss_transactional_messaging::policy::ShutdownBudget::new(Duration::from_secs(1))
            .expect("budget"),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(2)).expect("total"),
    )
    .expect("stack");
    let mut startup = stack.startup().expect("startup");
    startup.stage_task_with_token(registration);
    startup.commit().finish();

    assert_eq!(
        status.wait_stopped().await,
        rss_runtime::TaskExit::Failed(rss_runtime::ShutdownErrorKind::Operation)
    );
    let receipt = stack.shutdown().await.expect("bounded shutdown");
    assert!(matches!(
        &receipt.failures()[0].kind,
        rss_runtime::ShutdownFailureKind::Failed(error)
            if error.kind() == rss_runtime::ShutdownErrorKind::Operation
    ));
}

#[tokio::test]
async fn provider_panic_maps_to_typed_worker_failure() {
    let message = envelope(|_| {});
    let worker = ConsumerWorker::new(
        Arc::new(PanickingSubscribeSource),
        idle_inbox(),
        Arc::new(FakeTx {
            calls: Arc::new(AtomicUsize::new(0)),
            disposition: TerminalDisposition::Succeeded,
        }),
        ConsumerGroup::parse("panic-subscribe").expect("group"),
        Arc::new(TrustedIngress),
        subscription(&message),
        Arc::new(FixedClock(MonotonicInstant::from_elapsed(Duration::ZERO))),
        consumer_policy(),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::STANDARD,
    );
    let (registration, status) = worker.into_registration(
        "panic-subscribe",
        rss_transactional_messaging::policy::ShutdownBudget::new(Duration::from_secs(1))
            .expect("budget"),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(2)).expect("total"),
    )
    .expect("stack");
    let mut startup = stack.startup().expect("startup");
    startup.stage_task_with_token(registration);
    startup.commit().finish();

    assert_eq!(
        status.wait_stopped().await,
        rss_runtime::TaskExit::Failed(rss_runtime::ShutdownErrorKind::TaskPanicked)
    );
    let receipt = stack.shutdown().await.expect("bounded shutdown");
    assert!(matches!(
        receipt.failures()[0].kind,
        rss_runtime::ShutdownFailureKind::Panicked
    ));
}

struct UnlimitedInbox;

impl InboxStore for UnlimitedInbox {
    type Claim = Claim;

    async fn claim(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        Ok(IdempotencyDisposition::Acquired(Claim))
    }

    async fn read_terminal(
        &self,
        _identity: &ConsumerIdentity,
        _deadline: OperationDeadline,
    ) -> Result<Option<TerminalReceipt>, MessagingError> {
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

struct BlockingSettlement {
    gate: Option<Arc<tokio::sync::Notify>>,
    settled: Arc<AtomicUsize>,
}

impl DeliverySettlement for BlockingSettlement {
    async fn settle(
        self,
        _decision: rss_transactional_messaging::transaction::SettlementDecision,
        _deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        if let Some(gate) = self.gate {
            gate.notified().await;
        }
        self.settled.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn abandon(self, _deadline: OperationDeadline) -> Result<(), MessagingError> {
        Ok(())
    }
}

struct TwoDeliverySource {
    deliveries: Mutex<Vec<IncomingDelivery<Vec<u8>, BlockingSettlement>>>,
}

impl DeliverySource<Vec<u8>> for TwoDeliverySource {
    type Settlement = BlockingSettlement;
    type Deliveries =
        futures::stream::Iter<std::vec::IntoIter<IncomingDelivery<Vec<u8>, Self::Settlement>>>;

    async fn deliveries(
        &self,
        _subscription: &rss_transactional_messaging::message::SubscriptionIdentity,
    ) -> Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError> {
        let deliveries = std::mem::take(&mut *self.deliveries.lock().expect("deliveries"));
        Ok(ManagedDeliveryStream::from_provider(futures::stream::iter(
            deliveries,
        )))
    }
}

#[tokio::test]
async fn consumer_does_not_process_the_next_delivery_before_settlement() {
    let first = envelope(|fixture| fixture.id = "message-backpressure-1");
    let second = envelope(|fixture| fixture.id = "message-backpressure-2");
    let expected = subscription(&first);
    let gate = Arc::new(tokio::sync::Notify::new());
    let settled = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let worker = ConsumerWorker::new(
        Arc::new(TwoDeliverySource {
            deliveries: Mutex::new(vec![
                IncomingDelivery::Valid(Box::new(Delivery::new(
                    first,
                    BlockingSettlement {
                        gate: Some(Arc::clone(&gate)),
                        settled: Arc::clone(&settled),
                    },
                ))),
                IncomingDelivery::Valid(Box::new(Delivery::new(
                    second,
                    BlockingSettlement {
                        gate: None,
                        settled: Arc::clone(&settled),
                    },
                ))),
            ]),
        }),
        Arc::new(UnlimitedInbox),
        Arc::new(FakeTx {
            calls: Arc::clone(&calls),
            disposition: TerminalDisposition::Succeeded,
        }),
        ConsumerGroup::parse("backpressure").expect("group"),
        Arc::new(TrustedIngress),
        expected,
        Arc::new(ManualTimer::new()),
        consumer_policy(),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::STANDARD,
    );
    let (registration, status) = worker.into_registration(
        "backpressure",
        rss_transactional_messaging::policy::ShutdownBudget::new(Duration::from_secs(1))
            .expect("budget"),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(2)).expect("total"),
    )
    .expect("stack");
    let mut startup = stack.startup().expect("startup");
    startup.stage_task_with_token(registration);
    startup.commit().finish();
    tokio::time::timeout(Duration::from_secs(1), async {
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first handler");
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(settled.load(Ordering::SeqCst), 0);

    gate.notify_one();
    tokio::time::timeout(Duration::from_secs(1), async {
        while settled.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both settlements");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(stack.shutdown().await.expect("shutdown").is_clean());
    assert_eq!(
        status.wait_stopped().await,
        rss_runtime::TaskExit::Cancelled
    );
}

struct RecordingTimer {
    delays: Arc<Mutex<Vec<Duration>>>,
    permits: tokio::sync::Semaphore,
}

impl Clock for RecordingTimer {
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_elapsed(Duration::ZERO)
    }
}

impl ExecutionTimer for RecordingTimer {
    async fn sleep_until(&self, deadline: AbsoluteDeadline) {
        self.delays
            .lock()
            .expect("delays")
            .push(deadline.remaining(self));
        self.permits
            .acquire()
            .await
            .expect("timer semaphore")
            .forget();
    }
}

enum RecoveryStep {
    TransientError,
    EmptyStream,
}

struct RecoverySource {
    steps: Mutex<VecDeque<RecoveryStep>>,
}

impl DeliverySource<Vec<u8>> for RecoverySource {
    type Settlement = FakeSettlement;
    type Deliveries = futures::stream::Empty<IncomingDelivery<Vec<u8>, Self::Settlement>>;

    async fn deliveries(
        &self,
        _subscription: &rss_transactional_messaging::message::SubscriptionIdentity,
    ) -> Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError> {
        match self.steps.lock().expect("steps").pop_front() {
            Some(RecoveryStep::TransientError) => Err(MessagingError::new(
                MessagingErrorKind::Transient,
                std::io::Error::other("subscription unavailable"),
            )),
            Some(RecoveryStep::EmptyStream) | None => Ok(ManagedDeliveryStream::from_provider(
                futures::stream::empty(),
            )),
        }
    }
}

#[tokio::test]
async fn subscription_backoff_saturates_and_success_resets_the_cursor() {
    let message = envelope(|_| {});
    let delays = Arc::new(Mutex::new(Vec::new()));
    let timer = Arc::new(RecordingTimer {
        delays: Arc::clone(&delays),
        permits: tokio::sync::Semaphore::new(0),
    });
    let worker = ConsumerWorker::new(
        Arc::new(RecoverySource {
            steps: Mutex::new(VecDeque::from([
                RecoveryStep::TransientError,
                RecoveryStep::TransientError,
                RecoveryStep::EmptyStream,
            ])),
        }),
        idle_inbox(),
        Arc::new(FakeTx {
            calls: Arc::new(AtomicUsize::new(0)),
            disposition: TerminalDisposition::Succeeded,
        }),
        ConsumerGroup::parse("subscription-recovery").expect("group"),
        Arc::new(TrustedIngress),
        subscription(&message),
        Arc::clone(&timer),
        consumer_policy(),
        Arc::new(NoopEmitter),
        SubscriptionBackoffPolicy::new(Duration::from_millis(100), Duration::from_millis(150))
            .expect("backoff"),
    );
    let (registration, status) = worker.into_registration(
        "subscription-recovery",
        rss_transactional_messaging::policy::ShutdownBudget::new(Duration::from_secs(1))
            .expect("budget"),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(2)).expect("total"),
    )
    .expect("stack");
    let mut startup = stack.startup().expect("startup");
    startup.stage_task_with_token(registration);
    startup.commit().finish();

    for expected in 1..=3 {
        tokio::time::timeout(Duration::from_secs(1), async {
            while delays.lock().expect("delays").len() < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("recovery delay");
        if expected < 3 {
            timer.permits.add_permits(1);
        }
    }
    assert_eq!(
        *delays.lock().expect("delays"),
        [
            Duration::from_millis(100),
            Duration::from_millis(150),
            Duration::from_millis(100),
        ]
    );
    assert!(stack.shutdown().await.expect("shutdown").is_clean());
    assert_eq!(
        status.wait_stopped().await,
        rss_runtime::TaskExit::Cancelled
    );
}
