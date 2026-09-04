#![allow(clippy::expect_used)]
// reason: fixed canonical fixtures must fail loudly if their identity or protocol invariants drift.

use std::collections::BTreeMap;
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
use rss_transactional_messaging::message::{
    AuthoredMessageMetadata, ContractIdentity, MessageEnvelope, MessageFingerprint, MessageId,
    MessageMetadata, MessageMetadataExtensions, MessageRoute, MessagingDomain, PartitionIdentity,
    PartitionKey, TransportContext,
};
use rss_transactional_messaging::observability::{
    TransactionalMessagingEmitter, TransactionalMessagingObservation,
};
use rss_transactional_messaging::outbox::{OutboxDisposition, PartitionHead, PartitionHeadState};
use rss_transactional_messaging::policy::{
    AbsoluteDeadline, Clock, ConsumerExecutionPolicy, DeliveryBudget, DeliveryBudgetError,
    ExecutionBudget, ExecutionBudgetError, MonotonicInstant, OperationDeadline, RetryPolicy,
    RetryTimer,
};
use rss_transactional_messaging::transaction::{
    ConsumerExecution, ConsumerTx, FailureClass, LocalTxAttempt, ProcessingDisposition, RejectKind,
    SettlementKind, TerminalDisposition, TerminalReceipt, TransactionOutcome, process_delivery,
};
use rss_transactional_messaging::transport::{Delivery, DeliverySettlement};

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

impl RetryTimer for FixedClock {
    async fn delay(&self, _duration: Duration, _deadline: OperationDeadline) {}
}

struct NoopEmitter;

impl TransactionalMessagingEmitter for NoopEmitter {
    fn emit(&self, _observation: TransactionalMessagingObservation) {}
}

fn consumer_policy() -> ConsumerExecutionPolicy {
    ConsumerExecutionPolicy::new(RetryPolicy::STANDARD, ExecutionBudget::STANDARD)
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
    let deadline = AbsoluteDeadline::from_budget(&clock, execution).expect("deadline");
    assert_eq!(deadline.remaining(&clock), Duration::from_secs(5));
    let overflow_clock = FixedClock(MonotonicInstant::from_elapsed(Duration::MAX));
    assert_eq!(
        AbsoluteDeadline::from_budget(&overflow_clock, execution),
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
        lease: LeaseStatus::Held,
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

    let outcome = process_delivery(
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
        lease: LeaseStatus::Held,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let transaction = FakeTx {
        calls: Arc::clone(&calls),
        disposition: TerminalDisposition::Succeeded,
    };
    let expected = subscription(&message);
    let actions = Arc::new(Mutex::new(Vec::new()));

    let outcome = process_delivery(
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
    .expect("conflict settles");

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

    let outcome = process_delivery(
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

    let outcome = process_delivery(
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
async fn only_confirmed_transient_rollback_retries_locally() {
    let message = envelope(|_| {});
    let group = ConsumerGroup::parse("orders-projection").expect("group");
    let inbox = FakeInbox {
        disposition: Mutex::new(Some(IdempotencyDisposition::Acquired(Claim))),
        lease: LeaseStatus::Held,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let transaction = RetryThenCommitTx {
        calls: Arc::clone(&calls),
    };
    let expected = subscription(&message);
    let actions = Arc::new(Mutex::new(Vec::new()));

    let outcome = process_delivery(
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
    .expect("retry commits");

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
        lease: LeaseStatus::Held,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let transaction = FakeTx {
        calls: Arc::clone(&calls),
        disposition: TerminalDisposition::Rejected(RejectKind::Permanent),
    };
    let actions = Arc::new(Mutex::new(Vec::new()));

    let message = envelope(|_| {});
    let expected = subscription(&message);
    let outcome = process_delivery(
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
        lease: LeaseStatus::Held,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let transaction = FakeTx {
        calls: Arc::clone(&calls),
        disposition: TerminalDisposition::Succeeded,
    };
    let actions = Arc::new(Mutex::new(Vec::new()));

    let message = envelope(|_| {});
    let expected = subscription(&message);
    let outcome = process_delivery(
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
async fn process_delivery_fault_matrix_is_bounded_and_never_acks_uncertain_outcomes() {
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
            lease: LeaseStatus::Held,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let actions = Arc::new(Mutex::new(Vec::new()));
        let abandoned = Arc::new(AtomicUsize::new(0));
        let observations = Arc::new(Mutex::new(Vec::new()));
        let message = envelope(|_| {});
        let expected = subscription(&message);
        process_delivery(
            &inbox,
            &MatrixTx {
                outcome: kind,
                calls: Arc::clone(&calls),
            },
            &ConsumerExecution::new(
                ConsumerGroup::parse("matrix").expect("group"),
                &TrustedIngress,
                &expected,
                &FixedClock(MonotonicInstant::from_elapsed(Duration::ZERO)),
                consumer_policy(),
                &RecordingEmitter(Arc::clone(&observations)),
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
        .expect("matrix outcome");
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
