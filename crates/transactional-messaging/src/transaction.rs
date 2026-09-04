//! Closed transaction outcomes, durable terminal receipts, and settlement projection.

use crate::inbox::{ConsumerGroup, ConsumerIdentity};
use crate::message::{MessageEnvelope, MessageFingerprint, MessageId, SubscriptionIdentity};
use crate::observability::TransactionalMessagingTransactionStatus;
use crate::policy::OperationDeadline;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `FailureClass` protocol type.
pub enum FailureClass {
    /// `Transient` state in the closed protocol.
    Transient,
    /// `Permanent` state in the closed protocol.
    Permanent,
    /// `Infrastructure` state in the closed protocol.
    Infrastructure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `LocalTxDeadlineStage` protocol type.
pub enum LocalTxDeadlineStage {
    /// `Acquire` state in the closed protocol.
    Acquire,
    /// `Begin` state in the closed protocol.
    Begin,
    /// `Setup` state in the closed protocol.
    Setup,
    /// `Operation` state in the closed protocol.
    Operation,
    /// `Backoff` state in the closed protocol.
    Backoff,
    /// `Commit` state in the closed protocol.
    Commit,
    /// `Rollback` state in the closed protocol.
    Rollback,
}

impl LocalTxDeadlineStage {
    /// Canonical operation owned by the transactional messaging core.
    pub const ALL: &'static [Self] = &[
        Self::Acquire,
        Self::Begin,
        Self::Setup,
        Self::Operation,
        Self::Backoff,
        Self::Commit,
        Self::Rollback,
    ];

    #[must_use]
    /// `as_label` operation defined by this protocol type.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Acquire => "acquire",
            Self::Begin => "begin",
            Self::Setup => "setup",
            Self::Operation => "operation",
            Self::Backoff => "backoff",
            Self::Commit => "commit",
            Self::Rollback => "rollback",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `LocalTxFinalStatus` protocol type.
pub enum LocalTxFinalStatus {
    /// `Committed` state in the closed protocol.
    Committed,
    /// `RolledBack` state in the closed protocol.
    RolledBack,
    /// `RollbackFailed` state in the closed protocol.
    RollbackFailed,
    /// `CommitUnknown` state in the closed protocol.
    CommitUnknown,
}

impl LocalTxFinalStatus {
    /// Canonical operation owned by the transactional messaging core.
    pub const ALL: &'static [Self] = &[
        Self::Committed,
        Self::RolledBack,
        Self::RollbackFailed,
        Self::CommitUnknown,
    ];
    #[must_use]
    /// `as_label` operation defined by this protocol type.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::RolledBack => "rolled_back",
            Self::RollbackFailed => "rollback_failed",
            Self::CommitUnknown => "commit_unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `TxRetryClass` protocol type.
pub enum TxRetryClass {
    /// `Transient` state in the closed protocol.
    Transient,
    /// `Conflict` state in the closed protocol.
    Conflict,
    /// `Permanent` state in the closed protocol.
    Permanent,
    /// `OwnershipLost` state in the closed protocol.
    OwnershipLost,
}

impl TxRetryClass {
    /// Canonical operation owned by the transactional messaging core.
    pub const ALL: &'static [Self] = &[
        Self::Transient,
        Self::Conflict,
        Self::Permanent,
        Self::OwnershipLost,
    ];
    #[must_use]
    /// `as_label` operation defined by this protocol type.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Conflict => "conflict",
            Self::Permanent => "permanent",
            Self::OwnershipLost => "ownership_lost",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `TxRetryFinalStatus` protocol type.
pub enum TxRetryFinalStatus {
    /// `Success` state in the closed protocol.
    Success,
    /// `Exhausted` state in the closed protocol.
    Exhausted,
    /// `NotRetryable` state in the closed protocol.
    NotRetryable(TxRetryClass),
}

impl TxRetryFinalStatus {
    #[must_use]
    /// `as_label` operation defined by this protocol type.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Exhausted => "exhausted",
            Self::NotRetryable(TxRetryClass::Transient) => "transient_not_retried",
            Self::NotRetryable(TxRetryClass::Conflict) => "conflict",
            Self::NotRetryable(TxRetryClass::Permanent) => "permanent",
            Self::NotRetryable(TxRetryClass::OwnershipLost) => "ownership_lost",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `RejectKind` protocol type.
pub enum RejectKind {
    /// `Permanent` state in the closed protocol.
    Permanent,
    /// `Invariant` state in the closed protocol.
    Invariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `TerminalDisposition` protocol type.
pub enum TerminalDisposition {
    /// `Succeeded` state in the closed protocol.
    Succeeded,
    /// `Rejected` state in the closed protocol.
    Rejected(RejectKind),
}

impl TerminalDisposition {
    #[must_use]
    /// `as_label` operation defined by this protocol type.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Rejected(RejectKind::Permanent) => "rejected_permanent",
            Self::Rejected(RejectKind::Invariant) => "rejected_invariant",
        }
    }
}

/// Provider-authoritative durable terminal fact for one consumer/message/fingerprint tuple.
///
/// Private fields prevent business callers from relabeling the fact or projecting settlement
/// authority directly. They do not establish the truthfulness of the trusted provider that
/// rehydrates it.
pub struct TerminalReceipt {
    consumer: ConsumerIdentity,
    fingerprint: MessageFingerprint,
    disposition: TerminalDisposition,
}

impl TerminalReceipt {
    /// Rehydrate a receipt read from provider-authoritative durable storage.
    ///
    /// `Succeeded` is valid only when the provider committed this receipt atomically with the
    /// handler effect. Provider conformance, not this constructor, proves that obligation.
    #[must_use]
    pub const fn from_durable(
        consumer: ConsumerIdentity,
        fingerprint: MessageFingerprint,
        disposition: TerminalDisposition,
    ) -> Self {
        Self {
            consumer,
            fingerprint,
            disposition,
        }
    }

    #[must_use]
    /// `consumer` operation defined by this protocol type.
    pub const fn consumer(&self) -> &ConsumerIdentity {
        &self.consumer
    }
    #[must_use]
    /// `message_id` operation defined by this protocol type.
    pub const fn message_id(&self) -> &MessageId {
        self.consumer.message_id()
    }
    #[must_use]
    /// `fingerprint` operation defined by this protocol type.
    pub const fn fingerprint(&self) -> MessageFingerprint {
        self.fingerprint
    }
    #[must_use]
    /// `disposition` operation defined by this protocol type.
    pub const fn disposition(&self) -> TerminalDisposition {
        self.disposition
    }
    #[must_use]
    /// `matches` operation defined by this protocol type.
    pub fn matches(&self, consumer: &ConsumerIdentity, fingerprint: MessageFingerprint) -> bool {
        self.consumer == *consumer && self.fingerprint == fingerprint
    }
}

impl std::fmt::Debug for TerminalReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TerminalReceipt(<redacted>)")
    }
}

/// Core-minted, move-only binding that a transaction provider must consume when committing a
/// terminal receipt. External callers cannot construct or relabel it.
pub struct ReceiptIntent {
    consumer: ConsumerIdentity,
    fingerprint: MessageFingerprint,
}

impl ReceiptIntent {
    fn new(consumer: ConsumerIdentity, fingerprint: MessageFingerprint) -> Self {
        Self {
            consumer,
            fingerprint,
        }
    }

    /// Complete a provider commit with its private proof and terminal disposition.
    #[must_use]
    pub fn committed<P>(self, proof: P, disposition: TerminalDisposition) -> TransactionOutcome<P> {
        TransactionOutcome {
            state: TransactionOutcomeState::Committed(CommittedTransaction {
                proof,
                settlement: TerminalSettlement {
                    receipt: TerminalReceipt {
                        consumer: self.consumer,
                        fingerprint: self.fingerprint,
                        disposition,
                    },
                },
            }),
        }
    }
}

impl std::fmt::Debug for ReceiptIntent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReceiptIntent(<redacted>)")
    }
}

/// Closed `TransactionOutcome` protocol type.
pub struct TransactionOutcome<P> {
    state: TransactionOutcomeState<P>,
}

enum TransactionOutcomeState<P> {
    Committed(CommittedTransaction<P>),
    NotStarted(FailureClass),
    RolledBack(FailureClass),
    RollbackFailed,
    CommitUnknown,
    Fenced,
}

impl<P> TransactionOutcome<P> {
    #[must_use]
    /// `not_started` operation defined by this protocol type.
    pub const fn not_started(class: FailureClass) -> Self {
        Self {
            state: TransactionOutcomeState::NotStarted(class),
        }
    }
    #[must_use]
    /// `rolled_back` operation defined by this protocol type.
    pub const fn rolled_back(class: FailureClass) -> Self {
        Self {
            state: TransactionOutcomeState::RolledBack(class),
        }
    }
    #[must_use]
    /// `rollback_failed` operation defined by this protocol type.
    pub const fn rollback_failed() -> Self {
        Self {
            state: TransactionOutcomeState::RollbackFailed,
        }
    }
    #[must_use]
    /// `commit_unknown` operation defined by this protocol type.
    pub const fn commit_unknown() -> Self {
        Self {
            state: TransactionOutcomeState::CommitUnknown,
        }
    }
    #[must_use]
    /// `fenced` operation defined by this protocol type.
    pub const fn fenced() -> Self {
        Self {
            state: TransactionOutcomeState::Fenced,
        }
    }

    #[must_use]
    /// `may_retry` operation defined by this protocol type.
    pub const fn may_retry(&self) -> bool {
        matches!(
            &self.state,
            TransactionOutcomeState::NotStarted(FailureClass::Transient)
                | TransactionOutcomeState::RolledBack(FailureClass::Transient)
        )
    }

    /// Return the closed, low-cardinality transaction status without exposing the private state.
    #[must_use]
    pub const fn status(&self) -> TransactionalMessagingTransactionStatus {
        match &self.state {
            TransactionOutcomeState::Committed(_) => {
                TransactionalMessagingTransactionStatus::Committed
            }
            TransactionOutcomeState::NotStarted(FailureClass::Transient)
            | TransactionOutcomeState::RolledBack(FailureClass::Transient) => {
                TransactionalMessagingTransactionStatus::HandlerTransient
            }
            TransactionOutcomeState::NotStarted(FailureClass::Permanent)
            | TransactionOutcomeState::RolledBack(FailureClass::Permanent) => {
                TransactionalMessagingTransactionStatus::RejectedPermanent
            }
            TransactionOutcomeState::NotStarted(FailureClass::Infrastructure)
            | TransactionOutcomeState::RolledBack(FailureClass::Infrastructure) => {
                TransactionalMessagingTransactionStatus::InfrastructureTransient
            }
            TransactionOutcomeState::RollbackFailed => {
                TransactionalMessagingTransactionStatus::RollbackFailed
            }
            TransactionOutcomeState::CommitUnknown => {
                TransactionalMessagingTransactionStatus::CommitUnknown
            }
            TransactionOutcomeState::Fenced => TransactionalMessagingTransactionStatus::Fenced,
        }
    }

    /// Exhaustively consume the private outcome state.
    pub fn fold<R>(
        self,
        committed: impl FnOnce(CommittedTransaction<P>) -> R,
        not_started: impl FnOnce(FailureClass) -> R,
        rolled_back: impl FnOnce(FailureClass) -> R,
        rollback_failed: impl FnOnce() -> R,
        commit_unknown: impl FnOnce() -> R,
        fenced: impl FnOnce() -> R,
    ) -> R {
        match self.state {
            TransactionOutcomeState::Committed(value) => committed(value),
            TransactionOutcomeState::NotStarted(class) => not_started(class),
            TransactionOutcomeState::RolledBack(class) => rolled_back(class),
            TransactionOutcomeState::RollbackFailed => rollback_failed(),
            TransactionOutcomeState::CommitUnknown => commit_unknown(),
            TransactionOutcomeState::Fenced => fenced(),
        }
    }
}

/// A committed provider proof paired with its one-shot terminal settlement authority.
pub struct CommittedTransaction<P> {
    proof: P,
    settlement: TerminalSettlement,
}

impl<P> CommittedTransaction<P> {
    /// Consume the committed result into the provider proof and terminal settlement.
    #[must_use]
    pub fn into_parts(self) -> (P, TerminalSettlement) {
        (self.proof, self.settlement)
    }
}

/// A verified terminal result that can be projected into broker settlement exactly once.
pub struct TerminalSettlement {
    receipt: TerminalReceipt,
}

impl TerminalSettlement {
    /// Return the durable terminal disposition.
    #[must_use]
    pub const fn disposition(&self) -> TerminalDisposition {
        self.receipt.disposition
    }

    /// Consume the terminal authority into the corresponding ACK or Reject decision.
    #[must_use]
    pub fn into_decision(self) -> SettlementDecision {
        settlement_for_disposition(self.receipt.disposition)
    }
}

/// Opaque provider attempt preserving the historical exhaustive settlement fold.
pub struct LocalTxAttempt<T, E> {
    state: LocalTxAttemptState<T, E>,
}

enum LocalTxAttemptState<T, E> {
    Committed(T),
    NotStarted(E),
    RolledBack(E),
    RollbackFailed(E),
    CommitUnknown(E),
    Fenced(E),
}

impl<T, E> LocalTxAttempt<T, E> {
    #[must_use]
    /// `committed` operation defined by this protocol type.
    pub fn committed(value: T) -> Self {
        Self {
            state: LocalTxAttemptState::Committed(value),
        }
    }
    #[must_use]
    /// `not_started` operation defined by this protocol type.
    pub fn not_started(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::NotStarted(error),
        }
    }
    #[must_use]
    /// `rolled_back` operation defined by this protocol type.
    pub fn rolled_back(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::RolledBack(error),
        }
    }
    #[must_use]
    /// `rollback_failed` operation defined by this protocol type.
    pub fn rollback_failed(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::RollbackFailed(error),
        }
    }
    #[must_use]
    /// `commit_unknown` operation defined by this protocol type.
    pub fn commit_unknown(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::CommitUnknown(error),
        }
    }
    #[must_use]
    /// `fenced` operation defined by this protocol type.
    pub fn fenced(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::Fenced(error),
        }
    }

    /// `fold` operation defined by this protocol type.
    pub fn fold<R>(
        self,
        committed: impl FnOnce(T) -> R,
        not_started: impl FnOnce(E) -> R,
        rolled_back: impl FnOnce(E) -> R,
        rollback_failed: impl FnOnce(E) -> R,
        commit_unknown: impl FnOnce(E) -> R,
        fenced: impl FnOnce(E) -> R,
    ) -> R {
        match self.state {
            LocalTxAttemptState::Committed(value) => committed(value),
            LocalTxAttemptState::NotStarted(error) => not_started(error),
            LocalTxAttemptState::RolledBack(error) => rolled_back(error),
            LocalTxAttemptState::RollbackFailed(error) => rollback_failed(error),
            LocalTxAttemptState::CommitUnknown(error) => commit_unknown(error),
            LocalTxAttemptState::Fenced(error) => fenced(error),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `SettlementKind` protocol type.
pub enum SettlementKind {
    /// `Acknowledge` state in the closed protocol.
    Acknowledge,
    /// `Requeue` state in the closed protocol.
    Requeue,
    /// `Reject` state in the closed protocol.
    Reject,
}

/// Move-only settlement authority. Its constructor is deliberately private.
pub struct SettlementDecision(SettlementKind);

impl SettlementDecision {
    /// Construct the conservative redelivery decision available to runtime orchestration.
    #[must_use]
    pub const fn requeue() -> Self {
        Self(SettlementKind::Requeue)
    }

    #[must_use]
    /// `kind` operation defined by this protocol type.
    pub const fn kind(&self) -> SettlementKind {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `EnvelopeValidationFailure` protocol type.
pub enum EnvelopeValidationFailure {
    /// `MalformedIdentity` state in the closed protocol.
    MalformedIdentity,
    /// `MalformedMetadata` state in the closed protocol.
    MalformedMetadata,
    /// `UnsupportedContract` state in the closed protocol.
    UnsupportedContract,
    /// `FingerprintConflict` state in the closed protocol.
    FingerprintConflict,
}

impl EnvelopeValidationFailure {
    /// Stable low-cardinality diagnostic label for the rejected ingress fact.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::MalformedIdentity => "malformed_identity",
            Self::MalformedMetadata => "malformed_metadata",
            Self::UnsupportedContract => "unsupported_contract",
            Self::FingerprintConflict => "fingerprint_conflict",
        }
    }
}

fn settlement_for_disposition(disposition: TerminalDisposition) -> SettlementDecision {
    match disposition {
        TerminalDisposition::Succeeded => SettlementDecision(SettlementKind::Acknowledge),
        TerminalDisposition::Rejected(_) => SettlementDecision(SettlementKind::Reject),
    }
}

/// Trusted transaction provider that atomically binds handler effects and terminal receipt state.
///
/// A timeout may occur after commit begins, so implementations must quarantine or close an attempt
/// without an explicit commit/rollback acknowledgement; callers conservatively treat it as commit
/// outcome unknown.
pub trait ConsumerTx<P>: Send + Sync {
    /// Provider-owned `Claim` capability used by this port.
    type Claim: Send;
    /// Provider-owned `CommitProof` capability used by this port.
    type CommitProof: Send;

    /// Canonical operation owned by the transactional messaging core.
    fn execute(
        &self,
        claim: &Self::Claim,
        message: &MessageEnvelope<P>,
        receipt: ReceiptIntent,
        deadline: OperationDeadline,
    ) -> impl Future<Output = TransactionOutcome<Self::CommitProof>> + Send;
}

/// Core-issued, move-only ingress candidate. Only the delivery pipeline can construct it; a
/// validator can inspect its exact subscription/message pair and convert that same pair into a
/// verified capability after authority checks succeed.
pub struct IngressChallenge<'a, P> {
    subscription: &'a SubscriptionIdentity,
    message: &'a MessageEnvelope<P>,
}

impl<'a, P> IngressChallenge<'a, P> {
    fn new(subscription: &'a SubscriptionIdentity, message: &'a MessageEnvelope<P>) -> Self {
        Self {
            subscription,
            message,
        }
    }

    /// Subscription identity against which authority and contract routing must be checked.
    #[must_use]
    pub const fn subscription(&self) -> &SubscriptionIdentity {
        self.subscription
    }

    /// Exact immutable envelope that will enter the claim and transaction pipeline.
    #[must_use]
    pub const fn message(&self) -> &MessageEnvelope<P> {
        self.message
    }

    /// Bind successful validation to this exact subscription, tenant, message and fingerprint.
    #[must_use]
    pub fn verified(self) -> VerifiedIngress
    where
        P: AsRef<[u8]>,
    {
        VerifiedIngress {
            subscription: self.subscription.clone(),
            tenant_id: self.message.metadata().tenant_id(),
            message_id: self.message.id().clone(),
            contract: self.message.metadata().contract().clone(),
            fingerprint: MessageFingerprint::of(self.message),
        }
    }
}

/// Opaque evidence that ingress authority was checked for the exact delivered envelope.
pub struct VerifiedIngress {
    subscription: SubscriptionIdentity,
    tenant_id: rss_request_context::TenantId,
    message_id: MessageId,
    contract: crate::message::ContractIdentity,
    fingerprint: MessageFingerprint,
}

impl std::fmt::Debug for VerifiedIngress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedIngress(<redacted>)")
    }
}

/// Required ingress authority check performed before inbox identity or business effects are used.
pub trait IngressValidator<P>: Send + Sync {
    /// Validate and return the capability bound to the supplied core-issued challenge.
    fn validate(
        &self,
        challenge: IngressChallenge<'_, P>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure>;
}

/// Exact consumer identity and fingerprint proven by one ingress validation.
pub struct VerifiedConsumerBinding {
    identity: ConsumerIdentity,
    fingerprint: MessageFingerprint,
}

/// Opaque authority proving that core ingress verification rejected the exact challenge.
pub struct IngressRejection {
    reason: EnvelopeValidationFailure,
}

/// Core-minted authority to reject a delivery that a trusted provider adapter could not decode.
///
/// The private constructor prevents application code from manufacturing arbitrary Reject
/// decisions; only the transport boundary can mint this capability while constructing an invalid
/// incoming delivery.
pub struct DecodeRejection {
    reason: EnvelopeValidationFailure,
}

impl DecodeRejection {
    pub(crate) const fn new(reason: EnvelopeValidationFailure) -> Self {
        Self { reason }
    }

    /// Return the closed provider-neutral decode failure.
    #[must_use]
    pub const fn reason(&self) -> EnvelopeValidationFailure {
        self.reason
    }

    /// Consume the capability into the core-owned Reject decision.
    #[must_use]
    pub fn into_decision(self) -> SettlementDecision {
        SettlementDecision(SettlementKind::Reject)
    }
}

impl IngressRejection {
    /// Return the closed rejection reason for diagnostics and processing disposition.
    #[must_use]
    pub const fn reason(&self) -> EnvelopeValidationFailure {
        self.reason
    }

    /// Consume verified rejection authority into a one-shot broker Reject decision.
    #[must_use]
    pub fn into_decision(self) -> SettlementDecision {
        SettlementDecision(SettlementKind::Reject)
    }
}

impl VerifiedConsumerBinding {
    /// Return the exact durable inbox identity bound to the validated message.
    #[must_use]
    pub const fn identity(&self) -> &ConsumerIdentity {
        &self.identity
    }

    /// Mint a move-only receipt intent for one transaction attempt.
    #[must_use]
    pub fn receipt_intent(&self) -> ReceiptIntent {
        ReceiptIntent::new(self.identity.clone(), self.fingerprint)
    }

    /// Validate a provider-rehydrated terminal receipt before projecting settlement.
    pub fn validate_terminal(
        &self,
        receipt: TerminalReceipt,
    ) -> Result<TerminalSettlement, IngressRejection> {
        if receipt.matches(&self.identity, self.fingerprint) {
            Ok(TerminalSettlement { receipt })
        } else {
            Err(IngressRejection {
                reason: EnvelopeValidationFailure::FingerprintConflict,
            })
        }
    }
}

/// Validate one exact ingress envelope and bind it to a durable consumer identity.
///
/// The challenge constructor and verified fields remain private; callers receive an opaque binding
/// only when the validator's evidence matches the supplied subscription and message exactly.
pub fn verify_ingress<P, V>(
    validator: &V,
    group: ConsumerGroup,
    subscription: &SubscriptionIdentity,
    message: &MessageEnvelope<P>,
) -> Result<VerifiedConsumerBinding, IngressRejection>
where
    P: AsRef<[u8]>,
    V: IngressValidator<P>,
{
    let verified = validator
        .validate(IngressChallenge::new(subscription, message))
        .map_err(|reason| IngressRejection { reason })?;
    let fingerprint = MessageFingerprint::of(message);
    if verified.subscription != *subscription
        || verified.tenant_id != message.metadata().tenant_id()
        || verified.message_id != *message.id()
        || verified.contract != *message.metadata().contract()
        || verified.fingerprint != fingerprint
    {
        return Err(IngressRejection {
            reason: EnvelopeValidationFailure::FingerprintConflict,
        });
    }
    Ok(VerifiedConsumerBinding {
        identity: ConsumerIdentity::new(
            verified.tenant_id,
            group,
            verified.message_id,
            verified.contract,
        ),
        fingerprint,
    })
}
