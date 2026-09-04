//! Closed transaction outcomes, durable terminal receipts, and settlement projection.

use crate::error::MessagingError;
use crate::inbox::{ConsumerGroup, ConsumerIdentity, IdempotencyDisposition, InboxStore};
use crate::message::{MessageEnvelope, MessageFingerprint, MessageId, SubscriptionIdentity};
use crate::observability::{
    TransactionalMessagingDisposition, TransactionalMessagingEmitter,
    TransactionalMessagingIoOutcome, TransactionalMessagingObservation,
    TransactionalMessagingTransactionStatus,
};
use crate::policy::{AbsoluteDeadline, ConsumerExecutionPolicy, OperationDeadline, RetryTimer};
use crate::transport::{Delivery, DeliverySettlement};

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

/// Durable terminal fact for exactly one consumer/message/fingerprint tuple.
pub struct TerminalReceipt {
    consumer: ConsumerIdentity,
    fingerprint: MessageFingerprint,
    disposition: TerminalDisposition,
}

impl TerminalReceipt {
    /// Rehydrate a receipt read from provider-authoritative durable storage.
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

    /// `into_settlement` operation defined by this protocol type.
    pub(crate) fn into_settlement(self) -> SettlementDecision {
        settlement_for_disposition(self.disposition)
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
            state: TransactionOutcomeState::Committed {
                proof,
                receipt: TerminalReceipt {
                    consumer: self.consumer,
                    fingerprint: self.fingerprint,
                    disposition,
                },
            },
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
    Committed { proof: P, receipt: TerminalReceipt },
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

    #[must_use]
    /// `into_settlement` operation defined by this protocol type.
    pub const fn into_settlement(self) -> SettlementDecision {
        let _ = self;
        SettlementDecision(SettlementKind::Reject)
    }
}

fn settlement_for_disposition(disposition: TerminalDisposition) -> SettlementDecision {
    match disposition {
        TerminalDisposition::Succeeded => SettlementDecision(SettlementKind::Acknowledge),
        TerminalDisposition::Rejected(_) => SettlementDecision(SettlementKind::Reject),
    }
}

/// Closed `ConsumerTx` protocol type.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `ProcessingDisposition` protocol type.
pub enum ProcessingDisposition {
    /// `InProgress` state in the closed protocol.
    InProgress,
    /// `Duplicate` state in the closed protocol.
    Duplicate(TerminalDisposition),
    /// `Committed` state in the closed protocol.
    Committed(TerminalDisposition),
    /// Delivery rejected with a stable validation or identity-conflict reason.
    Rejected(EnvelopeValidationFailure),
    /// `Fenced` state in the closed protocol.
    Fenced,
    /// `Deferred` state in the closed protocol.
    Deferred,
}

/// Immutable consumer execution inputs shared by every delivery from one subscription.
pub struct ConsumerExecution<'a, V, R, E> {
    group: ConsumerGroup,
    validator: &'a V,
    subscription: &'a SubscriptionIdentity,
    timer: &'a R,
    policy: ConsumerExecutionPolicy,
    emitter: &'a E,
}

impl<'a, V, R, E> ConsumerExecution<'a, V, R, E> {
    /// Bind identity, ingress authority, time policy, and telemetry for one consumer subscription.
    #[must_use]
    pub const fn new(
        group: ConsumerGroup,
        validator: &'a V,
        subscription: &'a SubscriptionIdentity,
        timer: &'a R,
        policy: ConsumerExecutionPolicy,
        emitter: &'a E,
    ) -> Self {
        Self {
            group,
            validator,
            subscription,
            timer,
            policy,
            emitter,
        }
    }

    /// Return the exact ingress identity bound to this execution context.
    #[must_use]
    pub const fn subscription(&self) -> &SubscriptionIdentity {
        self.subscription
    }

    /// Return the mandatory telemetry sink bound to this execution context.
    #[must_use]
    pub const fn emitter(&self) -> &E {
        self.emitter
    }

    /// Mint a provider-operation deadline from this execution's single configured budget.
    pub fn operation_deadline(&self) -> Result<OperationDeadline, MessagingError>
    where
        R: RetryTimer,
    {
        AbsoluteDeadline::from_budget(self.timer, self.policy.budget())
            .map(|deadline| deadline.operation(self.timer))
            .map_err(|error| {
                MessagingError::new(crate::error::MessagingErrorKind::Invariant, error)
            })
    }
}

/// Execute the canonical claim → transaction → one-shot settlement pipeline.
///
/// A duplicate terminal receipt bypasses `ConsumerTx`; transaction uncertainty and fencing never
/// acknowledge the delivery; settlement I/O occurs after durable outcome selection and cannot
/// rewrite it.
pub async fn process_delivery<P, S, I, T, V, R, E>(
    inbox: &I,
    transaction: &T,
    execution: &ConsumerExecution<'_, V, R, E>,
    delivery: Delivery<P, S>,
) -> Result<ProcessingDisposition, MessagingError>
where
    P: AsRef<[u8]> + Send,
    S: DeliverySettlement,
    I: InboxStore,
    T: ConsumerTx<P, Claim = I::Claim>,
    V: IngressValidator<P>,
    R: RetryTimer,
    E: TransactionalMessagingEmitter,
{
    let (message, settlement) = delivery.into_parts();
    let deadline = match AbsoluteDeadline::from_budget(execution.timer, execution.policy.budget()) {
        Ok(deadline) => deadline,
        Err(error) => {
            drop(settlement);
            return Err(MessagingError::new(
                crate::error::MessagingErrorKind::Invariant,
                error,
            ));
        }
    };
    let verified =
        match execution
            .validator
            .validate(IngressChallenge::new(execution.subscription, &message))
        {
            Ok(verified) => verified,
            Err(failure) => {
                execution.emitter.emit(
                    TransactionalMessagingObservation::ConsumerIngressRejected { reason: failure },
                );
                settle_observed(
                    settlement,
                    failure.into_settlement(),
                    deadline.operation(execution.timer),
                    execution.emitter,
                )
                .await?;
                return Ok(ProcessingDisposition::Rejected(failure));
            }
        };
    let delivered_fingerprint = MessageFingerprint::of(&message);
    if verified.subscription != *execution.subscription
        || verified.tenant_id != message.metadata().tenant_id()
        || verified.message_id != *message.id()
        || verified.contract != *message.metadata().contract()
        || verified.fingerprint != delivered_fingerprint
    {
        execution
            .emitter
            .emit(TransactionalMessagingObservation::ConsumerIngressRejected {
                reason: EnvelopeValidationFailure::FingerprintConflict,
            });
        settle_observed(
            settlement,
            EnvelopeValidationFailure::FingerprintConflict.into_settlement(),
            deadline.operation(execution.timer),
            execution.emitter,
        )
        .await?;
        return Ok(ProcessingDisposition::Rejected(
            EnvelopeValidationFailure::FingerprintConflict,
        ));
    }
    let fingerprint = verified.fingerprint;
    let identity = ConsumerIdentity::new(
        verified.tenant_id,
        execution.group.clone(),
        verified.message_id,
        verified.contract,
    );

    let claimed = match inbox
        .claim(&identity, deadline.operation(execution.timer))
        .await
    {
        Ok(claimed) => claimed,
        Err(error) => {
            settlement
                .abandon(deadline.operation(execution.timer))
                .await?;
            return Err(error);
        }
    };
    match claimed {
        IdempotencyDisposition::InProgress => {
            execution
                .emitter
                .emit(TransactionalMessagingObservation::ConsumerClaimInProgress);
            settle_observed(
                settlement,
                SettlementDecision(SettlementKind::Requeue),
                deadline.operation(execution.timer),
                execution.emitter,
            )
            .await?;
            Ok(ProcessingDisposition::InProgress)
        }
        IdempotencyDisposition::Terminal(receipt) => {
            if !receipt.matches(&identity, fingerprint) {
                settle_observed(
                    settlement,
                    EnvelopeValidationFailure::FingerprintConflict.into_settlement(),
                    deadline.operation(execution.timer),
                    execution.emitter,
                )
                .await?;
                return Ok(ProcessingDisposition::Rejected(
                    EnvelopeValidationFailure::FingerprintConflict,
                ));
            }
            let disposition = receipt.disposition();
            settle_observed(
                settlement,
                receipt.into_settlement(),
                deadline.operation(execution.timer),
                execution.emitter,
            )
            .await?;
            Ok(ProcessingDisposition::Duplicate(disposition))
        }
        IdempotencyDisposition::Acquired(claim) => {
            process_acquired(
                inbox,
                transaction,
                execution,
                AcquiredDelivery {
                    message,
                    settlement,
                    claim,
                    identity,
                    fingerprint,
                    deadline,
                },
            )
            .await
        }
    }
}

struct AcquiredDelivery<P, S, C> {
    message: MessageEnvelope<P>,
    settlement: S,
    claim: C,
    identity: ConsumerIdentity,
    fingerprint: MessageFingerprint,
    deadline: AbsoluteDeadline,
}

async fn process_acquired<P, S, I, T, V, R, E>(
    inbox: &I,
    transaction: &T,
    execution: &ConsumerExecution<'_, V, R, E>,
    state: AcquiredDelivery<P, S, I::Claim>,
) -> Result<ProcessingDisposition, MessagingError>
where
    P: AsRef<[u8]> + Send,
    S: DeliverySettlement,
    I: InboxStore,
    T: ConsumerTx<P, Claim = I::Claim>,
    R: RetryTimer,
    E: TransactionalMessagingEmitter,
{
    let mut attempt = std::num::NonZeroU32::MIN;
    loop {
        if state.deadline.remaining(execution.timer)
            <= execution.policy.budget().settlement_reserve()
        {
            release_or_abandon(
                inbox,
                state.claim,
                state.settlement,
                state.deadline.operation(execution.timer),
                execution.emitter,
            )
            .await?;
            return Ok(ProcessingDisposition::Deferred);
        }
        let lease_status = match inbox
            .extend(&state.claim, state.deadline.operation(execution.timer))
            .await
        {
            Ok(status) => status,
            Err(error) => {
                state
                    .settlement
                    .abandon(state.deadline.operation(execution.timer))
                    .await?;
                return Err(error);
            }
        };
        if lease_status == crate::inbox::LeaseStatus::Lost {
            execution
                .emitter
                .emit(TransactionalMessagingObservation::ConsumerLeaseLost);
            state
                .settlement
                .abandon(state.deadline.operation(execution.timer))
                .await?;
            return Ok(ProcessingDisposition::Fenced);
        }
        let outcome = transaction
            .execute(
                &state.claim,
                &state.message,
                ReceiptIntent::new(state.identity.clone(), state.fingerprint),
                state.deadline.operation(execution.timer),
            )
            .await;
        execution
            .emitter
            .emit(TransactionalMessagingObservation::ConsumerTransaction {
                status: transaction_status(&outcome),
            });
        if should_retry(&outcome, attempt, execution, &state).await {
            attempt = attempt.saturating_add(1);
            continue;
        }
        return finalize_outcome(inbox, execution.timer, execution.emitter, state, outcome).await;
    }
}

async fn should_retry<P, S, C, Proof, V, R, E>(
    outcome: &TransactionOutcome<Proof>,
    attempt: std::num::NonZeroU32,
    execution: &ConsumerExecution<'_, V, R, E>,
    state: &AcquiredDelivery<P, S, C>,
) -> bool
where
    R: RetryTimer,
{
    if !outcome.may_retry()
        || !execution
            .policy
            .retry()
            .allows_attempt(attempt.saturating_add(1))
    {
        return false;
    }
    let delay = execution.policy.retry().delay_after(attempt);
    if state.deadline.remaining(execution.timer)
        <= delay.saturating_add(execution.policy.budget().settlement_reserve())
    {
        return false;
    }
    execution
        .timer
        .delay(delay, state.deadline.operation(execution.timer))
        .await;
    true
}

async fn finalize_outcome<P, S, I, Proof, E>(
    inbox: &I,
    clock: &impl crate::policy::Clock,
    emitter: &E,
    state: AcquiredDelivery<P, S, I::Claim>,
    outcome: TransactionOutcome<Proof>,
) -> Result<ProcessingDisposition, MessagingError>
where
    S: DeliverySettlement,
    I: InboxStore,
    E: TransactionalMessagingEmitter,
{
    match outcome.state {
        TransactionOutcomeState::Committed { proof, receipt } => {
            drop(proof);
            if !receipt.matches(&state.identity, state.fingerprint) {
                settle_observed(
                    state.settlement,
                    SettlementDecision(SettlementKind::Requeue),
                    state.deadline.operation(clock),
                    emitter,
                )
                .await?;
                Ok(ProcessingDisposition::Rejected(
                    EnvelopeValidationFailure::FingerprintConflict,
                ))
            } else {
                let disposition = receipt.disposition();
                settle_observed(
                    state.settlement,
                    receipt.into_settlement(),
                    state.deadline.operation(clock),
                    emitter,
                )
                .await?;
                Ok(ProcessingDisposition::Committed(disposition))
            }
        }
        TransactionOutcomeState::NotStarted(_) | TransactionOutcomeState::RolledBack(_) => {
            release_or_abandon(
                inbox,
                state.claim,
                state.settlement,
                state.deadline.operation(clock),
                emitter,
            )
            .await?;
            Ok(ProcessingDisposition::Deferred)
        }
        TransactionOutcomeState::RollbackFailed | TransactionOutcomeState::CommitUnknown => {
            state
                .settlement
                .abandon(state.deadline.operation(clock))
                .await?;
            Ok(ProcessingDisposition::Deferred)
        }
        TransactionOutcomeState::Fenced => {
            emitter.emit(TransactionalMessagingObservation::ConsumerLeaseLost);
            state
                .settlement
                .abandon(state.deadline.operation(clock))
                .await?;
            Ok(ProcessingDisposition::Fenced)
        }
    }
}

fn transaction_status<P>(
    outcome: &TransactionOutcome<P>,
) -> TransactionalMessagingTransactionStatus {
    match &outcome.state {
        TransactionOutcomeState::Committed { .. } => {
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

async fn settle_observed<S: DeliverySettlement>(
    settlement: S,
    decision: SettlementDecision,
    deadline: OperationDeadline,
    emitter: &impl TransactionalMessagingEmitter,
) -> Result<(), MessagingError> {
    let action = match decision.kind() {
        SettlementKind::Acknowledge => TransactionalMessagingDisposition::Ack,
        SettlementKind::Requeue => TransactionalMessagingDisposition::Requeue,
        SettlementKind::Reject => TransactionalMessagingDisposition::Reject,
    };
    let result = settlement.settle(decision, deadline).await;
    emitter.emit(TransactionalMessagingObservation::ConsumerSettlement {
        action,
        outcome: if result.is_ok() {
            TransactionalMessagingIoOutcome::Ok
        } else {
            TransactionalMessagingIoOutcome::Error
        },
    });
    result
}

async fn release_or_abandon<I: InboxStore, S: DeliverySettlement>(
    inbox: &I,
    claim: I::Claim,
    settlement: S,
    deadline: OperationDeadline,
    emitter: &impl TransactionalMessagingEmitter,
) -> Result<(), MessagingError> {
    match inbox.release(claim, deadline).await {
        Ok(()) => {
            settle_observed(
                settlement,
                SettlementDecision(SettlementKind::Requeue),
                deadline,
                emitter,
            )
            .await
        }
        Err(error) => {
            emitter.emit(TransactionalMessagingObservation::ConsumerReleaseFailed);
            settlement.abandon(deadline).await?;
            Err(error)
        }
    }
}
