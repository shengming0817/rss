//! Transaction outcomes and, with `consumer`, settlement authority.
//!
//! [`LocalTxAttempt`] preserves commit, rollback, and uncertainty as distinct outcomes; its
//! constructors report provider facts rather than executing or proving a transaction.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Failure category used with the transaction outcome to choose recovery.
pub enum FailureClass {
    /// A handler failure eligible for local retry only when no effect started or rollback was
    /// confirmed.
    Transient,
    /// The unchanged request cannot succeed; this classification alone grants no Reject authority.
    Permanent,
    /// Provider infrastructure failed; defer recovery to redelivery rather than local handler
    /// retry.
    Infrastructure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Transaction phase whose deadline elapsed, for bounded diagnostics.
pub enum LocalTxDeadlineStage {
    /// Waiting for a provider resource or connection.
    Acquire,
    /// Starting the local transaction.
    Begin,
    /// Establishing transaction-local context before the operation.
    Setup,
    /// Executing the handler or transactional operation.
    Operation,
    /// Waiting before another attempt under the original deadline.
    Backoff,
    /// Awaiting commit acknowledgement; expiry may leave the outcome unknown.
    Commit,
    /// Awaiting rollback acknowledgement; expiry leaves cleanup unconfirmed.
    Rollback,
}

impl LocalTxDeadlineStage {
    /// All supported deadline phases for exhaustive diagnostic registration.
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
    /// Stable phase label without transaction or provider data.
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
/// Provider-reported terminal transaction status for diagnostics.
pub enum LocalTxFinalStatus {
    /// Commit acknowledgement was received.
    Committed,
    /// Rollback acknowledgement was received.
    RolledBack,
    /// Rollback could not be confirmed; the attempt must be isolated.
    RollbackFailed,
    /// Commit may have happened; do not treat it as a confirmed rollback.
    CommitUnknown,
}

impl LocalTxFinalStatus {
    /// All terminal statuses for exhaustive diagnostic registration.
    pub const ALL: &'static [Self] = &[
        Self::Committed,
        Self::RolledBack,
        Self::RollbackFailed,
        Self::CommitUnknown,
    ];
    #[must_use]
    /// Stable outcome label without provider error text.
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
/// Reason a transaction attempt failed, distinct from whether its effects are known.
pub enum TxRetryClass {
    /// A later attempt may succeed if the transaction outcome permits retry.
    Transient,
    /// Submitted state conflicts with authoritative state.
    Conflict,
    /// The unchanged request cannot succeed.
    Permanent,
    /// This attempt no longer has lease or fencing authority.
    OwnershipLost,
}

impl TxRetryClass {
    /// All supported retry categories for exhaustive diagnostic registration.
    pub const ALL: &'static [Self] = &[
        Self::Transient,
        Self::Conflict,
        Self::Permanent,
        Self::OwnershipLost,
    ];
    #[must_use]
    /// Stable recovery-category label.
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
/// Why a bounded transaction retry sequence ended.
pub enum TxRetryFinalStatus {
    /// An attempt completed successfully.
    Success,
    /// The retry allowance was consumed without success.
    Exhausted,
    /// Retry stopped with the supplied classification.
    NotRetryable(TxRetryClass),
}

impl TxRetryFinalStatus {
    #[must_use]
    /// Stable final label, distinguishing a transient failure that was not retried.
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

/// Provider-reported attempt consumed through [`LocalTxAttempt::fold`] without losing uncertainty.
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
    /// Record acknowledged commit and retain its provider result; this performs no commit itself.
    pub fn committed(value: T) -> Self {
        Self {
            state: LocalTxAttemptState::Committed(value),
        }
    }
    #[must_use]
    /// Record failure before the transactional operation began.
    pub fn not_started(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::NotStarted(error),
        }
    }
    #[must_use]
    /// Record failure with acknowledged rollback of the transaction.
    pub fn rolled_back(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::RolledBack(error),
        }
    }
    #[must_use]
    /// Record unconfirmed rollback; the provider must isolate the unresolved attempt.
    pub fn rollback_failed(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::RollbackFailed(error),
        }
    }
    #[must_use]
    /// Record uncertain commit; the provider must not report rollback or retry as if no effect
    /// occurred.
    pub fn commit_unknown(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::CommitUnknown(error),
        }
    }
    #[must_use]
    /// Record loss of fencing authority, preventing further effects by this attempt.
    pub fn fenced(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::Fenced(error),
        }
    }

    /// Consume the attempt and invoke exactly one callback, preserving distinct uncertain outcomes.
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

#[cfg(feature = "consumer")]
mod consumer {
    use std::future::Future;

    use crate::inbox::{ConsumerGroup, ConsumerIdentity};
    use crate::message::{MessageEnvelope, MessageFingerprint, MessageId, SubscriptionIdentity};
    use crate::observability::TransactionalMessagingTransactionStatus;
    use crate::policy::OperationDeadline;

    use super::FailureClass;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    /// Reason for a durable terminal rejection.
    pub enum RejectKind {
        /// The message cannot be processed successfully without changing the request.
        Permanent,
        /// Processing violated a required invariant.
        Invariant,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    /// Durable terminal result whose validated projection determines broker settlement.
    pub enum TerminalDisposition {
        /// Handler effects and the terminal receipt committed together; projects to ACK.
        Succeeded,
        /// A terminal rejection was durably recorded; projects to Reject.
        Rejected(RejectKind),
    }

    impl TerminalDisposition {
        #[must_use]
        /// Stable terminal label, including the rejection category.
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
        /// Durable tenant, group, message, and contract identity reported by the provider.
        pub const fn consumer(&self) -> &ConsumerIdentity {
            &self.consumer
        }
        #[must_use]
        /// Message ID contained in the durable consumer identity.
        pub const fn message_id(&self) -> &MessageId {
            self.consumer.message_id()
        }
        #[must_use]
        /// Authored digest recorded with the terminal result.
        pub const fn fingerprint(&self) -> MessageFingerprint {
            self.fingerprint
        }
        #[must_use]
        /// Durable result reported by the provider, before ingress matching.
        pub const fn disposition(&self) -> TerminalDisposition {
            self.disposition
        }
        #[must_use]
        /// Compare the complete consumer identity and fingerprint; this does not authenticate
        /// storage evidence.
        pub fn matches(
            &self,
            consumer: &ConsumerIdentity,
            fingerprint: MessageFingerprint,
        ) -> bool {
            self.consumer == *consumer && self.fingerprint == fingerprint
        }
    }

    impl std::fmt::Debug for TerminalReceipt {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("TerminalReceipt(<redacted>)")
        }
    }

    /// Move-only identity and fingerprint obtained from
    /// [`VerifiedConsumerBinding::receipt_intent`].
    /// The trusted transaction provider consumes it after atomically persisting the terminal
    /// result.
    pub struct ReceiptIntent {
        consumer: ConsumerIdentity,
        fingerprint: MessageFingerprint,
    }

    impl ReceiptIntent {
        /// Identity authorized by the core for this receipt intent.
        #[must_use]
        pub const fn consumer(&self) -> &ConsumerIdentity {
            &self.consumer
        }

        /// Message digest authorized by the core for this receipt intent.
        #[must_use]
        pub const fn fingerprint(&self) -> MessageFingerprint {
            self.fingerprint
        }

        fn new(consumer: ConsumerIdentity, fingerprint: MessageFingerprint) -> Self {
            Self {
                consumer,
                fingerprint,
            }
        }

        /// Report acknowledged atomic commit and produce terminal settlement authority.
        /// Persist this intent's identity, fingerprint, and disposition with the handler effects
        /// before calling. This method performs no I/O and cannot validate the supplied proof.
        #[must_use]
        pub fn committed<P>(
            self,
            proof: P,
            disposition: TerminalDisposition,
        ) -> TransactionOutcome<P> {
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

    /// Consumer attempt result; only a consumed [`ReceiptIntent`] can form its committed branch.
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
        /// Record failure before handler effects began; no settlement authority is granted.
        pub const fn not_started(class: FailureClass) -> Self {
            Self {
                state: TransactionOutcomeState::NotStarted(class),
            }
        }
        #[must_use]
        /// Record a confirmed rollback; no settlement authority is granted.
        pub const fn rolled_back(class: FailureClass) -> Self {
            Self {
                state: TransactionOutcomeState::RolledBack(class),
            }
        }
        #[must_use]
        /// Record uncertain rollback; abandon the attempt without ACK or local retry.
        pub const fn rollback_failed() -> Self {
            Self {
                state: TransactionOutcomeState::RollbackFailed,
            }
        }
        #[must_use]
        /// Record uncertain commit; abandon the attempt without ACK or local retry.
        pub const fn commit_unknown() -> Self {
            Self {
                state: TransactionOutcomeState::CommitUnknown,
            }
        }
        #[must_use]
        /// Record loss of ownership; stop effects and abandon this attempt without ACK.
        pub const fn fenced() -> Self {
            Self {
                state: TransactionOutcomeState::Fenced,
            }
        }

        #[must_use]
        /// Whether a transient not-started or rolled-back attempt permits local retry; budget and
        /// lease checks still apply.
        pub const fn may_retry(&self) -> bool {
            matches!(
                &self.state,
                TransactionOutcomeState::NotStarted(FailureClass::Transient)
                    | TransactionOutcomeState::RolledBack(FailureClass::Transient)
            )
        }

        /// Return the closed, low-cardinality transaction status without exposing the private
        /// state.
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

    /// A verified terminal result that can be projected into broker settlement at most once.
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

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    /// Broker action label; possession of this enum alone grants no settlement authority.
    pub enum SettlementKind {
        /// Acknowledge a delivery backed by validated successful terminal evidence.
        Acknowledge,
        /// Return the delivery for a later attempt without claiming success.
        Requeue,
        /// Reject a delivery using terminal or ingress/decode rejection authority.
        Reject,
    }

    /// Move-only broker decision. Callers can directly request only [`Self::requeue`].
    /// ACK requires [`TerminalSettlement`]; Reject requires terminal, ingress, or decode authority.
    /// These capabilities depend on truthful trusted validators and providers.
    pub struct SettlementDecision(SettlementKind);

    impl SettlementDecision {
        /// Construct the conservative redelivery decision available to runtime orchestration.
        #[must_use]
        pub const fn requeue() -> Self {
            Self(SettlementKind::Requeue)
        }

        #[must_use]
        /// Inspect the authorized action without consuming or duplicating its authority.
        pub const fn kind(&self) -> SettlementKind {
            self.0
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    /// Safe reason for rejecting decoded input or mismatched ingress evidence.
    pub enum EnvelopeValidationFailure {
        /// Message identity or tenant authority could not be accepted.
        MalformedIdentity,
        /// Required authored metadata is invalid.
        MalformedMetadata,
        /// The envelope does not match the accepted routing or contract requirements.
        UnsupportedContract,
        /// Identity or authored digest differs from the evidence being checked.
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

    /// Trusted transaction provider that atomically binds handler effects and terminal receipt
    /// state.
    ///
    /// A timeout may occur after commit begins, so implementations must quarantine or close an
    /// attempt
    /// without an explicit commit/rollback acknowledgement; callers conservatively treat it as
    /// commit
    /// outcome unknown. The claim, message, and receipt must agree on tenant, identity, and digest;
    /// enforce fencing in the same transaction as the handler effects and terminal receipt.
    /// Call [`ReceiptIntent::committed`] only after acknowledged atomic commit. Success authorizes
    /// ACK; merely invoking a constructor cannot prove durability.
    ///
    /// # Failures and cancellation
    ///
    /// Preserve failure classes and commit/rollback uncertainty in [`TransactionOutcome`]. Enforce
    /// [`OperationDeadline`] as the provider I/O watchdog. The caller also uses
    /// [`within`](crate::policy::within); an execute timeout is conservatively `CommitUnknown`,
    /// followed by abandon rather than ACK. No uncertain or fenced outcome permits local retry.
    pub trait ConsumerTx<P>: Send + Sync {
        /// Inbox claim whose identity and fencing generation protect this transaction.
        type Claim: Send + Sync;
        /// Provider evidence retained alongside terminal settlement after acknowledged commit.
        type CommitProof: Send;

        /// Execute under the current claim and atomically commit handler effects with the supplied
        /// receipt identity.
        fn execute(
            &self,
            claim: &Self::Claim,
            message: &MessageEnvelope<P>,
            receipt: ReceiptIntent,
            deadline: OperationDeadline,
        ) -> impl Future<Output = TransactionOutcome<Self::CommitProof>> + Send;
    }

    /// Core-issued, move-only ingress candidate. Only the delivery pipeline can construct it; a
    /// validator checks this exact subscription/message pair before returning bound evidence.
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

        /// Bind the current facts after the validator has authenticated tenant authority and
        /// checked
        /// subscription compatibility. This method records the facts; it does not perform those
        /// checks.
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

    /// Trusted authority check before durable inbox access or business effects.
    ///
    /// Authenticate transport tenant authority against the authored tenant and verify the exact
    /// subscription's routing and contract requirements. Do not equate well-formed IDs or a
    /// matching
    /// fingerprint with authentication. Return [`IngressChallenge::verified`] only after these
    /// checks.
    pub trait IngressValidator<P>: Send + Sync {
        /// Return evidence for this challenge, or [`EnvelopeValidationFailure`] on rejected input.
        /// This synchronous boundary must not perform blocking provider I/O.
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

    /// Rejection authority supplied by a trusted provider decoder through
    /// [`IncomingDelivery::invalid_from_provider`](crate::transport::IncomingDelivery::invalid_from_provider).
    /// That public provider boundary reports a decode failure; it cannot prove the report is
    /// truthful.
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

        /// Match a durable receipt to verified ingress before granting ACK or Reject authority.
        /// Return an [`IngressRejection`] with `FingerprintConflict` on any identity or digest
        /// mismatch. Matching trusts the provider's durable fact; it does not re-read storage.
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
    /// The trusted [`IngressValidator`] establishes authority; this function checks that its
    /// evidence
    /// matches this exact subscription and envelope before creating the inbox binding. The binding
    /// supplies a [`ReceiptIntent`] for new work or validates a [`TerminalReceipt`] for a
    /// duplicate.
    ///
    /// # Errors
    ///
    /// Return the validator's rejection, or `FingerprintConflict` if returned evidence differs from
    /// the supplied facts. Neither path executes a handler or performs durable I/O.
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
}

#[cfg(feature = "consumer")]
pub use consumer::{
    CommittedTransaction, ConsumerTx, DecodeRejection, EnvelopeValidationFailure, IngressChallenge,
    IngressRejection, IngressValidator, ReceiptIntent, RejectKind, SettlementDecision,
    SettlementKind, TerminalDisposition, TerminalReceipt, TerminalSettlement, TransactionOutcome,
    VerifiedConsumerBinding, VerifiedIngress, verify_ingress,
};
