//! Durable publication admission and ordered settlement.
//!
//! [`OutboxStore`] owns storage; [`crate::transport::Publisher`] supplies publication evidence.
//! Retries preserve the original message ID and fingerprint. [`PartitionHead`] models the local
//! gate only: providers must enforce the same transitions with durable fencing and atomic updates.

use crate::error::MessagingError;
use crate::message::{MessageEnvelope, MessageFingerprint, MessageId, PartitionIdentity};
use crate::policy::OperationDeadline;
use std::num::NonZeroUsize;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Admission result inside the caller's transaction; durability still requires commit.
pub enum AppendOutcome {
    /// A new outbox record was staged in the transaction.
    Inserted,
    /// The same durable identity and fingerprint already exist; no replacement was made.
    AlreadyPresent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// State transition requested for an outbox record after a delivery attempt.
pub enum OutboxDisposition {
    /// Publication was confirmed; resolve the record and allow its successor.
    Published,
    /// Keep the same record and message ID eligible for another attempt.
    Retry,
    /// Stop automatic publication while keeping an ordered successor blocked.
    DeadLetter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Provider-authoritative ownership and remaining delivery budget.
pub enum OutboxLeaseStatus {
    /// This attempt still owns the fenced claim.
    Held {
        /// Provider-authoritative time remaining before the claim expires.
        remaining: Duration,
        /// Remaining same-ID delivery window. `None` means no provider window;
        /// `Some(Duration::ZERO)` means provider-authoritative expiry.
        delivery_remaining: Option<Duration>,
    },
    /// The claim expired or was fenced; do not publish or settle with it.
    Lost,
}

/// Core-classified durable resolution supplied to the store's settlement CAS.
pub enum OutboxSettlement<R> {
    /// Mark confirmed publication as resolved; the receipt need not itself be persisted.
    Published(R),
    /// Keep the original message ID and authored facts for redelivery, including ambiguous
    /// publication.
    Retry,
    /// Stop automatic attempts without unblocking the partition successor.
    DeadLetter,
}

impl<R> OutboxSettlement<R> {
    #[must_use]
    /// The requested transition without consuming its publication receipt.
    pub const fn disposition(&self) -> OutboxDisposition {
        match self {
            Self::Published(_) => OutboxDisposition::Published,
            Self::Retry => OutboxDisposition::Retry,
            Self::DeadLetter => OutboxDisposition::DeadLetter,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// In-memory ordering gate for one partition head.
pub enum PartitionHeadState {
    /// The head may be claimed; its successor remains blocked.
    Available,
    /// The head is being delivered; its successor remains blocked.
    InFlight,
    /// Automatic attempts stopped; explicit resolution is required to unblock the successor.
    DeadLettered,
    /// The head no longer blocks its successor.
    Resolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
/// A requested transition is invalid for the current head state; the state is unchanged.
pub enum PartitionTransitionError {
    #[error("partition head is not claimable")]
    /// Only an available head can be claimed.
    NotClaimable,
    #[error("partition head is not in flight")]
    /// Only an in-flight head can be settled.
    NotInFlight,
    #[error("partition head is not dead-lettered")]
    /// Only a dead-lettered head can be explicitly resolved.
    NotDeadLettered,
}

/// Provider-neutral head gate. A successor is blocked until this head is resolved, including while
/// a dead letter awaits explicit resolution. These methods do not perform storage I/O.
pub struct PartitionHead {
    identity: PartitionIdentity,
    message_id: MessageId,
    state: PartitionHeadState,
}

impl PartitionHead {
    #[must_use]
    /// Create an available head for the given partition and message.
    pub const fn new(identity: PartitionIdentity, message_id: MessageId) -> Self {
        Self {
            identity,
            message_id,
            state: PartitionHeadState::Available,
        }
    }

    #[must_use]
    /// Tenant, domain, and key defining this ordered sequence.
    pub const fn identity(&self) -> &PartitionIdentity {
        &self.identity
    }
    #[must_use]
    /// Message currently gating the sequence.
    pub const fn message_id(&self) -> &MessageId {
        &self.message_id
    }
    #[must_use]
    /// Current in-memory gate state.
    pub const fn state(&self) -> PartitionHeadState {
        self.state
    }
    #[must_use]
    /// Whether this head is resolved and no longer blocks the next message.
    pub const fn allows_successor(&self) -> bool {
        matches!(self.state, PartitionHeadState::Resolved)
    }

    /// Move an available head into flight, or return [`PartitionTransitionError::NotClaimable`].
    pub fn claim(&mut self) -> Result<(), PartitionTransitionError> {
        if self.state != PartitionHeadState::Available {
            return Err(PartitionTransitionError::NotClaimable);
        }
        self.state = PartitionHeadState::InFlight;
        Ok(())
    }

    /// Apply publication disposition to an in-flight head, or return
    /// [`PartitionTransitionError::NotInFlight`].
    pub fn settle(
        &mut self,
        disposition: OutboxDisposition,
    ) -> Result<(), PartitionTransitionError> {
        if self.state != PartitionHeadState::InFlight {
            return Err(PartitionTransitionError::NotInFlight);
        }
        self.state = match disposition {
            OutboxDisposition::Published => PartitionHeadState::Resolved,
            OutboxDisposition::Retry => PartitionHeadState::Available,
            OutboxDisposition::DeadLetter => PartitionHeadState::DeadLettered,
        };
        Ok(())
    }

    /// Unblock the successor, or return [`PartitionTransitionError::NotDeadLettered`] if resolution
    /// is inapplicable.
    pub fn resolve_dead_letter(&mut self) -> Result<(), PartitionTransitionError> {
        if self.state != PartitionHeadState::DeadLettered {
            return Err(PartitionTransitionError::NotDeadLettered);
        }
        self.state = PartitionHeadState::Resolved;
        Ok(())
    }
}

/// Envelope paired with its authored fingerprint for durable outbox admission.
pub struct PendingMessage<P> {
    envelope: MessageEnvelope<P>,
    fingerprint: MessageFingerprint,
}

impl<P: AsRef<[u8]>> PendingMessage<P> {
    #[must_use]
    /// Compute the fingerprint before handing the envelope to storage.
    pub fn new(envelope: MessageEnvelope<P>) -> Self {
        let fingerprint = MessageFingerprint::of(&envelope);
        Self {
            envelope,
            fingerprint,
        }
    }
}

impl<P> PendingMessage<P> {
    #[must_use]
    /// Original authored message to preserve across delivery attempts.
    pub const fn envelope(&self) -> &MessageEnvelope<P> {
        &self.envelope
    }
    #[must_use]
    /// Digest captured when this pending message was created.
    pub const fn fingerprint(&self) -> MessageFingerprint {
        self.fingerprint
    }
    #[must_use]
    /// Stable authored ID used on every publication attempt.
    pub const fn message_id(&self) -> &MessageId {
        self.envelope.id()
    }
    #[must_use]
    /// Optional tenant-scoped sequence whose head gates this message.
    pub fn partition(&self) -> Option<&PartitionIdentity> {
        self.envelope.metadata().partition()
    }
}

/// Provider-returned claim batch whose size was checked against the requested hard bound.
pub struct OutboxClaimBatch<C> {
    claims: Vec<C>,
}

/// A provider returned more durable claims than the caller admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("outbox provider returned {actual} claims for a requested limit of {limit}")]
pub struct OutboxClaimBatchError {
    limit: usize,
    actual: usize,
}

impl OutboxClaimBatchError {
    /// Requested maximum number of durable claims.
    #[must_use]
    pub const fn limit(self) -> usize {
        self.limit
    }

    /// Actual number of claims returned by the provider.
    #[must_use]
    pub const fn actual(self) -> usize {
        self.actual
    }
}

impl<C> OutboxClaimBatch<C> {
    /// Reject a batch larger than `limit` with [`OutboxClaimBatchError`].
    /// This only checks the vector length; the provider must bound acquisition itself and clean
    /// up any excess durable claims. Dropping rejected handles does not release them here.
    pub fn try_from_provider(
        claims: Vec<C>,
        limit: NonZeroUsize,
    ) -> Result<Self, OutboxClaimBatchError> {
        if claims.len() > limit.get() {
            return Err(OutboxClaimBatchError {
                limit: limit.get(),
                actual: claims.len(),
            });
        }
        Ok(Self { claims })
    }

    /// Number of admitted claims.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.claims.len()
    }

    /// Whether the provider returned no claims.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }
}

impl<C> IntoIterator for OutboxClaimBatch<C> {
    type Item = C;
    type IntoIter = std::vec::IntoIter<C>;

    fn into_iter(self) -> Self::IntoIter {
        self.claims.into_iter()
    }
}

/// Transactional admission and fenced settlement of durable outbox records.
///
/// Providers must isolate records by tenant and use authoritative time for leases and any same-ID
/// delivery window. Claim, renewal, and settlement must enforce fencing atomically; an expired
/// attempt cannot mutate another owner's record. Dead-letter heads continue blocking successors.
///
/// # Errors and cancellation
///
/// Report I/O failures through [`MessagingError`]. Settlement with lost ownership must fail with
/// [`OwnershipLost`](crate::error::MessagingErrorKind::OwnershipLost), not overwrite newer state.
/// Follow [`within`](crate::policy::within) for deadline and cancellation obligations. Recover
/// using the existing identity and authoritative state.
pub trait OutboxStore<P>: Send + Sync {
    /// Single provider-owned budget used for durable lease TTL and runtime delivery admission.
    fn delivery_budget(&self) -> crate::policy::DeliveryBudget;
    /// Caller transaction in which business effects and outbox admission commit together.
    type Transaction<'tx>;
    /// Durable record identity and fencing authority for one attempt.
    type Claim: Send;
    /// Confirmation evidence returned by the paired publisher.
    type PublishReceipt: Send;

    /// Stage the message in the supplied transaction; do not commit the caller's transaction.
    /// Return `AlreadyPresent` only for the same identity and fingerprint. Different authored facts
    /// under that identity must return [`Conflict`](crate::error::MessagingErrorKind::Conflict).
    /// This method has no deadline parameter: the caller owns the enclosing transaction's budget
    /// and must resolve or isolate that transaction on cancellation.
    fn append(
        &self,
        transaction: &mut Self::Transaction<'_>,
        message: PendingMessage<P>,
    ) -> impl Future<Output = Result<AppendOutcome, MessagingError>> + Send;

    /// Claim only the unresolved head of each `(tenant, domain, partition key)` sequence. An
    /// unresolved dead-letter head is not eligible and must continue blocking its successor.
    /// Atomically lease at most `limit` records; an empty batch means no eligible work was found.
    fn claim_partition_heads(
        &self,
        limit: NonZeroUsize,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<OutboxClaimBatch<Self::Claim>, MessagingError>> + Send;

    /// Check ownership using provider-authoritative time and fencing state.
    fn lease_status(
        &self,
        claim: &Self::Claim,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<OutboxLeaseStatus, MessagingError>> + Send;

    /// Extend only a still-owned lease and return the post-renewal remaining time.
    /// Return `Lost` if fenced or expired; renewal must not reset the same-ID delivery window.
    fn extend(
        &self,
        claim: &Self::Claim,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<OutboxLeaseStatus, MessagingError>> + Send;

    /// Borrow the original message associated with this claim, without performing I/O.
    fn message(claim: &Self::Claim) -> &PendingMessage<P>;

    /// Consume a claim and atomically persist its resolution using a fencing compare-and-set.
    /// `Published` marks confirmed publication durably before unblocking a successor; it does not
    /// require receipt persistence. `Retry` keeps the original identity and content; `DeadLetter`
    /// keeps an ordered successor blocked.
    fn settle(
        &self,
        claim: Self::Claim,
        settlement: OutboxSettlement<Self::PublishReceipt>,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<(), MessagingError>> + Send;
}
