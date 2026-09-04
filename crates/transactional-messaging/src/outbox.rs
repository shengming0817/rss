//! Transactional outbox state and storage port, independent from publication.

use crate::error::MessagingError;
use crate::message::{MessageEnvelope, MessageFingerprint, MessageId, PartitionIdentity};
use crate::policy::OperationDeadline;
use std::num::NonZeroUsize;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `AppendOutcome` protocol type.
pub enum AppendOutcome {
    /// `Inserted` state in the closed protocol.
    Inserted,
    /// `AlreadyPresent` state in the closed protocol.
    AlreadyPresent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `OutboxDisposition` protocol type.
pub enum OutboxDisposition {
    /// `Published` state in the closed protocol.
    Published,
    /// `Retry` state in the closed protocol.
    Retry,
    /// `DeadLetter` state in the closed protocol.
    DeadLetter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `OutboxLeaseStatus` protocol type.
pub enum OutboxLeaseStatus {
    /// `Held` state in the closed protocol.
    Held {
        /// Provider-authoritative time remaining before the claim expires.
        remaining: Duration,
    },
    /// `Lost` state in the closed protocol.
    Lost,
}

/// Core-classified durable resolution supplied to the store's settlement CAS.
pub enum OutboxSettlement<R> {
    /// `Published` state in the closed protocol.
    Published(R),
    /// `Retry` state in the closed protocol.
    Retry,
    /// `DeadLetter` state in the closed protocol.
    DeadLetter,
}

impl<R> OutboxSettlement<R> {
    #[must_use]
    /// `disposition` operation defined by this protocol type.
    pub const fn disposition(&self) -> OutboxDisposition {
        match self {
            Self::Published(_) => OutboxDisposition::Published,
            Self::Retry => OutboxDisposition::Retry,
            Self::DeadLetter => OutboxDisposition::DeadLetter,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `PartitionHeadState` protocol type.
pub enum PartitionHeadState {
    /// `Available` state in the closed protocol.
    Available,
    /// `InFlight` state in the closed protocol.
    InFlight,
    /// `DeadLettered` state in the closed protocol.
    DeadLettered,
    /// `Resolved` state in the closed protocol.
    Resolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
/// Closed `PartitionTransitionError` protocol type.
pub enum PartitionTransitionError {
    #[error("partition head is not claimable")]
    /// `NotClaimable` state in the closed protocol.
    NotClaimable,
    #[error("partition head is not in flight")]
    /// `NotInFlight` state in the closed protocol.
    NotInFlight,
    #[error("partition head is not dead-lettered")]
    /// `NotDeadLettered` state in the closed protocol.
    NotDeadLettered,
}

/// Provider-neutral head gate. A successor is blocked until this head is resolved, including while
/// a dead letter awaits explicit operator resolution.
pub struct PartitionHead {
    identity: PartitionIdentity,
    message_id: MessageId,
    state: PartitionHeadState,
}

impl PartitionHead {
    #[must_use]
    /// `new` operation defined by this protocol type.
    pub const fn new(identity: PartitionIdentity, message_id: MessageId) -> Self {
        Self {
            identity,
            message_id,
            state: PartitionHeadState::Available,
        }
    }

    #[must_use]
    /// `identity` operation defined by this protocol type.
    pub const fn identity(&self) -> &PartitionIdentity {
        &self.identity
    }
    #[must_use]
    /// `message_id` operation defined by this protocol type.
    pub const fn message_id(&self) -> &MessageId {
        &self.message_id
    }
    #[must_use]
    /// `state` operation defined by this protocol type.
    pub const fn state(&self) -> PartitionHeadState {
        self.state
    }
    #[must_use]
    /// `allows_successor` operation defined by this protocol type.
    pub const fn allows_successor(&self) -> bool {
        matches!(self.state, PartitionHeadState::Resolved)
    }

    /// `claim` operation defined by this protocol type.
    pub fn claim(&mut self) -> Result<(), PartitionTransitionError> {
        if self.state != PartitionHeadState::Available {
            return Err(PartitionTransitionError::NotClaimable);
        }
        self.state = PartitionHeadState::InFlight;
        Ok(())
    }

    /// `settle` operation defined by this protocol type.
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

    /// `resolve_dead_letter` operation defined by this protocol type.
    pub fn resolve_dead_letter(&mut self) -> Result<(), PartitionTransitionError> {
        if self.state != PartitionHeadState::DeadLettered {
            return Err(PartitionTransitionError::NotDeadLettered);
        }
        self.state = PartitionHeadState::Resolved;
        Ok(())
    }
}

/// Closed `PendingMessage` protocol type.
pub struct PendingMessage<P> {
    envelope: MessageEnvelope<P>,
    fingerprint: MessageFingerprint,
}

impl<P: AsRef<[u8]>> PendingMessage<P> {
    #[must_use]
    /// `new` operation defined by this protocol type.
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
    /// `envelope` operation defined by this protocol type.
    pub const fn envelope(&self) -> &MessageEnvelope<P> {
        &self.envelope
    }
    #[must_use]
    /// `fingerprint` operation defined by this protocol type.
    pub const fn fingerprint(&self) -> MessageFingerprint {
        self.fingerprint
    }
    #[must_use]
    /// `message_id` operation defined by this protocol type.
    pub const fn message_id(&self) -> &MessageId {
        self.envelope.id()
    }
    #[must_use]
    /// `partition` operation defined by this protocol type.
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
    /// Validate claims at the provider boundary before exposing them to runtime execution.
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

/// Closed `OutboxStore` protocol type.
pub trait OutboxStore<P>: Send + Sync {
    /// Provider-owned `Transaction` capability used by this port.
    type Transaction;
    /// Provider-owned `Claim` capability used by this port.
    type Claim: Send;
    /// Provider-owned `PublishReceipt` capability used by this port.
    type PublishReceipt: Send;

    /// Canonical operation owned by the transactional messaging core.
    fn append(
        &self,
        transaction: &mut Self::Transaction,
        message: PendingMessage<P>,
    ) -> impl Future<Output = Result<AppendOutcome, MessagingError>> + Send;

    /// Claim only the unresolved head of each `(tenant, domain, partition key)` sequence. An
    /// unresolved dead-letter head is not eligible and must continue blocking its successor.
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

    /// Extend an owned lease using provider-authoritative time.
    fn extend(
        &self,
        claim: &Self::Claim,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<OutboxLeaseStatus, MessagingError>> + Send;

    /// Canonical operation owned by the transactional messaging core.
    fn message(claim: &Self::Claim) -> &PendingMessage<P>;

    /// Canonical operation owned by the transactional messaging core.
    fn settle(
        &self,
        claim: Self::Claim,
        settlement: OutboxSettlement<Self::PublishReceipt>,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<(), MessagingError>> + Send;
}
