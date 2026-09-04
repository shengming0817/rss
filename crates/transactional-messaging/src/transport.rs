//! Provider-neutral publication, delivery, and one-shot settlement ports.

#[cfg(feature = "consumer")]
use futures::Stream;
#[cfg(feature = "consumer")]
use futures::StreamExt as _;

#[cfg(feature = "consumer")]
use crate::error::MessagingError;
#[cfg(any(feature = "consumer", feature = "producer"))]
use crate::message::MessageEnvelope;
#[cfg(feature = "consumer")]
use crate::message::SubscriptionIdentity;
#[cfg(feature = "producer")]
use crate::outbox::OutboxSettlement;
#[cfg(any(feature = "consumer", feature = "producer"))]
use crate::policy::OperationDeadline;
#[cfg(feature = "consumer")]
use crate::transaction::{DecodeRejection, EnvelopeValidationFailure, SettlementDecision};

#[cfg(feature = "producer")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `PublishFailureKind` protocol type.
pub enum PublishFailureKind {
    /// `Transient` state in the closed protocol.
    Transient,
    /// `Permanent` state in the closed protocol.
    Permanent,
}

/// Provider-neutral stage at which publication failed or became ambiguous.
#[cfg(feature = "producer")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishFailureStage {
    /// Envelope could not be encoded for the provider.
    Encode,
    /// Transport admission failed before any send was attempted.
    Admission,
    /// Provider send failed before acceptance was possible.
    Send,
    /// Provider acknowledgement or confirmation did not complete.
    Confirm,
}

#[cfg(feature = "producer")]
impl PublishFailureStage {
    /// Stable low-cardinality observation label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Encode => "encode",
            Self::Admission => "admission",
            Self::Send => "send",
            Self::Confirm => "confirm",
        }
    }
}

/// Safe closed reason retained across the provider-to-relay boundary.
#[cfg(feature = "producer")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishFailureReason {
    /// Authored message data cannot be represented by the provider.
    InvalidMessage,
    /// Provider transport is unavailable or fenced.
    TransportUnavailable,
    /// The core-owned operation deadline elapsed.
    DeadlineElapsed,
    /// The provider explicitly rejected the publication.
    ProviderRejected,
}

#[cfg(feature = "producer")]
impl PublishFailureReason {
    /// Stable low-cardinality observation label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::InvalidMessage => "invalid_message",
            Self::TransportUnavailable => "transport_unavailable",
            Self::DeadlineElapsed => "deadline_elapsed",
            Self::ProviderRejected => "provider_rejected",
        }
    }
}

/// Typed publication diagnostic without provider error text or message identity.
#[cfg(feature = "producer")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishFailure {
    kind: PublishFailureKind,
    stage: PublishFailureStage,
    reason: PublishFailureReason,
}

#[cfg(feature = "producer")]
impl PublishFailure {
    /// Construct a closed provider diagnostic at the adapter mapping boundary.
    #[must_use]
    pub const fn new(
        kind: PublishFailureKind,
        stage: PublishFailureStage,
        reason: PublishFailureReason,
    ) -> Self {
        Self {
            kind,
            stage,
            reason,
        }
    }

    /// Retry classification used by the canonical relay.
    #[must_use]
    pub const fn kind(self) -> PublishFailureKind {
        self.kind
    }
    /// Stable provider-neutral failure stage.
    #[must_use]
    pub const fn stage(self) -> PublishFailureStage {
        self.stage
    }
    /// Safe provider-neutral failure reason.
    #[must_use]
    pub const fn reason(self) -> PublishFailureReason {
        self.reason
    }
}

#[cfg(feature = "producer")]
impl PublishFailureKind {
    #[must_use]
    /// `is_retryable` operation defined by this protocol type.
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Transient)
    }
    #[must_use]
    /// `is_permanent` operation defined by this protocol type.
    pub const fn is_permanent(self) -> bool {
        matches!(self, Self::Permanent)
    }
}

#[cfg(feature = "producer")]
/// Closed `PublishOutcome` protocol type.
pub enum PublishOutcome<R> {
    /// `Confirmed` state in the closed protocol.
    Confirmed(R),
    /// `DefinitelyNotPublished` state in the closed protocol.
    DefinitelyNotPublished(PublishFailure),
    /// `Ambiguous` state in the closed protocol.
    Ambiguous(PublishFailure),
}

#[cfg(feature = "producer")]
impl<R> PublishOutcome<R> {
    /// Return the safe diagnostic retained for a failed or ambiguous publication.
    #[must_use]
    pub const fn failure(&self) -> Option<PublishFailure> {
        match self {
            Self::Confirmed(_) => None,
            Self::DefinitelyNotPublished(failure) | Self::Ambiguous(failure) => Some(*failure),
        }
    }

    /// Whether the provider may have accepted the message despite the failure.
    #[must_use]
    pub const fn is_ambiguous(&self) -> bool {
        matches!(self, Self::Ambiguous(_))
    }

    /// Exhaustively classify provider publication evidence for the store settlement CAS.
    #[must_use]
    pub fn into_settlement(self) -> OutboxSettlement<R> {
        match self {
            Self::Confirmed(receipt) => OutboxSettlement::Published(receipt),
            Self::DefinitelyNotPublished(failure) if failure.kind().is_retryable() => {
                OutboxSettlement::Retry
            }
            Self::DefinitelyNotPublished(_) => OutboxSettlement::DeadLetter,
            Self::Ambiguous(_) => OutboxSettlement::Retry,
        }
    }
}

#[cfg(feature = "producer")]
/// Closed `Publisher` protocol type.
pub trait Publisher<P>: Send + Sync {
    /// Provider-owned `Receipt` capability used by this port.
    type Receipt: Send;
    /// Canonical operation owned by the transactional messaging core.
    fn publish(
        &self,
        message: &MessageEnvelope<P>,
        deadline: OperationDeadline,
    ) -> impl Future<Output = PublishOutcome<Self::Receipt>> + Send;
}

#[cfg(feature = "consumer")]
/// Closed `DeliverySettlement` protocol type.
pub trait DeliverySettlement: Send {
    /// Canonical operation owned by the transactional messaging core.
    fn settle(
        self,
        decision: SettlementDecision,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<(), MessagingError>> + Send;

    /// Abandon without ACK/NACK/Reject and retire the provider session so the broker redelivers.
    fn abandon(
        self,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<(), MessagingError>> + Send;
}

#[cfg(feature = "consumer")]
/// Closed `Delivery` protocol type.
pub struct Delivery<P, S> {
    message: MessageEnvelope<P>,
    settlement: S,
}

#[cfg(feature = "consumer")]
impl<P, S> Delivery<P, S> {
    #[must_use]
    /// `new` operation defined by this protocol type.
    pub const fn new(message: MessageEnvelope<P>, settlement: S) -> Self {
        Self {
            message,
            settlement,
        }
    }
    /// `into_parts` operation defined by this protocol type.
    pub fn into_parts(self) -> (MessageEnvelope<P>, S) {
        (self.message, self.settlement)
    }
}

#[cfg(feature = "consumer")]
/// Closed `IncomingDelivery` protocol type.
pub enum IncomingDelivery<P, S> {
    /// `Valid` state in the closed protocol.
    Valid(Box<Delivery<P, S>>),
    /// `Invalid` state in the closed protocol.
    Invalid(InvalidDelivery<S>),
}

#[cfg(feature = "consumer")]
impl<P, S> IncomingDelivery<P, S> {
    /// Construct a fail-closed delivery at the trusted provider decode boundary.
    #[doc(hidden)]
    #[must_use]
    pub const fn invalid_from_provider(failure: EnvelopeValidationFailure, settlement: S) -> Self {
        Self::Invalid(InvalidDelivery {
            rejection: DecodeRejection::new(failure),
            settlement,
        })
    }
}

/// Move-only invalid delivery carrying core-minted Reject authority.
#[cfg(feature = "consumer")]
pub struct InvalidDelivery<S> {
    rejection: DecodeRejection,
    settlement: S,
}

#[cfg(feature = "consumer")]
impl<S> InvalidDelivery<S> {
    /// Consume the invalid delivery into its opaque rejection and provider settlement.
    #[must_use]
    pub fn into_parts(self) -> (DecodeRejection, S) {
        (self.rejection, self.settlement)
    }
}

/// Move-only ownership receipt for one provider delivery stream.
///
/// Consumers can advance the stream but cannot extract or combine its raw stream with a different
/// lifecycle owner.
#[cfg(feature = "consumer")]
pub struct ManagedDeliveryStream<S> {
    stream: S,
}

#[cfg(feature = "consumer")]
impl<S> ManagedDeliveryStream<S> {
    /// Wrap the stream created by one [`DeliverySource`] implementation.
    #[doc(hidden)]
    #[must_use]
    pub const fn from_provider(stream: S) -> Self {
        Self { stream }
    }
}

#[cfg(feature = "consumer")]
impl<S: Stream + Unpin> ManagedDeliveryStream<S> {
    /// Await the next delivery owned by this managed stream receipt.
    pub async fn next(&mut self) -> Option<S::Item> {
        self.stream.next().await
    }
}

#[cfg(feature = "consumer")]
/// Closed `DeliverySource` protocol type.
pub trait DeliverySource<P>: Send + Sync {
    /// Provider-owned `Settlement` capability used by this port.
    type Settlement: DeliverySettlement;
    /// Provider-owned `Deliveries` capability used by this port.
    type Deliveries: Stream<Item = IncomingDelivery<P, Self::Settlement>> + Send + Unpin;

    /// Canonical operation owned by the transactional messaging core.
    fn deliveries(
        &self,
        subscription: &SubscriptionIdentity,
    ) -> impl Future<Output = Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError>> + Send;
}
