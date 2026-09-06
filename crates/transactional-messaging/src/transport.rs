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
/// Whether the failure can be repaired by another attempt, independent of acceptance evidence.
/// Only [`PublishOutcome::DefinitelyNotPublished`] uses this classification to choose Retry or
/// DeadLetter; an ambiguous outcome always maps to Retry.
pub enum PublishFailureKind {
    /// A later attempt may succeed within the remaining delivery budget.
    Transient,
    /// Repeating the unchanged request cannot repair the failure.
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
    /// Sending failed; acceptance certainty is expressed by [`PublishOutcome`].
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
    /// Whether the failure is transient; acceptance evidence and budget still govern retry.
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Transient)
    }
    #[must_use]
    /// Whether repeating the unchanged request cannot repair this failure.
    pub const fn is_permanent(self) -> bool {
        matches!(self, Self::Permanent)
    }
}

#[cfg(feature = "producer")]
/// Provider evidence about whether the message was accepted; uncertainty must remain explicit.
pub enum PublishOutcome<R> {
    /// Acceptance was confirmed by the provider and is backed by the returned receipt.
    Confirmed(R),
    /// The provider can prove the message was not accepted.
    DefinitelyNotPublished(PublishFailure),
    /// Acceptance may have occurred; any retry must preserve the original message ID and content.
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

    /// Convert evidence to a store transition without performing I/O.
    /// Ambiguity always becomes `Retry`, even with a permanent diagnostic; only a definite
    /// non-publication with a permanent failure becomes `DeadLetter`.
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
/// Provider publisher with a mandatory second-layer I/O watchdog.
///
/// Follow [`crate::policy::within`] for deadline and cancellation obligations. Preserve the message
/// ID and authored facts on every attempt; a transport trace may change independently.
///
/// # Failures
///
/// Return [`PublishOutcome::DefinitelyNotPublished`] only with evidence of non-acceptance.
/// Missing confirmation, including timeout after sending, is [`PublishOutcome::Ambiguous`].
/// Confirmation establishes provider acceptance, not consumer processing or exactly-once delivery.
pub trait Publisher<P>: Send + Sync {
    /// Acceptance evidence understood by the paired outbox store.
    type Receipt: Send;
    /// Publish the authored envelope unchanged and return acceptance evidence or a classified
    /// failure.
    fn publish(
        &self,
        message: &MessageEnvelope<P>,
        deadline: OperationDeadline,
    ) -> impl Future<Output = PublishOutcome<Self::Receipt>> + Send;
}

#[cfg(feature = "consumer")]
/// One-shot provider settlement with a mandatory second-layer I/O watchdog.
///
/// A timed-out settlement has unknown transport outcome. Callers must not issue a second or
/// contradictory decision through another path. Enforce [`OperationDeadline`] for both methods;
/// cancellation must not trigger an implicit ACK. ACK authority comes from durable transaction
/// evidence checked by [`crate::transaction::VerifiedConsumerBinding`].
///
/// # Errors
///
/// Return [`MessagingError`] for provider I/O or ownership failures. An error alone does not
/// establish that the broker rejected the decision; retire uncertain session state safely.
pub trait DeliverySettlement: Send {
    /// Consume this delivery handle and apply exactly the supplied broker decision.
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
/// Decoded envelope paired with its one-shot provider settlement handle.
pub struct Delivery<P, S> {
    message: MessageEnvelope<P>,
    settlement: S,
}

#[cfg(feature = "consumer")]
impl<P, S> Delivery<P, S> {
    #[must_use]
    /// Pair an envelope with the handle for that same broker delivery; ingress remains unverified.
    pub const fn new(message: MessageEnvelope<P>, settlement: S) -> Self {
        Self {
            message,
            settlement,
        }
    }
    /// Consume the delivery to verify its envelope and later settle through its original handle.
    pub fn into_parts(self) -> (MessageEnvelope<P>, S) {
        (self.message, self.settlement)
    }
}

#[cfg(feature = "consumer")]
/// Provider decode result, prior to consumer ingress verification.
pub enum IncomingDelivery<P, S> {
    /// Decoding succeeded; tenant authority and subscription checks are still required.
    Valid(Box<Delivery<P, S>>),
    /// The trusted decoder rejected the envelope and supplied rejection authority.
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

/// Move-only decode failure carrying rejection authority issued at the trusted provider boundary.
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
    /// Await one delivery, or `None` when the source ends.
    /// This admission wait has no per-delivery deadline; the caller controls cancellation and
    /// shutdown. The underlying provider stream must preserve unyielded deliveries on cancellation.
    pub async fn next(&mut self) -> Option<S::Item> {
        self.stream.next().await
    }
}

#[cfg(feature = "consumer")]
/// Provider admission of deliveries for an exact subscription.
///
/// Establishment and stream polling are long-lived admission waits, outside the per-delivery
/// execution budget. Providers must support caller cancellation/shutdown without acknowledging
/// unprocessed deliveries, and bind each settlement handle to its original delivery/session.
///
/// # Errors
///
/// Establishment reports [`MessagingError`]; decode failures are [`IncomingDelivery::Invalid`].
/// A decoded envelope still requires ingress verification before any handler effect.
pub trait DeliverySource<P>: Send + Sync {
    /// One-shot handle for deciding the outcome of one broker delivery.
    type Settlement: DeliverySettlement;
    /// Stream of decoded envelopes or explicit decode rejections.
    type Deliveries: Stream<Item = IncomingDelivery<P, Self::Settlement>> + Send + Unpin;

    /// Establish a stream for this subscription, or return a classified admission error.
    fn deliveries(
        &self,
        subscription: &SubscriptionIdentity,
    ) -> impl Future<Output = Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError>> + Send;
}
