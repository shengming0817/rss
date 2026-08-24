//! Provider-neutral event identity and payload envelope.

use crate::metadata::EventMetadata;

/// Stable identity reused by every retry of one authored event.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct EventId(String);

/// Failure while constructing an [`EventId`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EventIdError {
    /// An empty identity cannot provide idempotency.
    #[error("event id must not be empty")]
    Empty,
}

impl EventId {
    /// Parses an opaque stable event identity, rejecting only the incomplete empty value.
    pub fn parse(raw: &str) -> Result<Self, EventIdError> {
        if raw.is_empty() {
            return Err(EventIdError::Empty);
        }
        Ok(Self(raw.to_owned()))
    }

    /// Borrows the opaque identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Complete provider-neutral authoring envelope for one typed payload.
///
/// Topic and provider coordinates are deliberately absent. Production routing remains bound by
/// generated facts, while external consumers may bind this value to their own transport fixture.
pub struct EventEnvelope<P> {
    contract: rss_contract::ContractDescriptor,
    event_id: EventId,
    metadata: EventMetadata,
    payload: P,
}

impl<P> EventEnvelope<P> {
    /// Constructs a complete event envelope.
    #[must_use]
    pub fn new(
        contract: rss_contract::ContractDescriptor,
        event_id: EventId,
        metadata: EventMetadata,
        payload: P,
    ) -> Self {
        Self {
            contract,
            event_id,
            metadata,
            payload,
        }
    }

    /// Returns the canonical contract identity.
    #[must_use]
    pub const fn contract(&self) -> rss_contract::ContractDescriptor {
        self.contract
    }

    /// Borrows the stable event identity.
    #[must_use]
    pub const fn event_id(&self) -> &EventId {
        &self.event_id
    }

    /// Borrows the closed event metadata.
    #[must_use]
    pub const fn metadata(&self) -> &EventMetadata {
        &self.metadata
    }

    /// Borrows the typed payload.
    #[must_use]
    pub const fn payload(&self) -> &P {
        &self.payload
    }

    /// Transforms only the payload while preserving identity and metadata by construction.
    pub fn map_payload<Q>(self, map: impl FnOnce(P) -> Q) -> EventEnvelope<Q> {
        EventEnvelope {
            contract: self.contract,
            event_id: self.event_id,
            metadata: self.metadata,
            payload: map(self.payload),
        }
    }

    /// Consumes the envelope into its complete canonical parts.
    pub fn into_parts(self) -> (rss_contract::ContractDescriptor, EventId, EventMetadata, P) {
        (self.contract, self.event_id, self.metadata, self.payload)
    }
}
