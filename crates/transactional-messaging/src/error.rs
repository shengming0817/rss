//! Opaque, safely classified failures crossing transactional messaging ports.

use rss_redact::RedactedSource;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Stable retry and authority classification for a failed provider operation.
pub enum MessagingErrorKind {
    /// The same operation may succeed while its absolute deadline remains valid.
    Transient,
    /// The request is permanently invalid for this provider.
    Permanent,
    /// Durable facts contradict the submitted stable identity or fingerprint.
    Conflict,
    /// Lease or fencing authority no longer belongs to this attempt.
    OwnershipLost,
    /// Trusted internal state contradicted a core invariant.
    Invariant,
    /// The core-owned absolute operation deadline elapsed.
    DeadlineElapsed,
}

impl MessagingErrorKind {
    #[must_use]
    /// Return the low-cardinality diagnostic label; it contains no provider or message data.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Permanent => "permanent",
            Self::Conflict => "conflict",
            Self::OwnershipLost => "ownership_lost",
            Self::Invariant => "invariant",
            Self::DeadlineElapsed => "deadline_elapsed",
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("transactional messaging operation failed: {}", .kind.as_label())]
/// Opaque port failure carrying only a public classification and a redacted source chain.
pub struct MessagingError {
    kind: MessagingErrorKind,
    #[source]
    source: RedactedSource,
}

impl MessagingError {
    /// Wrap a provider error while preventing its display text from becoming protocol output.
    pub fn new<E>(kind: MessagingErrorKind, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind,
            source: RedactedSource::new(source),
        }
    }

    #[must_use]
    /// Return the stable classification used by retry and settlement policy.
    pub const fn kind(&self) -> MessagingErrorKind {
        self.kind
    }
}
