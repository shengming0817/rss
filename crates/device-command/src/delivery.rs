//! Per-command delivery intent and evidence for correlating a device response.
use crate::{Command, Error};
use rss_transactional_messaging::{
    message::{MessageFingerprint, MessageId, MessagingDomain},
    outbox::PendingMessage,
};

/// Product-authored digest of the frozen bytes or descriptor to deliver.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ContentDigest([u8; 32]);
impl ContentDigest {
    /// Bind the product's immutable input digest.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Canonical persisted bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl std::fmt::Debug for ContentDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContentDigest(<redacted>)")
    }
}

/// Opaque non-nil identity supplied by the caller for one command's direct issuance.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClaimId(uuid::Uuid);
impl ClaimId {
    /// Parse the stable identity without allocating a new attempt.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        let id = uuid::Uuid::parse_str(raw).map_err(|_| Error::InvalidValue)?;
        if id.is_nil() {
            return Err(Error::InvalidValue);
        }
        Ok(Self(id))
    }
    /// Value for protocol correlation and persistence.
    pub const fn as_uuid(self) -> uuid::Uuid {
        self.0
    }
}
impl std::fmt::Debug for ClaimId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClaimId(<redacted>)")
    }
}

/// The immutable dispatch evidence retained for an Outbox command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxIdentity {
    /// Original messaging domain.
    pub domain: MessagingDomain,
    /// Original dispatch ID.
    pub message_id: MessageId,
    /// Fingerprint of the original authored message.
    pub fingerprint: MessageFingerprint,
}

/// The Outbox variant carries a pending message at creation and its identity in snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery<M = PendingMessage<Vec<u8>>> {
    /// Dispatch through the transactional Outbox.
    Outbox(M),
    /// The product holds the frozen payload and chooses when to offer it to a device.
    Direct {
        /// Digest of the frozen content.
        content_digest: ContentDigest,
    },
}
impl Delivery {
    /// Immutable facts used by creation, recovery and exact replay.
    pub fn identity(&self) -> Delivery<OutboxIdentity> {
        match self {
            Self::Outbox(message) => Delivery::Outbox(OutboxIdentity {
                domain: message.envelope().metadata().domain().clone(),
                message_id: message.envelope().id().clone(),
                fingerprint: message.fingerprint(),
            }),
            Self::Direct { content_digest } => Delivery::Direct {
                content_digest: *content_digest,
            },
        }
    }
}

/// The authenticated product correlates the device report to its original delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportSource {
    /// Correlated to the command delivered by the gateway.
    Outbox,
    /// Correlated to this exact durable direct issuance.
    Direct(ClaimId),
}

/// Inspect only after the enclosing transaction has confirmed commit.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "only a committed eligible claim can be considered for dispatch"]
pub enum DirectClaim {
    /// Eligible when the row was locked and the command clock was sampled. Later writes or elapsed time can invalidate this candidate.
    Eligible(Command),
    /// Already received, terminal, or expired. No further dispatch is authorized.
    Unavailable(Command),
}

impl DirectClaim {
    /// Check a committed candidate against the latest authorized command snapshot and the
    /// response handoff time (Unix microseconds). The caller revalidates product policy and
    /// protocol resend eligibility for this request before handing off any executable bytes.
    #[must_use]
    pub fn dispatch_id_at(&self, current: &Command, now: i64) -> Option<ClaimId> {
        let Self::Eligible(claimed) = self else {
            return None;
        };
        if claimed != current
            || current.status() != crate::Status::Claimed
            || now >= current.spec().deadline()
            || now < current.record().dispatched_at?
        {
            return None;
        }
        current.record().claim_id
    }
}
