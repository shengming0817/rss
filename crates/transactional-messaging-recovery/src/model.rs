use rss_request_context::TenantId;
use rss_transactional_messaging::{
    inbox::ConsumerGroup,
    message::{ContractIdentity, MessageId, MessageRoute, MessagingDomain},
    transaction::RejectKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Closed recovery failure; never includes payload or provider diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// HOT content was safely archived; new replay requires a separate cold recovery capability.
    #[error("recovery content archived")]
    Archived,
    /// Malformed identity, version, cursor or operation combination.
    #[error("invalid recovery input")]
    Invalid,
    /// Product authorization denied or did not bind the exact request.
    #[error("recovery unauthorized")]
    Unauthorized,
    /// Same identity denotes different facts, or the expected revision changed.
    #[error("recovery conflict")]
    Conflict,
    /// No recoverable record exists in this tenant.
    #[error("recovery target not found")]
    NotFound,
    /// The original same-ID delivery window has elapsed.
    #[error("redrive deadline expired")]
    Expired,
    /// Explicit expiration resolution is premature.
    #[error("recovery target is not expired")]
    NotExpired,
    /// Compensation evidence is absent, unrelated or not published.
    #[error("invalid compensation evidence")]
    Evidence,
    /// Capsule authentication, encoding or key access failed.
    #[error("recovery protection failed")]
    Protection,
    /// Backend operation failed; transaction status carries settlement certainty.
    #[error("recovery store failed: {0}")]
    Store(StoreFailureKind),
    /// Caller deadline elapsed; this alone never proves rollback.
    #[error("recovery deadline elapsed")]
    Deadline,
    /// Runtime schema or effective privileges violate the component contract.
    #[error("recovery storage contract mismatch")]
    StorageContract,
}

/// Stable backend classification, separate from transaction certainty. Transient alone never authorizes retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreFailureKind {
    /// Provider may recover within the caller's unchanged budget.
    Transient,
    /// Provider configuration or input must change before retry.
    Permanent,
    /// Lease or fencing authority has been lost.
    OwnershipLost,
    /// Durable/provider state violates an invariant.
    Invariant,
}
impl std::fmt::Display for StoreFailureKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Transient => "transient",
            Self::Permanent => "permanent",
            Self::OwnershipLost => "ownership_lost",
            Self::Invariant => "invariant",
        })
    }
}

macro_rules! identity {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
        pub struct $name(uuid::Uuid);
        impl $name {
            /// Generate a fresh operation/record identity.
            pub fn new() -> Self {
                Self(uuid::Uuid::new_v4())
            }
            /// Parse a non-nil UUID supplied by a caller or provider.
            pub fn parse(value: &str) -> Result<Self, Error> {
                let value = uuid::Uuid::parse_str(value).map_err(|_| Error::Invalid)?;
                if value.is_nil() {
                    return Err(Error::Invalid);
                }
                Ok(Self(value))
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}
identity!(
    OperationId,
    "Stable identity reused for uncertain operation readback."
);
identity!(
    DeadLetterId,
    "Provider-assigned identity of one authenticated consumer dead letter."
);

/// Monotonically increasing durable target revision; zero is not a persisted revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Version(i64);
impl Version {
    /// Validate a positive, database-representable revision.
    pub fn new(value: i64) -> Result<Self, Error> {
        if value <= 0 {
            Err(Error::Invalid)
        } else {
            Ok(Self(value))
        }
    }
    /// Persisted revision.
    pub const fn get(self) -> i64 {
        self.0
    }
}
/// Tenant-local recovery target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Target {
    /// Protected consumer dead letter.
    DeadLetter(DeadLetterId),
    /// Original durable Outbox message.
    Outbox(MessageId),
}
impl Target {
    /// Closed storage/query discriminator.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::DeadLetter(_) => "consumer",
            Self::Outbox(_) => "outbox",
        }
    }
    /// Stable tenant-local key, for provider binding rather than telemetry.
    pub fn key(&self) -> String {
        match self {
            Self::DeadLetter(id) => id.to_string(),
            Self::Outbox(id) => id.as_str().into(),
        }
    }
}
/// Explicit product decision for an expired, partition-blocking message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resolution {
    /// Product explicitly accepts the missing effect.
    AcceptedGap,
    /// Published message whose authored causation identifies the expired target.
    Compensated(MessageId),
}
/// Closed mutation; read APIs are separate from mutation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Append a new message identity using the original authored facts.
    Replay(MessageId),
    /// Retry the original identity within its original window.
    Redrive,
    /// Resolve expiration without claiming publication.
    Resolve(Resolution),
}
impl Action {
    /// Low-cardinality observation label.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Replay(_) => "replay",
            Self::Redrive => "redrive",
            Self::Resolve(_) => "resolve",
        }
    }
}
/// Immutable, validated mutation intent. Authority is obtained separately for these exact facts.
#[derive(Clone, Debug)]
pub struct Mutation {
    tenant: TenantId,
    operation: OperationId,
    target: Target,
    version: Version,
    action: Action,
}
impl Mutation {
    /// Reject actions incompatible with their target kind.
    pub fn new(
        tenant: TenantId,
        operation: OperationId,
        target: Target,
        version: Version,
        action: Action,
    ) -> Result<Self, Error> {
        if !matches!(
            (&target, &action),
            (Target::DeadLetter(_), Action::Replay(_))
                | (Target::Outbox(_), Action::Redrive | Action::Resolve(_))
        ) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            tenant,
            operation,
            target,
            version,
            action,
        })
    }
    /// Trusted tenant requested by the product.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Stable operation identity.
    pub const fn operation(&self) -> OperationId {
        self.operation
    }
    /// Exact target.
    pub const fn target(&self) -> &Target {
        &self.target
    }
    /// Expected durable revision.
    pub const fn version(&self) -> Version {
        self.version
    }
    /// Requested transition.
    pub const fn action(&self) -> &Action {
        &self.action
    }
    /// Canonical request digest, binding all mutation inputs.
    pub fn digest(&self) -> [u8; 32] {
        let (kind, id) = match &self.action {
            Action::Replay(id) => ("replay", id.as_str()),
            Action::Redrive => ("redrive", ""),
            Action::Resolve(Resolution::AcceptedGap) => ("accepted_gap", ""),
            Action::Resolve(Resolution::Compensated(id)) => ("compensated", id.as_str()),
        };
        hash(&[
            "rss-recovery-mutation-v1",
            &self.tenant.to_string(),
            &self.operation.to_string(),
            self.target.kind(),
            &self.target.key(),
            &self.version.get().to_string(),
            kind,
            id,
        ])
    }
}
pub(crate) fn hash(parts: &[&str]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    hash.finalize().into()
}
/// Keyset query restricted to one tenant and one source kind.
#[derive(Clone, Debug)]
pub struct Query {
    tenant: TenantId,
    kind: Source,
    after: Option<String>,
    limit: u16,
    target: Option<Target>,
}
/// Closed dead-letter source filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    /// Rejected consumer records with protected payloads.
    Consumer,
    /// Dead-lettered or explicitly resolved Outbox records.
    Outbox,
}
impl Source {
    /// Stable provider discriminator.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Consumer => "consumer",
            Self::Outbox => "outbox",
        }
    }
}
impl Query {
    /// Start bounded keyset pagination. Cursors bind tenant and source.
    pub fn list(
        tenant: TenantId,
        source: Source,
        limit: u16,
        cursor: Option<&str>,
    ) -> Result<Self, Error> {
        if limit == 0 || limit > 1000 {
            return Err(Error::Invalid);
        }
        let after = cursor
            .map(|raw| {
                let prefix = format!("{}:{}:", tenant, source.label());
                let key = raw.strip_prefix(&prefix).ok_or(Error::Invalid)?;
                if key.is_empty() || key.len() > 512 {
                    return Err(Error::Invalid);
                }
                Ok(key.to_owned())
            })
            .transpose()?;
        Ok(Self {
            tenant,
            kind: source,
            after,
            limit,
            target: None,
        })
    }
    /// Inspect only one exact tenant-local target, without exposing its payload.
    pub fn inspect(tenant: TenantId, target: Target) -> Self {
        let kind = match target {
            Target::DeadLetter(_) => Source::Consumer,
            Target::Outbox(_) => Source::Outbox,
        };
        Self {
            tenant,
            kind,
            after: None,
            limit: 1,
            target: Some(target),
        }
    }
    /// Tenant scope.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Source filter.
    pub const fn source(&self) -> Source {
        self.kind
    }
    /// Provider-exclusive last key.
    pub fn after(&self) -> Option<&str> {
        self.after.as_deref()
    }
    /// Maximum returned rows.
    pub const fn limit(&self) -> u16 {
        self.limit
    }
    /// Exact target when inspecting.
    pub const fn target(&self) -> Option<&Target> {
        self.target.as_ref()
    }
    /// Encode a cursor for this scope; providers supply the final returned stable key.
    pub fn cursor(&self, key: &str) -> String {
        format!("{}:{}:{key}", self.tenant, self.kind.label())
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        hash(&[
            "rss-recovery-query-v1",
            &self.tenant.to_string(),
            self.kind.label(),
            self.after.as_deref().unwrap_or(""),
            &self.limit.to_string(),
            &self.target.as_ref().map(Target::key).unwrap_or_default(),
        ])
    }
}
/// Payload-free state returned by a trusted provider.
#[derive(Debug)]
pub struct Entry {
    /// Tenant-local target.
    pub target: Target,
    /// Revision required by subsequent mutation.
    pub version: Version,
    /// Original message identity.
    pub message: MessageId,
    /// Source-specific facts needed for an informed recovery decision; never includes payload.
    pub details: Details,
}
/// Closed payload-free recovery inspection.
#[derive(Debug)]
pub enum Details {
    /// Trusted rejected consumer facts and replay history.
    Consumer(ConsumerDetails),
    /// Original Outbox routing and current delivery-window decision.
    Outbox(OutboxDetails),
}
/// Consumer-specific recovery decision facts.
#[derive(Debug)]
pub struct ConsumerDetails {
    /// Whether an authenticated HOT capsule remains available for a new replay.
    pub hot_available: bool,
    /// Original handler group.
    pub group: ConsumerGroup,
    /// Complete authored contract identity.
    pub contract: ContractIdentity,
    /// Closed terminal rejection reason.
    pub reason: RejectKind,
    /// Database capture time, as UTC epoch microseconds.
    pub captured_at_unix_micros: i64,
    /// Number of durably recorded replay operations.
    pub replay_count: u64,
    /// Most recently recorded replay message identity.
    pub last_replay: Option<MessageId>,
}
/// Database-authoritative eligibility at the query's observation time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Eligibility {
    /// No original delivery window has been established; redrive is not permitted.
    NoWindow,
    /// The original same-ID window is still open.
    WithinWindow,
    /// The original window expired; only explicit resolution is eligible.
    Expired,
    /// Explicit resolution has already unblocked the partition.
    Resolved,
}
/// Outbox-specific facts without payload or transport credentials.
#[derive(Debug)]
pub struct OutboxDetails {
    /// Authored domain.
    pub domain: MessagingDomain,
    /// Authored route; replay is not targeted to one consumer group.
    pub route: MessageRoute,
    /// Complete contract identity.
    pub contract: ContractIdentity,
    /// Original frozen same-ID deadline, as UTC epoch microseconds.
    pub deadline_unix_micros: Option<i64>,
    /// Eligibility observed using database time.
    pub eligibility: Eligibility,
}
/// One bounded query page.
#[derive(Debug)]
pub struct Page {
    /// At most the requested number of entries.
    pub entries: Vec<Entry>,
    /// Opaque cursor when another page may exist.
    pub next_cursor: Option<String>,
}
/// Durable successful mutation outcome, distinct from transaction settlement status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Outcome {
    /// New replay Outbox row appended.
    Replayed,
    /// Original Outbox row is eligible again.
    Redriven,
    /// Expired head resolved without publication.
    Resolved,
}
/// Provider-reported durable result; only acknowledged commit/readback establishes persistence.
#[derive(Clone, Debug)]
pub struct Receipt {
    /// Request identity, including tenant, source, target and action.
    pub request: Mutation,
    /// Exact successful transition.
    pub outcome: Outcome,
    /// Revision after the transition.
    pub version: Version,
}
