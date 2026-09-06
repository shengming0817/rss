//! Inbox identity, claim fencing, terminal receipts, and storage port.

use crate::error::MessagingError;
use crate::message::{ContractIdentity, MessageId};
use crate::policy::OperationDeadline;
use crate::transaction::TerminalReceipt;
use std::time::Duration;

#[derive(Clone, Eq, Hash, PartialEq)]
/// Independent handler group sharing inbox deduplication state.
pub struct ConsumerGroup(Box<str>);

impl ConsumerGroup {
    /// Parse 1–255 UTF-8 bytes without ASCII control characters; otherwise return
    /// [`ConsumerGroupError`].
    pub fn parse(raw: &str) -> Result<Self, ConsumerGroupError> {
        if raw.is_empty() {
            return Err(ConsumerGroupError::Empty);
        }
        if raw.len() > 255 {
            return Err(ConsumerGroupError::TooLong);
        }
        if raw.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(ConsumerGroupError::InvalidChar);
        }
        Ok(Self(raw.into()))
    }
    #[must_use]
    /// The group name as supplied, without redaction.
    pub const fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ConsumerGroup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("ConsumerGroup")
            .field(&self.as_str())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
/// Invalid consumer-group name.
pub enum ConsumerGroupError {
    #[error("consumer group must not be empty")]
    /// No group name was supplied.
    Empty,
    #[error("consumer group is too long")]
    /// The group name exceeds 255 UTF-8 bytes.
    TooLong,
    #[error("consumer group contains an invalid character")]
    /// The group name contains an ASCII control character.
    InvalidChar,
}

#[derive(Clone, Eq, PartialEq)]
/// Ingress and receipt identity: tenant, handler group, message ID, and contract.
/// This carries contract evidence; it does not define a provider's database uniqueness key.
pub struct ConsumerIdentity {
    tenant_id: rss_request_context::TenantId,
    group: ConsumerGroup,
    message_id: MessageId,
    contract: ContractIdentity,
}

impl ConsumerIdentity {
    #[must_use]
    /// Assemble receipt identity; authenticated ingress is required before using it for processing.
    pub const fn new(
        tenant_id: rss_request_context::TenantId,
        group: ConsumerGroup,
        message_id: MessageId,
        contract: ContractIdentity,
    ) -> Self {
        Self {
            tenant_id,
            group,
            message_id,
            contract,
        }
    }
    #[must_use]
    /// Tenant whose durable inbox is addressed.
    pub const fn tenant_id(&self) -> rss_request_context::TenantId {
        self.tenant_id
    }
    #[must_use]
    /// Handler group sharing this deduplication record.
    pub const fn group(&self) -> &ConsumerGroup {
        &self.group
    }
    #[must_use]
    /// Authored message identity being deduplicated.
    pub const fn message_id(&self) -> &MessageId {
        &self.message_id
    }
    #[must_use]
    /// Exact contract associated with this inbox record.
    pub const fn contract(&self) -> &ContractIdentity {
        &self.contract
    }
}

impl std::fmt::Debug for ConsumerIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConsumerIdentity(<redacted>)")
    }
}

/// Durable inbox state observed while attempting to acquire ownership.
pub enum IdempotencyDisposition<C> {
    /// This attempt acquired a fenced claim and may enter the transaction path.
    Acquired(C),
    /// Another live attempt owns the record; do not execute the handler.
    InProgress,
    /// A durable terminal result exists; validate it against verified ingress before settlement.
    Terminal(TerminalReceipt),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Provider-authoritative lease evidence for the current claim.
pub enum LeaseStatus {
    /// Provider-authoritative remaining lease time for a held claim.
    Held {
        /// Remaining duration observed after the provider renewed or checked the lease.
        remaining: Duration,
    },
    /// The attempt no longer owns the record; stop executing effects.
    Lost,
}

/// Trusted durable-state provider for inbox identity, leases, and terminal receipts.
///
/// Implementations are a semantic trust boundary: a terminal succeeded receipt must be rehydrated
/// only from provider-authoritative state committed atomically with the handler effect. The core
/// validates identity and fingerprint before granting settlement authority, but cannot prove that a
/// provider reported durable state truthfully. Providers must document their deduplication key and
/// contract-conflict policy, check requested identity and contract against durable state, and
/// enforce tenant isolation, authoritative lease time, and fencing atomically.
///
/// # Errors and cancellation
///
/// Classify I/O failures with [`MessagingError`]; expired ownership on release is
/// [`OwnershipLost`](crate::error::MessagingErrorKind::OwnershipLost). An expired claim must
/// never mutate a successor's record. Follow [`within`](crate::policy::within) for deadline and
/// cancellation obligations.
pub trait InboxStore: Send + Sync {
    /// Handle binding this attempt to its durable identity and fencing generation.
    type Claim: Send + Sync;

    /// Single provider-owned lease policy used for durable TTL and runtime renewal scheduling.
    fn lease_policy(&self) -> crate::policy::LeaseRenewalPolicy;

    /// Acquire exclusive ownership, or return the existing live or terminal state for the full
    /// identity.
    fn claim(
        &self,
        identity: &ConsumerIdentity,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<IdempotencyDisposition<Self::Claim>, MessagingError>> + Send;

    /// Read committed terminal state without acquiring ownership or modifying the record.
    /// `None` means no terminal result was observed, not permission to execute a handler.
    fn read_terminal(
        &self,
        identity: &ConsumerIdentity,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<Option<TerminalReceipt>, MessagingError>> + Send;

    /// Renew only the current fenced claim and report remaining time after renewal; return `Lost`
    /// if ownership ended.
    fn extend(
        &self,
        claim: &Self::Claim,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<LeaseStatus, MessagingError>> + Send;

    /// Release this claim without removing or downgrading a durable terminal result.
    fn release(
        &self,
        claim: Self::Claim,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<(), MessagingError>> + Send;
}
