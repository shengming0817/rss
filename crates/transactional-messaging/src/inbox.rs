//! Inbox identity, claim fencing, terminal receipts, and storage port.

use crate::error::MessagingError;
use crate::message::{ContractIdentity, MessageId};
use crate::policy::OperationDeadline;
use crate::transaction::TerminalReceipt;

#[derive(Clone, Eq, Hash, PartialEq)]
/// Closed `ConsumerGroup` protocol type.
pub struct ConsumerGroup(Box<str>);

impl ConsumerGroup {
    /// `parse` operation defined by this protocol type.
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
    /// `as_str` operation defined by this protocol type.
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
/// Closed `ConsumerGroupError` protocol type.
pub enum ConsumerGroupError {
    #[error("consumer group must not be empty")]
    /// `Empty` state in the closed protocol.
    Empty,
    #[error("consumer group is too long")]
    /// `TooLong` state in the closed protocol.
    TooLong,
    #[error("consumer group contains an invalid character")]
    /// `InvalidChar` state in the closed protocol.
    InvalidChar,
}

#[derive(Clone, Eq, PartialEq)]
/// Closed `ConsumerIdentity` protocol type.
pub struct ConsumerIdentity {
    tenant_id: rss_request_context::TenantId,
    group: ConsumerGroup,
    message_id: MessageId,
    contract: ContractIdentity,
}

impl ConsumerIdentity {
    #[must_use]
    /// `new` operation defined by this protocol type.
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
    /// `tenant_id` operation defined by this protocol type.
    pub const fn tenant_id(&self) -> rss_request_context::TenantId {
        self.tenant_id
    }
    #[must_use]
    /// `group` operation defined by this protocol type.
    pub const fn group(&self) -> &ConsumerGroup {
        &self.group
    }
    #[must_use]
    /// `message_id` operation defined by this protocol type.
    pub const fn message_id(&self) -> &MessageId {
        &self.message_id
    }
    #[must_use]
    /// `contract` operation defined by this protocol type.
    pub const fn contract(&self) -> &ContractIdentity {
        &self.contract
    }
}

impl std::fmt::Debug for ConsumerIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConsumerIdentity(<redacted>)")
    }
}

/// Closed `IdempotencyDisposition` protocol type.
pub enum IdempotencyDisposition<C> {
    /// `Acquired` state in the closed protocol.
    Acquired(C),
    /// `InProgress` state in the closed protocol.
    InProgress,
    /// `Terminal` state in the closed protocol.
    Terminal(TerminalReceipt),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `LeaseStatus` protocol type.
pub enum LeaseStatus {
    /// `Held` state in the closed protocol.
    Held,
    /// `Lost` state in the closed protocol.
    Lost,
}

/// Closed `InboxStore` protocol type.
pub trait InboxStore: Send + Sync {
    /// Provider-owned `Claim` capability used by this port.
    type Claim: Send;

    /// Canonical operation owned by the transactional messaging core.
    fn claim(
        &self,
        identity: &ConsumerIdentity,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<IdempotencyDisposition<Self::Claim>, MessagingError>> + Send;

    /// Read the durable terminal receipt without acquiring an execution claim.
    fn read_terminal(
        &self,
        identity: &ConsumerIdentity,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<Option<TerminalReceipt>, MessagingError>> + Send;

    /// Canonical operation owned by the transactional messaging core.
    fn extend(
        &self,
        claim: &Self::Claim,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<LeaseStatus, MessagingError>> + Send;

    /// Canonical operation owned by the transactional messaging core.
    fn release(
        &self,
        claim: Self::Claim,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<(), MessagingError>> + Send;
}
