//! Canonical authored message identity, envelope, metadata, and fingerprint.

use std::collections::BTreeMap;

use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_diag_context::CorrelationId;
use rss_request_context::TenantId;
use sha2::{Digest as _, Sha256};

const MESSAGE_ID_MAX_LEN: usize = 255;
const PARTITION_KEY_MAX_LEN: usize = 255;
const FINGERPRINT_DOMAIN: &str = "rss-transactional-message-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
/// Closed `MessageIdentityError` protocol type.
pub enum MessageIdentityError {
    #[error("message identity must not be empty")]
    /// `Empty` state in the closed protocol.
    Empty,
    #[error("message identity is too long")]
    /// `TooLong` state in the closed protocol.
    TooLong,
    #[error("message identity contains an invalid character")]
    /// `InvalidChar` state in the closed protocol.
    InvalidChar,
}

#[derive(Clone, Eq, Hash, PartialEq)]
/// Closed `MessageId` protocol type.
pub struct MessageId(Box<str>);

impl MessageId {
    /// `parse` operation defined by this protocol type.
    pub fn parse(raw: &str) -> Result<Self, MessageIdentityError> {
        validate_transport_identity(raw, MESSAGE_ID_MAX_LEN)?;
        Ok(Self(raw.into()))
    }

    #[must_use]
    /// `as_str` operation defined by this protocol type.
    pub const fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for MessageId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("MessageId")
            .field(&self.as_str())
            .finish()
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
/// Closed `MessagingDomain` protocol type.
pub struct MessagingDomain(Box<str>);

impl MessagingDomain {
    /// `parse` operation defined by this protocol type.
    pub fn parse(raw: &str) -> Result<Self, MessageIdentityError> {
        validate_transport_identity(raw, MESSAGE_ID_MAX_LEN)?;
        Ok(Self(raw.into()))
    }

    #[must_use]
    /// `as_str` operation defined by this protocol type.
    pub const fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for MessagingDomain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("MessagingDomain")
            .field(&self.as_str())
            .finish()
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
/// Closed `MessageRoute` protocol type.
pub struct MessageRoute(Box<str>);

impl MessageRoute {
    /// `parse` operation defined by this protocol type.
    pub fn parse(raw: &str) -> Result<Self, MessageIdentityError> {
        validate_transport_identity(raw, MESSAGE_ID_MAX_LEN)?;
        Ok(Self(raw.into()))
    }

    #[must_use]
    /// `as_str` operation defined by this protocol type.
    pub const fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for MessageRoute {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("MessageRoute")
            .field(&self.as_str())
            .finish()
    }
}

/// Exact identity a consumer subscribes to and accepts at ingress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionIdentity {
    domain: MessagingDomain,
    route: MessageRoute,
    contract: ContractIdentity,
}

impl SubscriptionIdentity {
    #[must_use]
    /// `new` operation defined by this protocol type.
    pub const fn new(
        domain: MessagingDomain,
        route: MessageRoute,
        contract: ContractIdentity,
    ) -> Self {
        Self {
            domain,
            route,
            contract,
        }
    }

    #[must_use]
    /// `domain` operation defined by this protocol type.
    pub const fn domain(&self) -> &MessagingDomain {
        &self.domain
    }

    #[must_use]
    /// `route` operation defined by this protocol type.
    pub const fn route(&self) -> &MessageRoute {
        &self.route
    }

    #[must_use]
    /// `contract` operation defined by this protocol type.
    pub const fn contract(&self) -> &ContractIdentity {
        &self.contract
    }

    #[must_use]
    /// `accepts` operation defined by this protocol type.
    pub fn accepts<P>(&self, message: &MessageEnvelope<P>) -> bool {
        message.metadata().domain() == self.domain()
            && message.metadata().route() == self.route()
            && message.metadata().contract() == self.contract()
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
/// Closed `PartitionKey` protocol type.
pub struct PartitionKey(Box<str>);

impl PartitionKey {
    /// `parse` operation defined by this protocol type.
    pub fn parse(raw: &str) -> Result<Self, MessageIdentityError> {
        if raw.is_empty() {
            return Err(MessageIdentityError::Empty);
        }
        if raw.len() > PARTITION_KEY_MAX_LEN {
            return Err(MessageIdentityError::TooLong);
        }
        if raw.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(MessageIdentityError::InvalidChar);
        }
        Ok(Self(raw.into()))
    }

    #[must_use]
    /// `as_str` operation defined by this protocol type.
    pub const fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for PartitionKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PartitionKey(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
/// Closed `PartitionIdentity` protocol type.
pub struct PartitionIdentity {
    tenant_id: TenantId,
    domain: MessagingDomain,
    key: PartitionKey,
}

impl PartitionIdentity {
    #[must_use]
    /// `new` operation defined by this protocol type.
    pub const fn new(tenant_id: TenantId, domain: MessagingDomain, key: PartitionKey) -> Self {
        Self {
            tenant_id,
            domain,
            key,
        }
    }

    #[must_use]
    /// `tenant_id` operation defined by this protocol type.
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    /// `domain` operation defined by this protocol type.
    pub const fn domain(&self) -> &MessagingDomain {
        &self.domain
    }

    #[must_use]
    /// `key` operation defined by this protocol type.
    pub const fn key(&self) -> &PartitionKey {
        &self.key
    }
}

impl std::fmt::Debug for PartitionIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PartitionIdentity(<redacted>)")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Closed `ContractIdentity` protocol type.
pub struct ContractIdentity {
    id: ContractId,
    version: ContractVersion,
    schema_digest: SchemaDigest,
}

impl ContractIdentity {
    #[must_use]
    /// `new` operation defined by this protocol type.
    pub const fn new(
        id: ContractId,
        version: ContractVersion,
        schema_digest: SchemaDigest,
    ) -> Self {
        Self {
            id,
            version,
            schema_digest,
        }
    }

    #[must_use]
    /// `id` operation defined by this protocol type.
    pub const fn id(&self) -> &ContractId {
        &self.id
    }
    #[must_use]
    /// `version` operation defined by this protocol type.
    pub const fn version(&self) -> ContractVersion {
        self.version
    }
    #[must_use]
    /// `schema_digest` operation defined by this protocol type.
    pub const fn schema_digest(&self) -> &SchemaDigest {
        &self.schema_digest
    }
}

/// Required authored identity and routing facts for one message.
pub struct AuthoredMessageMetadata {
    tenant_id: TenantId,
    occurred_at: Timepoint,
    domain: MessagingDomain,
    route: MessageRoute,
    contract: ContractIdentity,
}

impl AuthoredMessageMetadata {
    /// Bind all required metadata fields before optional extensions are supplied.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        occurred_at: Timepoint,
        domain: MessagingDomain,
        route: MessageRoute,
        contract: ContractIdentity,
    ) -> Self {
        Self {
            tenant_id,
            occurred_at,
            domain,
            route,
            contract,
        }
    }
}

/// Optional correlation, ordering and application metadata carried by one message.
#[derive(Default)]
pub struct MessageMetadataExtensions {
    correlation: Option<CorrelationId>,
    partition_key: Option<PartitionKey>,
    causation: Option<MessageId>,
    attributes: BTreeMap<String, String>,
}

impl MessageMetadataExtensions {
    /// Construct the complete optional extension set without positional ambiguity.
    #[must_use]
    pub fn new(
        correlation: Option<CorrelationId>,
        partition_key: Option<PartitionKey>,
        causation: Option<MessageId>,
        attributes: BTreeMap<String, String>,
    ) -> Self {
        Self {
            correlation,
            partition_key,
            causation,
            attributes,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
/// Validated metadata stored in the canonical message envelope.
pub struct MessageMetadata {
    tenant_id: TenantId,
    occurred_at: Timepoint,
    correlation: Option<Box<str>>,
    domain: MessagingDomain,
    route: MessageRoute,
    contract: ContractIdentity,
    partition: Option<PartitionIdentity>,
    causation: Option<MessageId>,
    attributes: BTreeMap<String, String>,
}

impl MessageMetadata {
    #[must_use]
    /// Combine required authored facts with the explicit optional extension group.
    pub fn new(required: AuthoredMessageMetadata, extensions: MessageMetadataExtensions) -> Self {
        let AuthoredMessageMetadata {
            tenant_id,
            occurred_at,
            domain,
            route,
            contract,
        } = required;
        let MessageMetadataExtensions {
            correlation,
            partition_key,
            causation,
            attributes,
        } = extensions;
        let partition =
            partition_key.map(|key| PartitionIdentity::new(tenant_id, domain.clone(), key));
        Self {
            tenant_id,
            occurred_at,
            correlation: correlation.map(|value| value.as_str().into()),
            domain,
            route,
            contract,
            partition,
            causation,
            attributes,
        }
    }

    #[must_use]
    /// `tenant_id` operation defined by this protocol type.
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
    #[must_use]
    /// `occurred_at` operation defined by this protocol type.
    pub const fn occurred_at(&self) -> Timepoint {
        self.occurred_at
    }
    #[must_use]
    /// `correlation` operation defined by this protocol type.
    pub fn correlation(&self) -> Option<&str> {
        self.correlation.as_deref()
    }
    #[must_use]
    /// `domain` operation defined by this protocol type.
    pub const fn domain(&self) -> &MessagingDomain {
        &self.domain
    }
    #[must_use]
    /// `route` operation defined by this protocol type.
    pub const fn route(&self) -> &MessageRoute {
        &self.route
    }
    #[must_use]
    /// `contract` operation defined by this protocol type.
    pub const fn contract(&self) -> &ContractIdentity {
        &self.contract
    }
    #[must_use]
    /// `partition` operation defined by this protocol type.
    pub fn partition(&self) -> Option<&PartitionIdentity> {
        self.partition.as_ref()
    }
    #[must_use]
    /// `causation` operation defined by this protocol type.
    pub fn causation(&self) -> Option<&MessageId> {
        self.causation.as_ref()
    }
    /// `attributes` operation defined by this protocol type.
    pub fn attributes(&self) -> impl Iterator<Item = (&str, &str)> {
        self.attributes
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }
}

impl std::fmt::Debug for MessageMetadata {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MessageMetadata(<redacted>)")
    }
}

#[derive(Clone, Default, Eq, PartialEq)]
/// Closed `TransportContext` protocol type.
pub struct TransportContext {
    trace: Option<String>,
    tenant_authority: Option<String>,
}

impl TransportContext {
    #[must_use]
    /// `new` operation defined by this protocol type.
    pub const fn new(trace: Option<String>, tenant_authority: Option<String>) -> Self {
        Self {
            trace,
            tenant_authority,
        }
    }

    #[must_use]
    /// `trace` operation defined by this protocol type.
    pub fn trace(&self) -> Option<&str> {
        self.trace.as_deref()
    }
    #[must_use]
    /// `tenant_authority` operation defined by this protocol type.
    pub fn tenant_authority(&self) -> Option<&str> {
        self.tenant_authority.as_deref()
    }
}

impl std::fmt::Debug for TransportContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TransportContext(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
/// Closed `MessageEnvelope` protocol type.
pub struct MessageEnvelope<P> {
    id: MessageId,
    metadata: MessageMetadata,
    transport: TransportContext,
    payload: P,
}

impl<P> MessageEnvelope<P> {
    #[must_use]
    /// `new` operation defined by this protocol type.
    pub fn new(id: MessageId, metadata: MessageMetadata, payload: P) -> Self {
        Self {
            id,
            metadata,
            transport: TransportContext::default(),
            payload,
        }
    }

    #[must_use]
    /// `with_transport_context` operation defined by this protocol type.
    pub fn with_transport_context(mut self, transport: TransportContext) -> Self {
        self.transport = transport;
        self
    }

    #[must_use]
    /// `id` operation defined by this protocol type.
    pub const fn id(&self) -> &MessageId {
        &self.id
    }
    #[must_use]
    /// `metadata` operation defined by this protocol type.
    pub const fn metadata(&self) -> &MessageMetadata {
        &self.metadata
    }
    #[must_use]
    /// `transport_context` operation defined by this protocol type.
    pub const fn transport_context(&self) -> &TransportContext {
        &self.transport
    }
    #[must_use]
    /// `payload` operation defined by this protocol type.
    pub const fn payload(&self) -> &P {
        &self.payload
    }
}

impl<P> std::fmt::Debug for MessageEnvelope<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MessageEnvelope")
            .field("id", &self.id)
            .field("metadata", &self.metadata)
            .field("transport", &self.transport)
            .field("payload", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
/// Closed `MessageFingerprint` protocol type.
pub struct MessageFingerprint([u8; 32]);

impl MessageFingerprint {
    /// Restore a durable digest value. This does not establish receipt authenticity.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    /// `of` operation defined by this protocol type.
    pub fn of<P: AsRef<[u8]>>(message: &MessageEnvelope<P>) -> Self {
        let mut digest = Sha256::new();
        frame(&mut digest, 0, FINGERPRINT_DOMAIN.as_bytes());
        frame(&mut digest, 1, message.id().as_str().as_bytes());
        frame(&mut digest, 2, &message.metadata().tenant_id().octets());
        frame(
            &mut digest,
            3,
            &message
                .metadata()
                .occurred_at()
                .unix_seconds()
                .to_be_bytes(),
        );
        frame_optional(
            &mut digest,
            4,
            message.metadata().correlation().map(str::as_bytes),
        );
        frame(
            &mut digest,
            5,
            message.metadata().domain().as_str().as_bytes(),
        );
        frame(
            &mut digest,
            6,
            message.metadata().route().as_str().as_bytes(),
        );
        frame(
            &mut digest,
            7,
            message.metadata().contract().id().as_str().as_bytes(),
        );
        frame(
            &mut digest,
            8,
            &message
                .metadata()
                .contract()
                .version()
                .major()
                .to_be_bytes(),
        );
        frame(
            &mut digest,
            9,
            message
                .metadata()
                .contract()
                .schema_digest()
                .as_str()
                .as_bytes(),
        );
        match message.metadata().partition() {
            Some(partition) => {
                frame(&mut digest, 10, &[1]);
                frame(&mut digest, 11, &partition.tenant_id().octets());
                frame(&mut digest, 12, partition.domain().as_str().as_bytes());
                frame(&mut digest, 13, partition.key().as_str().as_bytes());
            }
            None => frame(&mut digest, 10, &[0]),
        }
        frame_optional(
            &mut digest,
            14,
            message
                .metadata()
                .causation()
                .map(MessageId::as_str)
                .map(str::as_bytes),
        );
        frame(
            &mut digest,
            15,
            &u64::try_from(message.metadata().attributes.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for (key, value) in message.metadata().attributes() {
            frame(&mut digest, 16, key.as_bytes());
            frame(&mut digest, 17, value.as_bytes());
        }
        frame(&mut digest, 18, message.payload().as_ref());
        Self(digest.finalize().into())
    }

    #[must_use]
    /// `as_bytes` operation defined by this protocol type.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Detect same-ID authored drift without inspecting transport context.
    pub fn verify(self, message_id: &MessageId, actual: Self) -> Result<(), MessageConflict> {
        if self == actual {
            Ok(())
        } else {
            Err(MessageConflict {
                message_id: message_id.clone(),
                expected: self,
                actual,
            })
        }
    }
}

impl std::fmt::Debug for MessageFingerprint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MessageFingerprint(<redacted>)")
    }
}

/// Closed `MessageConflict` protocol type.
pub struct MessageConflict {
    message_id: MessageId,
    expected: MessageFingerprint,
    actual: MessageFingerprint,
}

impl MessageConflict {
    #[must_use]
    /// `message_id` operation defined by this protocol type.
    pub const fn message_id(&self) -> &MessageId {
        &self.message_id
    }
    #[must_use]
    /// `expected` operation defined by this protocol type.
    pub const fn expected(&self) -> MessageFingerprint {
        self.expected
    }
    #[must_use]
    /// `actual` operation defined by this protocol type.
    pub const fn actual(&self) -> MessageFingerprint {
        self.actual
    }
}

impl std::fmt::Debug for MessageConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MessageConflict(<redacted>)")
    }
}

impl std::fmt::Display for MessageConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("same message identity has conflicting authored content")
    }
}

impl std::error::Error for MessageConflict {}

fn validate_transport_identity(raw: &str, max_len: usize) -> Result<(), MessageIdentityError> {
    if raw.is_empty() {
        return Err(MessageIdentityError::Empty);
    }
    if raw.len() > max_len {
        return Err(MessageIdentityError::TooLong);
    }
    if !raw
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
    {
        return Err(MessageIdentityError::InvalidChar);
    }
    Ok(())
}

fn frame(digest: &mut Sha256, tag: u8, value: &[u8]) {
    digest.update([tag]);
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}
fn frame_optional(digest: &mut Sha256, tag: u8, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            frame(digest, tag, &[1]);
            frame(digest, tag, value);
        }
        None => frame(digest, tag, &[0]),
    }
}
