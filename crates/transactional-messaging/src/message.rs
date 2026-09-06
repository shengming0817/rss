//! Authored messages and per-delivery transport input.
//!
//! Persist authored facts unchanged for same-ID retries. [`MessageFingerprint`] detects changes
//! to those facts, including payload bytes, but excludes [`TransportContext`]. Neither a digest
//! nor an envelope authenticates a tenant or validates a payload schema.
//!
//! Metadata, partition keys, transport context, fingerprints, and payloads are hidden by envelope
//! `Debug`; message IDs remain visible. Raw accessors do not redact their results.

use std::collections::BTreeMap;

use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_diag_context::CorrelationId;
use rss_request_context::TenantId;
use sha2::{Digest as _, Sha256};

const MESSAGE_ID_MAX_LEN: usize = 255;
const PARTITION_KEY_MAX_LEN: usize = 255;
const FINGERPRINT_DOMAIN: &str = "rss-transactional-message-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
/// Invalid input to a message identifier or partition key.
pub enum MessageIdentityError {
    #[error("message identity must not be empty")]
    /// The identifier is empty.
    Empty,
    #[error("message identity is too long")]
    /// The identifier exceeds its byte limit.
    TooLong,
    #[error("message identity contains an invalid character")]
    /// The identifier contains a character forbidden by its type.
    InvalidChar,
}

#[derive(Clone, Eq, Hash, PartialEq)]
/// Stable authored identity; retries and ambiguous publication must reuse this value.
pub struct MessageId(Box<str>);

impl MessageId {
    /// Parse 1–255 bytes of ASCII letters, digits, `.`, `-`, `_`, or `:`; otherwise return
    /// [`MessageIdentityError`].
    pub fn parse(raw: &str) -> Result<Self, MessageIdentityError> {
        validate_transport_identity(raw, MESSAGE_ID_MAX_LEN)?;
        Ok(Self(raw.into()))
    }

    #[must_use]
    /// The validated identifier, without normalization.
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
/// Namespace separating independently routed message families.
pub struct MessagingDomain(Box<str>);

impl MessagingDomain {
    /// Parse using the same syntax and errors as [`MessageId::parse`].
    pub fn parse(raw: &str) -> Result<Self, MessageIdentityError> {
        validate_transport_identity(raw, MESSAGE_ID_MAX_LEN)?;
        Ok(Self(raw.into()))
    }

    #[must_use]
    /// The routing namespace as supplied.
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
/// Logical destination within a [`MessagingDomain`].
pub struct MessageRoute(Box<str>);

impl MessageRoute {
    /// Parse using the same syntax and errors as [`MessageId::parse`].
    pub fn parse(raw: &str) -> Result<Self, MessageIdentityError> {
        validate_transport_identity(raw, MESSAGE_ID_MAX_LEN)?;
        Ok(Self(raw.into()))
    }

    #[must_use]
    /// The logical destination as supplied.
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
    /// Bind the exact domain, route, and contract accepted by a subscription.
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
    /// Required routing namespace.
    pub const fn domain(&self) -> &MessagingDomain {
        &self.domain
    }

    #[must_use]
    /// Required logical destination.
    pub const fn route(&self) -> &MessageRoute {
        &self.route
    }

    #[must_use]
    /// Required contract ID, version, and schema digest.
    pub const fn contract(&self) -> &ContractIdentity {
        &self.contract
    }

    #[must_use]
    /// Check exact routing and contract equality; this does not authenticate tenant authority.
    pub fn accepts<P>(&self, message: &MessageEnvelope<P>) -> bool {
        message.metadata().domain() == self.domain()
            && message.metadata().route() == self.route()
            && message.metadata().contract() == self.contract()
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
/// Ordering key scoped by tenant and domain through [`PartitionIdentity`].
pub struct PartitionKey(Box<str>);

impl PartitionKey {
    /// Parse 1–255 UTF-8 bytes without ASCII control characters; otherwise return
    /// [`MessageIdentityError`].
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
    /// The unredacted ordering key; avoid exposing it in diagnostics.
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
/// Tenant and domain scope for messages sharing one ordered sequence.
pub struct PartitionIdentity {
    tenant_id: TenantId,
    domain: MessagingDomain,
    key: PartitionKey,
}

impl PartitionIdentity {
    #[must_use]
    /// Scope an ordering key to its tenant and messaging domain.
    pub const fn new(tenant_id: TenantId, domain: MessagingDomain, key: PartitionKey) -> Self {
        Self {
            tenant_id,
            domain,
            key,
        }
    }

    #[must_use]
    /// Tenant whose sequence is addressed.
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    /// Namespace containing the sequence.
    pub const fn domain(&self) -> &MessagingDomain {
        &self.domain
    }

    #[must_use]
    /// Ordering key within this tenant and domain.
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
/// Exact contract ID, version, and schema digest required for message compatibility.
pub struct ContractIdentity {
    id: ContractId,
    version: ContractVersion,
    schema_digest: SchemaDigest,
}

impl ContractIdentity {
    #[must_use]
    /// Combine contract facts; this does not check the payload against the schema.
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
    /// Contract name used at ingress.
    pub const fn id(&self) -> &ContractId {
        &self.id
    }
    #[must_use]
    /// Authored contract version.
    pub const fn version(&self) -> ContractVersion {
        self.version
    }
    #[must_use]
    /// Digest identifying the expected schema.
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
    /// Set authored extensions; attribute keys and values are stored without validation.
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
/// Authored metadata; construction scopes the partition but does not authenticate the tenant.
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
    /// Authored tenant identity; transport authority must be verified separately.
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
    #[must_use]
    /// Authored occurrence time, preserved on replay.
    pub const fn occurred_at(&self) -> Timepoint {
        self.occurred_at
    }
    #[must_use]
    /// Optional authored correlation value, included in the fingerprint.
    pub fn correlation(&self) -> Option<&str> {
        self.correlation.as_deref()
    }
    #[must_use]
    /// Authored routing namespace.
    pub const fn domain(&self) -> &MessagingDomain {
        &self.domain
    }
    #[must_use]
    /// Authored logical destination.
    pub const fn route(&self) -> &MessageRoute {
        &self.route
    }
    #[must_use]
    /// Contract the payload claims to implement.
    pub const fn contract(&self) -> &ContractIdentity {
        &self.contract
    }
    #[must_use]
    /// Optional ordering scope derived from this message's tenant, domain, and partition key.
    pub fn partition(&self) -> Option<&PartitionIdentity> {
        self.partition.as_ref()
    }
    #[must_use]
    /// Optional ID of the message that caused this one.
    pub fn causation(&self) -> Option<&MessageId> {
        self.causation.as_ref()
    }
    /// Authored attributes in key order; values are not redacted by this accessor.
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
/// Per-delivery trace and tenant-authority input, excluded from [`MessageFingerprint`].
pub struct TransportContext {
    trace: Option<String>,
    tenant_authority: Option<String>,
}

impl TransportContext {
    #[must_use]
    /// Store transport input without authenticating it; ingress validation owns verification.
    pub const fn new(trace: Option<String>, tenant_authority: Option<String>) -> Self {
        Self {
            trace,
            tenant_authority,
        }
    }

    #[must_use]
    /// Unverified transport trace input.
    pub fn trace(&self) -> Option<&str> {
        self.trace.as_deref()
    }
    #[must_use]
    /// Unverified tenant-authority input, which may contain credentials.
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
/// Authored identity, metadata, and payload with replaceable per-delivery context.
pub struct MessageEnvelope<P> {
    id: MessageId,
    metadata: MessageMetadata,
    transport: TransportContext,
    payload: P,
}

impl<P> MessageEnvelope<P> {
    #[must_use]
    /// Create an envelope with empty transport context; payload validation remains external.
    pub fn new(id: MessageId, metadata: MessageMetadata, payload: P) -> Self {
        Self {
            id,
            metadata,
            transport: TransportContext::default(),
            payload,
        }
    }

    #[must_use]
    /// Replace delivery context without changing authored facts or their fingerprint.
    pub fn with_transport_context(mut self, transport: TransportContext) -> Self {
        self.transport = transport;
        self
    }

    #[must_use]
    /// Stable identity to preserve across publication retries.
    pub const fn id(&self) -> &MessageId {
        &self.id
    }
    #[must_use]
    /// Authored metadata used for fingerprinting and ingress checks.
    pub const fn metadata(&self) -> &MessageMetadata {
        &self.metadata
    }
    #[must_use]
    /// Per-delivery input to tracing and authority verification.
    pub const fn transport_context(&self) -> &TransportContext {
        &self.transport
    }
    #[must_use]
    /// Authored payload; this accessor does not redact it.
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
/// SHA-256 digest for detecting authored drift under the same message ID; not an authenticity
/// proof.
pub struct MessageFingerprint([u8; 32]);

impl MessageFingerprint {
    /// Restore a durable digest value. This does not establish receipt authenticity.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    /// Hash the ID, all authored metadata, and payload bytes; exclude [`TransportContext`].
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
    /// Digest bytes for durable storage or equality checks.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compare digests, returning [`MessageConflict`] on mismatch.
    ///
    /// `message_id` labels the error; this method does not check that either digest belongs to it.
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

/// Expected and observed authored digests differ for a reported message ID.
pub struct MessageConflict {
    message_id: MessageId,
    expected: MessageFingerprint,
    actual: MessageFingerprint,
}

impl MessageConflict {
    #[must_use]
    /// Identity supplied by the caller for conflict reporting.
    pub const fn message_id(&self) -> &MessageId {
        &self.message_id
    }
    #[must_use]
    /// Previously recorded digest.
    pub const fn expected(&self) -> MessageFingerprint {
        self.expected
    }
    #[must_use]
    /// Digest observed on this attempt.
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
