use crate::Error;
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    message::{
        AuthoredMessageMetadata, MessageEnvelope, MessageFingerprint, MessageId, MessageMetadata,
        MessageMetadataExtensions,
    },
    outbox::PendingMessage,
};
use std::{collections::BTreeMap, num::NonZeroU64};

const TARGET_ID: &str = "webhookTargetId";
const TARGET_VERSION: &str = "webhookTargetVersion";

/// Product-owned stable destination identity; not a URL or authorization.
#[derive(Clone, Eq, PartialEq)]
pub struct TargetId(MessageId);
impl TargetId {
    /// Validate using the canonical message identity syntax.
    pub fn parse(value: &str) -> Result<Self, Error> {
        MessageId::parse(value)
            .map(Self)
            .map_err(|_| Error::Binding)
    }
    /// Raw identifier; avoid exposing it in ordinary diagnostics.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
/// Product-owned immutable endpoint revision. Changing the endpoint requires a new revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetVersion(NonZeroU64);
impl TargetVersion {
    /// Reject zero; the product owns allocation and retention of revisions.
    pub fn new(value: u64) -> Result<Self, Error> {
        NonZeroU64::new(value).map(Self).ok_or(Error::Binding)
    }
    /// Revision number.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}
/// Exact durable target; its tenant is taken from the enclosing message.
#[derive(Clone, Eq, PartialEq)]
pub struct Target {
    id: TargetId,
    version: TargetVersion,
}
impl Target {
    /// Combine a destination identity and immutable revision.
    pub const fn new(id: TargetId, version: TargetVersion) -> Self {
        Self { id, version }
    }
    /// Destination identity.
    pub const fn id(&self) -> &TargetId {
        &self.id
    }
    /// Exact revision; never implicitly upgraded to latest.
    pub const fn version(&self) -> TargetVersion {
        self.version
    }
    fn parse(metadata: &MessageMetadata) -> Result<Self, Error> {
        let attrs: BTreeMap<_, _> = metadata.attributes().collect();
        let id = TargetId::parse(attrs.get(TARGET_ID).ok_or(Error::Binding)?)?;
        let raw = *attrs.get(TARGET_VERSION).ok_or(Error::Binding)?;
        let version = TargetVersion::new(raw.parse().map_err(|_| Error::Binding)?)?;
        if raw != version.get().to_string() {
            return Err(Error::Binding);
        }
        Ok(Self { id, version })
    }
}
impl std::fmt::Debug for TargetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TargetId(<redacted>)")
    }
}
impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Target(<redacted>)")
    }
}

/// Build durable authored metadata without permitting collisions with adapter-owned fields.
/// Existing correlation, ordering and causation are preserved; payload bytes are never encoded.
pub fn pending_message(
    id: MessageId,
    metadata: MessageMetadata,
    target: Target,
    body: Vec<u8>,
) -> Result<PendingMessage<Vec<u8>>, Error> {
    let mut attributes: BTreeMap<String, String> = metadata
        .attributes()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
    if attributes.contains_key(TARGET_ID) || attributes.contains_key(TARGET_VERSION) {
        return Err(Error::Binding);
    }
    attributes.insert(TARGET_ID.into(), target.id.as_str().into());
    attributes.insert(TARGET_VERSION.into(), target.version.get().to_string());
    let required = AuthoredMessageMetadata::new(
        metadata.tenant_id(),
        metadata.occurred_at(),
        metadata.domain().clone(),
        metadata.route().clone(),
        metadata.contract().clone(),
    );
    let correlation = metadata
        .correlation()
        .map(rss_diag_context::CorrelationId::parse)
        .transpose()
        .map_err(|_| Error::Binding)?;
    let extensions = MessageMetadataExtensions::new(
        correlation,
        metadata.partition().map(|p| p.key().clone()),
        metadata.causation().cloned(),
        attributes,
    );
    let envelope = MessageEnvelope::new(id, MessageMetadata::new(required, extensions), body);
    Publication::parse(&envelope)?;
    Ok(PendingMessage::new(envelope))
}

/// Adapter-validated, read-only input to the trusted host's current authorization decision.
/// Neither metadata nor its fingerprint authenticate the tenant. The host must authorize it.
pub struct Publication<'a> {
    message: &'a MessageEnvelope<Vec<u8>>,
    target: Target,
    fingerprint: MessageFingerprint,
}
impl<'a> Publication<'a> {
    pub(crate) fn parse(message: &'a MessageEnvelope<Vec<u8>>) -> Result<Self, Error> {
        if message.id().as_str().contains('.') {
            return Err(Error::Binding);
        }
        Ok(Self {
            target: Target::parse(message.metadata())?,
            fingerprint: MessageFingerprint::of(message),
            message,
        })
    }
    /// Claimed tenant, to be authenticated/authorized by the host.
    pub fn tenant(&self) -> TenantId {
        self.message.metadata().tenant_id()
    }
    /// Original stable delivery identity.
    pub fn id(&self) -> &MessageId {
        self.message.id()
    }
    /// Full authored metadata for product authorization and event/resource lookup.
    pub fn metadata(&self) -> &MessageMetadata {
        self.message.metadata()
    }
    /// Core-owned fingerprint of all authored facts.
    pub const fn fingerprint(&self) -> MessageFingerprint {
        self.fingerprint
    }
    /// Exact target requested by the durable message.
    pub const fn target(&self) -> &Target {
        &self.target
    }
}
