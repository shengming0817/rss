use crate::{Action, ActorRef, AuditPayload, EventId, OperationId, ResourceRef, SourceIdentity};
use rss_contract::Timepoint;
use rss_diag_context::CorrelationId;
use rss_request_context::{RequestId, TenantId};

/// Closed persisted Audit record version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordVersion {
    /// Canonical binary V1.
    V1,
}

impl RecordVersion {
    pub(crate) const fn tag(self) -> u16 {
        1
    }
}

/// Closed neutral outcome classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The source operation succeeded.
    Succeeded,
    /// Policy or authorization denied the operation.
    Denied,
    /// The operation failed without succeeding.
    Failed,
    /// The source operation has not obtained a confirmed outcome.
    Unknown,
}

impl Outcome {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Succeeded => 1,
            Self::Denied => 2,
            Self::Failed => 3,
            Self::Unknown => 4,
        }
    }

    pub(crate) const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Succeeded),
            2 => Some(Self::Denied),
            3 => Some(Self::Failed),
            4 => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Stable tenant, source and event identity.
#[derive(Clone)]
pub struct RecordIdentity {
    tenant: TenantId,
    source: SourceIdentity,
    event_id: EventId,
}

impl RecordIdentity {
    /// Bind one event to its tenant and source.
    #[must_use]
    pub const fn new(tenant: TenantId, source: SourceIdentity, event_id: EventId) -> Self {
        Self {
            tenant,
            source,
            event_id,
        }
    }

    /// Tenant asserted by the trusted source adapter.
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Source and source contract.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Stable event ID within the source.
    #[must_use]
    pub const fn event_id(&self) -> &EventId {
        &self.event_id
    }
}

impl std::fmt::Debug for RecordIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecordIdentity([redacted])")
    }
}

/// Source-owned audit facts and occurrence time.
pub struct EventFacts {
    actor: ActorRef,
    action: Action,
    resource: ResourceRef,
    outcome: Outcome,
    occurred_at: Timepoint,
}

impl EventFacts {
    /// Combine the required source-owned facts.
    #[must_use]
    pub const fn new(
        actor: ActorRef,
        action: Action,
        resource: ResourceRef,
        outcome: Outcome,
        occurred_at: Timepoint,
    ) -> Self {
        Self {
            actor,
            action,
            resource,
            outcome,
            occurred_at,
        }
    }

    /// Actor reference.
    #[must_use]
    pub const fn actor(&self) -> &ActorRef {
        &self.actor
    }

    /// Source-owned action.
    #[must_use]
    pub const fn action(&self) -> &Action {
        &self.action
    }

    /// Resource reference.
    #[must_use]
    pub const fn resource(&self) -> &ResourceRef {
        &self.resource
    }

    /// Neutral result classification.
    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// Source-asserted occurrence time.
    #[must_use]
    pub const fn occurred_at(&self) -> Timepoint {
        self.occurred_at
    }
}

impl std::fmt::Debug for EventFacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EventFacts([redacted])")
    }
}

/// Optional, separately typed audit coordinates.
pub struct Coordinates {
    correlation_id: Option<CorrelationId>,
    request_id: Option<RequestId>,
    operation_id: Option<OperationId>,
}

impl Coordinates {
    /// Combine independently optional correlation, request and operation coordinates.
    #[must_use]
    pub const fn new(
        correlation_id: Option<CorrelationId>,
        request_id: Option<RequestId>,
        operation_id: Option<OperationId>,
    ) -> Self {
        Self {
            correlation_id,
            request_id,
            operation_id,
        }
    }

    /// Correlation coordinate.
    #[must_use]
    pub const fn correlation_id(&self) -> Option<&CorrelationId> {
        self.correlation_id.as_ref()
    }

    /// Request coordinate.
    #[must_use]
    pub const fn request_id(&self) -> Option<&RequestId> {
        self.request_id.as_ref()
    }

    /// Operation coordinate.
    #[must_use]
    pub const fn operation_id(&self) -> Option<&OperationId> {
        self.operation_id.as_ref()
    }
}

impl std::fmt::Debug for Coordinates {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Coordinates([redacted])")
    }
}

/// Optional coordinates and bounded source payload.
pub struct EventContext {
    coordinates: Coordinates,
    payload: AuditPayload,
}

impl EventContext {
    /// Combine optional coordinates and exact payload bytes.
    #[must_use]
    pub const fn new(coordinates: Coordinates, payload: AuditPayload) -> Self {
        Self {
            coordinates,
            payload,
        }
    }

    /// Optional coordinates.
    #[must_use]
    pub const fn coordinates(&self) -> &Coordinates {
        &self.coordinates
    }

    /// Exact bounded payload.
    #[must_use]
    pub const fn payload(&self) -> &AuditPayload {
        &self.payload
    }
}

impl std::fmt::Debug for EventContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EventContext([redacted])")
    }
}

/// Validated source event before Audit assigns a recording time.
pub struct AuditEventV1 {
    identity: RecordIdentity,
    facts: EventFacts,
    context: EventContext,
}

impl AuditEventV1 {
    /// Construct a source event. This does not authenticate or persist it.
    #[must_use]
    pub const fn new(identity: RecordIdentity, facts: EventFacts, context: EventContext) -> Self {
        Self {
            identity,
            facts,
            context,
        }
    }

    /// Stable record identity.
    #[must_use]
    pub const fn identity(&self) -> &RecordIdentity {
        &self.identity
    }

    /// Source-owned facts.
    #[must_use]
    pub const fn facts(&self) -> &EventFacts {
        &self.facts
    }

    /// Coordinates and payload.
    #[must_use]
    pub const fn context(&self) -> &EventContext {
        &self.context
    }
}

impl std::fmt::Debug for AuditEventV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuditEventV1([redacted])")
    }
}

/// Structurally valid decoded V1 bytes. This is not authentication or commit evidence.
pub struct DecodedAuditV1 {
    event: AuditEventV1,
    recorded_at: Timepoint,
}

impl DecodedAuditV1 {
    pub(crate) const fn new(event: AuditEventV1, recorded_at: Timepoint) -> Self {
        Self { event, recorded_at }
    }

    /// Canonical record version.
    #[must_use]
    pub const fn version(&self) -> RecordVersion {
        RecordVersion::V1
    }

    /// Decoded source event.
    #[must_use]
    pub const fn event(&self) -> &AuditEventV1 {
        &self.event
    }

    /// Recorder-supplied time encoded in the record.
    #[must_use]
    pub const fn recorded_at(&self) -> Timepoint {
        self.recorded_at
    }
}

impl std::fmt::Debug for DecodedAuditV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DecodedAuditV1([redacted])")
    }
}
