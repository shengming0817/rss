//! DLQ inspection and replay/redrive service port (#1214).
//!
//! This is intentionally an internal Rust API. It gives operators a typed boundary for:
//! - listing DLQ summaries without exposing payload bytes;
//! - replaying consumer `dead_letter` rows with a caller-supplied new outbox id;
//! - redriving outbox relay `dlx` rows back to `pending`.

use consistency::IdemKey;
use diport::{DeadLetterSource, DlqOperatorAuthorization, dlq_operator_action};
use eventing::observability::{
    EventingDeadLetterReplayFailure, EventingDeadLetterReplayResult, EventingEmitter,
    EventingObservation, EventingOutboxDlxRedriveFailure, EventingOutboxDlxRedriveResult,
    EventingOutboxDlxResolveFailure, EventingOutboxDlxResolveResult,
};

use crate::dead_letter::DeadLetterId;

/// Which backing queue row a summary represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlqEntryKind {
    /// Row in the unified `dead_letter` audit table.
    DeadLetter,
    /// Outbox row currently in `status='dlx'`.
    OutboxDlx,
}

impl DlqEntryKind {
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::DeadLetter => "dead_letter",
            Self::OutboxDlx => "outbox_dlx",
        }
    }

    pub const fn cursor_part(self) -> &'static str {
        self.as_label()
    }

    fn parse_cursor_part(raw: &str) -> Option<Self> {
        match raw {
            "dead_letter" => Some(Self::DeadLetter),
            "outbox_dlx" => Some(Self::OutboxDlx),
            _ => None,
        }
    }
}

/// Exact payload-free DLQ inspection target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlqInspectTarget {
    /// Row in the unified `dead_letter` audit table.
    DeadLetter(DeadLetterId),
    /// Outbox row currently in `status='dlx'`.
    OutboxDlx(IdemKey),
}

impl DlqInspectTarget {
    pub fn kind(&self) -> DlqEntryKind {
        match self {
            Self::DeadLetter(_) => DlqEntryKind::DeadLetter,
            Self::OutboxDlx(_) => DlqEntryKind::OutboxDlx,
        }
    }
}

/// Payload-free DLQ list row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlqEntrySummary {
    kind: DlqEntryKind,
    id: String,
    source: DeadLetterSource,
    tenant: rss_request_context::TenantId,
    message_id: String,
    producer_domain: String,
    consumer_domain: Option<String>,
    contract_id: String,
    topic: String,
    consumer_group: Option<String>,
    payload_len: u64,
    error_summary: String,
    num_attempts: u32,
    last_attempt_epoch_secs: i64,
}

impl DlqEntrySummary {
    #[allow(clippy::too_many_arguments)]
    // reason: DTO mirrors a single audit list row; all fields are required and payload is intentionally absent.
    pub fn new(
        kind: DlqEntryKind,
        id: impl Into<String>,
        source: DeadLetterSource,
        tenant: rss_request_context::TenantId,
        message_id: impl Into<String>,
        producer_domain: impl Into<String>,
        consumer_domain: Option<String>,
        contract_id: impl Into<String>,
        topic: impl Into<String>,
        consumer_group: Option<String>,
        payload_len: u64,
        error_summary: impl Into<String>,
        num_attempts: u32,
        last_attempt_epoch_secs: i64,
    ) -> Self {
        Self {
            kind,
            id: id.into(),
            source,
            tenant,
            message_id: message_id.into(),
            producer_domain: producer_domain.into(),
            consumer_domain,
            contract_id: contract_id.into(),
            topic: topic.into(),
            consumer_group,
            payload_len,
            error_summary: error_summary.into(),
            num_attempts,
            last_attempt_epoch_secs,
        }
    }

    pub fn kind(&self) -> DlqEntryKind {
        self.kind
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn source(&self) -> DeadLetterSource {
        self.source
    }

    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.tenant
    }

    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    pub fn producer_domain(&self) -> &str {
        &self.producer_domain
    }

    pub fn consumer_domain(&self) -> Option<&str> {
        self.consumer_domain.as_deref()
    }

    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    pub fn topic(&self) -> &str {
        &self.topic
    }

    pub fn consumer_group(&self) -> Option<&str> {
        self.consumer_group.as_deref()
    }

    pub fn payload_len(&self) -> u64 {
        self.payload_len
    }

    pub fn error_summary(&self) -> &str {
        &self.error_summary
    }

    pub fn num_attempts(&self) -> u32 {
        self.num_attempts
    }

    pub fn last_attempt_epoch_secs(&self) -> i64 {
        self.last_attempt_epoch_secs
    }
}

/// Cursor returned by [`DlqListResult`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlqCursor {
    last_epoch_secs: i64,
    last_kind: DlqEntryKind,
    last_id: String,
}

impl DlqCursor {
    pub fn parse(raw: &str) -> Result<Self, DlqError> {
        let mut parts = raw.splitn(3, ':');
        let Some(epoch) = parts.next() else {
            return Err(DlqError::InvalidCursor);
        };
        let Some(kind) = parts.next() else {
            return Err(DlqError::InvalidCursor);
        };
        let Some(id) = parts.next() else {
            return Err(DlqError::InvalidCursor);
        };
        Ok(Self {
            last_epoch_secs: epoch.parse().map_err(|_| DlqError::InvalidCursor)?,
            last_kind: DlqEntryKind::parse_cursor_part(kind).ok_or(DlqError::InvalidCursor)?,
            last_id: id.to_string(),
        })
    }

    fn from_page(last: &DlqEntrySummary) -> Self {
        Self {
            last_epoch_secs: last.last_attempt_epoch_secs(),
            last_kind: last.kind(),
            last_id: last.id().to_string(),
        }
    }

    pub fn last_epoch_secs(&self) -> i64 {
        self.last_epoch_secs
    }

    pub fn last_kind(&self) -> DlqEntryKind {
        self.last_kind
    }

    pub fn last_id(&self) -> &str {
        &self.last_id
    }

    pub fn encode(&self) -> String {
        format!(
            "{}:{}:{}",
            self.last_epoch_secs,
            self.last_kind.cursor_part(),
            self.last_id
        )
    }
}

/// DLQ list filter. Tenant is mandatory; producer domain, consumer domain, source, and contract
/// are optional.
#[derive(Debug)]
pub struct DlqListQuery {
    authorization: DlqOperatorAuthorization<dlq_operator_action::List>,
    producer_domain: Option<String>,
    consumer_domain: Option<String>,
    contract_id: Option<String>,
    source: Option<DeadLetterSource>,
    limit: u32,
    cursor: Option<DlqCursor>,
}

/// Exact payload-free DLQ inspection query. Tenant is mandatory.
#[derive(Debug)]
pub struct DlqInspectRequest {
    authorization: DlqOperatorAuthorization<dlq_operator_action::Inspect>,
    target: DlqInspectTarget,
}

impl DlqInspectRequest {
    pub fn new(
        authorization: DlqOperatorAuthorization<dlq_operator_action::Inspect>,
        target: DlqInspectTarget,
    ) -> Self {
        Self {
            authorization,
            target,
        }
    }

    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.authorization.tenant()
    }

    pub fn target(&self) -> &DlqInspectTarget {
        &self.target
    }
}

impl DlqListQuery {
    pub fn new(authorization: DlqOperatorAuthorization<dlq_operator_action::List>) -> Self {
        Self {
            authorization,
            producer_domain: None,
            consumer_domain: None,
            contract_id: None,
            source: None,
            limit: 100,
            cursor: None,
        }
    }

    pub fn with_producer_domain(mut self, producer_domain: impl Into<String>) -> Self {
        self.producer_domain = Some(producer_domain.into());
        self
    }

    pub fn with_consumer_domain(mut self, consumer_domain: impl Into<String>) -> Self {
        self.consumer_domain = Some(consumer_domain.into());
        self
    }

    pub fn with_contract_id(mut self, contract_id: impl Into<String>) -> Self {
        self.contract_id = Some(contract_id.into());
        self
    }

    pub fn with_source(mut self, source: DeadLetterSource) -> Self {
        self.source = Some(source);
        self
    }

    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = limit.clamp(1, 500);
        self
    }

    pub fn with_cursor(mut self, cursor: DlqCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.authorization.tenant()
    }

    pub fn producer_domain(&self) -> Option<&str> {
        self.producer_domain.as_deref()
    }

    pub fn consumer_domain(&self) -> Option<&str> {
        self.consumer_domain.as_deref()
    }

    pub fn contract_id(&self) -> Option<&str> {
        self.contract_id.as_deref()
    }

    pub fn source(&self) -> Option<DeadLetterSource> {
        self.source
    }

    pub fn limit(&self) -> u32 {
        self.limit
    }

    pub fn cursor(&self) -> Option<&DlqCursor> {
        self.cursor.as_ref()
    }

    pub fn fetch_limit(&self) -> u32 {
        self.limit.saturating_add(1)
    }
}

/// Paginated DLQ list result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlqListResult {
    data: Vec<DlqEntrySummary>,
    has_more: bool,
    next_cursor: Option<String>,
}

impl DlqListResult {
    pub fn from_sorted_rows(query: &DlqListQuery, mut rows: Vec<DlqEntrySummary>) -> Self {
        rows.sort_by(compare_summary);
        let limit = query.limit() as usize;
        let mut data: Vec<_> = rows
            .into_iter()
            .filter(|row| {
                query
                    .contract_id()
                    .is_none_or(|contract_id| row.contract_id() == contract_id)
                    && query
                        .producer_domain()
                        .is_none_or(|domain| row.producer_domain() == domain)
                    && query
                        .consumer_domain()
                        .is_none_or(|domain| row.consumer_domain() == Some(domain))
                    && query.source().is_none_or(|source| row.source() == source)
                    && query
                        .cursor()
                        .is_none_or(|cursor| compare_summary_to_cursor(row, cursor).is_gt())
            })
            .take(limit + 1)
            .collect();
        let has_more = data.len() > limit;
        if has_more {
            data.truncate(limit);
        }
        let next_cursor = if has_more {
            data.last().map(|last| DlqCursor::from_page(last).encode())
        } else {
            None
        };
        Self {
            data,
            has_more,
            next_cursor,
        }
    }

    pub fn data(&self) -> &[DlqEntrySummary] {
        &self.data
    }

    pub fn into_data(self) -> Vec<DlqEntrySummary> {
        self.data
    }

    pub fn has_more(&self) -> bool {
        self.has_more
    }

    pub fn next_cursor(&self) -> Option<&str> {
        self.next_cursor.as_deref()
    }
}

/// Replay a consumer dead_letter row by inserting a new outbox event id.
#[derive(Debug)]
pub struct DlqReplayRequest {
    authorization: DlqOperatorAuthorization<dlq_operator_action::ReplayDeadLetter>,
    dead_letter_id: DeadLetterId,
    replay_id: IdemKey,
}

impl DlqReplayRequest {
    pub fn new(
        authorization: DlqOperatorAuthorization<dlq_operator_action::ReplayDeadLetter>,
        dead_letter_id: DeadLetterId,
        replay_id: IdemKey,
    ) -> Self {
        Self {
            authorization,
            dead_letter_id,
            replay_id,
        }
    }

    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.authorization.tenant()
    }

    pub fn dead_letter_id(&self) -> &DeadLetterId {
        &self.dead_letter_id
    }

    pub fn replay_id(&self) -> &IdemKey {
        &self.replay_id
    }

    pub fn operator_subject(&self) -> &str {
        self.authorization.operator_subject()
    }

    pub fn start_audit_id(&self) -> &diport::DlqOperatorStartAuditId {
        self.authorization.start_audit_id()
    }
}

/// Redrive an outbox relay DLX row back to pending.
#[derive(Debug)]
pub struct DlqRedriveRequest {
    authorization: DlqOperatorAuthorization<dlq_operator_action::RedriveOutbox>,
    event_id: IdemKey,
}

/// Audited change ticket authorizing an expired outbox terminal resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxResolutionChangeTicket(String);

impl OutboxResolutionChangeTicket {
    pub fn parse(raw: &str) -> Result<Self, DlqError> {
        parse_resolution_text(raw, 128).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn parse_resolution_text(raw: &str, max_len: usize) -> Result<String, DlqError> {
    let value = raw.trim();
    if value.is_empty()
        || value != raw
        || value.len() > max_len
        || value.chars().any(char::is_control)
    {
        return Err(DlqError::InvalidResolutionInput);
    }
    Ok(value.to_owned())
}

/// Closed terminal strategy for an expired, partition-blocking outbox DLX row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxExpiredResolutionKind {
    AcceptedGap,
    Compensated,
}

impl OutboxExpiredResolutionKind {
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::AcceptedGap => "accepted_gap",
            Self::Compensated => "compensated",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, DlqError> {
        match raw {
            "accepted_gap" => Ok(Self::AcceptedGap),
            "compensated" => Ok(Self::Compensated),
            _ => Err(DlqError::InvalidResolutionInput),
        }
    }
}

/// Typed, capability-bearing request for resolving an expired outbox DLX head.
#[derive(Debug)]
pub struct OutboxExpiredResolutionRequest {
    authorization: DlqOperatorAuthorization<dlq_operator_action::ResolveExpiredOutbox>,
    event_id: IdemKey,
    kind: OutboxExpiredResolutionKind,
    evidence_event_id: Option<IdemKey>,
    change_ticket: OutboxResolutionChangeTicket,
}

impl OutboxExpiredResolutionRequest {
    pub fn accepted_gap(
        authorization: DlqOperatorAuthorization<dlq_operator_action::ResolveExpiredOutbox>,
        event_id: IdemKey,
        change_ticket: OutboxResolutionChangeTicket,
    ) -> Self {
        Self {
            authorization,
            event_id,
            kind: OutboxExpiredResolutionKind::AcceptedGap,
            evidence_event_id: None,
            change_ticket,
        }
    }

    pub fn compensated(
        authorization: DlqOperatorAuthorization<dlq_operator_action::ResolveExpiredOutbox>,
        event_id: IdemKey,
        evidence_event_id: IdemKey,
        change_ticket: OutboxResolutionChangeTicket,
    ) -> Self {
        Self {
            authorization,
            event_id,
            kind: OutboxExpiredResolutionKind::Compensated,
            evidence_event_id: Some(evidence_event_id),
            change_ticket,
        }
    }

    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.authorization.tenant()
    }

    pub fn event_id(&self) -> &IdemKey {
        &self.event_id
    }

    pub fn kind(&self) -> OutboxExpiredResolutionKind {
        self.kind
    }

    pub fn evidence_event_id(&self) -> Option<&IdemKey> {
        self.evidence_event_id.as_ref()
    }

    pub fn change_ticket(&self) -> &OutboxResolutionChangeTicket {
        &self.change_ticket
    }

    pub fn operator_subject(&self) -> &str {
        self.authorization.operator_subject()
    }

    pub fn start_audit_id(&self) -> &diport::DlqOperatorStartAuditId {
        self.authorization.start_audit_id()
    }
}

impl DlqRedriveRequest {
    pub fn new(
        authorization: DlqOperatorAuthorization<dlq_operator_action::RedriveOutbox>,
        event_id: IdemKey,
    ) -> Self {
        Self {
            authorization,
            event_id,
        }
    }

    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.authorization.tenant()
    }

    pub fn event_id(&self) -> &IdemKey {
        &self.event_id
    }

    pub fn operator_subject(&self) -> &str {
        self.authorization.operator_subject()
    }

    pub fn start_audit_id(&self) -> &diport::DlqOperatorStartAuditId {
        self.authorization.start_audit_id()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlqReplayOutcome {
    Inserted,
    AlreadyExists,
}

impl DlqReplayOutcome {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Inserted => "inserted",
            Self::AlreadyExists => "already_exists",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlqRedriveOutcome {
    Redriven,
    NotFound,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxExpiredResolutionOutcome {
    Resolved,
    NotFound,
    NotExpired,
    EvidenceRejected,
}

/// Mutation outcome whose finish audit was committed in the same tenant transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurablyAuditedDlqMutation<O> {
    outcome: O,
}

impl<O> DurablyAuditedDlqMutation<O> {
    /// Constructs the receipt only after mutation outcome and finish audit commit together.
    ///
    /// Implementations of [`DlqStore`] must not return this value before the shared transaction is
    /// durably acknowledged.
    pub fn committed(outcome: O) -> Self {
        Self { outcome }
    }

    /// Consumes the durable receipt and returns its mutation outcome.
    pub fn into_outcome(self) -> O {
        self.outcome
    }

    /// Borrows the committed mutation outcome without discarding the durable-audit receipt.
    pub const fn outcome(&self) -> &O {
        &self.outcome
    }
}

impl OutboxExpiredResolutionOutcome {
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::NotFound => "not_found",
            Self::NotExpired => "not_expired",
            Self::EvidenceRejected => "evidence_rejected",
        }
    }
}

impl DlqRedriveOutcome {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Redriven => "redriven",
            Self::NotFound => "not_found",
            Self::Expired => "expired",
        }
    }
}

/// Closed failure stage for PostgreSQL-backed dead-letter replay storage.
///
/// The stage is intentionally data-free: it is safe for logs and metric labels and prevents
/// adapter errors from leaking payload, metadata, capsule, key-reference, or database details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlqReplayStoreStage {
    FetchDeadLetter,
    EncodeMetadata,
    AppendOutbox,
    ProjectionMirror,
    Transaction,
}

impl DlqReplayStoreStage {
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::FetchDeadLetter => "fetch_dead_letter",
            Self::EncodeMetadata => "encode_metadata",
            Self::AppendOutbox => "append_outbox",
            Self::ProjectionMirror => "projection_mirror",
            Self::Transaction => "transaction",
        }
    }
}

impl std::fmt::Display for DlqReplayStoreStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_label())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DlqError {
    #[error("dlq cursor is invalid")]
    InvalidCursor,
    #[error("dlq entry not found")]
    NotFound,
    #[error("dlq entry source is not replayable")]
    NotReplayable,
    #[error("dlq entry payload is invalid")]
    InvalidPayload,
    #[error("dlq entry schema headers are invalid")]
    InvalidSchemaHeaders,
    #[error("dlq payload key provider is unavailable")]
    PayloadKeyUnavailable,
    #[error("dlq payload key provider rejected configuration or authorization")]
    PayloadKeyForbidden,
    #[error("dlq replay outbox fact conflict")]
    FactConflict(#[source] consistency::OutboxFactConflict),
    #[error("dlq replay store failed at {0}")]
    ReplayStore(DlqReplayStoreStage),
    #[error("dlq store failed")]
    Store,
    #[error("expired outbox resolution input is invalid")]
    InvalidResolutionInput,
}

impl DlqError {
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::InvalidCursor => "invalid_cursor",
            Self::NotFound => "not_found",
            Self::NotReplayable => "not_replayable",
            Self::InvalidPayload => "invalid_payload",
            Self::InvalidSchemaHeaders => "invalid_schema_headers",
            Self::PayloadKeyUnavailable => "payload_key_unavailable",
            Self::PayloadKeyForbidden => "payload_key_forbidden",
            Self::FactConflict(_) => "fact_conflict",
            Self::ReplayStore(stage) => stage.as_label(),
            Self::Store => "store",
            Self::InvalidResolutionInput => "invalid_resolution_input",
        }
    }
}

pub fn record_dlq_replay(emitter: &dyn EventingEmitter, outcome: DlqReplayOutcome) {
    let result = match outcome {
        DlqReplayOutcome::Inserted => EventingDeadLetterReplayResult::Inserted,
        DlqReplayOutcome::AlreadyExists => EventingDeadLetterReplayResult::AlreadyExists,
    };
    emitter.emit(EventingObservation::DeadLetterReplay { result });
}

pub fn record_dlq_outbox_redrive(emitter: &dyn EventingEmitter, outcome: DlqRedriveOutcome) {
    let result = match outcome {
        DlqRedriveOutcome::Redriven => EventingOutboxDlxRedriveResult::Redriven,
        DlqRedriveOutcome::NotFound => EventingOutboxDlxRedriveResult::NotFound,
        DlqRedriveOutcome::Expired => EventingOutboxDlxRedriveResult::Expired,
    };
    emitter.emit(EventingObservation::OutboxDlxRedrive { result });
}

pub fn record_outbox_expired_resolution(
    emitter: &dyn EventingEmitter,
    outcome: OutboxExpiredResolutionOutcome,
) {
    let result = match outcome {
        OutboxExpiredResolutionOutcome::Resolved => EventingOutboxDlxResolveResult::Resolved,
        OutboxExpiredResolutionOutcome::NotFound => EventingOutboxDlxResolveResult::NotFound,
        OutboxExpiredResolutionOutcome::NotExpired => EventingOutboxDlxResolveResult::NotExpired,
        OutboxExpiredResolutionOutcome::EvidenceRejected => {
            EventingOutboxDlxResolveResult::EvidenceRejected
        }
    };
    emitter.emit(EventingObservation::OutboxDlxResolveExpired { result });
}

pub fn record_dlq_replay_error(emitter: &dyn EventingEmitter, error: &DlqError) {
    emitter.emit(EventingObservation::DeadLetterReplay {
        result: EventingDeadLetterReplayResult::Failed(dlq_replay_failure(error)),
    });
}

pub fn record_dlq_outbox_redrive_error(emitter: &dyn EventingEmitter, error: &DlqError) {
    emitter.emit(EventingObservation::OutboxDlxRedrive {
        result: EventingOutboxDlxRedriveResult::Failed(dlq_redrive_failure(error)),
    });
}

pub fn record_outbox_expired_resolution_error(emitter: &dyn EventingEmitter, error: &DlqError) {
    emitter.emit(EventingObservation::OutboxDlxResolveExpired {
        result: EventingOutboxDlxResolveResult::Failed(dlq_resolve_failure(error)),
    });
}

fn dlq_replay_failure(error: &DlqError) -> EventingDeadLetterReplayFailure {
    match error {
        DlqError::InvalidCursor | DlqError::InvalidResolutionInput => {
            EventingDeadLetterReplayFailure::Invariant
        }
        DlqError::NotFound => EventingDeadLetterReplayFailure::NotFound,
        DlqError::NotReplayable => EventingDeadLetterReplayFailure::NotReplayable,
        DlqError::InvalidPayload => EventingDeadLetterReplayFailure::InvalidPayload,
        DlqError::InvalidSchemaHeaders => EventingDeadLetterReplayFailure::InvalidSchemaHeaders,
        DlqError::PayloadKeyUnavailable => EventingDeadLetterReplayFailure::PayloadKeyUnavailable,
        DlqError::PayloadKeyForbidden => EventingDeadLetterReplayFailure::PayloadKeyForbidden,
        DlqError::FactConflict(_) => EventingDeadLetterReplayFailure::FactConflict,
        DlqError::ReplayStore(stage) => match stage {
            DlqReplayStoreStage::FetchDeadLetter => {
                EventingDeadLetterReplayFailure::FetchDeadLetter
            }
            DlqReplayStoreStage::EncodeMetadata => EventingDeadLetterReplayFailure::EncodeMetadata,
            DlqReplayStoreStage::AppendOutbox => EventingDeadLetterReplayFailure::AppendOutbox,
            DlqReplayStoreStage::ProjectionMirror => {
                EventingDeadLetterReplayFailure::ProjectionMirror
            }
            DlqReplayStoreStage::Transaction => EventingDeadLetterReplayFailure::Transaction,
        },
        DlqError::Store => EventingDeadLetterReplayFailure::Store,
    }
}

fn dlq_redrive_failure(error: &DlqError) -> EventingOutboxDlxRedriveFailure {
    match error {
        DlqError::Store => EventingOutboxDlxRedriveFailure::Store,
        DlqError::InvalidCursor
        | DlqError::NotFound
        | DlqError::NotReplayable
        | DlqError::InvalidPayload
        | DlqError::InvalidSchemaHeaders
        | DlqError::PayloadKeyUnavailable
        | DlqError::PayloadKeyForbidden
        | DlqError::FactConflict(_)
        | DlqError::ReplayStore(_)
        | DlqError::InvalidResolutionInput => EventingOutboxDlxRedriveFailure::Invariant,
    }
}

fn dlq_resolve_failure(error: &DlqError) -> EventingOutboxDlxResolveFailure {
    match error {
        DlqError::InvalidResolutionInput => EventingOutboxDlxResolveFailure::InvalidResolutionInput,
        DlqError::Store => EventingOutboxDlxResolveFailure::Store,
        DlqError::InvalidCursor
        | DlqError::NotFound
        | DlqError::NotReplayable
        | DlqError::InvalidPayload
        | DlqError::InvalidSchemaHeaders
        | DlqError::PayloadKeyUnavailable
        | DlqError::PayloadKeyForbidden
        | DlqError::FactConflict(_)
        | DlqError::ReplayStore(_) => EventingOutboxDlxResolveFailure::Invariant,
    }
}

#[allow(async_fn_in_trait)]
// reason: service-internal native AFIT port; adapters implement it directly and callers use static dispatch.
pub trait DlqStore: Send + Sync {
    async fn list_dlq(&self, query: DlqListQuery) -> Result<DlqListResult, DlqError>;
    async fn inspect_dlq(&self, request: DlqInspectRequest) -> Result<DlqEntrySummary, DlqError>;
    async fn replay_dead_letter(
        &self,
        request: DlqReplayRequest,
    ) -> Result<DurablyAuditedDlqMutation<DlqReplayOutcome>, DlqError>;
    async fn redrive_outbox(
        &self,
        request: DlqRedriveRequest,
    ) -> Result<DurablyAuditedDlqMutation<DlqRedriveOutcome>, DlqError>;
    async fn resolve_expired_outbox(
        &self,
        request: OutboxExpiredResolutionRequest,
    ) -> Result<DurablyAuditedDlqMutation<OutboxExpiredResolutionOutcome>, DlqError>;
}

fn compare_summary(a: &DlqEntrySummary, b: &DlqEntrySummary) -> std::cmp::Ordering {
    b.last_attempt_epoch_secs()
        .cmp(&a.last_attempt_epoch_secs())
        .then_with(|| a.kind().cursor_part().cmp(b.kind().cursor_part()))
        .then_with(|| a.id().cmp(b.id()))
}

fn compare_summary_to_cursor(a: &DlqEntrySummary, b: &DlqCursor) -> std::cmp::Ordering {
    b.last_epoch_secs()
        .cmp(&a.last_attempt_epoch_secs())
        .then_with(|| a.kind().cursor_part().cmp(b.last_kind().cursor_part()))
        .then_with(|| a.id().cmp(b.last_id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::expect_used)]
    fn authorization<A: diport::DlqOperatorAction>(
        tenant: rss_request_context::TenantId,
    ) -> diport::DlqOperatorAuthorization<A> {
        diport::test_support::dlq_operator_authorization(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            "test-dlq-operator",
            tenant,
            diport::DlqOperatorStartAuditId::parse("dlq-test-audit").expect("valid audit id"),
        )
    }

    #[test]
    fn fact_conflict_has_closed_safe_label() {
        let error = DlqError::FactConflict(consistency::OutboxFactConflict);
        assert_eq!(error.as_label(), "fact_conflict");
        assert_eq!(error.to_string(), "dlq replay outbox fact conflict");
        assert!(!format!("{error:?}").contains("fingerprint"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id.
    fn list_summary_debug_does_not_expose_payload_bytes() {
        let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let summary = DlqEntrySummary::new(
            DlqEntryKind::DeadLetter,
            "row-1",
            DeadLetterSource::Consumer,
            tenant,
            "msg-1",
            "runtime",
            Some("observer".to_string()),
            "contract-session",
            "session.created",
            Some("runtime.fact.consumer".to_string()),
            4,
            "max retries exhausted",
            3,
            1_700_000_000,
        );

        let rendered = format!("{summary:?}");
        assert!(!rendered.contains("[1, 2, 3, 4]"));
        assert!(rendered.contains("payload_len"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id.
    fn query_limit_is_bounded() {
        let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        assert_eq!(
            DlqListQuery::new(authorization(tenant))
                .with_limit(0)
                .limit(),
            1
        );
        assert_eq!(
            DlqListQuery::new(authorization(tenant))
                .with_limit(999)
                .limit(),
            500
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses known canonical ids.
    fn list_result_reports_cursor_when_more_rows_exist() {
        let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let rows: Vec<_> = (0..3)
            .map(|i| {
                DlqEntrySummary::new(
                    DlqEntryKind::DeadLetter,
                    format!("row-{i}"),
                    DeadLetterSource::Consumer,
                    tenant,
                    format!("msg-{i}"),
                    "runtime",
                    Some("observer".to_string()),
                    "contract-session",
                    "session.created",
                    Some("runtime.fact.consumer".to_string()),
                    4,
                    "max retries exhausted",
                    3,
                    1_700_000_000 - i,
                )
            })
            .collect();

        let query = DlqListQuery::new(authorization(tenant)).with_limit(2);
        let result = DlqListResult::from_sorted_rows(&query, rows);
        assert!(result.has_more());
        assert_eq!(result.data().len(), 2);
        assert!(result.next_cursor().is_some());
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id.
    fn list_result_filters_by_contract_id_before_pagination() {
        let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let rows = vec![
            DlqEntrySummary::new(
                DlqEntryKind::DeadLetter,
                "row-a",
                DeadLetterSource::Consumer,
                tenant,
                "msg-a",
                "runtime",
                Some("observer".to_string()),
                "runtime.fact-recorded",
                "session.created",
                Some("runtime.fact.consumer".to_string()),
                4,
                "max retries exhausted",
                3,
                1_700_000_000,
            ),
            DlqEntrySummary::new(
                DlqEntryKind::DeadLetter,
                "row-b",
                DeadLetterSource::Consumer,
                tenant,
                "msg-b",
                "runtime",
                Some("observer".to_string()),
                "runtime.fact-updated",
                "role.assigned",
                Some("identity.role.consumer".to_string()),
                4,
                "max retries exhausted",
                3,
                1_700_000_001,
            ),
        ];

        let result = DlqListResult::from_sorted_rows(
            &DlqListQuery::new(authorization(tenant))
                .with_contract_id("runtime.fact-recorded")
                .with_limit(1),
            rows,
        );

        assert_eq!(result.data().len(), 1);
        assert_eq!(result.data()[0].contract_id(), "runtime.fact-recorded");
        assert!(
            !result.has_more(),
            "filtered-out rows must not force paging"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id.
    fn list_result_filters_producer_and_consumer_domains_independently() {
        let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let rows = ["observer", "search"]
            .into_iter()
            .map(|consumer_domain| {
                DlqEntrySummary::new(
                    DlqEntryKind::DeadLetter,
                    format!("row-{consumer_domain}"),
                    DeadLetterSource::Consumer,
                    tenant,
                    format!("msg-{consumer_domain}"),
                    "runtime",
                    Some(consumer_domain.to_string()),
                    "runtime.fact-recorded",
                    "session.created",
                    Some(format!("{consumer_domain}.session.consumer")),
                    4,
                    "max retries exhausted",
                    3,
                    1_700_000_000,
                )
            })
            .collect();

        let result = DlqListResult::from_sorted_rows(
            &DlqListQuery::new(authorization(tenant))
                .with_producer_domain("runtime")
                .with_consumer_domain("observer"),
            rows,
        );

        assert_eq!(result.data().len(), 1);
        assert_eq!(result.data()[0].producer_domain(), "runtime");
        assert_eq!(result.data()[0].consumer_domain(), Some("observer"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id.
    fn list_cursor_is_keyset_not_offset() {
        let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let rows: Vec<_> = (0..4)
            .map(|i| {
                DlqEntrySummary::new(
                    DlqEntryKind::DeadLetter,
                    format!("row-{i}"),
                    DeadLetterSource::Consumer,
                    tenant,
                    format!("msg-{i}"),
                    "runtime",
                    Some("observer".to_string()),
                    "contract-session",
                    "session.created",
                    Some("runtime.fact.consumer".to_string()),
                    4,
                    "max retries exhausted",
                    3,
                    1_700_000_000 - i,
                )
            })
            .collect();

        let first = DlqListResult::from_sorted_rows(
            &DlqListQuery::new(authorization(tenant)).with_limit(2),
            rows,
        );
        let cursor = DlqCursor::parse(first.next_cursor().expect("cursor")).expect("valid cursor");
        let mut changed_rows = first.into_data();
        changed_rows.push(DlqEntrySummary::new(
            DlqEntryKind::DeadLetter,
            "new-head",
            DeadLetterSource::Consumer,
            tenant,
            "msg-new",
            "runtime",
            Some("observer".to_string()),
            "contract-session",
            "session.created",
            Some("runtime.fact.consumer".to_string()),
            4,
            "newer row",
            1,
            1_700_000_100,
        ));
        changed_rows.push(DlqEntrySummary::new(
            DlqEntryKind::DeadLetter,
            "row-tail",
            DeadLetterSource::Consumer,
            tenant,
            "msg-tail",
            "runtime",
            Some("observer".to_string()),
            "contract-session",
            "session.created",
            Some("runtime.fact.consumer".to_string()),
            4,
            "older row",
            1,
            1_699_999_990,
        ));

        let second = DlqListResult::from_sorted_rows(
            &DlqListQuery::new(authorization(tenant))
                .with_limit(10)
                .with_cursor(cursor),
            changed_rows,
        );
        assert_eq!(second.data()[0].id(), "row-tail");
        assert!(
            second.data().iter().all(|row| row.id() != "new-head"),
            "new rows before the cursor must not shift the next page"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id.
    fn list_cursor_paginates_same_second_rows_without_skipping() {
        let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let rows: Vec<_> = (0..3)
            .map(|i| {
                DlqEntrySummary::new(
                    DlqEntryKind::DeadLetter,
                    format!("row-{i}"),
                    DeadLetterSource::Consumer,
                    tenant,
                    format!("msg-{i}"),
                    "runtime",
                    Some("observer".to_string()),
                    "contract-session",
                    "session.created",
                    Some("runtime.fact.consumer".to_string()),
                    4,
                    "max retries exhausted",
                    3,
                    1_700_000_000,
                )
            })
            .collect();

        let first = DlqListResult::from_sorted_rows(
            &DlqListQuery::new(authorization(tenant)).with_limit(2),
            rows.clone(),
        );
        assert_eq!(
            first
                .data()
                .iter()
                .map(DlqEntrySummary::id)
                .collect::<Vec<_>>(),
            vec!["row-0", "row-1"]
        );
        let cursor = DlqCursor::parse(first.next_cursor().expect("cursor")).expect("valid cursor");
        let second = DlqListResult::from_sorted_rows(
            &DlqListQuery::new(authorization(tenant))
                .with_limit(2)
                .with_cursor(cursor),
            rows,
        );
        assert_eq!(
            second
                .data()
                .iter()
                .map(DlqEntrySummary::id)
                .collect::<Vec<_>>(),
            vec!["row-2"]
        );
    }

    #[test]
    fn malformed_dead_letter_id_is_rejected_before_adapter_sql() {
        assert!(matches!(
            DeadLetterId::parse("not-a-uuid"),
            Err(crate::DeadLetterIdError)
        ));
    }

    #[test]
    fn every_request_requires_an_exact_operator_authorization() {
        let _replay: fn(
            diport::DlqOperatorAuthorization<dlq_operator_action::ReplayDeadLetter>,
            DeadLetterId,
            IdemKey,
        ) -> DlqReplayRequest = DlqReplayRequest::new;
        let _redrive: fn(
            diport::DlqOperatorAuthorization<dlq_operator_action::RedriveOutbox>,
            IdemKey,
        ) -> DlqRedriveRequest = DlqRedriveRequest::new;
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: typed operator fixtures are fixed non-empty values and a canonical tenant/event id.
    fn expired_outbox_resolution_request_is_typed_and_shape_closed() {
        let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let event_id = IdemKey::parse("evt-blocked").expect("canonical event id");
        let evidence = IdemKey::parse("evt-compensation").expect("canonical evidence id");
        let ticket = OutboxResolutionChangeTicket::parse("CHG-1742").expect("valid ticket");
        let accepted = OutboxExpiredResolutionRequest::accepted_gap(
            authorization(tenant),
            event_id.clone(),
            ticket.clone(),
        );
        assert_eq!(accepted.kind(), OutboxExpiredResolutionKind::AcceptedGap);
        assert!(accepted.evidence_event_id().is_none());

        let compensated = OutboxExpiredResolutionRequest::compensated(
            authorization(tenant),
            event_id,
            evidence.clone(),
            ticket,
        );
        assert_eq!(compensated.kind(), OutboxExpiredResolutionKind::Compensated);
        assert_eq!(compensated.evidence_event_id(), Some(&evidence));
        assert_eq!(
            OutboxExpiredResolutionOutcome::Resolved.as_label(),
            "resolved"
        );
        assert_eq!(
            OutboxExpiredResolutionOutcome::EvidenceRejected.as_label(),
            "evidence_rejected"
        );
        for dirty in [" CHG-1742", "CHG-1742 ", "CHG-1742\n"] {
            assert!(matches!(
                OutboxResolutionChangeTicket::parse(dirty),
                Err(DlqError::InvalidResolutionInput)
            ));
        }
    }

    #[test]
    fn dlq_redrive_uses_closed_typed_results() {
        #[derive(Default)]
        struct Recorder(std::sync::Mutex<Vec<EventingObservation>>);
        impl EventingEmitter for Recorder {
            fn emit(&self, observation: EventingObservation) {
                self.0
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push(observation);
            }
        }
        let recorder = Recorder::default();
        record_dlq_replay(&recorder, DlqReplayOutcome::Inserted);
        record_dlq_replay(&recorder, DlqReplayOutcome::AlreadyExists);
        record_dlq_outbox_redrive(&recorder, DlqRedriveOutcome::Redriven);
        record_dlq_outbox_redrive(&recorder, DlqRedriveOutcome::NotFound);
        record_dlq_outbox_redrive(&recorder, DlqRedriveOutcome::Expired);
        record_outbox_expired_resolution(&recorder, OutboxExpiredResolutionOutcome::Resolved);
        record_outbox_expired_resolution(&recorder, OutboxExpiredResolutionOutcome::NotFound);
        record_outbox_expired_resolution(&recorder, OutboxExpiredResolutionOutcome::NotExpired);
        record_outbox_expired_resolution(
            &recorder,
            OutboxExpiredResolutionOutcome::EvidenceRejected,
        );
        record_dlq_outbox_redrive_error(&recorder, &DlqError::NotFound);
        record_dlq_replay_error(
            &recorder,
            &DlqError::ReplayStore(DlqReplayStoreStage::ProjectionMirror),
        );
        record_outbox_expired_resolution_error(&recorder, &DlqError::InvalidResolutionInput);

        assert_eq!(
            *recorder.0.lock().unwrap_or_else(|error| error.into_inner()),
            vec![
                EventingObservation::DeadLetterReplay {
                    result: EventingDeadLetterReplayResult::Inserted,
                },
                EventingObservation::DeadLetterReplay {
                    result: EventingDeadLetterReplayResult::AlreadyExists,
                },
                EventingObservation::OutboxDlxRedrive {
                    result: EventingOutboxDlxRedriveResult::Redriven,
                },
                EventingObservation::OutboxDlxRedrive {
                    result: EventingOutboxDlxRedriveResult::NotFound,
                },
                EventingObservation::OutboxDlxRedrive {
                    result: EventingOutboxDlxRedriveResult::Expired,
                },
                EventingObservation::OutboxDlxResolveExpired {
                    result: EventingOutboxDlxResolveResult::Resolved,
                },
                EventingObservation::OutboxDlxResolveExpired {
                    result: EventingOutboxDlxResolveResult::NotFound,
                },
                EventingObservation::OutboxDlxResolveExpired {
                    result: EventingOutboxDlxResolveResult::NotExpired,
                },
                EventingObservation::OutboxDlxResolveExpired {
                    result: EventingOutboxDlxResolveResult::EvidenceRejected,
                },
                EventingObservation::OutboxDlxRedrive {
                    result: EventingOutboxDlxRedriveResult::Failed(
                        EventingOutboxDlxRedriveFailure::Invariant,
                    ),
                },
                EventingObservation::DeadLetterReplay {
                    result: EventingDeadLetterReplayResult::Failed(
                        EventingDeadLetterReplayFailure::ProjectionMirror,
                    ),
                },
                EventingObservation::OutboxDlxResolveExpired {
                    result: EventingOutboxDlxResolveResult::Failed(
                        EventingOutboxDlxResolveFailure::InvalidResolutionInput,
                    ),
                },
            ]
        );
    }

    #[test]
    fn replay_store_stages_have_fixed_display_error_and_metric_labels() {
        for (stage, expected) in [
            (DlqReplayStoreStage::FetchDeadLetter, "fetch_dead_letter"),
            (DlqReplayStoreStage::EncodeMetadata, "encode_metadata"),
            (DlqReplayStoreStage::AppendOutbox, "append_outbox"),
            (DlqReplayStoreStage::ProjectionMirror, "projection_mirror"),
            (DlqReplayStoreStage::Transaction, "transaction"),
        ] {
            assert_eq!(stage.as_label(), expected);
            assert_eq!(stage.to_string(), expected);
            let error = DlqError::ReplayStore(stage);
            assert_eq!(error.as_label(), expected);
            assert_eq!(dlq_replay_failure(&error).as_label(), expected);
            assert_eq!(
                error.to_string(),
                format!("dlq replay store failed at {expected}")
            );
        }
    }

    #[test]
    fn dlq_failure_projection_is_exhaustive_per_operation() {
        let replay_cases = vec![
            (
                DlqError::InvalidCursor,
                EventingDeadLetterReplayFailure::Invariant,
            ),
            (
                DlqError::NotFound,
                EventingDeadLetterReplayFailure::NotFound,
            ),
            (
                DlqError::NotReplayable,
                EventingDeadLetterReplayFailure::NotReplayable,
            ),
            (
                DlqError::InvalidPayload,
                EventingDeadLetterReplayFailure::InvalidPayload,
            ),
            (
                DlqError::InvalidSchemaHeaders,
                EventingDeadLetterReplayFailure::InvalidSchemaHeaders,
            ),
            (
                DlqError::PayloadKeyUnavailable,
                EventingDeadLetterReplayFailure::PayloadKeyUnavailable,
            ),
            (
                DlqError::PayloadKeyForbidden,
                EventingDeadLetterReplayFailure::PayloadKeyForbidden,
            ),
            (
                DlqError::FactConflict(consistency::OutboxFactConflict),
                EventingDeadLetterReplayFailure::FactConflict,
            ),
            (DlqError::Store, EventingDeadLetterReplayFailure::Store),
            (
                DlqError::InvalidResolutionInput,
                EventingDeadLetterReplayFailure::Invariant,
            ),
        ];
        for (error, expected) in replay_cases {
            assert_eq!(dlq_replay_failure(&error), expected);
        }
        for (stage, expected) in [
            (
                DlqReplayStoreStage::FetchDeadLetter,
                EventingDeadLetterReplayFailure::FetchDeadLetter,
            ),
            (
                DlqReplayStoreStage::EncodeMetadata,
                EventingDeadLetterReplayFailure::EncodeMetadata,
            ),
            (
                DlqReplayStoreStage::AppendOutbox,
                EventingDeadLetterReplayFailure::AppendOutbox,
            ),
            (
                DlqReplayStoreStage::ProjectionMirror,
                EventingDeadLetterReplayFailure::ProjectionMirror,
            ),
            (
                DlqReplayStoreStage::Transaction,
                EventingDeadLetterReplayFailure::Transaction,
            ),
        ] {
            assert_eq!(dlq_replay_failure(&DlqError::ReplayStore(stage)), expected);
        }

        let invariant_errors = vec![
            DlqError::InvalidCursor,
            DlqError::NotFound,
            DlqError::NotReplayable,
            DlqError::InvalidPayload,
            DlqError::InvalidSchemaHeaders,
            DlqError::PayloadKeyUnavailable,
            DlqError::PayloadKeyForbidden,
            DlqError::FactConflict(consistency::OutboxFactConflict),
            DlqError::ReplayStore(DlqReplayStoreStage::Transaction),
        ];
        for error in &invariant_errors {
            assert_eq!(
                dlq_redrive_failure(error),
                EventingOutboxDlxRedriveFailure::Invariant
            );
            assert_eq!(
                dlq_resolve_failure(error),
                EventingOutboxDlxResolveFailure::Invariant
            );
        }
        assert_eq!(
            dlq_redrive_failure(&DlqError::InvalidResolutionInput),
            EventingOutboxDlxRedriveFailure::Invariant
        );
        assert_eq!(
            dlq_redrive_failure(&DlqError::Store),
            EventingOutboxDlxRedriveFailure::Store
        );
        assert_eq!(
            dlq_resolve_failure(&DlqError::InvalidResolutionInput),
            EventingOutboxDlxResolveFailure::InvalidResolutionInput
        );
        assert_eq!(
            dlq_resolve_failure(&DlqError::Store),
            EventingOutboxDlxResolveFailure::Store
        );
    }
}
