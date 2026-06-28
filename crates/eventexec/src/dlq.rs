//! DLQ inspection and replay/redrive service port (#1214).
//!
//! This is intentionally an internal Rust API. It gives operators a typed boundary for:
//! - listing DLQ summaries without exposing payload bytes;
//! - replaying consumer/saga `dead_letter` rows with a caller-supplied new outbox id;
//! - redriving outbox relay `dlx` rows back to `pending`.

use consistency::IdemKey;
use diport::DeadLetterSource;

/// Operator authorization witness for DLQ mutation APIs.
///
/// Listing is read-only and tenant-scoped. Replay/redrive mutate durable state, so callers must
/// pass this capability after an admin/PDP layer has authorized the operator action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorDlqCapability {
    _seal: (),
}

impl OperatorDlqCapability {
    /// Issue the DLQ mutation capability after the caller has verified operator authorization.
    ///
    /// This mirrors `vocab::CrossTenantCapability`: the type makes replay/redrive signatures carry
    /// an explicit authorization witness until the HTTP/CLI admin contract lands.
    pub fn issue_for_authorized_operator() -> Self {
        Self { _seal: () }
    }
}

/// Which backing queue row a summary represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlqEntryKind {
    /// Row in the unified `dead_letter` audit table.
    DeadLetter,
    /// Outbox row currently in `status='dlx'`.
    OutboxDlx,
}

impl DlqEntryKind {
    const fn as_cursor_part(self) -> &'static str {
        match self {
            Self::DeadLetter => "dead_letter",
            Self::OutboxDlx => "outbox_dlx",
        }
    }

    fn parse_cursor_part(raw: &str) -> Option<Self> {
        match raw {
            "dead_letter" => Some(Self::DeadLetter),
            "outbox_dlx" => Some(Self::OutboxDlx),
            _ => None,
        }
    }
}

/// Payload-free DLQ list row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlqEntrySummary {
    kind: DlqEntryKind,
    id: String,
    source: DeadLetterSource,
    tenant: vocab::TenantId,
    message_id: String,
    domain: String,
    contract_id: String,
    topic: String,
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
        tenant: vocab::TenantId,
        message_id: impl Into<String>,
        domain: impl Into<String>,
        contract_id: impl Into<String>,
        topic: impl Into<String>,
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
            domain: domain.into(),
            contract_id: contract_id.into(),
            topic: topic.into(),
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

    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    pub fn topic(&self) -> &str {
        &self.topic
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

/// Parsed `dead_letter.id` UUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadLetterId(String);

impl DeadLetterId {
    pub fn parse(raw: &str) -> Result<Self, DlqError> {
        uuid::Uuid::parse_str(raw)
            .map(|id| Self(id.to_string()))
            .map_err(|_| DlqError::InvalidId)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DeadLetterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Cursor returned by [`DlqListResult`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlqCursor {
    offset: u32,
    last_epoch_secs: i64,
    last_kind: DlqEntryKind,
    last_id: String,
}

impl DlqCursor {
    pub fn parse(raw: &str) -> Result<Self, DlqError> {
        let mut parts = raw.splitn(4, ':');
        let Some(offset) = parts.next() else {
            return Err(DlqError::InvalidCursor);
        };
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
            offset: offset.parse().map_err(|_| DlqError::InvalidCursor)?,
            last_epoch_secs: epoch.parse().map_err(|_| DlqError::InvalidCursor)?,
            last_kind: DlqEntryKind::parse_cursor_part(kind).ok_or(DlqError::InvalidCursor)?,
            last_id: id.to_string(),
        })
    }

    fn from_page(offset: u32, last: &DlqEntrySummary) -> Self {
        Self {
            offset,
            last_epoch_secs: last.last_attempt_epoch_secs(),
            last_kind: last.kind(),
            last_id: last.id().to_string(),
        }
    }

    pub fn offset(&self) -> u32 {
        self.offset
    }

    pub fn encode(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.offset,
            self.last_epoch_secs,
            self.last_kind.as_cursor_part(),
            self.last_id
        )
    }
}

/// DLQ list filter. Tenant is mandatory; domain/source are optional.
#[derive(Debug, Clone)]
pub struct DlqListQuery {
    tenant: vocab::TenantId,
    domain: Option<String>,
    source: Option<DeadLetterSource>,
    limit: u32,
    cursor: Option<DlqCursor>,
}

impl DlqListQuery {
    pub fn new(tenant: vocab::TenantId) -> Self {
        Self {
            tenant,
            domain: None,
            source: None,
            limit: 100,
            cursor: None,
        }
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
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

    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
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
        self.cursor
            .as_ref()
            .map_or(self.limit.saturating_add(1), |cursor| {
                cursor.offset().saturating_add(self.limit).saturating_add(1)
            })
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
        let offset = query.cursor().map_or(0, DlqCursor::offset) as usize;
        let limit = query.limit() as usize;
        let mut data: Vec<_> = rows.into_iter().skip(offset).take(limit + 1).collect();
        let has_more = data.len() > limit;
        if has_more {
            data.truncate(limit);
        }
        let next_cursor = if has_more {
            data.last()
                .map(|last| DlqCursor::from_page((offset + data.len()) as u32, last).encode())
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

/// Replay a consumer/saga dead_letter row by inserting a new outbox event id.
#[derive(Debug, Clone)]
pub struct DlqReplayRequest {
    tenant: vocab::TenantId,
    dead_letter_id: DeadLetterId,
    replay_id: IdemKey,
    capability: OperatorDlqCapability,
}

impl DlqReplayRequest {
    pub fn new(
        tenant: vocab::TenantId,
        dead_letter_id: DeadLetterId,
        replay_id: IdemKey,
        capability: OperatorDlqCapability,
    ) -> Self {
        Self {
            tenant,
            dead_letter_id,
            replay_id,
            capability,
        }
    }

    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    pub fn dead_letter_id(&self) -> &DeadLetterId {
        &self.dead_letter_id
    }

    pub fn replay_id(&self) -> &IdemKey {
        &self.replay_id
    }

    pub fn capability(&self) -> OperatorDlqCapability {
        self.capability
    }
}

/// Redrive an outbox relay DLX row back to pending.
#[derive(Debug, Clone)]
pub struct DlqRedriveRequest {
    tenant: vocab::TenantId,
    event_id: IdemKey,
    capability: OperatorDlqCapability,
}

impl DlqRedriveRequest {
    pub fn new(
        tenant: vocab::TenantId,
        event_id: IdemKey,
        capability: OperatorDlqCapability,
    ) -> Self {
        Self {
            tenant,
            event_id,
            capability,
        }
    }

    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    pub fn event_id(&self) -> &IdemKey {
        &self.event_id
    }

    pub fn capability(&self) -> OperatorDlqCapability {
        self.capability
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlqReplayOutcome {
    Inserted,
    AlreadyExists,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlqRedriveOutcome {
    Redriven,
    NotFound,
}

#[derive(Debug, thiserror::Error)]
pub enum DlqError {
    #[error("dlq id is invalid")]
    InvalidId,
    #[error("dlq cursor is invalid")]
    InvalidCursor,
    #[error("dlq entry not found")]
    NotFound,
    #[error("dlq entry source is not replayable")]
    NotReplayable,
    #[error("dlq entry tenant mismatch")]
    TenantMismatch,
    #[error("dlq entry payload is invalid")]
    InvalidPayload,
    #[error("dlq store failed")]
    Store,
}

#[allow(async_fn_in_trait)]
// reason: service-internal native AFIT port; adapters implement it directly and callers use static dispatch.
pub trait DlqStore: Send + Sync {
    async fn list_dlq(&self, query: DlqListQuery) -> Result<DlqListResult, DlqError>;
    async fn replay_dead_letter(
        &self,
        request: DlqReplayRequest,
    ) -> Result<DlqReplayOutcome, DlqError>;
    async fn redrive_outbox(
        &self,
        request: DlqRedriveRequest,
    ) -> Result<DlqRedriveOutcome, DlqError>;
}

fn compare_summary(a: &DlqEntrySummary, b: &DlqEntrySummary) -> std::cmp::Ordering {
    b.last_attempt_epoch_secs()
        .cmp(&a.last_attempt_epoch_secs())
        .then_with(|| a.kind().as_cursor_part().cmp(b.kind().as_cursor_part()))
        .then_with(|| a.id().cmp(b.id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id.
    fn list_summary_debug_does_not_expose_payload_bytes() {
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let summary = DlqEntrySummary::new(
            DlqEntryKind::DeadLetter,
            "row-1",
            DeadLetterSource::Consumer,
            tenant,
            "msg-1",
            "identity",
            "contract-session",
            "session.created",
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
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        assert_eq!(DlqListQuery::new(tenant).with_limit(0).limit(), 1);
        assert_eq!(DlqListQuery::new(tenant).with_limit(999).limit(), 500);
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses known canonical ids.
    fn list_result_reports_cursor_when_more_rows_exist() {
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let rows: Vec<_> = (0..3)
            .map(|i| {
                DlqEntrySummary::new(
                    DlqEntryKind::DeadLetter,
                    format!("row-{i}"),
                    DeadLetterSource::Consumer,
                    tenant,
                    format!("msg-{i}"),
                    "identity",
                    "contract-session",
                    "session.created",
                    4,
                    "max retries exhausted",
                    3,
                    1_700_000_000 - i,
                )
            })
            .collect();

        let query = DlqListQuery::new(tenant).with_limit(2);
        let result = DlqListResult::from_sorted_rows(&query, rows);
        assert!(result.has_more());
        assert_eq!(result.data().len(), 2);
        assert!(result.next_cursor().is_some());
    }

    #[test]
    fn malformed_dead_letter_id_is_rejected_before_adapter_sql() {
        assert!(matches!(
            DeadLetterId::parse("not-a-uuid"),
            Err(DlqError::InvalidId)
        ));
    }

    #[test]
    fn replay_and_redrive_require_operator_capability() {
        let _issue: fn() -> OperatorDlqCapability =
            OperatorDlqCapability::issue_for_authorized_operator;
        let _replay: fn(
            vocab::TenantId,
            DeadLetterId,
            IdemKey,
            OperatorDlqCapability,
        ) -> DlqReplayRequest = DlqReplayRequest::new;
        let _redrive: fn(vocab::TenantId, IdemKey, OperatorDlqCapability) -> DlqRedriveRequest =
            DlqRedriveRequest::new;
    }
}
