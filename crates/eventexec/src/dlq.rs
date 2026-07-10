//! DLQ inspection and replay/redrive service port (#1214).
//!
//! This is intentionally an internal Rust API. It gives operators a typed boundary for:
//! - listing DLQ summaries without exposing payload bytes;
//! - replaying consumer `dead_letter` rows with a caller-supplied new outbox id;
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
    /// an explicit authorization witness. Production callsites are restricted by the
    /// `rss_dlq_operator_callsite` dylint allowlist to the admin/PDP boundary.
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
    tenant: vocab::TenantId,
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
        tenant: vocab::TenantId,
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

    pub fn tenant(&self) -> vocab::TenantId {
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
#[derive(Debug, Clone)]
pub struct DlqListQuery {
    tenant: vocab::TenantId,
    producer_domain: Option<String>,
    consumer_domain: Option<String>,
    contract_id: Option<String>,
    source: Option<DeadLetterSource>,
    limit: u32,
    cursor: Option<DlqCursor>,
}

/// Exact payload-free DLQ inspection query. Tenant is mandatory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlqInspectRequest {
    tenant: vocab::TenantId,
    target: DlqInspectTarget,
}

impl DlqInspectRequest {
    pub fn new(tenant: vocab::TenantId, target: DlqInspectTarget) -> Self {
        Self { tenant, target }
    }

    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    pub fn target(&self) -> &DlqInspectTarget {
        &self.target
    }
}

impl DlqListQuery {
    pub fn new(tenant: vocab::TenantId) -> Self {
        Self {
            tenant,
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

    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
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
}

impl DlqRedriveOutcome {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Redriven => "redriven",
            Self::NotFound => "not_found",
        }
    }
}

/// DLQ mutation kind for `dlq_redrive_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlqMutationKind {
    /// Consumer dead_letter replay into a new outbox id.
    DeadLetterReplay,
    /// Outbox relay DLX row restored to pending.
    OutboxDlxRedrive,
}

impl DlqMutationKind {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::DeadLetterReplay => "dead_letter_replay",
            Self::OutboxDlxRedrive => "outbox_dlx_redrive",
        }
    }
}

/// Closed outcome label for `dlq_redrive_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlqMutationMetricOutcome {
    label: &'static str,
}

impl DlqMutationMetricOutcome {
    pub fn replay(outcome: DlqReplayOutcome) -> Self {
        Self {
            label: outcome.as_label(),
        }
    }

    pub fn redrive(outcome: DlqRedriveOutcome) -> Self {
        Self {
            label: outcome.as_label(),
        }
    }

    pub fn error(error: &DlqError) -> Self {
        Self {
            label: error.as_label(),
        }
    }

    pub fn as_label(self) -> &'static str {
        self.label
    }
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
    #[error("dlq entry payload is invalid")]
    InvalidPayload,
    #[error("dlq entry schema headers are invalid")]
    InvalidSchemaHeaders,
    #[error("dlq payload key provider is unavailable")]
    PayloadKeyUnavailable,
    #[error("dlq payload key provider rejected configuration or authorization")]
    PayloadKeyForbidden,
    #[error("dlq store failed")]
    Store,
}

impl DlqError {
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::InvalidId => "invalid_id",
            Self::InvalidCursor => "invalid_cursor",
            Self::NotFound => "not_found",
            Self::NotReplayable => "not_replayable",
            Self::InvalidPayload => "invalid_payload",
            Self::InvalidSchemaHeaders => "invalid_schema_headers",
            Self::PayloadKeyUnavailable => "payload_key_unavailable",
            Self::PayloadKeyForbidden => "payload_key_forbidden",
            Self::Store => "store",
        }
    }
}

/// Emit a DLQ replay/redrive counter with closed labels.
fn record_dlq_redrive_metric(
    tenant: vocab::TenantId,
    kind: DlqMutationKind,
    outcome: DlqMutationMetricOutcome,
) {
    metrics::counter!(
        "dlq_redrive_total",
        "tenant_id" => tenant.to_string(),
        "kind" => kind.as_label(),
        "outcome" => outcome.as_label(),
    )
    .increment(1);
}

pub fn record_dlq_replay(tenant: vocab::TenantId, outcome: DlqReplayOutcome) {
    record_dlq_redrive_metric(
        tenant,
        DlqMutationKind::DeadLetterReplay,
        DlqMutationMetricOutcome::replay(outcome),
    );
}

pub fn record_dlq_outbox_redrive(tenant: vocab::TenantId, outcome: DlqRedriveOutcome) {
    record_dlq_redrive_metric(
        tenant,
        DlqMutationKind::OutboxDlxRedrive,
        DlqMutationMetricOutcome::redrive(outcome),
    );
}

pub fn record_dlq_mutation_error(tenant: vocab::TenantId, kind: DlqMutationKind, error: &DlqError) {
    record_dlq_redrive_metric(tenant, kind, DlqMutationMetricOutcome::error(error));
}

#[allow(async_fn_in_trait)]
// reason: service-internal native AFIT port; adapters implement it directly and callers use static dispatch.
pub trait DlqStore: Send + Sync {
    async fn list_dlq(&self, query: DlqListQuery) -> Result<DlqListResult, DlqError>;
    async fn inspect_dlq(&self, request: DlqInspectRequest) -> Result<DlqEntrySummary, DlqError>;
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
            Some("audit".to_string()),
            "contract-session",
            "session.created",
            Some("identity.session.consumer".to_string()),
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
                    Some("audit".to_string()),
                    "contract-session",
                    "session.created",
                    Some("identity.session.consumer".to_string()),
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
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id.
    fn list_result_filters_by_contract_id_before_pagination() {
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let rows = vec![
            DlqEntrySummary::new(
                DlqEntryKind::DeadLetter,
                "row-a",
                DeadLetterSource::Consumer,
                tenant,
                "msg-a",
                "identity",
                Some("audit".to_string()),
                "identity.session-created",
                "session.created",
                Some("identity.session.consumer".to_string()),
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
                "identity",
                Some("audit".to_string()),
                "identity.role-assigned",
                "role.assigned",
                Some("identity.role.consumer".to_string()),
                4,
                "max retries exhausted",
                3,
                1_700_000_001,
            ),
        ];

        let result = DlqListResult::from_sorted_rows(
            &DlqListQuery::new(tenant)
                .with_contract_id("identity.session-created")
                .with_limit(1),
            rows,
        );

        assert_eq!(result.data().len(), 1);
        assert_eq!(result.data()[0].contract_id(), "identity.session-created");
        assert!(
            !result.has_more(),
            "filtered-out rows must not force paging"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id.
    fn list_result_filters_producer_and_consumer_domains_independently() {
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let rows = ["audit", "search"]
            .into_iter()
            .map(|consumer_domain| {
                DlqEntrySummary::new(
                    DlqEntryKind::DeadLetter,
                    format!("row-{consumer_domain}"),
                    DeadLetterSource::Consumer,
                    tenant,
                    format!("msg-{consumer_domain}"),
                    "identity",
                    Some(consumer_domain.to_string()),
                    "identity.session-created",
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
            &DlqListQuery::new(tenant)
                .with_producer_domain("identity")
                .with_consumer_domain("audit"),
            rows,
        );

        assert_eq!(result.data().len(), 1);
        assert_eq!(result.data()[0].producer_domain(), "identity");
        assert_eq!(result.data()[0].consumer_domain(), Some("audit"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id.
    fn list_cursor_is_keyset_not_offset() {
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let rows: Vec<_> = (0..4)
            .map(|i| {
                DlqEntrySummary::new(
                    DlqEntryKind::DeadLetter,
                    format!("row-{i}"),
                    DeadLetterSource::Consumer,
                    tenant,
                    format!("msg-{i}"),
                    "identity",
                    Some("audit".to_string()),
                    "contract-session",
                    "session.created",
                    Some("identity.session.consumer".to_string()),
                    4,
                    "max retries exhausted",
                    3,
                    1_700_000_000 - i,
                )
            })
            .collect();

        let first = DlqListResult::from_sorted_rows(&DlqListQuery::new(tenant).with_limit(2), rows);
        let cursor = DlqCursor::parse(first.next_cursor().expect("cursor")).expect("valid cursor");
        let mut changed_rows = first.into_data();
        changed_rows.push(DlqEntrySummary::new(
            DlqEntryKind::DeadLetter,
            "new-head",
            DeadLetterSource::Consumer,
            tenant,
            "msg-new",
            "identity",
            Some("audit".to_string()),
            "contract-session",
            "session.created",
            Some("identity.session.consumer".to_string()),
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
            "identity",
            Some("audit".to_string()),
            "contract-session",
            "session.created",
            Some("identity.session.consumer".to_string()),
            4,
            "older row",
            1,
            1_699_999_990,
        ));

        let second = DlqListResult::from_sorted_rows(
            &DlqListQuery::new(tenant).with_limit(10).with_cursor(cursor),
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
                    Some("audit".to_string()),
                    "contract-session",
                    "session.created",
                    Some("identity.session.consumer".to_string()),
                    4,
                    "max retries exhausted",
                    3,
                    1_700_000_000,
                )
            })
            .collect();

        let first =
            DlqListResult::from_sorted_rows(&DlqListQuery::new(tenant).with_limit(2), rows.clone());
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
            &DlqListQuery::new(tenant).with_limit(2).with_cursor(cursor),
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

    #[test]
    #[allow(clippy::expect_used)]
    // reason: metric fixture uses a known canonical tenant id.
    fn dlq_redrive_metric_uses_closed_kind_and_outcome_labels() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        metrics::with_local_recorder(&recorder, || {
            record_dlq_replay(tenant, DlqReplayOutcome::Inserted);
            record_dlq_mutation_error(
                tenant,
                DlqMutationKind::OutboxDlxRedrive,
                &DlqError::NotFound,
            );
        });

        let rendered = handle.render();
        assert!(rendered.contains("dlq_redrive_total"), "{rendered}");
        assert!(
            rendered.contains("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
            "{rendered}"
        );
        assert!(rendered.contains("dead_letter_replay"), "{rendered}");
        assert!(rendered.contains("outbox_dlx_redrive"), "{rendered}");
        assert!(rendered.contains("inserted"), "{rendered}");
        assert!(rendered.contains("not_found"), "{rendered}");
    }
}
