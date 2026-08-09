//! Outbox 持久化实现——L2 OutboxFact adapter（#1117 P4）。
//!
//! [`PgOutbox`] impl [`consistency::OutboxRelay`] / [`consistency::RetentionSweeper`]——两个 native
//! AFIT trait（泛型静态分发，非 dyn，不引 dynosaur）。
//!
//! **`append_outbox`**（`pub(crate)` free fn，收 `&mut TenantTx`）是 L1 原子性的编译期硬约束：
//! 只能在已有事务内调用，不能脱离事务双写；tenant-scoped 业务写经
//! `TenantDb<ServingWriteLane>::producer_tx` 注入租户事务后传入能力令牌，全局 outbox-only infra
//! 路径也必须先显式打开事务并由 postgres adapter 铸造令牌——类型系统天然阻止无事务直接调用。
//!
//! **生产 INSERT funnel** 由 `cotx/eventing.rs` 的 `outbox_insert_generated` /
//! `outbox_insert_replayed` 持有；本文件只做 relay / settlement / retention。
//!
//! **CAS fencing**：`claim_batch` 在数据库内原子选择并铸造 token/deadline；settle 同时精确匹配二者且
//! 拒绝过期租约。CAS 只围栏 durable 状态写回，不提供 broker exactly-once。
//!
//! **崩溃重投**：`claim_batch` 捞回 `status='publishing' AND lease_until <= clock_timestamp()` 的 stale 行；
//! publish 成功而 settle 前崩溃会以同一 event/message id 重投，broker 可能收到重复 delivery；消费端 inbox
//! 幂等才把重复业务副作用收口为一次。
//!
//! ref: serverlesstechnology/cqrs `persistence/postgres-es/src/event_repository.rs@main`
//! （`rows_affected()==1` 乐观锁 + UNIQUE 幂等 idiom 采纳来源）。

use std::future::Future;
use std::sync::Arc;
#[cfg(feature = "fault-matrix-test-support")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use consistency::{
    BacklogMetricSample, BacklogObservation, BacklogSample, EngineError, EngineErrorKind,
    EventEntry, IdemKey, OutboxAppendOutcome, OutboxBacklog, OutboxContractId, OutboxFactConflict,
    OutboxFactFingerprint, OutboxFactIdentity, OutboxMetricSubject, OutboxPayload, OutboxRelay,
    RetentionSweeper, StoredOutboxEntry,
};
use diport::{
    DeadLetterSource, DynPublisher, EnvelopeCausationId, EnvelopeHeaderError, EnvelopeMetadata,
    EnvelopeSubjectId, KEY_ACTOR, KEY_CORRELATION, KEY_OCCURRED_AT, KEY_SCHEMA_HASH,
    KEY_SCHEMA_VERSION, KEY_SUBJECT_ID, KEY_TENANT_ID, KEY_TRACE, MetadataError, OutboxActor,
    OutboxEmitError, PublishErrorKind, PublishRequest, Publisher, PublisherError,
    RESERVED_METADATA_KEYS,
};
use eventexec::{RelayBudget, TenantAuthority, TenantAuthorityBinding};
use sqlx::Row;

use crate::PgStore;
use crate::cotx::eventing::{EventingTx, GeneratedOutboxConcern};
use crate::cotx::{
    ServingWriteLane, TenantDb, deadline_global_transaction, infra_tenant_scope, io_deadline_after,
};
use crate::dead_letter_payload::{DlxPayloadContext, DlxPayloadProtector};
#[cfg(feature = "fault-matrix-test-support")]
use crate::pool::PgRuntimeStores;
#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
use crate::pool::VerifiedPgWriteStore;
use crate::projection_events::{ProjectionWriteRegistry, append_projection_event_if_bound};

mod settlement;

// ── 常量 ─────────────────────────────────────────────────────────────────────

/// relay 每次最多重试次数（含当次）；超过后转 dlx。
pub(crate) const MAX_PUBLISH_ATTEMPTS: i32 = 10;

/// 单次原子 claim 的 provider 边界；与 0057 SQL 防线由单测互锁。
const OUTBOX_CLAIM_BATCH_MAX: usize = 10_000;

/// outbox status 值集测试锚点。生产 INSERT 省略状态并依赖数据库 `pending` default；状态迁移 SQL 由固定
/// SECURITY DEFINER 函数持有。测试常量与 migration CHECK 由 `status_consts_match_migration_check` 对齐守。
#[cfg(test)]
pub(crate) const STATUS_PENDING: &str = "pending";
// reason(dead_code): 0031 SECURITY DEFINER SQL owns relay state transitions; constants remain test
// anchors for migration CHECK/status drift.
#[allow(dead_code)]
pub(crate) const STATUS_PUBLISHING: &str = "publishing";
// reason(dead_code): see STATUS_PUBLISHING.
#[allow(dead_code)]
pub(crate) const STATUS_PUBLISHED: &str = "published";
#[cfg(test)]
pub(crate) const STATUS_ABANDONED: &str = "abandoned";
const OUTBOX_RELAY_DLX_SUMMARY: &str = "outbox relay publish failed";
const OUTBOX_RELAY_ENVELOPE_DLX_SUMMARY: &str = "outbox relay envelope validation failed";
const OUTBOX_AUTOMATIC_WINDOW_EXPIRED_SUMMARY: &str =
    "outbox same-ID automatic delivery window expired";
const OUTBOX_REDRIVE_WINDOW_EXPIRED_SUMMARY: &str =
    "outbox same-ID redrive delivery window expired";
const OUTBOX_AUTOMATIC_WINDOW_EXPIRED_REASON: &str = "automatic_window_expired";
const OUTBOX_REDRIVE_WINDOW_EXPIRED_REASON: &str = "redrive_window_expired";
const KEY_RELAY_FAILURE_REASON: &str = "relayFailureReason";
#[derive(sqlx::FromRow)]
struct ClaimedOutboxRow {
    tenant_id: String,
    contract_id: String,
    topic: String,
    event_id: String,
    payload: Vec<u8>,
    retry_count: i32,
    metadata: String,
    domain: String,
    contract_version: String,
    schema_hash: String,
    claimed_at_epoch_seconds: i64,
    lease_token: String,
    deadline_epoch_micros: i64,
}

/// PostgreSQL 原子 claim 返回的 provider-owned relay capability。
///
/// 字段与构造路径均封闭在 postgres adapter；外部调用方只能从 [`OutboxRelay::claim_batch`]
/// 获得并按值交给同一 provider 的 [`OutboxRelay::relay`]。本类型刻意不实现 `Clone`。
pub struct PgClaimedOutboxEntry {
    provider: Arc<OutboxProviderIdentity>,
    entry: StoredOutboxEntry,
    subject: OutboxMetricSubject,
    retry_count: u32,
    domain: vocab::DomainName,
    contract_version: String,
    schema_hash: String,
    metadata: serde_json::Map<String, serde_json::Value>,
    claimed_at_epoch_seconds: i64,
    lease: OutboxLease,
}

impl std::fmt::Debug for PgClaimedOutboxEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgClaimedOutboxEntry")
            .field("entry", &"<redacted>")
            .field("provider", &"<bound>")
            .field("subject", &self.subject)
            .field("retry_count", &self.retry_count)
            .field("domain", &self.domain)
            .field("contract_version", &self.contract_version)
            .field("schema_hash", &self.schema_hash)
            .field("metadata", &"<redacted>")
            .field("claimed_at_epoch_seconds", &self.claimed_at_epoch_seconds)
            .field("lease", &self.lease)
            .finish()
    }
}

/// 单个 [`PgOutbox`] 实例不可伪造的 publisher provenance；pointer identity 同时绑定 domain 与 publisher。
struct OutboxProviderIdentity {
    domain: vocab::DomainName,
}

impl PgClaimedOutboxEntry {
    pub(crate) fn entry(&self) -> &StoredOutboxEntry {
        &self.entry
    }

    pub(crate) fn topic(&self) -> &consistency::StoredOutboxTopic {
        self.entry.topic()
    }

    pub(crate) fn idem_key(&self) -> &IdemKey {
        self.entry.idem_key()
    }

    pub(crate) fn subject(&self) -> &OutboxMetricSubject {
        &self.subject
    }

    fn retry_count(&self) -> u32 {
        self.retry_count
    }

    fn domain(&self) -> &vocab::DomainName {
        &self.domain
    }

    fn contract_version(&self) -> &str {
        &self.contract_version
    }

    fn schema_hash(&self) -> &str {
        &self.schema_hash
    }

    fn metadata(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.metadata
    }

    fn claimed_at_epoch_seconds(&self) -> i64 {
        self.claimed_at_epoch_seconds
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn claim_epoch_seconds(&self) -> i64 {
        self.claimed_at_epoch_seconds
    }

    fn lease_token(&self) -> &str {
        self.lease.token()
    }

    fn lease_deadline_epoch_micros(&self) -> i64 {
        #[cfg(feature = "fault-matrix-test-support")]
        self.lease
            .fault_matrix_sql_deadline_bound
            .store(true, Ordering::Release);
        self.lease.deadline_epoch_micros()
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn test_lease_token(&self) -> &str {
        self.lease_token()
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn test_lease_deadline_epoch_micros(&self) -> i64 {
        self.lease_deadline_epoch_micros()
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn test_override_lease_deadlines(
        &mut self,
        deadline_epoch_micros: i64,
        monotonic_remaining: std::time::Duration,
    ) {
        self.lease
            .test_override_deadlines(deadline_epoch_micros, monotonic_remaining);
    }
}

pub(crate) struct OutboxLease {
    token: String,
    deadline_epoch_micros: i64,
    monotonic_deadline: tokio::time::Instant,
    #[cfg(feature = "fault-matrix-test-support")]
    fault_matrix_sql_deadline_bound: AtomicBool,
}

impl std::fmt::Debug for OutboxLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxLease")
            .field("token", &"<redacted>")
            .field("deadline_epoch_micros", &"<sealed>")
            .field("monotonic_deadline", &"<sealed>")
            .finish()
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutboxLeaseError {
    #[error("lease token is not a canonical uuid")]
    Token,
    #[error("lease token is not uuid v4")]
    TokenVersion,
    #[error("lease deadline is not positive epoch microseconds")]
    Deadline,
}

impl OutboxLease {
    pub(crate) fn hydrate(
        token: String,
        deadline_epoch_micros: i64,
        monotonic_deadline: tokio::time::Instant,
    ) -> Result<Self, OutboxLeaseError> {
        let parsed = uuid::Uuid::try_parse(&token).map_err(|_| OutboxLeaseError::Token)?;
        if parsed.hyphenated().to_string() != token {
            return Err(OutboxLeaseError::Token);
        }
        if parsed.get_version_num() != 4 {
            return Err(OutboxLeaseError::TokenVersion);
        }
        if deadline_epoch_micros <= 0 {
            return Err(OutboxLeaseError::Deadline);
        }
        Ok(Self {
            token,
            deadline_epoch_micros,
            monotonic_deadline,
            #[cfg(feature = "fault-matrix-test-support")]
            fault_matrix_sql_deadline_bound: AtomicBool::new(false),
        })
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    pub(crate) fn deadline_epoch_micros(&self) -> i64 {
        self.deadline_epoch_micros
    }

    #[cfg(feature = "domain-identity")]
    pub(crate) fn monotonic_deadline(&self) -> tokio::time::Instant {
        self.monotonic_deadline
    }

    #[cfg(any(
        all(test, feature = "integration"),
        feature = "fault-matrix-test-support"
    ))]
    fn test_override_deadlines(
        &mut self,
        deadline_epoch_micros: i64,
        monotonic_remaining: std::time::Duration,
    ) {
        self.deadline_epoch_micros = deadline_epoch_micros;
        self.monotonic_deadline = io_deadline_after(monotonic_remaining);
        #[cfg(feature = "fault-matrix-test-support")]
        self.fault_matrix_sql_deadline_bound
            .store(false, Ordering::Release);
    }
}

#[cfg(feature = "fault-matrix-test-support")]
impl PgClaimedOutboxEntry {
    pub(crate) fn fault_matrix_expire_persisted_deadline(
        &mut self,
        deadline_epoch_micros: i64,
        relay_budget: RelayBudget,
    ) {
        let monotonic_remaining = relay_budget
            .settle_timeout()
            .saturating_add(relay_budget.safety_margin());
        self.lease
            .test_override_deadlines(deadline_epoch_micros, monotonic_remaining);
    }

    fn fault_matrix_sql_deadline_was_bound(&self) -> bool {
        self.lease
            .fault_matrix_sql_deadline_bound
            .load(Ordering::Acquire)
    }
}

#[cfg(feature = "fault-matrix-test-support")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FaultMatrixPublishedSettlementEvidence {
    Settled,
    PersistedDeadlineExpired,
    LocalDeadlineExpired,
    LostLease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishPreflight {
    Allowed,
    LostLease,
    AutomaticExpired,
    RedriveExpired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PublishPreflightDiscriminantError;

impl TryFrom<i16> for PublishPreflight {
    type Error = PublishPreflightDiscriminantError;

    fn try_from(value: i16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Allowed),
            1 => Ok(Self::LostLease),
            2 => Ok(Self::AutomaticExpired),
            3 => Ok(Self::RedriveExpired),
            _ => Err(PublishPreflightDiscriminantError),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SameIdDeliveryPhase {
    Automatic,
    Redrive,
}

impl SameIdDeliveryPhase {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::Redrive => "redrive",
        }
    }

    const fn dlx_summary(self) -> &'static str {
        match self {
            Self::Automatic => OUTBOX_AUTOMATIC_WINDOW_EXPIRED_SUMMARY,
            Self::Redrive => OUTBOX_REDRIVE_WINDOW_EXPIRED_SUMMARY,
        }
    }

    const fn failure_reason(self) -> &'static str {
        match self {
            Self::Automatic => OUTBOX_AUTOMATIC_WINDOW_EXPIRED_REASON,
            Self::Redrive => OUTBOX_REDRIVE_WINDOW_EXPIRED_REASON,
        }
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
enum ClaimHydrationError {
    #[error("invalid metric subject")]
    MetricSubject,
    #[error("invalid event id")]
    EventId,
    #[error("invalid stored entry")]
    StoredEntry,
    #[error("invalid retry count")]
    RetryCount,
    #[error("invalid domain")]
    Domain,
    #[error("claim domain does not match provider")]
    ProviderDomain,
    #[error("invalid metadata")]
    Metadata,
    #[error("invalid lease token")]
    LeaseToken,
    #[error("invalid lease token version")]
    LeaseTokenVersion,
    #[error("invalid lease deadline")]
    LeaseDeadline,
    #[error("empty contract version")]
    ContractVersion,
    #[error("empty schema hash")]
    SchemaHash,
    #[error("invalid claim epoch")]
    ClaimedAt,
}

impl ClaimHydrationError {
    fn phase(self) -> &'static str {
        match self {
            Self::MetricSubject => "metric_subject",
            Self::EventId => "event_id",
            Self::StoredEntry => "stored_entry",
            Self::RetryCount => "retry_count",
            Self::Domain => "domain",
            Self::ProviderDomain => "provider_domain",
            Self::Metadata => "metadata",
            Self::LeaseToken => "lease_token",
            Self::LeaseTokenVersion => "lease_token_version",
            Self::LeaseDeadline => "lease_deadline",
            Self::ContractVersion => "contract_version",
            Self::SchemaHash => "schema_hash",
            Self::ClaimedAt => "claimed_at",
        }
    }
}

struct TenantAuthoritySignInput<'a> {
    tenant: vocab::TenantId,
    domain: &'a str,
    contract_id: &'a str,
    topic: &'a str,
    event_id: &'a str,
    now_epoch: i64,
}

impl<'a> TenantAuthoritySignInput<'a> {
    fn binding(&self) -> TenantAuthorityBinding<'a> {
        TenantAuthorityBinding::new(
            self.tenant,
            self.domain,
            self.contract_id,
            self.topic,
            self.event_id,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayEnvelopeValidationReason {
    MissingTenantId,
    InvalidTenantId,
    MissingSchemaVersion,
    InvalidSchemaVersion,
    MissingSchemaHash,
    InvalidSchemaHash,
    SchemaVersionMismatch,
    SchemaHashMismatch,
}

impl RelayEnvelopeValidationReason {
    fn as_label(self) -> &'static str {
        match self {
            Self::MissingTenantId => "envelope_missing_tenant_id",
            Self::InvalidTenantId => "envelope_invalid_tenant_id",
            Self::MissingSchemaVersion => "envelope_missing_schema_version",
            Self::InvalidSchemaVersion => "envelope_invalid_schema_version",
            Self::MissingSchemaHash => "envelope_missing_schema_hash",
            Self::InvalidSchemaHash => "envelope_invalid_schema_hash",
            Self::SchemaVersionMismatch => "envelope_schema_version_mismatch",
            Self::SchemaHashMismatch => "envelope_schema_hash_mismatch",
        }
    }
}

impl From<&EnvelopeHeaderError> for RelayEnvelopeValidationReason {
    fn from(error: &EnvelopeHeaderError) -> Self {
        match error {
            EnvelopeHeaderError::MissingTenantId => Self::MissingTenantId,
            EnvelopeHeaderError::InvalidTenantId => Self::InvalidTenantId,
            EnvelopeHeaderError::MissingSchemaVersion => Self::MissingSchemaVersion,
            EnvelopeHeaderError::InvalidSchemaVersion => Self::InvalidSchemaVersion,
            EnvelopeHeaderError::MissingSchemaHash => Self::MissingSchemaHash,
            EnvelopeHeaderError::InvalidSchemaHash => Self::InvalidSchemaHash,
            EnvelopeHeaderError::SchemaVersionMismatch => Self::SchemaVersionMismatch,
            EnvelopeHeaderError::SchemaHashMismatch => Self::SchemaHashMismatch,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("outbox relay envelope validation failed")]
struct RelayEnvelopeValidationError {
    reason: RelayEnvelopeValidationReason,
    #[source]
    source: EnvelopeHeaderError,
}

impl RelayEnvelopeValidationError {
    fn new(source: EnvelopeHeaderError) -> Self {
        let reason = RelayEnvelopeValidationReason::from(&source);
        Self { reason, source }
    }

    fn reason(&self) -> RelayEnvelopeValidationReason {
        self.reason
    }
}

enum RelayPublishFailure {
    Publisher(PublisherError),
    Envelope(RelayEnvelopeValidationError),
}

impl RelayPublishFailure {
    fn kind(&self) -> PublishErrorKind {
        match self {
            Self::Publisher(err) => err.kind(),
            Self::Envelope(_) => PublishErrorKind::Permanent,
        }
    }

    fn reason_label(&self) -> &'static str {
        match self {
            Self::Publisher(err) => match err.kind() {
                PublishErrorKind::Transient => "publisher_transient",
                PublishErrorKind::Permanent => "publisher_permanent",
                PublishErrorKind::Ambiguous => "publisher_ambiguous",
            },
            Self::Envelope(err) => err.reason().as_label(),
        }
    }

    fn dlx_summary(&self) -> &'static str {
        match self {
            Self::Publisher(_) => OUTBOX_RELAY_DLX_SUMMARY,
            Self::Envelope(_) => OUTBOX_RELAY_ENVELOPE_DLX_SUMMARY,
        }
    }

    fn relay_failure_reason(&self) -> Option<&'static str> {
        match self {
            Self::Publisher(_) => None,
            Self::Envelope(err) => Some(err.reason().as_label()),
        }
    }
}

// ── OutboxMetadata（typed sealed funnel，F1）──────────────────────────────────
//
// reserved key / subject key 常量已迁至 diport 单源（#1160 A4）：
// `diport::{RESERVED_METADATA_KEYS, KEY_OCCURRED_AT, KEY_TRACE, KEY_CORRELATION,
//           KEY_TENANT_ID, KEY_SUBJECT_ID}`。本 adapter funnel 逻辑不变，key 字面量引 diport 单源。

/// Outbox envelope metadata——**sealed typed funnel**（私有内层 `Map`，仅经受控入口构造）。
///
/// 安全边界从「调用方注释自律」上移到类型层：raw `serde_json::Value` 入口已删，外部无法绕过；
/// reserved key（[`RESERVED_METADATA_KEYS`]）被 [`OutboxMetadata::try_insert`] fail-closed 拒；
/// principal 仅允许 opaque subject id（[`OutboxMetadata::with_subject_id`]，不容完整 Principal / PII，
/// `observability.md` §outbox envelope）。
///
/// # INVARIANT: OUTBOX-METADATA-FUNNEL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
///
/// envelope metadata 只能经此 funnel 构造（Hard：无 raw `Value` 入口，reserved/PII 不可表达）；
/// reserved key 拒绝由 `metadata_try_insert_rejects_reserved_key` 负向单测守 anti-vacuity。
#[derive(Clone)]
pub(crate) struct OutboxMetadata {
    tenant: vocab::TenantId,
    contract_version: String,
    schema_hash: String,
    map: serde_json::Map<String, serde_json::Value>,
}

impl OutboxMetadata {
    /// 由 reserved `occurred_at`（unix 秒 i64，producer 端事件发生时刻）+ typed `tenantId`
    /// + codegen 契约绑定 schema header 构造。
    ///
    /// occurred_at / tenantId / schemaVersion / schemaHash 注入折叠进构造器 ⇒「缺标准 header 的 outbox
    /// metadata」**类型层不可表达**（Hard），杜绝
    /// producer 漏接：三条生产路径（`PgEmitter` / `PgAuthGrantLifecycle` / `PgConfigRepo`）各从注入 `Clock`
    /// 取 `unix_secs(clock.now())` 传入，新增 producer 也必须提供（缺失即编译错误）。reserved key 不经业务可见
    /// 入口写入——[`OutboxMetadata::try_insert`] 对 free-form 路径仍 fail-closed 拒 reserved（业务侧不可伪造）。
    ///
    /// `occurredAt` 仅供**诊断 / 观测**，**不**进入 relay / sweep 的 SQL WHERE 谓词、不建索引。trace 经
    /// #1224 接线（emit 侧 `tracewire::capture_current`）；correlation 已接线 #1160；principal 待 #1397。
    pub(crate) fn new(
        occurred_at_secs: i64,
        tenant: vocab::TenantId,
        contract: vocab::ContractBinding,
    ) -> Self {
        // KEY_OCCURRED_AT = diport 单源（#1160 A4）。
        let mut map = serde_json::Map::new();
        map.insert(
            KEY_OCCURRED_AT.to_string(),
            serde_json::Value::from(occurred_at_secs),
        );
        map.insert(
            KEY_TENANT_ID.to_string(),
            serde_json::Value::String(tenant.to_string()),
        );
        let contract_version = contract.version().to_string();
        let schema_hash = contract.schema_hash().to_string();
        map.insert(
            KEY_SCHEMA_VERSION.to_string(),
            serde_json::Value::String(contract_version.clone()),
        );
        map.insert(
            KEY_SCHEMA_HASH.to_string(),
            serde_json::Value::String(schema_hash.clone()),
        );
        Self {
            tenant,
            contract_version,
            schema_hash,
            map,
        }
    }

    /// 借出 envelope 所属 tenant；与 JSON metadata 中 `tenantId` 同源，避免生产路径运行期反解析。
    pub(crate) fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    /// 借出契约版本；与 metadata `schemaVersion` 同源，供 outbox 物理列写入。
    pub(crate) fn contract_version(&self) -> &str {
        &self.contract_version
    }

    /// 借出 schema hash；与 metadata `schemaHash` 同源，供 outbox 物理列写入。
    pub(crate) fn schema_hash(&self) -> &str {
        &self.schema_hash
    }

    /// 设置 opaque 主体 id（唯一允许的 principal 形态——不容完整 Principal / PII）。
    /// 生产 caller：`PgEmitter::write` 从 sealed `ReviewedEvent` envelope 组装（T008/#1100）。
    /// KEY_SUBJECT_ID = diport 单源（#1160 A4）。
    pub(crate) fn with_subject_id(mut self, subject_id: EnvelopeSubjectId) -> Self {
        self.map.insert(
            KEY_SUBJECT_ID.to_string(),
            serde_json::Value::String(subject_id.as_str().to_string()),
        );
        self
    }

    /// 设置最小化 actor envelope（persisted-only，不进 broker header）。
    pub(crate) fn with_actor(mut self, actor: OutboxActor) -> Self {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "kind".to_string(),
            serde_json::Value::String(actor.kind().as_actor_metadata_label().to_string()),
        );
        obj.insert(
            "id".to_string(),
            serde_json::Value::String(actor.actor_id().as_str().to_string()),
        );
        if let Some(tenant) = actor.tenant() {
            obj.insert(
                "tenantId".to_string(),
                serde_json::Value::String(tenant.to_string()),
            );
        }
        obj.insert(
            "scope".to_string(),
            serde_json::Value::String(actor.scope().as_label().to_string()),
        );
        self.map
            .insert(KEY_ACTOR.to_string(), serde_json::Value::Object(obj));
        self
    }

    /// 注入 reserved key `trace`（#1193）——**sealed setter**：funnel 内特权写 reserved key（business
    /// free-form [`OutboxMetadata::try_insert`] 仍 fail-closed 拒），承载「业务不可伪造 trace」（Hard）。
    /// KEY_TRACE = diport 单源（#1160 A4）。
    /// 生产 caller：[`metadata_with_ambient`]（从当前 tracing span 经 `tracewire::capture_current` 取 W3C traceparent，
    /// fail-open；#1224 接线，关闭 #1076 预留槽）。
    pub(crate) fn with_trace(mut self, trace: impl Into<String>) -> Self {
        self.map.insert(
            KEY_TRACE.to_string(),
            serde_json::Value::String(trace.into()),
        );
        self
    }

    /// 注入 reserved key `correlation`（#1193 / #1160 B3）——**sealed setter**：funnel 内特权写 reserved key
    /// （同 [`OutboxMetadata::with_trace`]，业务侧 `try_insert` 仍拒），承载「业务不可伪造 correlation」（Hard）。
    /// 生产 caller：[`metadata_with_ambient`]（从 `diagctx` ambient 读回 correlation，fail-open）。
    /// KEY_CORRELATION = diport 单源（#1160 A4）。
    pub(crate) fn with_correlation(mut self, correlation: impl Into<String>) -> Self {
        self.map.insert(
            KEY_CORRELATION.to_string(),
            serde_json::Value::String(correlation.into()),
        );
        self
    }

    /// 插入 free-form key（fail-closed 拒 reserved key）。
    /// RESERVED_METADATA_KEYS = diport 单源（#1160 A4）。
    // reason(dead_code): 生产 caller 在 T008/#1100 接入；负向单测行使 reserved 拒绝。
    #[allow(dead_code)]
    pub(crate) fn try_insert(
        &mut self,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Result<(), MetadataError> {
        let key = key.into();
        if RESERVED_METADATA_KEYS.contains(&key.as_str()) {
            return Err(MetadataError::ReservedKey);
        }
        self.map.insert(key, value);
        Ok(())
    }

    /// 序列化为 JSON object 字符串（绑 `$N::jsonb` 用）。
    fn to_json_string(&self) -> String {
        serde_json::to_string(&self.map).unwrap_or_else(|_| "{}".to_string())
        // reason: Map<String, Value> 序列化理论上不失败（已验证 JSON 树）；
        // 即便极端情况失败，退化到空对象比 panic 更安全（不阻写路径）。
    }
}

// ── 时间编码 ──────────────────────────────────────────────────────────────────

/// `SystemTime` → UNIX epoch 秒（i64）；负偏移收口 0、溢出收口 `i64::MAX`。
///
/// 本 crate **时间编码单源**（#1129 合并）：emitter / auth_grant_lifecycle 的 envelope `occurred_at` 与 session 行
/// `expires_at` / `created_at` 共用，消除同 crate 内重复。timestamptz / 整数秒由 server-side `to_timestamp($N)`
/// 或直绑生成（不给 sqlx 加 time feature）。负偏移 / 正常路径由 outbox 单测 `unix_secs_*` 守。
///
/// 溢出分支（`as_secs > i64::MAX`，约年 ~2920 亿）为防御性收口：`i64::try_from(..).unwrap_or(i64::MAX)`
/// **类型层静态保证不 panic**；该输入 `SystemTime` 不可移植构造（`UNIX_EPOCH + Duration::from_secs(u64::MAX)`
/// 在 `SystemTime::add` 即 panic），故不写平台相关红 case（沿用合并前 auth_grant_lifecycle 的既定理由）。
///
/// 跨 crate 另有 `identity::application::unix_secs` / `settings::application::unix_secs` 同名 helper（域 crate
/// 不依赖本 adapter，故各自「独立维护、语义对齐」）；跨 crate 收敛为单源 + governance 守语义一致已登记 #1294。
pub(crate) fn unix_secs(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

// ── metadata_with_ambient ─────────────────────────────────────────────────────

/// occurred_at 构造期必填 + 有 ambient correlation / 当前 trace 则盖章（均 fail-open：无则省略）。
///
/// 三条生产 outbox 路径（`PgEmitter` / `PgAuthGrantLifecycle` / `PgConfigRepo`）统一经此 helper 构造
/// envelope metadata，保证 correlation ambient（#1160 B3）+ trace 透传（#1224）接线一致。
/// - correlation：从 `diagctx` ambient 读回（无 scope → 省略）。
/// - trace：`tracewire::capture_current()` 从当前 tracing span 导出 W3C traceparent（emit 与 handler 同 task同步执行
///   ⇒ `Span::current()` 即请求 span；无 otel 层 → `None` 省略）。落 outbox `metadata` 保留键 `trace`，
///   经 relay → broker header → consumer `tracewire::restore_remote_parent` 还原，使 handler span 与 producer 同 trace_id。
///
/// 全部缺失（worker 任务 / 批次未绑 correlation、无 otel）→ 仅含 occurred_at，不 panic（fail-open，不阻投递）。
pub(crate) fn metadata_with_ambient(
    occurred_at_secs: i64,
    tenant: vocab::TenantId,
    contract: vocab::ContractBinding,
) -> OutboxMetadata {
    let mut m = OutboxMetadata::new(occurred_at_secs, tenant, contract);
    if let Some(c) = diagctx::correlation() {
        m = m.with_correlation(c.as_str());
    }
    if let Some(context) = tracewire::capture_current() {
        m = m.with_trace(context.into_traceparent());
    }
    m
}

/// 持久化 epoch 秒（`extract(epoch ...)::bigint`）→ `SystemTime`：[`unix_secs`] 的**解码对称**（编码 / 解码
/// 同源单向往返）。负值（早于 epoch，理论不可达）收口 epoch 0，不 panic。session / credential 等 adapter 读
/// 路径共用此 decode 单源（避免各模块重复 decode helper；与 `unix_secs` encode 单源并列，#1316 review C-F1）。
#[cfg(feature = "domain-identity")]
pub(crate) fn epoch_secs_to_time(secs: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(u64::try_from(secs).unwrap_or(0))
}

// ── OutboxEnvelope ────────────────────────────────────────────────────────────

/// Outbox 行 envelope（adapter 本地，`pub(crate)`；由域写路径在 `append_outbox` 调用前构造）。
///
/// `metadata` 经 [`OutboxMetadata`] sealed funnel 收口（拒 reserved key + 仅 opaque subject id，
/// PII 边界；`observability.md` §outbox envelope）。
/// `partition_key` 来自 [`diport::OutboxEnvelopeParts::partition_key`]，`None` = 无序并行（DB NULL）、
/// `Some(s)` = 串行有序（head-of-partition gating，#1211）。
#[derive(Clone)]
pub(crate) struct OutboxEnvelope {
    domain: String,
    contract_id: String,
    contract_version: String,
    schema_hash: String,
    tenant: vocab::TenantId,
    metadata: OutboxMetadata,
    causation_id: Option<String>,
    partition_key: Option<String>,
}

impl OutboxEnvelope {
    /// 构造 envelope（funnel；字段私有，仅经此入口）。
    /// 生产 caller：`PgEmitter::write` 从 sealed `ReviewedEvent` envelope 组装（T008/#1100）。
    pub(crate) fn new(domain: String, contract_id: String, metadata: OutboxMetadata) -> Self {
        let tenant = metadata.tenant();
        let contract_version = metadata.contract_version().to_string();
        let schema_hash = metadata.schema_hash().to_string();
        Self {
            domain,
            contract_id,
            contract_version,
            schema_hash,
            tenant,
            metadata,
            causation_id: None,
            partition_key: None,
        }
    }

    /// 设置可选分区键（builder；`None` = 无序并行，`Some(PartitionKey)` → adapter 内存 String，#1211）。
    pub(crate) fn with_partition_key_opt(mut self, key: Option<consistency::PartitionKey>) -> Self {
        self.partition_key = key.map(|k| k.as_str().to_string());
        self
    }

    /// 设置可选 causation id（persisted-only，`None` → DB NULL）。
    pub(crate) fn with_causation_id_opt(
        mut self,
        causation_id: Option<EnvelopeCausationId>,
    ) -> Self {
        self.causation_id = causation_id.map(|id| id.as_str().to_string());
        self
    }

    /// 借出 domain。
    pub(crate) fn domain(&self) -> &str {
        &self.domain
    }

    /// 借出 contract_id。
    pub(crate) fn contract_id(&self) -> &str {
        &self.contract_id
    }

    /// 借出 contract_version 物理列值。
    pub(crate) fn contract_version(&self) -> &str {
        &self.contract_version
    }

    /// 借出 schema_hash 物理列值。
    pub(crate) fn schema_hash(&self) -> &str {
        &self.schema_hash
    }

    /// Exact-match a generated fact contract against every persisted routing identity column.
    /// Producer receipts are checked through this funnel immediately before an authorized append.
    #[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
    pub(crate) fn matches_contract(&self, contract: vocab::ContractBinding) -> bool {
        self.domain() == contract.domain()
            && self.contract_id() == contract.contract_id()
            && self.contract_version() == contract.version()
            && self.schema_hash() == contract.schema_hash()
    }

    /// 借出 tenant_id；outbox 表列、RLS 与 metadata `tenantId` 共享此类型层来源。
    pub(crate) fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    /// 借出可选分区键（`None` → DB NULL，无序并行；`Some(&str)` → 串行有序）。
    pub(crate) fn partition_key(&self) -> Option<&str> {
        self.partition_key.as_deref()
    }

    /// 借出可选 causation_id 物理列值。
    pub(crate) fn causation_id(&self) -> Option<&str> {
        self.causation_id.as_deref()
    }

    /// metadata 序列化为 JSON 字符串（绑 `$N::jsonb` 用）。
    pub(crate) fn metadata_json(&self) -> String {
        self.metadata.to_json_string()
    }
}

// ── append_outbox ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub(crate) enum OutboxAppendError {
    #[error("outbox append storage failed")]
    Storage(#[from] sqlx::Error),
    #[error(transparent)]
    Conflict(#[from] OutboxFactConflict),
    #[error("outbox canonical fingerprint drift")]
    CanonicalDrift,
    #[error("outbox canonical identity is invalid")]
    InvalidIdentity,
}

impl OutboxAppendError {
    pub(crate) const fn identity_failure_reason(&self) -> Option<&'static str> {
        match self {
            Self::Conflict(_) => Some("fact_conflict"),
            Self::CanonicalDrift => Some("canonical_drift"),
            Self::InvalidIdentity => Some("canonical_identity_invalid"),
            Self::Storage(_) => None,
        }
    }

    pub(crate) fn into_emit_error(self) -> OutboxEmitError {
        match self {
            Self::Conflict(conflict) => OutboxEmitError::fact_conflict(conflict),
            other => OutboxEmitError::new(other),
        }
    }

    pub(crate) fn into_observed_emit_error(self) -> OutboxEmitError {
        if let Some(reason) = self.identity_failure_reason() {
            tracing::warn!(
                target: "postgres",
                stage = "append-outbox",
                reason,
                "outbox: append rejected; transaction will roll back"
            );
        }
        self.into_emit_error()
    }
}

/// DLQ replay 重新创建 outbox 行的受控输入。
///
/// replay 的原始 dead_letter 行只保存 wire 侧字符串字段，无法重建 generated `ContractBinding`；
/// 但 #1622 已要求 replay fail-closed 解析 schema header 后写入物理列。该结构把 replay 专用写入仍收口到
/// `cotx/eventing.rs` 的 `outbox_insert_replayed` funnel，避免在 operator 路径散落第二份
/// `INSERT INTO outbox`。
pub(crate) struct ReplayedOutboxAppend {
    pub(crate) event_id: String,
    pub(crate) tenant: vocab::TenantId,
    pub(crate) domain: String,
    pub(crate) topic: String,
    pub(crate) contract_id: String,
    pub(crate) contract_version: String,
    pub(crate) schema_hash: String,
    pub(crate) payload: secure::Plaintext,
    pub(crate) metadata_json: secure::Plaintext,
    pub(crate) causation_id: Option<String>,
}

/// 在事务内向 outbox 双写一条 entry（L1 原子性硬约束）。
///
/// **`pub(crate)`，收 `&mut TenantTx`**——类型系统保证只能经 postgres adapter 从 live
/// `sqlx::Transaction` 铸造后调用；裸 `PgPool` / `PgConnection` 无法调用本入口。
///
/// ON CONFLICT (event_id) DO NOTHING：同 idem_key 的 entry 已在表中时幂等跳过（不报错）。
/// uuid/timestamptz 生成全部交给 server-side SQL（不给 sqlx 加 uuid/time feature）。
///
/// # INVARIANT: OUTBOX-ATOMIC-IDEM-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
///
/// outbox 双写必须在业务事务内原子执行——active producer 须经 `TenantDb<ServingWriteLane>` 的
/// concern-specific transaction funnel 传入 `EventingTx`；裸 `PgPool::acquire()` / `PgConnection` 无法调用（Hard）。
// 生产 caller：`PgEmitter::write`（impl `eventexec::event::ReviewedEventWriter`）在事务内调用——域 crate 不直接 import 本
// adapter（域→adapter 反向依赖被 deny.toml 禁），域侧只经 sealed reviewed-event writer 触发该 durable 写路径（T008/#1100）。
pub(crate) trait OutboxWriteEntry {
    fn topic_str(&self) -> &str;
    fn event_id(&self) -> &str;
    fn payload(&self) -> &[u8];
}

impl OutboxWriteEntry for EventEntry {
    fn topic_str(&self) -> &str {
        self.topic().as_str()
    }

    fn event_id(&self) -> &str {
        self.idem_key().as_str()
    }

    fn payload(&self) -> &[u8] {
        self.payload()
    }
}

impl OutboxWriteEntry for StoredOutboxEntry {
    fn topic_str(&self) -> &str {
        self.topic().as_str()
    }

    fn event_id(&self) -> &str {
        self.idem_key().as_str()
    }

    fn payload(&self) -> &[u8] {
        self.payload()
    }
}

/// Adapter-private durable fact assembled from the complete write entry + envelope pair.
///
/// Standard emit SQL binds every stable identity column through this value. DLQ replay uses its
/// own adjacent construction because its payload and metadata remain zeroize-on-drop all the way
/// to the SQL bind boundary rather than being copied into ordinary envelope buffers.
pub(crate) struct CanonicalOutboxFact<'a> {
    tenant: vocab::TenantId,
    event_id: &'a str,
    domain: &'a str,
    topic: &'a str,
    contract_id: &'a str,
    contract_version: &'a str,
    schema_hash: &'a str,
    payload: &'a [u8],
    metadata_json: String,
    partition_key: Option<&'a str>,
    causation_id: Option<&'a str>,
    fingerprint: OutboxFactFingerprint,
}

impl<'a> CanonicalOutboxFact<'a> {
    pub(crate) fn from_entry_env<E: OutboxWriteEntry>(
        entry: &'a E,
        env: &'a OutboxEnvelope,
    ) -> Self {
        let tenant_id = env.tenant().to_string();
        let metadata = serde_json::Value::Object(env.metadata.map.clone());
        let fingerprint = OutboxFactIdentity::new(
            entry.event_id(),
            &tenant_id,
            env.domain(),
            entry.topic_str(),
            env.contract_id(),
            env.contract_version(),
            env.schema_hash(),
            entry.payload(),
            env.partition_key(),
            env.causation_id(),
            &metadata,
        )
        .fingerprint();
        Self {
            tenant: env.tenant(),
            event_id: entry.event_id(),
            domain: env.domain(),
            topic: entry.topic_str(),
            contract_id: env.contract_id(),
            contract_version: env.contract_version(),
            schema_hash: env.schema_hash(),
            payload: entry.payload(),
            metadata_json: env.metadata_json(),
            partition_key: env.partition_key(),
            causation_id: env.causation_id(),
            fingerprint,
        }
    }

    pub(crate) fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    pub(crate) fn event_id(&self) -> &str {
        self.event_id
    }

    pub(crate) fn domain(&self) -> &str {
        self.domain
    }

    pub(crate) fn topic(&self) -> &str {
        self.topic
    }

    pub(crate) fn contract_id(&self) -> &str {
        self.contract_id
    }

    pub(crate) fn contract_version(&self) -> &str {
        self.contract_version
    }

    pub(crate) fn schema_hash(&self) -> &str {
        self.schema_hash
    }

    pub(crate) fn payload(&self) -> &[u8] {
        self.payload
    }

    pub(crate) fn metadata_json(&self) -> &str {
        &self.metadata_json
    }

    pub(crate) fn partition_key(&self) -> Option<&str> {
        self.partition_key
    }

    pub(crate) fn causation_id(&self) -> Option<&str> {
        self.causation_id
    }

    pub(crate) fn fingerprint(&self) -> OutboxFactFingerprint {
        self.fingerprint
    }
}

pub(crate) async fn append_outbox<E: OutboxWriteEntry, C: GeneratedOutboxConcern>(
    tx: &mut EventingTx<'_, ServingWriteLane, C>,
    entry: &E,
    env: &OutboxEnvelope,
) -> Result<OutboxAppendOutcome, OutboxAppendError> {
    let fact = CanonicalOutboxFact::from_entry_env(entry, env);
    let inserted = tx.outbox_insert_generated(&fact).await?;
    classify_append(tx, fact.event_id(), fact.fingerprint(), inserted).await
}

/// Append outbox and mirror to projection_events only for newly inserted generated-bound facts.
pub(crate) async fn append_outbox_with_projection<C: GeneratedOutboxConcern>(
    tx: &mut EventingTx<'_, ServingWriteLane, C>,
    entry: &EventEntry,
    env: &OutboxEnvelope,
    projection_registry: &ProjectionWriteRegistry,
) -> Result<OutboxAppendOutcome, OutboxAppendError> {
    let outcome = append_outbox(tx, entry, env).await?;
    match outcome {
        OutboxAppendOutcome::Inserted => {
            append_projection_event_if_bound(tx, entry, env, projection_registry).await?;
        }
        OutboxAppendOutcome::SameFact => {}
    }
    Ok(outcome)
}

async fn classify_append<C: GeneratedOutboxConcern>(
    tx: &mut EventingTx<'_, ServingWriteLane, C>,
    event_id: &str,
    expected: OutboxFactFingerprint,
    inserted: Option<Vec<u8>>,
) -> Result<OutboxAppendOutcome, OutboxAppendError> {
    if let Some(stored) = inserted.as_deref() {
        return classify_append_fingerprint(
            expected,
            AppendFingerprintObservation::Inserted(stored),
        );
    }

    let stored = tx.outbox_load_fingerprint(event_id).await?;
    classify_append_fingerprint(
        expected,
        AppendFingerprintObservation::Existing(stored.as_deref()),
    )
}

pub(crate) enum AppendFingerprintObservation<'a> {
    Inserted(&'a [u8]),
    Existing(Option<&'a [u8]>),
}

pub(crate) fn classify_append_fingerprint(
    expected: OutboxFactFingerprint,
    observed: AppendFingerprintObservation<'_>,
) -> Result<OutboxAppendOutcome, OutboxAppendError> {
    match observed {
        AppendFingerprintObservation::Inserted(stored) if stored == expected.as_bytes() => {
            Ok(OutboxAppendOutcome::Inserted)
        }
        AppendFingerprintObservation::Inserted(_) => Err(OutboxAppendError::CanonicalDrift),
        AppendFingerprintObservation::Existing(Some(stored)) if stored == expected.as_bytes() => {
            Ok(OutboxAppendOutcome::SameFact)
        }
        AppendFingerprintObservation::Existing(Some(_) | None) => Err(OutboxFactConflict.into()),
    }
}

// ── PgOutbox ──────────────────────────────────────────────────────────────────

/// PostgreSQL outbox adapter：impl [`OutboxRelay`] + [`RetentionSweeper`]。
///
/// 持 `PgPool`（clone 自 [`PgStore`]）、`Box<DynPublisher>`（Send 变体，跨 await 安全）、
/// [`TenantAuthority`]（租户权威签名）与 [`DlxPayloadProtector`]（DLX payload 加密）。这些持久化、
/// broker、租户权威和 DLX 保护依赖均为构造期必填位置参数，缺失即编译失败。
///
/// **时间源**：`claim_batch` / `settle_retry` / `sweep` 的所有时间谓词
/// 用 PostgreSQL 时钟，**刻意不注入 `Clock`**——relay 多实例并发下需要单一、
/// 无跨进程偏移的时间源（lease TTL / retry_after / 保留期比较都在 DB 端一致求值）。这是对
/// rust-standards `Clock` 构造器位置参规则的有意例外（clippy `disallowed_methods` 不覆盖 SQL `now()`）。
pub struct PgOutbox {
    pool: sqlx::PgPool,
    tenant_pool: TenantDb<ServingWriteLane>,
    provider: Arc<OutboxProviderIdentity>,
    publisher: Box<DynPublisher<'static>>,
    relay_budget: RelayBudget,
    tenant_authority: Arc<TenantAuthority>,
    payload_protector: DlxPayloadProtector,
}

impl PgOutbox {
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(
        store: &crate::PgStore,
        domain: vocab::DomainName,
        publisher: Box<DynPublisher<'static>>,
        relay_budget: RelayBudget,
        tenant_authority: Arc<TenantAuthority>,
        payload_protector: DlxPayloadProtector,
    ) -> Self {
        Self {
            pool: store.pool.clone(),
            tenant_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(store),
            provider: Arc::new(OutboxProviderIdentity { domain }),
            publisher,
            relay_budget,
            tenant_authority,
            payload_protector,
        }
    }

    /// 由 [`PgStore`]、typed domain、`Box<DynPublisher>`、`Arc<TenantAuthority>` 与
    /// [`DlxPayloadProtector`] 构造；domain 与 publisher 共同绑定 provider identity，其余依次提供
    /// 持久化、broker 发布、租户权威签名和 DLX payload 保护能力。
    /// pool 从 `PgStore.pool`（`pub(crate)`，同 crate 可取）clone；DynPublisher 转移所有权。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Identity>::outbox` 收口。
    #[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
    pub(crate) fn new(
        store: &VerifiedPgWriteStore,
        domain: vocab::DomainName,
        publisher: Box<DynPublisher<'static>>,
        relay_budget: RelayBudget,
        tenant_authority: Arc<TenantAuthority>,
        payload_protector: DlxPayloadProtector,
    ) -> Self {
        Self {
            pool: store.pool().clone(),
            tenant_pool: TenantDb::<ServingWriteLane>::new(store),
            provider: Arc::new(OutboxProviderIdentity { domain }),
            publisher,
            relay_budget,
            tenant_authority,
            payload_protector,
        }
    }

    /// Atomically claim one exact durable event without leasing any other eligible row.
    ///
    /// The fault matrix drives named crash points and therefore cannot consume a domain batch as
    /// though it were an event lookup. This seam retains the production claim predicate, partition
    /// gate, governed lease policy, opaque provider binding, hydration rollback, and commit-before-
    /// return semantics while narrowing selection by the durable event identity.
    ///
    /// The owner pool remains inside the feature-gated adapter harness. Production serving roles
    /// claim only through the governed `SECURITY DEFINER` batch function; this privileged test seam
    /// must not widen that runtime API or expose raw SQL outside the postgres adapter.
    #[cfg(feature = "fault-matrix-test-support")]
    pub(crate) async fn fault_matrix_claim_exact(
        &self,
        owner_pool: &sqlx::PgPool,
        event_id: &str,
    ) -> Result<Option<PgClaimedOutboxEntry>, EngineError> {
        let domain = self.provider.domain.as_str();
        let mut tx = owner_pool.begin().await.map_err(|error| {
            tracing::warn!(
                target: "postgres",
                domain,
                error = %secure::redact_error(&error),
                "outbox: exact fault-matrix claim begin error"
            );
            EngineError::new(EngineErrorKind::Transient)
        })?;
        let monotonic_deadline = io_deadline_after(self.relay_budget.lease_ttl());
        let row: Option<ClaimedOutboxRow> = sqlx::query_as(
            r#"
            WITH claim_clock AS MATERIALIZED (
                SELECT clock_timestamp() AS claimed_at
            ),
            governed_policy AS MATERIALIZED (
                SELECT automatic_retry_window_seconds, relay_lease_ttl_ms
                FROM event_delivery_policy
                WHERE singleton
                  AND relay_lease_ttl_ms = $3
                  AND relay_publish_timeout_ms
                      + relay_settle_timeout_ms
                      + relay_safety_margin_ms = $4
            ),
            eligible AS MATERIALIZED (
                SELECT o.id, o.seq, claim_clock.claimed_at,
                       governed_policy.automatic_retry_window_seconds,
                       governed_policy.relay_lease_ttl_ms
                FROM outbox AS o
                CROSS JOIN claim_clock
                CROSS JOIN governed_policy
                WHERE o.domain = $1
                  AND o.event_id = $2
                  AND (
                        (o.status = 'pending'
                         AND (o.retry_after IS NULL
                              OR o.retry_after <= claim_clock.claimed_at))
                     OR (o.status = 'publishing'
                         AND o.lease_until <= claim_clock.claimed_at)
                  )
                  AND (
                        o.partition_key IS NULL
                     OR NOT EXISTS (
                            SELECT 1
                            FROM outbox AS blocker
                            WHERE blocker.tenant_id = o.tenant_id
                              AND blocker.domain = o.domain
                              AND blocker.partition_key = o.partition_key
                              AND blocker.seq < o.seq
                              AND blocker.status NOT IN ('published', 'abandoned')
                        )
                  )
                FOR UPDATE OF o SKIP LOCKED
            ),
            claimed AS (
                UPDATE outbox AS o
                SET status = 'publishing',
                    lease_token = gen_random_uuid(),
                    lease_until = eligible.claimed_at
                        + eligible.relay_lease_ttl_ms * interval '1 millisecond',
                    automatic_retry_deadline = COALESCE(
                        o.automatic_retry_deadline,
                        eligible.claimed_at
                            + make_interval(
                                secs => eligible.automatic_retry_window_seconds::double precision
                            )
                    ),
                    published_at = NULL,
                    dlx_at = NULL,
                    updated_at = eligible.claimed_at
                FROM eligible
                WHERE o.id = eligible.id
                RETURNING o.tenant_id::text AS tenant_id, o.contract_id, o.topic, o.event_id,
                          o.payload, o.retry_count, o.metadata::text AS metadata, o.domain,
                          o.contract_version, o.schema_hash, eligible.claimed_at,
                          o.lease_token::text AS lease_token, o.lease_until
            )
            SELECT claimed.tenant_id, claimed.contract_id, claimed.topic, claimed.event_id,
                   claimed.payload, claimed.retry_count, claimed.metadata, claimed.domain,
                   claimed.contract_version, claimed.schema_hash,
                   EXTRACT(EPOCH FROM claimed.claimed_at)::bigint AS claimed_at_epoch_seconds,
                   claimed.lease_token,
                   (EXTRACT(EPOCH FROM claimed.lease_until) * 1000000)::bigint
                       AS deadline_epoch_micros
            FROM claimed
            "#,
        )
        .bind(domain)
        .bind(event_id)
        .bind(self.relay_budget.lease_ttl_millis())
        .bind(self.relay_budget.required_budget_millis())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| {
            tracing::warn!(
                target: "postgres",
                domain,
                error = %secure::redact_error(&error),
                "outbox: exact fault-matrix claim db error"
            );
            EngineError::new(EngineErrorKind::Transient)
        })?;

        let claim = row
            .map(|row| hydrate_claimed_outbox_row(row, &self.provider, monotonic_deadline))
            .transpose()
            .map_err(|error| {
                tracing::error!(
                    target: "postgres",
                    domain,
                    hydration_phase = error.phase(),
                    error = %error,
                    "outbox: exact fault-matrix claim hydration error; rolling back"
                );
                EngineError::new(EngineErrorKind::Invariant)
            })?;
        tx.commit().await.map_err(|error| {
            tracing::warn!(
                target: "postgres",
                domain,
                error = %secure::redact_error(&error),
                "outbox: exact fault-matrix claim commit error"
            );
            EngineError::new(EngineErrorKind::Transient)
        })?;
        Ok(claim)
    }
}

fn publish_request(entry: &StoredOutboxEntry, metadata: EnvelopeMetadata) -> PublishRequest {
    PublishRequest::new(
        diport::Topic::new(entry.topic().as_str()),
        diport::MessageId::new(entry.idem_key().as_str()),
        entry.payload().to_vec(),
    )
    .with_metadata(metadata)
}

#[cfg(feature = "fault-matrix-test-support")]
pub(crate) async fn fault_matrix_publish_before_settle(
    pool: &sqlx::PgPool,
    publisher: Box<DynPublisher<'static>>,
    relay_budget: RelayBudget,
    tenant_authority: Arc<TenantAuthority>,
    payload_protector: DlxPayloadProtector,
    domain: &str,
    event_id: &str,
) -> Result<(), EngineError> {
    let store = Arc::new(PgStore { pool: pool.clone() });
    let stores = PgRuntimeStores::from_unverified_for_test(Arc::clone(&store), store);
    let domain = vocab::DomainName::parse(domain)
        .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
    let relay = PgOutbox::new(
        stores.writer_capability(),
        domain,
        publisher,
        relay_budget,
        tenant_authority,
        payload_protector,
    );
    let claimed = relay
        .fault_matrix_claim_exact(pool, event_id)
        .await?
        .ok_or_else(|| EngineError::new(EngineErrorKind::Invariant))?;
    match relay.publish_claimed(&claimed).await {
        Ok(()) => Ok(()),
        Err(ClaimPublishError::Engine(error)) => Err(error),
        Err(ClaimPublishError::Publish(_)) => Err(EngineError::new(EngineErrorKind::Transient)),
    }
}

/// PostgreSQL outbox maintenance adapter：impl [`OutboxBacklog`] + [`RetentionSweeper`]，不持 publisher。
///
/// relay 需要 per-domain publisher，因此仍由 [`PgOutbox`] 承载；sampler/sweeper 只需要 DB pool，不应为了
/// 采样/清理而构造可发布的 relay outbox（#1429）。本类型经 [`crate::PgInfraDeps::outbox_maintenance`]
/// 暴露给组合根，用于 runtime module worker 接线。
#[derive(Clone)]
pub struct PgOutboxMaintenance {
    pool: sqlx::PgPool,
}

impl PgOutboxMaintenance {
    /// 由 [`PgStore`] 构造 outbox maintenance 能力（pool clone，轻量）。
    ///
    /// `pub(crate)`（PG-BUNDLE-FUNNEL-01）：经 [`crate::PgInfraDeps::outbox_maintenance`] 收口。
    pub(crate) fn new(store: &PgStore) -> Self {
        Self {
            pool: store.pool.clone(),
        }
    }
}

// ── OutboxRelay impl ──────────────────────────────────────────────────────────

impl OutboxRelay for PgOutbox {
    type Claim = PgClaimedOutboxEntry;

    fn claim_subject(claim: &Self::Claim) -> &OutboxMetricSubject {
        claim.subject()
    }

    fn claim_domain(&self) -> &vocab::DomainName {
        &self.provider.domain
    }

    /// 原子 claim `domain` 下至多 `limit` 条待发 entry（pending 且到期，或 lease 过期 stale publishing）。
    ///
    /// **Head-of-partition gating（#1211/#1581）**：对 `partition_key IS NOT NULL` 的行，仅当同
    /// `(tenant_id, domain, partition_key)` 内所有 `seq < o.seq` 的行均已 `published` 时才放行，
    /// 保证同 tenant partition 内按 seq 顺序串行投递。
    /// `partition_key IS NULL` 的行保持原语义——无序并行，不受 gate 约束。
    ///
    /// - **dlx fail-closed 语义**：队头进 dlx 会**阻塞**该 partition。deadline 前可经
    ///   `DlqStore::redrive_outbox` 保留 same-ID 重投；deadline 到期后只能经显式 terminal resolution
    ///   将队头结清为 `abandoned`，不再允许 same-ID broker publish。
    /// - **已知前提**：`b.seq < o.seq` 队头判据假设同 partition 行按 seq 序提交，成立条件是同 partition 写入由
    ///   聚合根并发控制（行锁/version CAS）串行化（partition = aggregate 标准契约）。
    /// - **backlog 注意**：head-of-partition gate 是 **claim-only by design**——被 gate 的后继仍计入 backlog
    ///   depth（见 `sample_backlog` 注释），否则 stalled partition 对 SLO 失明。
    ///
    /// `FOR UPDATE OF o SKIP LOCKED` 与同 statement `UPDATE ... RETURNING` 原子 claim，避免扫描/租约间隙。
    /// publish 成功、settle 前崩溃仍允许 broker duplicate，须由 consumer inbox 幂等收口。
    /// parse 失败（topic / idem_key 无效）→ `EngineErrorKind::Invariant`（我们写入的数据不该无效）。
    ///
    /// INVARIANT: OUTBOX-PARTITION-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
    async fn claim_batch(&self, limit: usize) -> Result<Vec<Self::Claim>, EngineError> {
        if !(1..=OUTBOX_CLAIM_BATCH_MAX).contains(&limit) {
            return Err(EngineError::new(EngineErrorKind::Invariant));
        }
        let domain = self.provider.domain.as_str();
        let limit =
            i64::try_from(limit).map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
        let mut tx = self.pool.begin().await.map_err(|e| {
            tracing::warn!(target: "postgres", domain, error = %secure::redact_error(&e), "outbox: claim_batch begin error");
            EngineError::new(EngineErrorKind::Transient)
        })?;
        // Pool acquisition is not part of a lease that PostgreSQL has not minted yet. Start the
        // conservative local clock immediately before the claim SQL; any SQL/hydration/commit delay
        // still consumes this bound and is rechecked before publish I/O.
        let monotonic_deadline = io_deadline_after(self.relay_budget.lease_ttl());
        let rows: Vec<ClaimedOutboxRow> = sqlx::query_as(
            crate::outbox_routine::OutboxCallableRoutine::ClaimBatch.sql(),
        )
        .bind(domain)
        .bind(limit)
        .bind(self.relay_budget.lease_ttl_millis())
        .bind(self.relay_budget.required_budget_millis())
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| {
            tracing::warn!(target: "postgres", domain, error = %secure::redact_error(&e), "outbox: claim_batch db error");
            EngineError::new(EngineErrorKind::Transient)
        })?;

        let claims = rows
            .into_iter()
            .map(|row| hydrate_claimed_outbox_row(row, &self.provider, monotonic_deadline))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                tracing::error!(
                    target: "postgres",
                    domain,
                    hydration_phase = error.phase(),
                    error = %error,
                    "outbox: claim_batch hydration error; rolling back batch"
                );
                EngineError::new(EngineErrorKind::Invariant)
            })?;
        tx.commit().await.map_err(|e| {
            tracing::warn!(target: "postgres", domain, error = %secure::redact_error(&e), "outbox: claim_batch commit error");
            EngineError::new(EngineErrorKind::Transient)
        })?;
        Ok(claims)
    }

    /// relay 单条 typed claim：publish → strict-deadline settle。
    ///
    /// `PublisherError` 携闭合三态 kind（#1212/#1821）：`Permanent`（序列化 / 路由 / 编码非法）
    /// 首投即 dlx（跳过重试预算）；definitive `Transient` 表示明确未发送或已拒绝，使用原 event ID
    /// 退避重试；`Ambiguous` 表示 broker 可能已接收，仍以稳定 event ID 重试并由消费端幂等收口。
    /// 分流见 [`settle_publish_failure`] / [`dlx_decision`]。DB/CAS 失败（含 LostLease）返
    /// `Err(EngineError)`；publish 失败仅在 retry/DLX settle 成功后才是**已处置**（返
    /// `Ok(Disposition)`）。
    async fn relay(&self, claimed: Self::Claim) -> Result<consistency::Disposition, EngineError> {
        let event_id = claimed.idem_key().as_str();
        self.validate_claim_provider(&claimed)?;
        if !local_publish_budget_available(claimed.lease.monotonic_deadline, self.relay_budget) {
            return Err(expired_lease_error(event_id, "pre_publish_local_budget"));
        }
        let publish_deadline = io_deadline_after(self.relay_budget.publisher_watchdog_timeout());
        let preflight_deadline = publish_deadline - self.relay_budget.publish_timeout();
        match publish_preflight(&self.pool, &claimed, self.relay_budget, preflight_deadline).await?
        {
            PublishPreflight::Allowed => {}
            PublishPreflight::LostLease => {
                return Err(lost_lease_error(event_id, "pre_publish_budget"));
            }
            PublishPreflight::AutomaticExpired => {
                return self
                    .settle_delivery_window_expired(
                        claimed.subject().tenant_id(),
                        &claimed,
                        SameIdDeliveryPhase::Automatic,
                    )
                    .await;
            }
            PublishPreflight::RedriveExpired => {
                return self
                    .settle_delivery_window_expired(
                        claimed.subject().tenant_id(),
                        &claimed,
                        SameIdDeliveryPhase::Redrive,
                    )
                    .await;
            }
        }
        let tenant = claimed.subject().tenant_id();
        let publish_result = match self
            .publish_claimed_before(&claimed, publish_deadline)
            .await
        {
            Ok(()) => Ok(()),
            Err(ClaimPublishError::Engine(error)) => return Err(error),
            Err(ClaimPublishError::Publish(error)) => Err(error),
        };

        match publish_result {
            Ok(()) => {
                // 3a. 发布成功 → published（以本次 lease_token 比对，防 stale 持租者结算）。
                // LostLease（0 行 CAS）不是干净成功：即使 broker 已收到事件，当前 worker 也未能证明
                // durable settle，故返 Transient 让调度层显式感知并按租约状态恢复。
                match settlement::published(&self.tenant_pool, &claimed, self.relay_budget).await? {
                    settlement::Settlement::Settled((), _) => Ok(consistency::Disposition::Ack),
                    settlement::Settlement::Expired(_) => {
                        Err(expired_lease_error(event_id, "settle_published"))
                    }
                    settlement::Settlement::LostLease(_) => {
                        Err(lost_lease_error(event_id, "settle_published"))
                    }
                }
            }
            // 3b. 发布失败 → dlx（预算耗尽）/ retry（退避），见 helper。
            Err(e) => self.settle_publish_failure(tenant, &claimed, &e).await,
        }
    }
}

fn local_publish_budget_available(
    monotonic_deadline: tokio::time::Instant,
    relay_budget: RelayBudget,
) -> bool {
    monotonic_deadline.saturating_duration_since(io_deadline_after(std::time::Duration::ZERO))
        > relay_budget.required_budget()
}

impl PgOutbox {
    async fn settle_delivery_window_expired(
        &self,
        tenant: vocab::TenantId,
        claimed: &PgClaimedOutboxEntry,
        phase: SameIdDeliveryPhase,
    ) -> Result<consistency::Disposition, EngineError> {
        let event_id = claimed.idem_key().as_str();
        match settlement::same_id_expiry_dlx(
            &self.tenant_pool,
            &self.payload_protector,
            tenant,
            claimed,
            phase,
            self.relay_budget,
        )
        .await?
        {
            settlement::Settlement::Settled(_, _) => {
                record_same_id_window_expired(claimed.domain(), claimed.subject(), phase);
                Ok(consistency::Disposition::Reject)
            }
            settlement::Settlement::Expired(_) => Err(expired_lease_error(
                event_id,
                "settle_delivery_window_expired",
            )),
            settlement::Settlement::LostLease(_) => {
                Err(lost_lease_error(event_id, "settle_delivery_window_expired"))
            }
        }
    }

    fn validate_claim_provider(&self, claimed: &PgClaimedOutboxEntry) -> Result<(), EngineError> {
        if Arc::ptr_eq(&self.provider, &claimed.provider) {
            return Ok(());
        }
        tracing::error!(
            target: "postgres",
            expected_domain = self.provider.domain.as_str(),
            claim_domain = claimed.domain().as_str(),
            "outbox: claim belongs to a different provider instance"
        );
        Err(EngineError::new(EngineErrorKind::Invariant))
    }

    fn prepare_publish_request(
        &self,
        claimed: &PgClaimedOutboxEntry,
    ) -> Result<PublishRequest, ClaimPublishError> {
        let tenant = claimed.subject().tenant_id();
        let mut metadata = hydrate_claimed_metadata(claimed.metadata());
        metadata.insert_wire_pair(KEY_TENANT_ID, tenant.to_string());
        apply_schema_headers_from_columns(
            &mut metadata,
            claimed.contract_version(),
            claimed.schema_hash(),
        );
        let metadata = self
            .sign_metadata(
                metadata,
                TenantAuthoritySignInput {
                    tenant,
                    domain: claimed.domain().as_str(),
                    contract_id: claimed.subject().contract_id().as_str(),
                    topic: claimed.topic().as_str(),
                    event_id: claimed.idem_key().as_str(),
                    now_epoch: claimed.claimed_at_epoch_seconds(),
                },
            )
            .map_err(ClaimPublishError::Engine)?;
        let request = publish_request(claimed.entry(), metadata);
        validate_publish_request_envelope(&request).map_err(|error| {
            record_relay_envelope_validation_failure(
                claimed.domain().as_str(),
                claimed.subject(),
                error.reason(),
            );
            ClaimPublishError::Publish(RelayPublishFailure::Envelope(error))
        })?;
        Ok(request)
    }

    #[cfg(feature = "fault-matrix-test-support")]
    async fn publish_claimed(
        &self,
        claimed: &PgClaimedOutboxEntry,
    ) -> Result<(), ClaimPublishError> {
        let deadline = io_deadline_after(self.relay_budget.publisher_watchdog_timeout());
        self.publish_claimed_before(claimed, deadline).await
    }

    async fn publish_claimed_before(
        &self,
        claimed: &PgClaimedOutboxEntry,
        deadline: tokio::time::Instant,
    ) -> Result<(), ClaimPublishError> {
        let request = self.prepare_publish_request(claimed)?;
        with_publisher_watchdog(deadline, self.relay_budget, self.publisher.publish(request))
            .await
            .map_err(|error| ClaimPublishError::Publish(RelayPublishFailure::Publisher(error)))
    }

    // reason: tenant-authority signing binds the protocol fields exactly as they are stored in the
    // outbox row; wrapping them only for this call would add DB-only code without stronger invariants.
    #[allow(clippy::too_many_arguments)]
    fn sign_metadata(
        &self,
        mut metadata: EnvelopeMetadata,
        input: TenantAuthoritySignInput<'_>,
    ) -> Result<EnvelopeMetadata, EngineError> {
        let token = self
            .tenant_authority
            .sign_at(input.binding(), input.now_epoch)
            .map_err(|e| {
                tracing::error!(
                    target: "postgres",
                    domain = input.domain,
                    contract_id = input.contract_id,
                    topic = input.topic,
                    event_id = input.event_id,
                    error = %secure::redact_error(&e),
                    "outbox relay failed to sign tenant authority"
                );
                EngineError::new(EngineErrorKind::Invariant)
            })?;
        metadata.insert_wire_pair(diport::KEY_TENANT_AUTHORITY, token);
        Ok(metadata)
    }
}

enum ClaimPublishError {
    Engine(EngineError),
    Publish(RelayPublishFailure),
}

/// outbox.metadata（jsonb→text）→ [`EnvelopeMetadata`]：逐 key-value 经 `insert_wire_pair` 透传。
///
/// string 值直接用；number / bool 等 stringify（occurred_at 在 DB 存 number → 十进制 string，
/// [`EnvelopeMetadata::occurred_at_secs`] 再反解析）。
// reason: fail-safe——非对象 JSON / 解析失败返 empty 而非 Err，不阻 relay；relay 核心语义是
// at-least-once 投递，envelope 降级省略 metadata 比阻断投递更安全。
#[cfg(test)]
fn hydrate_envelope_metadata(json: &str) -> EnvelopeMetadata {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(json) else {
        tracing::debug!(target: "postgres", json_len = json.len(), "outbox: hydrate_envelope_metadata: non-object/invalid json, proceeding without metadata");
        return EnvelopeMetadata::empty();
    };
    let mut md = EnvelopeMetadata::empty();
    for (k, v) in map {
        let s = match v {
            serde_json::Value::String(s) => s,
            // number（如 occurred_at）→ 十进制 string（无 JSON 引号），boolean/null → compact form。
            other => other.to_string(),
        };
        md.insert_wire_pair(k, s);
    }
    md
}

fn hydrate_claimed_metadata(map: &serde_json::Map<String, serde_json::Value>) -> EnvelopeMetadata {
    let mut metadata = EnvelopeMetadata::empty();
    for (key, value) in map {
        let value = match value {
            serde_json::Value::String(value) => value.clone(),
            other => other.to_string(),
        };
        metadata.insert_wire_pair(key, value);
    }
    metadata
}

fn hydrate_claimed_outbox_row(
    row: ClaimedOutboxRow,
    provider: &Arc<OutboxProviderIdentity>,
    monotonic_deadline: tokio::time::Instant,
) -> Result<PgClaimedOutboxEntry, ClaimHydrationError> {
    let subject = parse_metric_subject(&row.tenant_id, &row.contract_id)
        .map_err(|_| ClaimHydrationError::MetricSubject)?;
    let idem_key = IdemKey::parse(&row.event_id).map_err(|_| ClaimHydrationError::EventId)?;
    let entry = StoredOutboxEntry::hydrate(
        row.topic,
        idem_key,
        OutboxPayload::from_reviewed_event_bytes(row.payload),
    )
    .map_err(|_| ClaimHydrationError::StoredEntry)?;
    let retry_count =
        u32::try_from(row.retry_count).map_err(|_| ClaimHydrationError::RetryCount)?;
    let domain = vocab::DomainName::parse(&row.domain).map_err(|_| ClaimHydrationError::Domain)?;
    if domain != provider.domain {
        return Err(ClaimHydrationError::ProviderDomain);
    }
    let metadata = match serde_json::from_str(&row.metadata) {
        Ok(serde_json::Value::Object(metadata)) => metadata,
        Ok(_) | Err(_) => return Err(ClaimHydrationError::Metadata),
    };
    let lease = OutboxLease::hydrate(
        row.lease_token,
        row.deadline_epoch_micros,
        monotonic_deadline,
    )
    .map_err(|error| match error {
        OutboxLeaseError::Token => ClaimHydrationError::LeaseToken,
        OutboxLeaseError::TokenVersion => ClaimHydrationError::LeaseTokenVersion,
        OutboxLeaseError::Deadline => ClaimHydrationError::LeaseDeadline,
    })?;
    if row.contract_version.is_empty() {
        return Err(ClaimHydrationError::ContractVersion);
    }
    if row.schema_hash.is_empty() {
        return Err(ClaimHydrationError::SchemaHash);
    }
    if row.claimed_at_epoch_seconds <= 0 {
        return Err(ClaimHydrationError::ClaimedAt);
    }
    Ok(PgClaimedOutboxEntry {
        provider: Arc::clone(provider),
        entry,
        subject,
        retry_count,
        domain,
        contract_version: row.contract_version,
        schema_hash: row.schema_hash,
        metadata,
        claimed_at_epoch_seconds: row.claimed_at_epoch_seconds,
        lease,
    })
}

fn apply_schema_headers_from_columns(
    metadata: &mut EnvelopeMetadata,
    contract_version: &str,
    schema_hash: &str,
) {
    metadata.insert_wire_pair(KEY_SCHEMA_VERSION, contract_version);
    metadata.insert_wire_pair(KEY_SCHEMA_HASH, schema_hash);
}

/// Relay 发布前标准 envelope header gate：缺 tenant/schema header 视为永久发布失败，进入现有 DLX 分流。
fn validate_publish_request_envelope(
    request: &PublishRequest,
) -> Result<(), RelayEnvelopeValidationError> {
    request
        .try_header()
        .map(|_| ())
        .map_err(RelayEnvelopeValidationError::new)
}

fn record_relay_envelope_validation_failure(
    domain: &str,
    subject: &OutboxMetricSubject,
    reason: RelayEnvelopeValidationReason,
) {
    metrics::counter!(
        "outbox_relay_envelope_validation_failure_total",
        "domain" => domain.to_owned(),
        "contract_id" => subject.contract_id().as_str().to_owned(),
        "tenant_id" => subject.tenant_id().to_string(),
        "reason" => reason.as_label(),
    )
    .increment(1);
}

fn record_same_id_window_expired(
    domain: &vocab::DomainName,
    subject: &OutboxMetricSubject,
    phase: SameIdDeliveryPhase,
) {
    metrics::counter!(
        "outbox_same_id_window_expired_total",
        "domain" => domain.as_str().to_owned(),
        "contract_id" => subject.contract_id().as_str().to_owned(),
        "tenant_id" => subject.tenant_id().to_string(),
        "phase" => phase.as_label(),
    )
    .increment(1);
}

/// publish 失败处置（抽出控制 `relay` 认知复杂度 ≤15）：永久错误首投即 dlx、预算耗尽 → dlx；否则退避 retry
/// （#1212，分流谓词见 [`dlx_decision`]）。
///
/// settle CAS 命中 `LostLease`（0 行）⇒ 行已被新租约接管：本租约不拥有该行、不重复处置，并返回
/// `Transient` 使 worker 降级；不得把 publish/settle 的未确认结果伪装成 Ack。
impl PgOutbox {
    async fn settle_publish_failure(
        &self,
        tenant: vocab::TenantId,
        claimed: &PgClaimedOutboxEntry,
        err: &RelayPublishFailure,
    ) -> Result<consistency::Disposition, EngineError> {
        let entry = claimed.entry();
        let retry_count = i32::try_from(claimed.retry_count())
            .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
        let event_id = entry.idem_key().as_str();
        let new_count = retry_count
            .checked_add(1)
            .ok_or_else(|| EngineError::new(EngineErrorKind::Invariant))?;
        let kind = err.kind();
        let permanent = matches!(kind, PublishErrorKind::Permanent);
        log_publish_failed(event_id, entry.topic().as_str(), retry_count, err);
        if dlx_decision(kind, new_count) {
            match settlement::ordinary_dlx(
                &self.tenant_pool,
                &self.payload_protector,
                tenant,
                claimed,
                err,
                self.relay_budget,
            )
            .await?
            {
                settlement::Settlement::Settled(authoritative_retry_count, _) => {
                    log_dlx(
                        event_id,
                        authoritative_retry_count,
                        permanent,
                        err.reason_label(),
                    );
                    Ok(consistency::Disposition::Reject)
                }
                settlement::Settlement::Expired(_) => {
                    Err(expired_lease_error(event_id, "settle_dlx"))
                }
                settlement::Settlement::LostLease(_) => {
                    Err(lost_lease_error(event_id, "settle_dlx"))
                }
            }
        } else {
            match settlement::retry(&self.tenant_pool, claimed, self.relay_budget).await? {
                settlement::Settlement::Settled((), _) => Ok(consistency::Disposition::Requeue),
                settlement::Settlement::Expired(_) => {
                    Err(expired_lease_error(event_id, "settle_retry"))
                }
                settlement::Settlement::LostLease(_) => {
                    Err(lost_lease_error(event_id, "settle_retry"))
                }
            }
        }
    }
}

// ── 结构化日志 helper（抽出 tracing 宏展开，控制调用方认知复杂度 ≤15）。勿记 payload/PII。──

/// publish 失败：退避/dlx 前结构化记录（带 `event_id` 关联键，F9）。
/// `PublisherError::Display` 是受控安全摘要（diport PII 边界）；`permanent` 字段（#1212）让单条日志即可
/// 区分「瞬态退避重试」与「永久即将首投 DLX」，无需关联后续 `log_dlx`（便于 metric 聚合 / alert）。
fn log_publish_failed(event_id: &str, topic: &str, retry_count: i32, err: &RelayPublishFailure) {
    match err {
        RelayPublishFailure::Publisher(source) => {
            log_publisher_failed(event_id, topic, retry_count, err.reason_label(), source);
        }
        RelayPublishFailure::Envelope(source) => {
            log_envelope_validation_failed(event_id, topic, retry_count, source);
        }
    }
}

fn log_publisher_failed(
    event_id: &str,
    topic: &str,
    retry_count: i32,
    reason: &'static str,
    err: &PublisherError,
) {
    tracing::warn!(target: "postgres", event_id, topic, retry_count, publish_error_kind = ?err.kind(), permanent = err.is_permanent(), retryable = err.is_retryable(), ambiguous = err.is_ambiguous(), reason, error = %secure::redact_error(err), "outbox: publish failed");
}

fn log_envelope_validation_failed(
    event_id: &str,
    topic: &str,
    retry_count: i32,
    err: &RelayEnvelopeValidationError,
) {
    tracing::warn!(target: "postgres", event_id, topic, retry_count, permanent = true, reason = err.reason().as_label(), error = %secure::redact_error(err), "outbox: publish failed");
}

/// 进 dlx（运维须感知）。`permanent`：`true`=错误本身永久（首投即 DLX，跳过预算）；`false`=瞬态重试预算耗尽。
///
/// **排障路径**：relay 侧 Entry 不携 partition_key；dlx 冻结某 partition 时，运维可经
/// `SELECT partition_key, domain FROM outbox WHERE event_id = $event_id` 定位被冻结的 partition，
/// deadline 前可经 `DlqStore::redrive_outbox`重投；deadline 到期后 redrive 必须拒绝，只能经
/// `DlqStore::resolve_expired_outbox` 提交 tenant-scoped resolution evidence 并结清为 `abandoned`，
/// 然后放行后继。
/// 主动 partition 级监控信号（batch dlx gauge）见 issue **#1406**（不在本 PR）。
fn log_dlx(event_id: &str, attempts: i32, permanent: bool, reason: &'static str) {
    tracing::error!(target: "postgres", event_id, attempts, permanent, reason, "outbox: publish failed, moved to dlx");
}

/// settle CAS 0 行（lost-lease fencing miss）：行已被新租约接管或已终结。结构化 warn（benign handoff，
/// 运维据 `event_id` + `operation` 关联，区分「干净结算」与「丢租约」，F3/F9）。
fn log_lost_lease(event_id: &str, operation: &str) {
    tracing::warn!(target: "postgres", event_id, operation, "outbox: settle hit lost lease (0 rows); row owned by another lease");
}

fn lost_lease_error(event_id: &str, operation: &str) -> EngineError {
    log_lost_lease(event_id, operation);
    EngineError::new(EngineErrorKind::Transient)
}

fn expired_lease_error(event_id: &str, operation: &str) -> EngineError {
    tracing::warn!(target: "postgres", event_id, operation, "outbox: settlement lease expired");
    EngineError::new(EngineErrorKind::Transient)
}

// ── RetentionSweeper impl ────────────────────────────────────────────────────────

impl RetentionSweeper for PgOutbox {
    /// 删除 `status='published'` 且 `published_at` 早于保留期的行，返回删除条数。
    /// dlx 行不删（留运维巡检）。
    ///
    /// 时间谓词用 PostgreSQL `now()`（DB 事务时间）是刻意决策——见 [`PgOutbox`] 顶注。
    async fn sweep(&self, retain_seconds: u64) -> Result<u64, EngineError> {
        sweep_published_outbox(&self.pool, retain_seconds).await
    }
}

impl RetentionSweeper for PgOutboxMaintenance {
    /// 删除 `status='published'` 且 `published_at` 早于保留期的行，返回删除条数。
    async fn sweep(&self, retain_seconds: u64) -> Result<u64, EngineError> {
        sweep_published_outbox(&self.pool, retain_seconds).await
    }
}

// ── OutboxBacklog impl ────────────────────────────────────────────────────────

/// Outbox 积压采样实现（单次聚合 SELECT，服务端 `now()`，读路径，不 FOR UPDATE）。
///
/// **索引决策（无新建）**：pre-GA 阶段 pending 行量小；现有
/// `idx_outbox_relay_scan ON outbox (domain, status, retry_after)` 已覆盖
/// `WHERE domain = $1 AND status = $2 AND (retry_after IS NULL OR retry_after <= now())`
/// 谓词，代价低廉。`min(created_at)` 聚合运行在已被索引过滤的小行集上，额外排序开销可忽略。
/// 若后续 profiling 显示瓶颈，跟进路径为偏索引
/// `CREATE INDEX ON outbox (domain, status, created_at) WHERE status = 'pending'`。
impl OutboxBacklog for PgOutbox {
    /// 采样 `domain` 的**可投递积压**（深度 + 最老积压龄）。
    ///
    /// 谓词与 [`OutboxRelay::claim_batch`] 的可重捞集合**同源**：
    /// `(status=pending 且到期) OR (status=publishing 且显式 `lease_until <= clock_timestamp()`)`。
    /// stale `publishing`（崩溃/超时 in-flight）会被 relay 重投，属可投递积压，**必须计入**——否则 oldest-age
    /// SLO 对可恢复积压失明（relay 重捞但 gauge 报 0）。只排除 lease 仍有效的正常 in-flight。无可投递行 ⇒
    /// [`BacklogSample::empty`]。**不变式**：本谓词须随 `claim_batch` 同步改（集成测试 T16/T18 + stale-publishing
    /// 用例锁定漂移）。
    ///
    /// **head-of-partition gate 是 claim-only by design**——被 gate 的后继仍计入 backlog depth（否则 stalled
    /// partition 对 SLO 失明）。backlog 谓词刻意不含 head-of-partition gate（见 `claim_batch` INVARIANT:
    /// OUTBOX-PARTITION-ORDER-01）。
    async fn sample_backlog(&self, domain: &str) -> Result<BacklogObservation, EngineError> {
        sample_outbox_backlog(&self.pool, domain)
            .await
            .map(BacklogObservation::Active)
    }
}

impl OutboxBacklog for PgOutboxMaintenance {
    /// 采样 `domain` 的**可投递积压**（深度 + 最老积压龄）。
    async fn sample_backlog(&self, domain: &str) -> Result<BacklogObservation, EngineError> {
        sample_outbox_backlog(&self.pool, domain)
            .await
            .map(BacklogObservation::Active)
    }
}

async fn sweep_published_outbox(
    pool: &sqlx::PgPool,
    retain_seconds: u64,
) -> Result<u64, EngineError> {
    // u64→i64：超 i64::MAX 的保留期是非法输入（负 interval 会反向清空全表），fail-closed。
    let secs =
        i64::try_from(retain_seconds).map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
    let result = sqlx::query(
        crate::outbox_routine::OutboxCallableRoutine::SweepPublished.sql(),
    )
    .bind(secs)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::warn!(target: "postgres", error = %secure::redact_error(&e), "outbox: sweep db error");
        EngineError::new(EngineErrorKind::Transient)
    })?;

    let deleted_rows: i64 = result.try_get("deleted_rows").map_err(|e| {
        tracing::warn!(target: "postgres", error = %secure::redact_error(&e), "outbox: sweep result decode error");
        EngineError::new(EngineErrorKind::Transient)
    })?;
    u64::try_from(deleted_rows).map_err(|_| EngineError::new(EngineErrorKind::Invariant))
}

async fn sample_outbox_backlog(
    pool: &sqlx::PgPool,
    domain: &str,
) -> Result<Vec<BacklogMetricSample>, EngineError> {
    let rows: Vec<(String, String, i64, i64, i64)> = sqlx::query_as(
        crate::outbox_routine::OutboxCallableRoutine::SampleBacklog.sql(),
    )
    .bind(domain)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        tracing::warn!(target: "postgres", domain, error = %secure::redact_error(&e), "outbox: sample_backlog db error");
        EngineError::new(EngineErrorKind::Transient)
    })?;

    rows.into_iter()
        .map(
            |(tenant_id, contract_id, raw_depth, raw_age, raw_partition_blocked)| {
                let subject = parse_metric_subject(&tenant_id, &contract_id)?;
                // count(*) 恒 ≥ 0；i64→u64 转换失败在理论上不可表达，fail-closed。
                let depth = u64::try_from(raw_depth)
                    .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
                let partition_blocked_depth = u64::try_from(raw_partition_blocked)
                    .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;

                // clock skew 或极端 EXTRACT 结果可能返负值；负龄无语义，截断到 0。
                let oldest_age_seconds = u64::try_from(raw_age.max(0))
                    .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;

                Ok(BacklogMetricSample::with_partition_blocked_depth(
                    subject,
                    BacklogSample::new(depth, oldest_age_seconds),
                    partition_blocked_depth,
                ))
            },
        )
        .collect()
}

// ── relay 拆分 helper fn（认知复杂度 ≤ 15）────────────────────────────────────

async fn with_publisher_watchdog<F>(
    deadline: tokio::time::Instant,
    relay_budget: RelayBudget,
    future: F,
) -> Result<(), PublisherError>
where
    F: Future<Output = Result<(), PublisherError>>,
{
    match tokio::time::timeout_at(deadline, future).await {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!(
                target: "postgres",
                phase = "publisher_watchdog",
                publish_timeout_ms = relay_budget.publish_timeout_millis(),
                publisher_watchdog_timeout_ms = relay_budget.publisher_watchdog_timeout_millis(),
                delivery_outcome = "unknown",
                broker_may_have_received = true,
                "outbox publisher watchdog timed out"
            );
            Err(PublisherError::ambiguous(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "outbox publisher watchdog timed out",
            )))
        }
    }
}

/// The preflight starts and completes inside the safety-margin deadline. It owns the acquired
/// connection so a timed-out query cannot later re-enter the idle pool and publish stale work.
async fn publish_preflight(
    pool: &sqlx::PgPool,
    claimed: &PgClaimedOutboxEntry,
    relay_budget: RelayBudget,
    deadline: tokio::time::Instant,
) -> Result<PublishPreflight, EngineError> {
    let event_id = claimed.idem_key().as_str().to_string();
    let lease_token = claimed.lease_token().to_string();
    let lease_deadline_epoch_micros = claimed.lease_deadline_epoch_micros();
    let lease_ttl_millis = relay_budget.lease_ttl_millis();
    let required_budget_millis = relay_budget.required_budget_millis();
    let discriminant = deadline_global_transaction(
        pool,
        deadline,
        move |connection| {
            Box::pin(async move {
                sqlx::query_scalar::<_, i16>(
                    crate::outbox_routine::OutboxCallableRoutine::PublishPreflight.sql(),
                )
                .bind(event_id)
                .bind(lease_token)
                .bind(lease_deadline_epoch_micros)
                .bind(lease_ttl_millis)
                .bind(required_budget_millis)
                .fetch_one(connection)
                .await
                .map_err(|error| {
                    tracing::warn!(
                        target: "postgres",
                        error = %secure::redact_error(&error),
                        "outbox: lease publish-budget preflight failed"
                    );
                    EngineError::new(EngineErrorKind::Transient)
                })
            })
        },
        |error| {
            tracing::warn!(
                target: "postgres",
                error = %secure::redact_error(&error),
                "outbox: lease publish-budget preflight transaction failed"
            );
            EngineError::new(EngineErrorKind::Transient)
        },
        || {
            tracing::warn!(
                target: "postgres",
                phase = "publish_preflight",
                preflight_timeout_ms = relay_budget.safety_margin_millis(),
                "outbox publish preflight timed out"
            );
            EngineError::new(EngineErrorKind::Transient)
        },
    )
    .await?;
    PublishPreflight::try_from(discriminant).map_err(|_| {
        tracing::error!(
            target: "postgres",
            discriminant,
            "outbox: unknown publish preflight discriminant"
        );
        EngineError::new(EngineErrorKind::Invariant)
    })
}

fn parse_metadata_json(json: &str) -> Result<serde_json::Value, EngineError> {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(serde_json::Value::Object(_)) => {
            serde_json::from_str(json).map_err(|_| EngineError::new(EngineErrorKind::Invariant))
        }
        Ok(_) | Err(_) => Err(EngineError::new(EngineErrorKind::Invariant)),
    }
}

fn parse_tenant_id(raw: &str) -> Result<vocab::TenantId, EngineError> {
    vocab::TenantId::parse(raw).map_err(|_| EngineError::new(EngineErrorKind::Invariant))
}

fn parse_outbox_contract_id(raw: &str) -> Result<OutboxContractId, EngineError> {
    OutboxContractId::parse(raw).map_err(|_| EngineError::new(EngineErrorKind::Invariant))
}

fn parse_metric_subject(
    tenant_id: &str,
    contract_id: &str,
) -> Result<OutboxMetricSubject, EngineError> {
    Ok(OutboxMetricSubject::new(
        parse_tenant_id(tenant_id)?,
        parse_outbox_contract_id(contract_id)?,
    ))
}

fn metadata_json_with_column_tenant(
    json: &str,
    tenant: vocab::TenantId,
) -> Result<serde_json::Value, EngineError> {
    let mut metadata = parse_metadata_json(json)?;
    let serde_json::Value::Object(ref mut map) = metadata else {
        return Err(EngineError::new(EngineErrorKind::Invariant));
    };
    map.insert(
        KEY_TENANT_ID.to_string(),
        serde_json::Value::String(tenant.to_string()),
    );
    Ok(metadata)
}

fn metadata_json_with_relay_failure(
    json: &str,
    tenant: vocab::TenantId,
    contract_version: &str,
    schema_hash: &str,
    relay_failure_reason: Option<&'static str>,
) -> Result<serde_json::Value, EngineError> {
    let mut metadata = metadata_json_with_column_tenant(json, tenant)?;
    let serde_json::Value::Object(ref mut map) = metadata else {
        return Err(EngineError::new(EngineErrorKind::Invariant));
    };
    map.insert(
        KEY_SCHEMA_VERSION.to_string(),
        serde_json::Value::String(contract_version.to_string()),
    );
    map.insert(
        KEY_SCHEMA_HASH.to_string(),
        serde_json::Value::String(schema_hash.to_string()),
    );
    if let Some(reason) = relay_failure_reason {
        map.insert(
            KEY_RELAY_FAILURE_REASON.to_string(),
            serde_json::Value::String(reason.to_string()),
        );
    }
    Ok(metadata)
}

// ── 纯函数（单测覆盖）────────────────────────────────────────────────────────

/// 该次 publish 失败是否应进 DLX（而非退避重试）——#1212/#1821 三态分流谓词。
///
/// `Permanent` 首投即 dlx（重试同一消息无意义，跳过预算）；`Transient | Ambiguous` 使用原 event ID
/// 熬满重试预算后才 dlx。`new_count` 是本次失败后的累计重试次数（= UPDATE 前 `retry_count + 1`）。
fn dlx_decision(kind: PublishErrorKind, new_count: i32) -> bool {
    match kind {
        PublishErrorKind::Permanent => true,
        PublishErrorKind::Transient | PublishErrorKind::Ambiguous => {
            new_count >= MAX_PUBLISH_ATTEMPTS
        }
    }
}

/// 指数退避（秒），上限 3600。`retry_count` 是当前已重试次数（0-based，即 UPDATE 前的值）。
///
/// backoff = min(2^retry_count, 3600)。数据库冻结 policy 独立限定 same-ID 重投绝对窗口；
/// 该函数只描述窗口内单次重试退避。
#[cfg(test)]
pub(crate) const fn backoff_seconds(retry_count: i32) -> i64 {
    const MAX_BACKOFF: i64 = 3600;
    if retry_count < 0 {
        // DB retry_count 理论恒 ≥0（DEFAULT 0，只递增）；防御负值左移 panic（debug）/ 掩码异常（release）。
        return 1;
    }
    if retry_count >= 12 {
        // 2^12 = 4096 > 3600，提前封顶避免 i64 溢出（12 次后全部封顶）。
        return MAX_BACKOFF;
    }
    let val = 1i64 << retry_count; // 2^retry_count
    if val < MAX_BACKOFF { val } else { MAX_BACKOFF }
}

// ── 单测 ──────────────────────────────────────────────────────────────────────

#[cfg(any(
    all(test, feature = "integration"),
    feature = "fault-matrix-test-support"
))]
impl PgOutbox {
    async fn observed_published_settlement_outcome(
        &self,
        claimed: &PgClaimedOutboxEntry,
    ) -> Result<&'static str, EngineError> {
        match settlement::published(&self.tenant_pool, claimed, self.relay_budget).await? {
            settlement::Settlement::Settled((), _) => Ok("settled"),
            settlement::Settlement::Expired(_) => Ok("expired"),
            settlement::Settlement::LostLease(_) => Ok("lost_lease"),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn test_published_settlement_outcome(
        &self,
        claimed: &PgClaimedOutboxEntry,
    ) -> Result<&'static str, EngineError> {
        self.observed_published_settlement_outcome(claimed).await
    }

    #[cfg(feature = "fault-matrix-test-support")]
    pub(crate) async fn fault_matrix_published_settlement_outcome(
        &self,
        claimed: &PgClaimedOutboxEntry,
    ) -> Result<&'static str, EngineError> {
        self.observed_published_settlement_outcome(claimed).await
    }

    #[cfg(feature = "fault-matrix-test-support")]
    pub(crate) async fn fault_matrix_persisted_deadline_settlement_evidence(
        &self,
        claimed: &PgClaimedOutboxEntry,
    ) -> Result<FaultMatrixPublishedSettlementEvidence, EngineError> {
        let outcome = settlement::published(&self.tenant_pool, claimed, self.relay_budget).await?;
        let sql_deadline_was_bound = claimed.fault_matrix_sql_deadline_was_bound();
        Ok(match outcome {
            settlement::Settlement::Settled((), _) => {
                FaultMatrixPublishedSettlementEvidence::Settled
            }
            settlement::Settlement::Expired(_) if sql_deadline_was_bound => {
                FaultMatrixPublishedSettlementEvidence::PersistedDeadlineExpired
            }
            settlement::Settlement::Expired(_) => {
                FaultMatrixPublishedSettlementEvidence::LocalDeadlineExpired
            }
            settlement::Settlement::LostLease(_) => {
                FaultMatrixPublishedSettlementEvidence::LostLease
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    // reserved key / subject key 常量来自 diport 单源（#1160 A4）。
    use super::{
        AppendFingerprintObservation, CanonicalOutboxFact, ClaimHydrationError, ClaimedOutboxRow,
        MAX_PUBLISH_ATTEMPTS, OUTBOX_CLAIM_BATCH_MAX, OutboxAppendError, OutboxEnvelope,
        OutboxLease, OutboxLeaseError, OutboxMetadata, OutboxWriteEntry, PublishPreflight,
        RelayEnvelopeValidationReason, RelayPublishFailure, STATUS_ABANDONED, STATUS_PENDING,
        STATUS_PUBLISHED, STATUS_PUBLISHING, apply_schema_headers_from_columns, backoff_seconds,
        classify_append_fingerprint, dlx_decision, hydrate_claimed_outbox_row,
        hydrate_envelope_metadata, metadata_with_ambient, publish_request,
        record_relay_envelope_validation_failure, unix_secs, validate_publish_request_envelope,
        with_publisher_watchdog,
    };
    use diport::{
        EnvelopeMetadata, EnvelopeSubjectId, KEY_ACTOR, KEY_CORRELATION, KEY_OCCURRED_AT,
        KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION, KEY_TENANT_ID, KEY_TRACE, MessageId, MetadataError,
        OpaqueActorId, OutboxActor, PublishErrorKind, PublishRequest, PublisherError,
        RESERVED_METADATA_KEYS, Topic as PublishTopic,
    };

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const LEGACY_MIGRATION_LEASE_TTL_SECONDS: i64 = 60;

    fn valid_claimed_row() -> ClaimedOutboxRow {
        ClaimedOutboxRow {
            tenant_id: TENANT.to_string(),
            contract_id: "identity.session-created".to_string(),
            topic: "identity.session-created".to_string(),
            event_id: "evt-opaque-claim".to_string(),
            payload: b"SECRET_CLAIM_PAYLOAD".to_vec(),
            retry_count: 2,
            metadata: r#"{"trace":"SECRET_CLAIM_METADATA"}"#.to_string(),
            domain: "identity".to_string(),
            contract_version: "v1".to_string(),
            schema_hash: HASH.to_string(),
            claimed_at_epoch_seconds: 1_700_000_000,
            lease_token: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            deadline_epoch_micros: 1_700_000_060_000_000,
        }
    }

    #[allow(clippy::expect_used)]
    fn relay_budget() -> eventexec::RelayBudget {
        eventexec::RelayBudget::new(
            Duration::from_millis(20),
            Duration::from_millis(10),
            Duration::from_millis(3),
            Duration::from_millis(2),
        )
        .expect("valid test relay budget")
    }

    #[allow(clippy::expect_used)]
    fn test_provider_identity() -> Arc<super::OutboxProviderIdentity> {
        Arc::new(super::OutboxProviderIdentity {
            domain: vocab::DomainName::parse("identity").expect("valid test domain"),
        })
    }

    #[test]
    fn provider_lease_rejects_invalid_token_version_and_deadline() {
        assert!(matches!(
            OutboxLease::hydrate(
                "not-a-uuid".to_string(),
                1,
                super::io_deadline_after(Duration::from_secs(1))
            ),
            Err(OutboxLeaseError::Token)
        ));
        assert!(matches!(
            OutboxLease::hydrate(
                "f47ac10b-58cc-1372-a567-0e02b2c3d479".to_string(),
                1,
                super::io_deadline_after(Duration::from_secs(1))
            ),
            Err(OutboxLeaseError::TokenVersion)
        ));
        assert!(matches!(
            OutboxLease::hydrate(
                "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
                0,
                super::io_deadline_after(Duration::from_secs(1))
            ),
            Err(OutboxLeaseError::Deadline)
        ));
    }

    #[test]
    fn publish_preflight_discriminants_are_closed_and_fail_unknown() {
        assert_eq!(PublishPreflight::try_from(0), Ok(PublishPreflight::Allowed));
        assert_eq!(
            PublishPreflight::try_from(1),
            Ok(PublishPreflight::LostLease)
        );
        assert_eq!(
            PublishPreflight::try_from(2),
            Ok(PublishPreflight::AutomaticExpired)
        );
        assert_eq!(
            PublishPreflight::try_from(3),
            Ok(PublishPreflight::RedriveExpired)
        );
        assert!(PublishPreflight::try_from(-1).is_err());
        assert!(PublishPreflight::try_from(4).is_err());
    }

    const SETTLE_TIMEOUT_BRANCH_WIRINGS: [(&str, &str); 4] = [
        ("published", "settlement::published("),
        ("same_id_expiry_dlx", "settlement::same_id_expiry_dlx("),
        ("ordinary_dlx", "settlement::ordinary_dlx("),
        ("retry", "settlement::retry("),
    ];

    fn compact_production_outbox_source() -> String {
        include_str!("outbox.rs")
            .split("// ── 单测")
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect()
    }

    fn missing_settle_timeout_branches(source: &str) -> Vec<&'static str> {
        SETTLE_TIMEOUT_BRANCH_WIRINGS
            .into_iter()
            .filter_map(|(branch, exact_wiring)| {
                (source.matches(exact_wiring).count() != 1).then_some(branch)
            })
            .collect()
    }

    #[test]
    fn every_relay_settle_branch_has_exactly_one_timeout_wrapper() {
        let source = compact_production_outbox_source();
        assert_eq!(missing_settle_timeout_branches(&source), Vec::<&str>::new());
    }

    #[test]
    fn settle_timeout_branch_wiring_guard_has_synthetic_red_for_each_branch() {
        let source = compact_production_outbox_source();

        for (_, exact_wiring) in SETTLE_TIMEOUT_BRANCH_WIRINGS {
            let mutated = source.replacen(exact_wiring, "wrapper_removed", 1);
            assert_eq!(
                missing_settle_timeout_branches(&mutated).len(),
                1,
                "removing one relay settle wrapper must make the wiring guard red"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn local_publish_budget_requires_strictly_more_than_the_full_budget() {
        let budget = relay_budget();
        let now = crate::cotx::io_deadline_after(Duration::ZERO);
        assert!(!super::local_publish_budget_available(
            now + budget.required_budget(),
            budget,
        ));
        assert!(super::local_publish_budget_available(
            now + budget.required_budget() + Duration::from_millis(1),
            budget,
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn publisher_watchdog_uses_the_shared_absolute_deadline() {
        let budget = relay_budget();
        assert!(budget.publisher_watchdog_timeout() > budget.publish_timeout());
        let deadline = super::io_deadline_after(Duration::from_millis(15));
        tokio::time::advance(Duration::from_millis(6)).await;

        let result = with_publisher_watchdog(deadline, budget, async {
            std::future::pending::<()>().await;
            Ok(())
        })
        .await;

        assert!(matches!(result, Err(error) if error.is_ambiguous() && error.is_retryable()));
        assert_eq!(super::io_deadline_after(Duration::ZERO), deadline);
    }

    #[test]
    fn publisher_failure_reason_labels_are_closed_over_all_kinds() {
        let cases = [
            (
                PublisherError::transient(std::io::Error::other("transient")),
                "publisher_transient",
            ),
            (
                PublisherError::permanent(std::io::Error::other("permanent")),
                "publisher_permanent",
            ),
            (
                PublisherError::ambiguous(std::io::Error::other("ambiguous")),
                "publisher_ambiguous",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(
                RelayPublishFailure::Publisher(error).reason_label(),
                expected
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: fixed provider hydration fixture is valid by construction.
    fn provider_claim_hydration_is_complete_and_debug_redacted() {
        let claim = hydrate_claimed_outbox_row(
            valid_claimed_row(),
            &test_provider_identity(),
            super::io_deadline_after(Duration::from_secs(60)),
        )
        .expect("valid provider claim");
        assert_eq!(claim.subject().tenant_id(), tenant());
        assert_eq!(
            claim.subject().contract_id().as_str(),
            "identity.session-created"
        );
        assert_eq!(claim.idem_key().as_str(), "evt-opaque-claim");
        assert_eq!(claim.retry_count(), 2);
        assert_eq!(claim.domain().as_str(), "identity");
        assert_eq!(claim.contract_version(), "v1");
        assert_eq!(claim.schema_hash(), HASH);
        assert_eq!(claim.claimed_at_epoch_seconds(), 1_700_000_000);
        assert_eq!(claim.lease_deadline_epoch_micros(), 1_700_000_060_000_000);

        let debug = format!("{claim:?}");
        assert!(!debug.contains("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!debug.contains("1700000060000000"));
        assert!(!debug.contains("SECRET_CLAIM_PAYLOAD"));
        assert!(!debug.contains("SECRET_CLAIM_METADATA"));
    }

    #[test]
    fn provider_claim_hydration_reports_typed_failure_phase() {
        let mut row = valid_claimed_row();
        row.retry_count = -1;
        let error = hydrate_claimed_outbox_row(
            row,
            &test_provider_identity(),
            super::io_deadline_after(Duration::from_secs(60)),
        )
        .err();
        assert_eq!(error, Some(ClaimHydrationError::RetryCount));
        assert_eq!(error.map(ClaimHydrationError::phase), Some("retry_count"));
    }

    #[test]
    fn append_identity_failure_reasons_are_closed_and_payload_free() {
        let cases = [
            (
                OutboxAppendError::Conflict(consistency::OutboxFactConflict),
                Some("fact_conflict"),
            ),
            (OutboxAppendError::CanonicalDrift, Some("canonical_drift")),
            (
                OutboxAppendError::InvalidIdentity,
                Some("canonical_identity_invalid"),
            ),
            (OutboxAppendError::Storage(sqlx::Error::RowNotFound), None),
        ];
        for (error, expected) in cases {
            assert_eq!(error.identity_failure_reason(), expected);
        }
    }

    fn contract() -> vocab::ContractBinding {
        vocab::ContractBinding::from_static("identity", "identity.session-created", "v1", HASH)
    }

    #[allow(clippy::expect_used)]
    fn tenant() -> vocab::TenantId {
        vocab::TenantId::parse(TENANT).expect("canonical tenant")
    }

    fn metadata(occurred_at_secs: i64) -> OutboxMetadata {
        OutboxMetadata::new(occurred_at_secs, tenant(), contract())
    }

    #[allow(clippy::expect_used)]
    fn metric_subject() -> consistency::OutboxMetricSubject {
        consistency::OutboxMetricSubject::new(
            tenant(),
            consistency::OutboxContractId::parse("identity.session-created")
                .expect("valid contract id"),
        )
    }

    fn valid_publish_metadata() -> EnvelopeMetadata {
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_TENANT_ID, TENANT);
        md.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
        md.insert_wire_pair(KEY_SCHEMA_HASH, HASH);
        md
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn event_and_stored_entries_share_only_the_private_write_view() {
        let event = consistency::EventEntry::new(
            consistency::EventTopic::parse("identity.session-created").expect("event topic"),
            consistency::IdemKey::parse("event-entry-id").expect("event id"),
            consistency::OutboxPayload::from_reviewed_event_bytes(b"event".to_vec()),
        );
        assert_eq!(
            OutboxWriteEntry::topic_str(&event),
            "identity.session-created"
        );
        assert_eq!(OutboxWriteEntry::event_id(&event), "event-entry-id");
        assert_eq!(OutboxWriteEntry::payload(&event), b"event");

        let stored = consistency::StoredOutboxEntry::hydrate(
            "seed.commands.do-thing",
            consistency::IdemKey::parse("stored-entry-id").expect("stored id"),
            consistency::OutboxPayload::from_reviewed_event_bytes(b"stored".to_vec()),
        )
        .expect("stored command topic hydrates read-side entry");
        assert_eq!(
            OutboxWriteEntry::topic_str(&stored),
            "seed.commands.do-thing"
        );
        assert_eq!(OutboxWriteEntry::event_id(&stored), "stored-entry-id");
        assert_eq!(OutboxWriteEntry::payload(&stored), b"stored");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn append_fingerprint_classifier_is_single_and_exhaustive() {
        let entry = consistency::EventEntry::new(
            consistency::EventTopic::parse("identity.session-created").expect("event topic"),
            consistency::IdemKey::parse("classifier-event-id").expect("event id"),
            consistency::OutboxPayload::from_reviewed_event_bytes(b"payload".to_vec()),
        );
        let env = OutboxEnvelope::new(
            "identity".to_string(),
            "identity.session-created".to_string(),
            metadata(42),
        );
        let expected = CanonicalOutboxFact::from_entry_env(&entry, &env).fingerprint();
        let matching = expected.as_bytes();
        let mismatching = [0_u8; 32];

        assert_eq!(
            classify_append_fingerprint(
                expected,
                AppendFingerprintObservation::Inserted(matching),
            )
            .expect("matching inserted fingerprint"),
            consistency::OutboxAppendOutcome::Inserted
        );
        assert!(matches!(
            classify_append_fingerprint(
                expected,
                AppendFingerprintObservation::Inserted(&mismatching),
            ),
            Err(OutboxAppendError::CanonicalDrift)
        ));
        assert_eq!(
            classify_append_fingerprint(
                expected,
                AppendFingerprintObservation::Existing(Some(matching)),
            )
            .expect("matching existing fingerprint"),
            consistency::OutboxAppendOutcome::SameFact
        );
        for existing in [Some(mismatching.as_slice()), None] {
            assert!(matches!(
                classify_append_fingerprint(
                    expected,
                    AppendFingerprintObservation::Existing(existing),
                ),
                Err(OutboxAppendError::Conflict(_))
            ));
        }
    }

    #[allow(clippy::expect_used)]
    fn subject(raw: &str) -> EnvelopeSubjectId {
        EnvelopeSubjectId::from_opaque(raw).expect("valid envelope subject")
    }

    #[allow(clippy::expect_used)]
    fn actor(raw: &str) -> OutboxActor {
        OutboxActor::scoped(
            vocab::PrincipalKind::Admin,
            OpaqueActorId::from_opaque(raw).expect("valid actor id"),
            tenant(),
            vocab::ScopedTenant::Tenant,
        )
    }

    #[test]
    fn validate_publish_request_envelope_rejects_missing_schema_permanently() {
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_TENANT_ID, TENANT);
        let request = PublishRequest::new(
            PublishTopic::new("session.created"),
            MessageId::new("evt-missing-schema"),
            b"payload".to_vec(),
        )
        .with_metadata(md);

        let result = validate_publish_request_envelope(&request);
        assert!(
            result.is_err(),
            "missing schema header must be rejected before publish"
        );
        let Err(err) = result else {
            return;
        };
        assert_eq!(
            err.reason().as_label(),
            "envelope_missing_schema_version",
            "missing schema must carry a structured relay validation reason"
        );
    }

    #[test]
    fn validate_publish_request_envelope_accepts_standard_header() {
        let request = PublishRequest::new(
            PublishTopic::new("session.created"),
            MessageId::new("evt-standard-header"),
            b"payload".to_vec(),
        )
        .with_metadata(valid_publish_metadata());

        assert!(validate_publish_request_envelope(&request).is_ok());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn relay_publish_request_reuses_durable_identity_on_every_attempt() {
        let entry = consistency::StoredOutboxEntry::hydrate(
            "identity.session-created",
            consistency::IdemKey::parse("session-created-01").expect("valid event id"),
            consistency::OutboxPayload::from_reviewed_event_bytes(b"payload".to_vec()),
        )
        .expect("valid stored outbox entry");

        let first = publish_request(&entry, valid_publish_metadata());
        let retried = publish_request(&entry, valid_publish_metadata());

        assert_eq!(first.event_id().as_str(), entry.idem_key().as_str());
        assert_eq!(retried.event_id().as_str(), first.event_id().as_str());
        assert_eq!(retried.topic().as_str(), first.topic().as_str());
        assert_eq!(retried.payload(), first.payload());
    }

    #[test]
    fn relay_validation_failure_metric_emits_scope_and_reason_labels() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let subject = metric_subject();
        metrics::with_local_recorder(&recorder, || {
            record_relay_envelope_validation_failure(
                "identity",
                &subject,
                RelayEnvelopeValidationReason::MissingSchemaVersion,
            );
        });

        let rendered = handle.render();
        assert!(
            rendered.contains("outbox_relay_envelope_validation_failure_total"),
            "{rendered}"
        );
        assert!(rendered.contains(r#"domain="identity""#), "{rendered}");
        assert!(
            rendered.contains(r#"contract_id="identity.session-created""#),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!(r#"tenant_id="{TENANT}""#)),
            "{rendered}"
        );
        assert!(
            rendered.contains(r#"reason="envelope_missing_schema_version""#),
            "{rendered}"
        );
    }

    #[test]
    fn relay_schema_headers_from_columns_override_metadata() {
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_TENANT_ID, TENANT);
        md.insert_wire_pair(KEY_SCHEMA_VERSION, "v999");
        md.insert_wire_pair(
            KEY_SCHEMA_HASH,
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );

        apply_schema_headers_from_columns(
            &mut md,
            "v1",
            "sha256:999d2b098e6c89de6d1841416099942cad21279843456dfc287b1fcaa67a7516",
        );

        assert_eq!(md.get(KEY_SCHEMA_VERSION), Some("v1"));
        assert_eq!(
            md.get(KEY_SCHEMA_HASH),
            Some("sha256:999d2b098e6c89de6d1841416099942cad21279843456dfc287b1fcaa67a7516")
        );
    }

    // #1212/#1821 dlx 分流谓词表驱动：permanent 首投即 dlx；transient/ambiguous 仅预算耗尽
    // 才 dlx。anti-vacuity：两个 retryable kind 未到预算均返 false（仍以同一 event ID 退避）。
    #[test]
    fn dlx_decision_table() {
        let cases: &[(PublishErrorKind, i32, bool)] = &[
            (PublishErrorKind::Permanent, 1, true),
            (PublishErrorKind::Permanent, MAX_PUBLISH_ATTEMPTS, true),
            (PublishErrorKind::Transient, 1, false),
            (PublishErrorKind::Transient, MAX_PUBLISH_ATTEMPTS - 1, false),
            (PublishErrorKind::Transient, MAX_PUBLISH_ATTEMPTS, true),
            (PublishErrorKind::Ambiguous, 1, false),
            (PublishErrorKind::Ambiguous, MAX_PUBLISH_ATTEMPTS - 1, false),
            (PublishErrorKind::Ambiguous, MAX_PUBLISH_ATTEMPTS, true),
        ];
        for &(kind, new_count, want) in cases {
            assert_eq!(
                dlx_decision(kind, new_count),
                want,
                "dlx_decision(kind={kind:?}, new_count={new_count})"
            );
        }
    }

    // OutboxEnvelope 构造 + 字段访问（metadata 经 OutboxMetadata funnel，F1）。
    #[test]
    fn envelope_new_and_fields() -> Result<(), serde_json::Error> {
        use super::OutboxEnvelope;
        let env = OutboxEnvelope::new(
            "identity".to_string(),
            "contract-1".to_string(),
            metadata(1_700_000_000).with_subject_id(subject("tenant-42")),
        );
        assert_eq!(env.domain(), "identity");
        assert_eq!(env.contract_id(), "contract-1");
        assert_eq!(env.contract_version(), "v1");
        assert_eq!(env.schema_hash(), HASH);
        assert_eq!(env.causation_id(), None);
        let parsed = serde_json::from_str::<serde_json::Value>(&env.metadata_json())?;
        assert_eq!(
            parsed,
            serde_json::json!({
                "occurredAt": 1_700_000_000,
                "subjectId": "tenant-42",
                "tenantId": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "schemaVersion": "v1",
                "schemaHash": HASH,
            })
        );
        Ok(())
    }

    #[allow(clippy::expect_used)]
    #[test]
    fn envelope_causation_id_is_persisted_only_column_value() {
        let env = OutboxEnvelope::new(
            "identity".to_string(),
            "contract-1".to_string(),
            metadata(1_700_000_000).with_subject_id(subject("tenant-42")),
        )
        .with_causation_id_opt(Some(
            diport::EnvelopeCausationId::from_opaque("cause-evt-1").expect("opaque causation"),
        ));
        assert_eq!(env.causation_id(), Some("cause-evt-1"));
        assert!(
            !env.metadata_json().contains("cause-evt-1"),
            "causation_id persisted-only，不得写入 metadata: {}",
            env.metadata_json()
        );
    }

    // #262/#1618 F1：标准 header 构造期必填——`new(secs, tenant, contract)` 即含该 reserved key 集。
    #[test]
    fn metadata_new_always_carries_standard_header() -> Result<(), serde_json::Error> {
        use super::OutboxEnvelope;
        let env = OutboxEnvelope::new("d".to_string(), "c".to_string(), metadata(0));
        let parsed = serde_json::from_str::<serde_json::Value>(&env.metadata_json())?;
        assert_eq!(
            parsed,
            serde_json::json!({
                "occurredAt": 0,
                "tenantId": TENANT,
                "schemaVersion": "v1",
                "schemaHash": HASH,
            })
        );
        Ok(())
    }

    // F1 负向（anti-vacuity，INVARIANT OUTBOX-METADATA-FUNNEL-01）：reserved key 经 try_insert
    // fail-closed 拒；非 reserved key 接受并经 funnel 序列化（occurredAt 由 new 构造期注入）。
    #[test]
    fn metadata_try_insert_rejects_reserved_key() -> serde_json::Result<()> {
        for reserved in RESERVED_METADATA_KEYS {
            let mut m = metadata(0);
            assert_eq!(
                m.try_insert(reserved, serde_json::Value::Bool(true)),
                Err(MetadataError::ReservedKey),
                "reserved key must be rejected: {reserved}"
            );
        }
        let mut ok = metadata(0);
        assert!(
            ok.try_insert("tenantTier", serde_json::Value::String("gold".into()))
                .is_ok()
        );
        let env = super::OutboxEnvelope::new("d".to_string(), "c".to_string(), ok);
        let parsed = serde_json::from_str::<serde_json::Value>(&env.metadata_json())?;
        assert_eq!(parsed["occurredAt"], 0);
        assert_eq!(parsed["tenantId"], TENANT);
        assert_eq!(parsed["schemaVersion"], "v1");
        assert_eq!(parsed["schemaHash"], HASH);
        assert_eq!(parsed["tenantTier"], "gold");
        Ok(())
    }

    // #1129/#262 F1：new(secs) 构造期注入 reserved occurredAt（unix 秒 i64）；opaque subjectId 共存。
    // 本测试走**直接** new()+with_subject_id 路径（非 metadata_with_ambient）：trace（#1224 经
    // tracewire::capture_current 注入）/ correlation（#1160 经 diagctx 注入）/ principal（待 #1397）都只在 ambient
    // helper 路径盖章，故此直接构造路径不含——验证 new 的最小接缝不夹带 ambient reserved key。
    #[test]
    fn metadata_new_writes_occurred_at_unix_secs() {
        let env = super::OutboxEnvelope::new(
            "identity".to_string(),
            "c".to_string(),
            metadata(1_700_000_000).with_subject_id(subject("subj-1")),
        );
        let json = env.metadata_json();
        assert!(
            json.contains(r#""occurredAt":1700000000"#),
            "occurredAt 应以 unix 秒 i64 写入: {json}"
        );
        assert!(
            json.contains(r#""subjectId":"subj-1""#),
            "opaque subjectId 应共存: {json}"
        );
        for absent in ["trace", "correlation", "principal"] {
            assert!(
                !json.contains(absent),
                "此路径（new+with_subject_id，非 metadata_with_ambient）不盖章 ambient reserved key {absent}: {json}"
            );
        }
    }

    // #1129/#262 anti-vacuity：构造期 new 注入 occurred_at，而业务 free-form try_insert 对同名 reserved key
    // 仍 fail-closed 拒——构造期注入与业务写入两路径互斥，业务侧不可伪造 reserved。
    #[test]
    fn occurred_at_construct_writes_but_free_form_rejects() {
        // 构造期注入成功。
        let sealed = metadata(42);
        let env = super::OutboxEnvelope::new("d".to_string(), "c".to_string(), sealed);
        assert!(env.metadata_json().contains(r#""occurredAt":42"#));
        // 业务 free-form 路径仍拒同名 reserved key。
        let mut free = metadata(0);
        assert_eq!(
            free.try_insert(KEY_OCCURRED_AT, serde_json::Value::from(42)),
            Err(MetadataError::ReservedKey),
            "业务 free-form 路径不得写 reserved occurred_at"
        );
    }

    // #1129 drift-lock：构造期注入的 occurred_at key 必属 reserved 集（注入集 ⊆ 拒绝集，防漂移）。
    #[test]
    fn occurred_at_key_is_reserved() {
        assert!(
            RESERVED_METADATA_KEYS.contains(&KEY_OCCURRED_AT),
            "new 写的 occurred_at key 必须在 RESERVED_METADATA_KEYS 内"
        );
    }

    // #1193 正向：sealed setter with_trace / with_correlation 写入对应 reserved key（funnel 特权），
    // 与 occurred_at / subjectId 共存。键序 order-independent 断言——`serde_json::Map` 序列化次序随
    // `preserve_order` feature 变（workspace 统一 on=插入序 / 隔离 off=字母序），故逐 key-value 子串校验。
    #[test]
    fn sealed_setters_write_reserved_keys() -> Result<(), serde_json::Error> {
        let env = super::OutboxEnvelope::new(
            "identity".to_string(),
            "identity.session-created".to_string(),
            metadata(1_700_000_000)
                .with_subject_id(subject("subj-1"))
                .with_actor(actor("actor-1"))
                .with_trace("trace-abc")
                .with_correlation("corr-xyz"),
        );
        let json = env.metadata_json();
        for kv in [
            r#""occurredAt":1700000000"#,
            r#""subjectId":"subj-1""#,
            r#""trace":"trace-abc""#,
            r#""correlation":"corr-xyz""#,
            r#""schemaVersion":"v1""#,
        ] {
            assert!(
                json.contains(kv),
                "sealed setter metadata 应含 {kv}: {json}"
            );
        }
        assert!(json.contains(HASH), "schemaHash 应存在: {json}");
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(parsed["actor"]["kind"], "admin");
        assert_eq!(parsed["actor"]["id"], "actor-1");
        assert_eq!(parsed["actor"]["scope"], "tenant");
        assert_eq!(parsed["actor"]["tenantId"], TENANT);
        Ok(())
    }

    // #1193 anti-vacuity：sealed setter 注入成功，而业务 free-form try_insert 对同名 reserved key 仍
    // fail-closed 拒——两路径互斥，业务侧不可伪造 trace / correlation。
    #[test]
    fn sealed_setter_keys_rejected_on_free_form() {
        for reserved in [KEY_TRACE, KEY_CORRELATION] {
            let mut free = metadata(0);
            assert_eq!(
                free.try_insert(reserved, serde_json::Value::String("x".into())),
                Err(MetadataError::ReservedKey),
                "业务 free-form 路径不得写 reserved {reserved}"
            );
        }
    }

    // #1193 drift-lock：sealed setter 注入的 trace / correlation key 必属 reserved 集（注入集 ⊆ 拒绝集）。
    #[test]
    fn reserved_setter_keys_are_reserved() {
        for key in [
            KEY_TRACE,
            KEY_CORRELATION,
            KEY_ACTOR,
            KEY_SCHEMA_VERSION,
            KEY_SCHEMA_HASH,
        ] {
            assert!(
                RESERVED_METADATA_KEYS.contains(&key),
                "sealed setter 写的 {key} 必须在 RESERVED_METADATA_KEYS 内"
            );
        }
    }

    // #1129 unix_secs 边界收口（从 auth_grant_lifecycle 合并入本 crate 单源）：正常偏移直映。
    #[test]
    fn unix_secs_maps_offset() {
        let t = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        assert_eq!(unix_secs(t), 1_700_000_000);
    }

    // 负偏移（早于 epoch，时钟偏斜）：duration_since 返回 Err → 收口 0（不 panic、不返负）。
    #[test]
    fn unix_secs_clamps_before_epoch_to_zero() {
        let t = std::time::SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(1);
        assert_eq!(unix_secs(t), 0);
    }

    // 常量合理值（MAX_PUBLISH_ATTEMPTS > 0；legacy migration TTL > 0）——编译期常量断言。
    #[test]
    fn constants_sane() {
        const { assert!(MAX_PUBLISH_ATTEMPTS > 0) };
        const { assert!(LEGACY_MIGRATION_LEASE_TTL_SECONDS > 0) };
    }

    // F8 anti-vacuity：解析 forward migration 的最终 `CHECK (status IN (...))` 子句，断言与生产 const 集同源
    // （SQL 全经 .bind(STATUS_*)，此测试守 const ↔ migration 不漂移；两处任一改动不同步即红）。
    // 集合相等比较隐式覆盖「四常量互异」——migration 四值互异，若两常量重复则集合不等而失败。
    #[test]
    #[allow(clippy::expect_used)]
    // reason: 测试解析编译期 include_str! 的已知 migration 文本，CHECK 子句缺失即应 fail（测试本身的断言），
    // item-level carve-out（error-handling.md §Carve-out）。
    fn status_consts_match_migration_check() {
        const MIGRATION: &str =
            include_str!("../migrations/0060_bound_same_id_delivery_window.sql");
        let in_pos = MIGRATION
            .find("status IN (")
            .expect("migration must declare status CHECK IN clause");
        let rest = &MIGRATION[in_pos..];
        let open = rest.find('(').expect("IN clause needs '('");
        let close = rest.find(')').expect("IN clause needs ')'");
        let mut migration_values: Vec<&str> = rest[open + 1..close]
            .split(',')
            .map(|s| s.trim().trim_matches('\''))
            .collect();
        migration_values.sort_unstable();
        let mut const_values = [
            STATUS_PENDING,
            STATUS_PUBLISHING,
            STATUS_PUBLISHED,
            "dlx",
            STATUS_ABANDONED,
        ];
        const_values.sort_unstable();
        assert_eq!(
            migration_values, const_values,
            "outbox status const 集与 migration 0060 CHECK 漂移"
        );
    }

    #[test]
    fn outbox_definer_migration_matches_status_and_lease_consts() {
        const MIGRATION: &str = include_str!("../migrations/0031_harden_outbox_tenant_scope.sql");
        const MIGRATION_0036: &str =
            include_str!("../migrations/0036_add_outbox_schema_columns.sql");
        const MIGRATION_0037: &str =
            include_str!("../migrations/0037_outbox_metric_scope_functions.sql");
        const MIGRATION_0047: &str =
            include_str!("../migrations/0047_outbox_partition_blocked_metric.sql");
        let ttl = format!("make_interval(secs => {LEGACY_MIGRATION_LEASE_TTL_SECONDS})");
        assert_eq!(
            MIGRATION.matches(&ttl).count(),
            3,
            "0031 definer SQL must use the Rust lease TTL constant everywhere"
        );
        for status in [STATUS_PENDING, STATUS_PUBLISHING, STATUS_PUBLISHED, "dlx"] {
            assert!(
                MIGRATION.contains(&format!("'{status}'")),
                "0031 definer SQL must reference status literal {status}"
            );
        }
        for needle in [
            "RETURNS TABLE(\n    retry_count int,\n    lease_token text,\n    tenant_id text",
            "RETURNS TABLE(tenant_id text, domain text",
            "CREATE OR REPLACE FUNCTION rss_outbox_redrive(p_event_id text, p_tenant_id uuid)",
            "rss_outbox_poll_pending poll limit must be in range [1, 10000]",
            "RAISE EXCEPTION 'rss_sweep_outbox_published retain seconds must be non-negative'",
            "outbox_metadata_tenant_matches",
        ] {
            assert!(MIGRATION.contains(needle), "0031 drift: missing {needle}");
        }
        for needle in [
            "ALTER TABLE outbox ADD COLUMN contract_version text",
            "ALTER TABLE outbox ADD COLUMN schema_hash text",
            "ALTER TABLE outbox ADD COLUMN causation_id text",
            "outbox_contract_version_valid",
            "outbox_schema_hash_valid",
            "outbox_causation_id_valid",
            "outbox_metadata_schema_matches_columns",
            "CREATE INDEX idx_outbox_contract_schema",
            "DROP FUNCTION IF EXISTS rss_outbox_acquire_lease(text)",
            "DROP FUNCTION IF EXISTS rss_outbox_mark_dlx(text, int, uuid)",
            "contract_version text,\n    schema_hash text,\n    now_epoch bigint",
            "metadata text,\n    contract_version text,\n    schema_hash text",
            "ALTER FUNCTION rss_outbox_acquire_lease(text) OWNER TO rss_outbox_maintenance",
            "ALTER FUNCTION rss_outbox_mark_dlx(text, int, uuid) OWNER TO rss_outbox_maintenance",
            "GRANT EXECUTE ON FUNCTION rss_outbox_acquire_lease(text) TO rss_app",
            "GRANT EXECUTE ON FUNCTION rss_outbox_mark_dlx(text, int, uuid) TO rss_app",
        ] {
            assert!(
                MIGRATION_0036.contains(needle),
                "0036 drift: missing {needle}"
            );
        }
        assert_eq!(
            MIGRATION_0037.matches(&ttl).count(),
            2,
            "0037 poll/backlog SQL must use the Rust lease TTL constant everywhere"
        );
        for needle in [
            "DROP FUNCTION IF EXISTS rss_outbox_poll_pending(text, bigint)",
            "RETURNS TABLE(tenant_id text, contract_id text, topic text, event_id text, payload bytea)",
            "DROP FUNCTION IF EXISTS rss_outbox_sample_backlog(text)",
            "RETURNS TABLE(tenant_id text, contract_id text, depth bigint, oldest_age_seconds bigint)",
            "count(*) FILTER (WHERE is_backlog)::bigint AS depth",
            "GROUP BY tenant_id, contract_id",
            "GRANT EXECUTE ON FUNCTION rss_outbox_poll_pending(text, bigint) TO rss_app",
            "GRANT EXECUTE ON FUNCTION rss_outbox_sample_backlog(text) TO rss_app",
        ] {
            assert!(
                MIGRATION_0037.contains(needle),
                "0037 drift: missing {needle}"
            );
        }
        assert_eq!(
            MIGRATION_0047.matches(&ttl).count(),
            1,
            "0047 sample_backlog SQL must use the Rust lease TTL constant"
        );
        for needle in [
            "DROP FUNCTION IF EXISTS rss_outbox_sample_backlog(text)",
            "partition_blocked_depth bigint",
            "b.status <> 'published'",
            "count(*) FILTER (WHERE is_partition_blocked)::bigint AS partition_blocked_depth",
            "GRANT EXECUTE ON FUNCTION rss_outbox_sample_backlog(text) TO rss_app",
        ] {
            assert!(
                MIGRATION_0047.contains(needle),
                "0047 drift: missing {needle}"
            );
        }
    }

    #[test]
    fn outbox_terminal_timestamp_migration_locks_schema_and_transitions() {
        const MIGRATION: &str =
            include_str!("../migrations/0056_add_outbox_terminal_timestamps.sql");
        for needle in [
            "SET LOCAL lock_timeout = '5s'",
            "SET LOCAL statement_timeout = '5min'",
            "pg_total_relation_size('outbox'::regclass) > 10737418240",
            "outbox exceeds 10 GiB terminal timestamp migration capacity limit",
            "ALTER TABLE outbox ADD COLUMN published_at timestamptz",
            "ALTER TABLE outbox ADD COLUMN dlx_at timestamptz",
            "published_at = CASE WHEN status = 'published' THEN updated_at ELSE NULL END",
            "dlx_at = CASE WHEN status = 'dlx' THEN updated_at ELSE NULL END",
            "WHERE status IN ('published', 'dlx')",
            "CONSTRAINT outbox_published_at_matches_status",
            "CHECK ((status = 'published') = (published_at IS NOT NULL))",
            "CONSTRAINT outbox_dlx_at_matches_status",
            "CHECK ((status = 'dlx') = (dlx_at IS NOT NULL))",
            "ON outbox (published_at)\n    WHERE status = 'published'",
            "SET status = 'published',\n        published_at = now(),\n        dlx_at = NULL",
            "SET status = 'dlx',\n        retry_count = p_retry_count,\n        published_at = NULL,\n        dlx_at = now()",
            "lease_token = NULL,\n        published_at = NULL,\n        dlx_at = NULL",
            "IF p_retain_seconds IS NULL OR p_retain_seconds <= 0 THEN",
            "published_at <= now() - make_interval",
        ] {
            assert!(MIGRATION.contains(needle), "0056 drift: missing {needle}");
        }
        let sweep_marker = "CREATE OR REPLACE FUNCTION rss_sweep_outbox_published";
        assert!(MIGRATION.contains(sweep_marker));
        let current_sweep = MIGRATION.rsplit(sweep_marker).next().unwrap_or_default();
        assert!(
            !current_sweep.contains("created_at"),
            "0056 current sweeper must not retain the legacy created_at predicate"
        );
    }

    #[test]
    fn outbox_terminal_timestamp_migration_restores_function_privileges() {
        const MIGRATION: &str =
            include_str!("../migrations/0056_add_outbox_terminal_timestamps.sql");
        for signature in [
            "rss_outbox_settle_published(text, uuid)",
            "rss_outbox_mark_dlx(text, int, uuid)",
            "rss_outbox_redrive(text, uuid)",
            "rss_sweep_outbox_published(bigint)",
        ] {
            assert!(
                MIGRATION.contains(&format!(
                    "ALTER FUNCTION {signature} OWNER TO rss_outbox_maintenance"
                )),
                "0056 must restore owner for {signature}"
            );
            assert!(
                MIGRATION.contains(&format!("REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")),
                "0056 must revoke PUBLIC for {signature}"
            );
            assert!(
                MIGRATION.contains(&format!("GRANT EXECUTE ON FUNCTION {signature} TO rss_app")),
                "0056 must grant rss_app execute for {signature}"
            );
        }
    }

    #[test]
    fn atomic_claim_migration_is_deadline_fenced_and_breaking() {
        const MIGRATION: &str = include_str!("../migrations/0057_atomic_outbox_claim.sql");
        for needle in [
            "SET LOCAL lock_timeout = '5s'",
            "SET LOCAL statement_timeout = '5min'",
            "pg_total_relation_size('outbox'::regclass) > 10737418240",
            "ALTER TABLE outbox ADD COLUMN lease_until timestamptz",
            "publishing outbox rows must have lease_token before atomic claim migration",
            "lease_until = updated_at + make_interval(secs => 60)",
            "CONSTRAINT outbox_lease_token_matches_status",
            "CONSTRAINT outbox_lease_deadline_matches_status",
            "CONSTRAINT outbox_lease_deadline_after_claim",
            "CONSTRAINT outbox_retry_count_nonnegative",
            "ON outbox (domain, lease_until)",
            "DROP FUNCTION IF EXISTS rss_outbox_poll_pending(text, bigint)",
            "DROP FUNCTION IF EXISTS rss_outbox_acquire_lease(text)",
            "CREATE FUNCTION rss_outbox_claim_batch(p_domain text, p_limit bigint)",
            "CREATE FUNCTION rss_outbox_lease_can_publish(",
            "o.lease_until > clock_timestamp() + interval '50 seconds'",
            "FOR UPDATE OF o SKIP LOCKED",
            "ORDER BY claimed.seq",
            "deadline_epoch_micros bigint",
            "lease_until > settled_at",
            "retry_count = o.retry_count + 1",
            "WHEN o.retry_count >= 12 THEN 3600::double precision",
            "ELSE (1::bigint << o.retry_count)::double precision",
            "status = 'publishing' AND o.lease_until <= claim_clock.claimed_at",
            "status = 'publishing' AND o.lease_until <= sample_clock.sampled_at",
        ] {
            assert!(MIGRATION.contains(needle), "0057 drift: missing {needle}");
        }

        for legacy_signature in [
            "rss_outbox_settle_published(text, uuid)",
            "rss_outbox_settle_retry(text, int, bigint, uuid)",
            "rss_outbox_settle_retry(text, int, bigint, uuid, bigint)",
            "rss_outbox_settle_retry(text, bigint, uuid, bigint)",
            "rss_outbox_mark_dlx(text, int, uuid)",
            "rss_outbox_mark_dlx(text, int, uuid, bigint)",
        ] {
            assert!(
                MIGRATION.contains(&format!("DROP FUNCTION IF EXISTS {legacy_signature}")),
                "0057 must remove legacy overload {legacy_signature}"
            );
        }
        assert_eq!(
            MIGRATION
                .matches("WITH claim_clock AS MATERIALIZED")
                .count(),
            1,
            "claim must use one materialized database clock"
        );
        assert!(MIGRATION.contains(&format!(
            "p_limit < 1 OR p_limit > {OUTBOX_CLAIM_BATCH_MAX}"
        )));
        assert_eq!(
            MIGRATION.matches("INTO locked_id").count(),
            3,
            "all settle functions must identify and lock their exact lease row"
        );
        assert_eq!(
            MIGRATION.matches("FOR UPDATE OF o;").count(),
            3,
            "all settle functions must acquire the row lock before taking the clock"
        );
        assert_eq!(
            MIGRATION
                .matches("settled_at := clock_timestamp();")
                .count(),
            3,
            "all settle functions must take their deadline clock after the row lock"
        );
        assert_eq!(
            MIGRATION.matches("SET lock_timeout = '5s'").count(),
            3,
            "all settle functions must bound row-lock waits"
        );
    }

    #[test]
    fn atomic_claim_migration_restores_least_privilege_surface() {
        const MIGRATION: &str = include_str!("../migrations/0057_atomic_outbox_claim.sql");
        for signature in [
            "rss_outbox_claim_batch(text, bigint)",
            "rss_outbox_lease_can_publish(text, uuid, bigint)",
            "rss_outbox_settle_published(text, uuid, bigint)",
            "rss_outbox_settle_retry(text, uuid, bigint)",
            "rss_outbox_mark_dlx(text, uuid, bigint)",
            "rss_outbox_redrive(text, uuid)",
            "rss_outbox_sample_backlog(text)",
        ] {
            assert!(
                MIGRATION.contains(&format!(
                    "ALTER FUNCTION {signature} OWNER TO rss_outbox_maintenance"
                )),
                "0057 must restore owner for {signature}"
            );
            assert!(
                MIGRATION.contains(&format!("REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")),
                "0057 must revoke PUBLIC for {signature}"
            );
            assert!(
                MIGRATION.contains(&format!("GRANT EXECUTE ON FUNCTION {signature} TO rss_app")),
                "0057 must grant rss_app execute for {signature}"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: static migration-contract test must fail loudly when the reviewed SQL shape drifts.
    fn same_id_delivery_window_migration_is_breaking_and_fail_closed() {
        const MIGRATION: &str =
            include_str!("../migrations/0060_bound_same_id_delivery_window.sql");
        for needle in [
            "CREATE TABLE event_delivery_policy",
            "automatic_retry_window_seconds bigint NOT NULL",
            "same_id_redrive_horizon_seconds bigint NOT NULL",
            "safety_margin_seconds bigint NOT NULL",
            "inbox_receipt_retention_seconds bigint NOT NULL",
            "same_id_delivery_phase text NOT NULL DEFAULT 'automatic'",
            "automatic_retry_deadline timestamptz",
            "same_id_redrive_deadline timestamptz",
            "abandoned_at timestamptz",
            "CREATE TABLE outbox_expired_resolutions",
            "CREATE FUNCTION rss_outbox_resolve_expired(",
            "status IN ('pending', 'publishing', 'published', 'dlx', 'abandoned')",
            "CREATE FUNCTION rss_outbox_publish_preflight(",
            "CREATE FUNCTION rss_sweep_inbox_receipts()",
            "DROP FUNCTION rss_outbox_lease_can_publish(text, uuid, bigint)",
            "DROP FUNCTION rss_sweep_inbox_receipts(bigint)",
            "REVOKE ALL ON FUNCTION rss_outbox_redrive(text, uuid) FROM rss_app",
            "REVOKE INSERT ON outbox FROM rss_app",
            "GRANT INSERT (",
        ] {
            assert!(MIGRATION.contains(needle), "0060 drift: missing {needle}");
        }
        let (_, column_grant_tail) = MIGRATION
            .split_once("GRANT INSERT (")
            .expect("0060 must replace broad INSERT with a column grant");
        let (column_grant, _) = column_grant_tail
            .split_once(") ON outbox TO rss_app;")
            .expect("0060 column grant must target rss_app outbox INSERT");
        for fact_column in [
            "event_id",
            "tenant_id",
            "domain",
            "topic",
            "contract_id",
            "contract_version",
            "schema_hash",
            "payload",
            "metadata",
            "partition_key",
            "causation_id",
        ] {
            assert!(
                column_grant.lines().any(|line| {
                    line.trim()
                        .trim_end_matches(',')
                        .eq_ignore_ascii_case(fact_column)
                }),
                "0060 must grant the immutable fact column {fact_column}"
            );
        }
        for state_column in [
            "status",
            "same_id_delivery_phase",
            "automatic_retry_deadline",
            "same_id_redrive_deadline",
            "abandoned_at",
            "retry_count",
            "retry_after",
            "lease_token",
            "lease_until",
            "published_at",
            "dlx_at",
            "created_at",
            "updated_at",
        ] {
            assert!(
                !column_grant.lines().any(|line| {
                    line.trim()
                        .trim_end_matches(',')
                        .eq_ignore_ascii_case(state_column)
                }),
                "0060 must keep database-owned column {state_column} out of the app grant"
            );
        }
        assert!(
            !MIGRATION
                .contains("GRANT EXECUTE ON FUNCTION rss_outbox_redrive(text, uuid) TO rss_app"),
            "serving rss_app must not retain the operator redrive capability"
        );
        const VALIDATION: &str =
            include_str!("../migrations/0061_validate_same_id_delivery_constraints.sql");
        assert_eq!(VALIDATION.matches("ALTER TABLE outbox").count(), 1);
        assert_eq!(VALIDATION.matches("VALIDATE CONSTRAINT").count(), 1);
        assert!(VALIDATION.contains("VALIDATE CONSTRAINT outbox_same_id_state_valid"));
    }

    #[test]
    fn l2_dr_recovery_migration_is_single_receipt_atomic_and_function_only() {
        const MIGRATION: &str = include_str!("../migrations/0100_install_l2_dr_recovery.sql");
        for needle in [
            "CREATE TABLE public.event_l2_dr_recovery_receipt",
            "ALTER TABLE public.event_l2_dr_recovery_receipt ENABLE ROW LEVEL SECURITY",
            "ALTER TABLE public.event_l2_dr_recovery_receipt FORCE ROW LEVEL SECURITY",
            "CREATE FUNCTION public.rss_l2_dr_recovery_apply(",
            "CREATE FUNCTION public.rss_l2_dr_recovery_record_start_audit(",
            "CREATE FUNCTION public.rss_l2_dr_recovery_record_finish_audit(",
            "status = 'published'",
            "same_id_delivery_phase = 'redrive'",
            "same_id_redrive_deadline = COALESCE(",
            "LEAST(",
            "automatic_retry_deadline",
            "published_at",
            "GRANT EXECUTE ON FUNCTION public.rss_l2_dr_recovery_apply(",
            "TO rss_l2_dr_recovery_executor",
            "TO rss_l2_dr_recovery_auditor",
            "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM",
            "REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM",
            "rss_l2_dr_recovery_auditor, rss_l2_dr_recovery_executor;",
            "GRANT SELECT ON TABLE public.event_l2_dr_recovery_receipt TO rss_app_read",
            "pg_advisory_xact_lock",
            ") UNIQUE",
            "'sha256:' || pg_catalog.encode(p_plan_digest, 'hex')",
        ] {
            assert!(MIGRATION.contains(needle), "0098 drift: missing {needle}");
        }
        assert_eq!(
            MIGRATION
                .matches("CREATE TABLE public.event_l2_dr_recovery_receipt")
                .count(),
            1,
            "recovery keeps one immutable receipt relation instead of plan/result mirrors"
        );
        assert!(!MIGRATION.contains("now() +"));
        assert!(!MIGRATION.contains("clock_timestamp() +"));
        assert!(!MIGRATION.contains("GRANT UPDATE"));
        assert!(!MIGRATION.contains("GRANT DELETE"));
        assert!(!MIGRATION.contains("TO rss_app;"));
        assert!(!MIGRATION.contains("rss_l2_dr_recovery_operator"));
        assert!(!MIGRATION.contains("UPDATE public.inbox_receipts"));
        assert!(!MIGRATION.contains("DELETE FROM public.inbox_receipts"));
    }

    #[test]
    fn relay_budget_migration_is_parameterized_breaking_and_least_privilege() {
        const MIGRATION: &str =
            include_str!("../migrations/0064_parameterize_outbox_relay_budget.sql");

        for needle in [
            "DROP FUNCTION rss_outbox_claim_batch(text, bigint)",
            "DROP FUNCTION rss_outbox_publish_preflight(text, uuid, bigint)",
            "CREATE FUNCTION rss_outbox_claim_batch(",
            "p_lease_ttl_ms bigint",
            "p_required_budget_ms bigint",
            "CREATE FUNCTION rss_outbox_publish_preflight(",
            "p_required_budget_ms >= p_lease_ttl_ms",
            "p_lease_ttl_ms > 86400000 OR p_required_budget_ms > 86400000",
            "p_lease_ttl_ms * interval '1 millisecond'",
            "v_lease_until <= v_checked_at + p_required_budget_ms * interval '1 millisecond'",
        ] {
            assert!(MIGRATION.contains(needle), "0064 drift: missing {needle}");
        }

        for signature in [
            "rss_outbox_claim_batch(text, bigint, bigint, bigint)",
            "rss_outbox_publish_preflight(text, uuid, bigint, bigint, bigint)",
        ] {
            assert!(MIGRATION.contains(&format!(
                "ALTER FUNCTION {signature} OWNER TO rss_outbox_maintenance"
            )));
            assert!(MIGRATION.contains(&format!("REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")));
            assert!(
                MIGRATION.contains(&format!("GRANT EXECUTE ON FUNCTION {signature} TO rss_app"))
            );
        }
        assert!(!MIGRATION.contains("secs => 60"));
        assert!(!MIGRATION.contains("interval '50 seconds'"));
    }

    #[test]
    fn governed_relay_budget_migration_is_fail_closed_and_resets_settle_limits() {
        const MIGRATION: &str = include_str!("../migrations/0065_govern_outbox_relay_budget.sql");

        for needle in [
            "ALTER TABLE event_delivery_policy",
            "relay_budget_revision text NOT NULL",
            "relay_publish_timeout_ms::numeric",
            "< relay_lease_ttl_ms::numeric",
            "ALTER TABLE event_delivery_policy OWNER TO rss_outbox_maintenance",
            "REVOKE ALL ON event_delivery_policy FROM rss_app",
            "p_lease_ttl_ms <> v_lease_ttl_ms",
            "p_required_budget_ms <> v_required_budget_ms",
            "lease_until = eligible.claimed_at + v_lease_ttl_ms * interval '1 millisecond'",
            "v_lease_until <= v_checked_at + v_required_budget_ms * interval '1 millisecond'",
            "ALTER FUNCTION rss_outbox_settle_published(text, uuid, bigint) RESET lock_timeout",
            "ALTER FUNCTION rss_outbox_settle_retry(text, uuid, bigint) RESET lock_timeout",
            "ALTER FUNCTION rss_outbox_mark_dlx(text, uuid, bigint) RESET lock_timeout",
        ] {
            assert!(MIGRATION.contains(needle), "0065 drift: missing {needle}");
        }

        for signature in [
            "rss_outbox_claim_batch(text, bigint, bigint, bigint)",
            "rss_outbox_publish_preflight(text, uuid, bigint, bigint, bigint)",
        ] {
            assert!(MIGRATION.contains(&format!(
                "ALTER FUNCTION {signature} OWNER TO rss_outbox_maintenance"
            )));
            assert!(MIGRATION.contains(&format!("REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")));
            assert!(
                MIGRATION.contains(&format!("GRANT EXECUTE ON FUNCTION {signature} TO rss_app"))
            );
        }
        assert!(!MIGRATION.contains("p_lease_ttl_ms * interval '1 millisecond'"));
        assert!(!MIGRATION.contains("p_required_budget_ms * interval '1 millisecond'"));
    }

    #[test]
    fn sealed_settlement_migration_has_closed_type_and_least_privilege() {
        let migration = include_str!("../migrations/0066_seal_outbox_settlement_outcomes.sql");
        assert!(migration.contains(
            "CREATE TYPE rss_outbox_settlement_outcome AS ENUM ('settled', 'expired', 'lost_lease')"
        ));
        assert!(
            migration.contains(
                "ALTER TYPE rss_outbox_settlement_outcome OWNER TO rss_outbox_maintenance"
            )
        );
        assert!(migration.contains("REVOKE ALL ON TYPE rss_outbox_settlement_outcome FROM PUBLIC"));
        assert!(migration.contains("GRANT USAGE ON TYPE rss_outbox_settlement_outcome TO rss_app"));
    }

    #[test]
    fn sealed_settlement_migration_replaces_each_function_and_restores_acl() {
        let migration = include_str!("../migrations/0066_seal_outbox_settlement_outcomes.sql");
        for signature in [
            "rss_outbox_settle_published(text, uuid, bigint)",
            "rss_outbox_settle_retry(text, uuid, bigint)",
            "rss_outbox_mark_dlx(text, uuid, bigint)",
        ] {
            assert!(migration.contains(&format!("DROP FUNCTION {signature}")));
            assert!(migration.contains(&format!(
                "ALTER FUNCTION {signature} OWNER TO rss_outbox_maintenance"
            )));
            assert!(migration.contains(&format!("REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")));
            assert!(
                migration.contains(&format!("GRANT EXECUTE ON FUNCTION {signature} TO rss_app"))
            );
        }
    }

    #[test]
    fn sealed_settlement_migration_locks_before_clock_and_keeps_exact_cas() {
        let migration = include_str!("../migrations/0066_seal_outbox_settlement_outcomes.sql");
        assert_eq!(migration.matches("FOR UPDATE OF o").count(), 3);
        assert_eq!(
            migration
                .matches("v_settled_at := clock_timestamp()")
                .count(),
            3
        );
        assert_eq!(migration.matches("RETURN 'expired'").count(), 2);
        assert!(migration.contains("'expired'::rss_outbox_settlement_outcome"));
        assert_eq!(
            migration.matches("o.lease_token = p_lease_token").count(),
            6
        );
        assert_eq!(
            migration
                .matches("p_lease_deadline_epoch_micros * interval '1 microsecond'")
                .count(),
            6
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: static source-contract test must fail loudly when a production INSERT loses its fingerprint terminator.
    fn production_outbox_inserts_supply_fact_columns_only() {
        // Production INSERT funnels live in cotx/eventing.rs (generated + replayed).
        // fault_matrix / integration_tests seed INSERTs are out of scope for this scan.
        let source = include_str!("cotx/eventing.rs");
        let insert_start = ["INSERT INTO ", "outbox ("].concat();
        let insert_end = ["RETURNING fact_", "fingerprint"].concat();
        let blocks: Vec<&str> = source
            .match_indices(&insert_start)
            .map(|(start, _)| {
                let tail = &source[start..];
                let end = tail
                    .find(&insert_end)
                    .expect("every production outbox insert must return its fingerprint");
                &tail[..end]
            })
            .collect();
        assert_eq!(
            blocks.len(),
            2,
            "mutable and replay funnels must stay unique"
        );
        for block in blocks {
            for fact_column in [
                "event_id",
                "tenant_id",
                "domain",
                "topic",
                "contract_id",
                "contract_version",
                "schema_hash",
                "payload",
                "metadata",
                "partition_key",
                "causation_id",
            ] {
                assert!(
                    block.contains(fact_column),
                    "production INSERT must supply fact column {fact_column}: {block}"
                );
            }
            for state_column in [
                "status",
                "retry_count",
                "retry_after",
                "lease_token",
                "lease_until",
                "published_at",
                "dlx_at",
                "same_id_delivery_phase",
                "automatic_retry_deadline",
                "same_id_redrive_deadline",
            ] {
                assert!(
                    !block.contains(state_column),
                    "production INSERT must not forge DB-owned {state_column}: {block}"
                );
            }
        }
    }

    #[test]
    fn runtime_serving_migration_hardens_current_outbox_runtime_dml_to_functions() {
        const LEGACY_GRANTS: &str = include_str!("../migrations/0030_grant_runtime_serving.sql");
        const HARDENING: &str = include_str!("../migrations/0031_harden_outbox_tenant_scope.sql");
        assert!(
            LEGACY_GRANTS.contains("GRANT SELECT, INSERT, UPDATE, DELETE ON outbox TO rss_app"),
            "anti-vacuity: 0030 used to grant broad outbox DML"
        );
        assert!(
            HARDENING.contains("REVOKE UPDATE, DELETE ON outbox FROM rss_app")
                && HARDENING.contains("GRANT SELECT, INSERT ON outbox TO rss_app"),
            "0031 must narrow rss_app outbox table privileges"
        );
        for signature in [
            "rss_outbox_acquire_lease(text)",
            "rss_outbox_settle_published(text, uuid)",
            "rss_outbox_settle_retry(text, int, bigint, uuid)",
            "rss_outbox_mark_dlx(text, int, uuid)",
            "rss_outbox_redrive(text, uuid)",
            "rss_sweep_outbox_published(bigint)",
            "rss_outbox_sample_backlog(text)",
        ] {
            assert!(
                HARDENING.contains(&format!("GRANT EXECUTE ON FUNCTION {signature} TO rss_app")),
                "0031 must expose fixed function {signature} to rss_app"
            );
        }
        assert!(
            LEGACY_GRANTS.contains("ON dead_letter TO rss_app"),
            "anti-vacuity: runtime serving migration should still contain serving grants"
        );
    }

    // backoff_seconds 表驱动（指数 + 封顶 3600）。
    #[test]
    fn backoff_seconds_table() {
        let cases: &[(i32, i64)] = &[
            (-100, 1), // 负值防御：恒返 1（不 panic）
            (-1, 1),
            (0, 1),
            (1, 2),
            (2, 4),
            (3, 8),
            (4, 16),
            (5, 32),
            (6, 64),
            (7, 128),
            (8, 256),
            (9, 512),
            (10, 1024),
            (11, 2048),
            (12, 3600), // 2^12=4096 → 封顶
            (20, 3600),
            (100, 3600),
        ];
        for &(retry_count, expected) in cases {
            assert_eq!(
                backoff_seconds(retry_count),
                expected,
                "retry_count={retry_count}"
            );
        }
    }

    // backoff 单调不减且上限 3600。
    #[test]
    fn backoff_seconds_monotone_and_capped() {
        let mut prev = backoff_seconds(0);
        for rc in 1..=20 {
            let cur = backoff_seconds(rc);
            assert!(cur >= prev, "not monotone at retry_count={rc}");
            assert!(cur <= 3600, "exceeds cap at retry_count={rc}");
            prev = cur;
        }
    }

    // ── hydrate_envelope_metadata 表驱动（#1160 A4）──────────────────────────

    // occurredAt number → 十进制 string（occurred_at_secs() 可反解析）。
    // subjectId string → 原值透传。
    // correlation string → 原值透传。
    // 空对象 → empty metadata。
    // 无效 JSON → empty metadata（fail-safe，不阻 relay）。
    // 多键确定性（BTreeMap 序）→ 全部可读取。
    // boolean/null value → compact string（other.to_string() 分支）。
    #[test]
    fn hydrate_envelope_metadata_table() {
        // occurredAt number → string（occurred_at_secs 解析为 i64）。
        let md = hydrate_envelope_metadata(r#"{"occurredAt":1700000000}"#);
        assert_eq!(
            md.occurred_at_secs(),
            Some(1_700_000_000),
            "occurredAt number → parseable string"
        );

        // subjectId string → 直接透传。
        let md = hydrate_envelope_metadata(r#"{"subjectId":"user-7"}"#);
        assert_eq!(
            md.get("subjectId"),
            Some("user-7"),
            "subjectId string passthrough"
        );

        // correlation string → 直接透传。
        let md = hydrate_envelope_metadata(r#"{"correlation":"corr-1"}"#);
        assert_eq!(
            md.get("correlation"),
            Some("corr-1"),
            "correlation string passthrough"
        );

        // 空对象 → empty（is_empty 为真）。
        let md = hydrate_envelope_metadata("{}");
        assert!(md.is_empty(), "空对象 → empty metadata");

        // 无效 JSON → fail-safe empty（不阻 relay）。
        let md = hydrate_envelope_metadata("not-valid-json");
        assert!(md.is_empty(), "invalid JSON → empty metadata (fail-safe)");

        // 多键：全部可读。
        let md =
            hydrate_envelope_metadata(r#"{"correlation":"c","occurredAt":42,"subjectId":"u"}"#);
        assert_eq!(md.occurred_at_secs(), Some(42), "multi-key occurredAt");
        assert_eq!(md.get("subjectId"), Some("u"), "multi-key subjectId");
        assert_eq!(md.get("correlation"), Some("c"), "multi-key correlation");

        // boolean value → "true"（other.to_string() 分支，F4）。
        let md = hydrate_envelope_metadata(r#"{"k":true}"#);
        assert_eq!(md.get("k"), Some("true"), "boolean true → \"true\"");

        // null value → "null"（other.to_string() 分支，F4）。
        let md = hydrate_envelope_metadata(r#"{"k":null}"#);
        assert_eq!(md.get("k"), Some("null"), "null → \"null\"");
    }

    // anti-vacuity（fail-safe）：有效 object 解析成功（上面测过）；这里再验 non-object 也走 empty 分支
    // （JSON array 是合法 JSON 但不是 object）。
    #[test]
    fn hydrate_envelope_metadata_non_object_json_is_empty() {
        let md = hydrate_envelope_metadata("[1,2,3]");
        assert!(md.is_empty(), "JSON array 不是 object → empty");
    }

    // ── metadata_with_ambient 测试（#1160 B3）────────────────────────────────

    // 有 diagctx scope → correlation 注入到 metadata（与 occurredAt 共存）。
    #[tokio::test]
    async fn metadata_with_ambient_injects_correlation_inside_scope() {
        // reason: 测试 fixture，输入为合法 correlation id。
        #[allow(clippy::unwrap_used)]
        let ctx = diagctx::DiagnosticCtx::new(diagctx::CorrelationId::parse("corr-x").unwrap());
        let json = diagctx::scope(ctx, async {
            let m = metadata_with_ambient(42, tenant(), contract());
            OutboxEnvelope::new("d".to_string(), "c".to_string(), m).metadata_json()
        })
        .await;
        assert!(
            json.contains(r#""correlation":"corr-x""#),
            "scope 内应含 correlation: {json}"
        );
        assert!(
            json.contains(r#""occurredAt":42"#),
            "occurredAt 应存在: {json}"
        );
        assert!(
            json.contains(r#""schemaVersion":"v1""#) && json.contains(HASH),
            "schema header 应存在: {json}"
        );
    }

    // 无 scope → correlation 不注入（fail-open 省略），occurredAt 仍在。
    // anti-vacuity：无 scope 不 panic、不 Err（fail-open 契约）。
    #[tokio::test]
    async fn metadata_with_ambient_omits_correlation_outside_scope() {
        let m = metadata_with_ambient(42, tenant(), contract());
        let json = OutboxEnvelope::new("d".to_string(), "c".to_string(), m).metadata_json();
        assert!(
            !json.contains("correlation"),
            "无 scope 时不应含 correlation key: {json}"
        );
        assert!(
            json.contains(r#""occurredAt":42"#),
            "occurredAt 应存在: {json}"
        );
        assert!(
            json.contains(r#""schemaVersion":"v1""#) && json.contains(HASH),
            "schema header 应存在: {json}"
        );
    }

    // ── metadata_with_ambient trace 透传测试（#1224）─────────────────────────

    // 活跃采样 span → metadata_with_ambient 经 tracewire::capture_current 盖章 reserved key `trace`
    //（W3C traceparent，与 occurredAt 共存）——#1224 emit 接线正路。otel subscriber 经 tracewire 脚手架装配
    //（本 crate 不直接 import otel）。
    #[test]
    fn metadata_with_ambient_stamps_trace_inside_span() {
        let json = tracewire::with_test_subscriber(|| {
            tracing::info_span!("producer").in_scope(|| {
                OutboxEnvelope::new(
                    "d".to_string(),
                    "c".to_string(),
                    metadata_with_ambient(7, tenant(), contract()),
                )
                .metadata_json()
            })
        });
        assert!(
            json.contains(r#""trace":"00-"#),
            "活跃 span 应盖章 W3C traceparent trace 键: {json}"
        );
        assert!(
            json.contains(r#""occurredAt":7"#),
            "occurredAt 应存在: {json}"
        );
    }

    // 无 otel 层（capture→None）→ 不盖章 trace（fail-open 省略），occurredAt 仍在。
    // anti-vacuity：缺 otel 不 panic、不写 trace 键（与 inside-span 正路互证分支）。
    #[test]
    fn metadata_with_ambient_omits_trace_without_otel() {
        let json = OutboxEnvelope::new(
            "d".to_string(),
            "c".to_string(),
            metadata_with_ambient(7, tenant(), contract()),
        )
        .metadata_json();
        assert!(
            !json.contains(r#""trace""#),
            "无 otel 时不应含 trace 键: {json}"
        );
        assert!(
            json.contains(r#""occurredAt":7"#),
            "occurredAt 应存在: {json}"
        );
    }
}
