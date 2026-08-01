//! PostgreSQL projection_events adapter（append-only changelog 源，#1122/#1628）。
//!
//! 写路径没有 naked `PgPool` / `PgConnection` append API。生产 outbox 持久化在同一事务内拿
//! [`crate::cotx::eventing::EventingTx`] 调 [`append_projection_event_if_bound`]，该 helper 仅在 outbox `event_id`
//! 新插入且 `(source_domain, contract_id, version, schema_hash, topic)` 命中 generated
//! [`ProjectionWriteRegistry`] 时，
//! 调用 DB 固定 `rss_append_projection_event(...)` 函数写入 projection journal。
//!
//! 读路径只能通过独立 `rss_projection_reader` 凭据调用 tenant / projection / definition / generation
//! 固定的 `rss_read_projection_events_scoped(...)` 函数。`rss_app` 与 reader 均不持 raw table 权限。
//!
//! **append-only**：DB 层 `REVOKE UPDATE, DELETE` + fixed-shape SECURITY DEFINER functions 是主守卫；
//! 代码侧不保留裸 append 函数。INVARIANT PROJECTION-APPEND-ONLY-01。
//!
//! **物理全局表、逻辑强制分区**：历史表无 tenant_id / RLS；payload 只能经固定函数在 DB 内先按 metadata
//! tenant + sealed projection/definition/generation/input identity 过滤后返回，任何凭据都没有 raw SELECT。
//!
//! **事件源接缝**：adapter 实现 `consistency::ProjectionEventSource`，返回 engine-owned
//! `ProjectionEventRecord`；harness 当前仍不注入源（方案 B）。
//!
//! **时间戳**：`occurred_at`/`created_at` 用 DB DEFAULT `now()`（不注入 Clock，
//! 对标 DB-owned journal/changelog timestamp）。
//!
//! **错误 PII 边界**：append 路径 sqlx 错误不进 Display——经 [`ProjectionEventsError::new`] 包成
//! source；read source 路径只返回 [`EngineError`] 分类（error-handling.md §Message 与 PII）。
//!
//! ref: adapters/postgres/src/saga.rs（tenant-scoped append-only journal 范式）。

use std::sync::Arc;

use consistency::{
    EngineError, EngineErrorKind, EventTopic, Lsn, PartitionSerialDelivery, ProjectionBatchLimit,
    ProjectionEventMetadata, ProjectionEventRecord, ProjectionEventSource,
};
use diport::RedactedSource;
#[cfg(test)]
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use vocab::ProjectionInputBinding;

use crate::PgStore;
use crate::cotx::ServingWriteLane;
use crate::cotx::eventing::{EventingTx, GeneratedOutboxConcern};
use crate::outbox::OutboxEnvelope;
use crate::pool::{VerifiedPgProjectionOperatorStore, VerifiedPgProjectionSourceReadStore};

/// PostgreSQL projection_events adapter（append-only changelog 源）。
///
/// 持独立 reader pool 与不可伪造的 [`eventexec::ProjectionSourceScope`]。只能经
/// [`crate::PgProjectionOperatorDeps`] 的 receipt-bound scoped funnel 构造。
pub(crate) struct PgProjectionSourceReader {
    operator_pool: PgPool,
    pool: PgPool,
    scope: eventexec::ProjectionSourceScope,
}

/// Opaque 256-bit database authority. It is neither cloneable nor printable and is wiped on drop.
#[derive(zeroize::ZeroizeOnDrop)]
pub(crate) struct ProjectionSourceCapability([u8; 32]);

impl ProjectionSourceCapability {
    pub(crate) fn from_uuid_halves(first: &str, second: &str) -> Result<Self, uuid::Error> {
        let first = uuid::Uuid::parse_str(first)?;
        let second = uuid::Uuid::parse_str(second)?;
        let mut token = [0_u8; 32];
        token[..16].copy_from_slice(first.as_bytes());
        token[16..].copy_from_slice(second.as_bytes());
        Ok(Self(token))
    }

    fn uuid_halves(&self) -> (zeroize::Zeroizing<String>, zeroize::Zeroizing<String>) {
        let mut first = [0_u8; 16];
        let mut second = [0_u8; 16];
        first.copy_from_slice(&self.0[..16]);
        second.copy_from_slice(&self.0[16..]);
        let first = uuid::Uuid::from_bytes(first);
        let second = uuid::Uuid::from_bytes(second);
        (
            zeroize::Zeroizing::new(first.to_string()),
            zeroize::Zeroizing::new(second.to_string()),
        )
    }
}

/// Immutable projection writer registry selected by the compiled assembly workflow plan.
///
/// The registry owns its bindings so no caller can mutate the serving selection after startup.
/// There is no production API to add raw `(source_domain, contract_id, topic)` tuples.
#[derive(Clone, Debug, Default)]
pub(crate) struct ProjectionWriteRegistry {
    bindings: Arc<[ProjectionInputBinding]>,
}

impl ProjectionWriteRegistry {
    pub(crate) fn from_capture(capture: eventexec::ProjectionCaptureView<'_>) -> Self {
        Self::owned(capture.bindings())
    }

    #[cfg(test)]
    pub(crate) fn from_selected(bindings: &[ProjectionInputBinding]) -> Self {
        Self::owned(bindings)
    }

    fn owned(bindings: &[ProjectionInputBinding]) -> Self {
        Self {
            bindings: Arc::from(bindings),
        }
    }

    pub(crate) fn empty() -> Self {
        Self::default()
    }

    pub(crate) fn bindings(&self) -> &[ProjectionInputBinding] {
        &self.bindings
    }

    pub(crate) fn is_bound(
        &self,
        source_domain: &str,
        contract_id: &str,
        contract_version: &str,
        schema_hash: &str,
        topic: &str,
    ) -> bool {
        self.bindings.iter().any(|binding| {
            binding.domain() == source_domain
                && binding.contract_id() == contract_id
                && binding.version() == contract_version
                && binding.schema_hash() == schema_hash
                && binding.topic() == topic
        })
    }
}

/// Active PostgreSQL projection-capture selection, including the global catalog generation it
/// must be a member of. Disabled workflow plans are represented by `None` at carrier boundaries.
#[derive(Clone, Debug)]
pub(crate) struct ProjectionCaptureRegistration {
    generation: &'static str,
    registry: ProjectionWriteRegistry,
    inputs: Arc<[ProjectionInputRegistration]>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ProjectionInputRegistration {
    projection_id: Box<str>,
    definition_version: Box<str>,
    definition_schema_digest: Box<str>,
    source_domain: Box<str>,
    contract_id: Box<str>,
    contract_version: Box<str>,
    schema_hash: Box<str>,
    topic: Box<str>,
}

type ProjectionInputIdentityRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

impl ProjectionCaptureRegistration {
    pub(crate) fn from_capture(capture: eventexec::ProjectionCaptureView<'_>) -> Option<Self> {
        capture.generation().map(|generation| {
            let inputs = capture
                .entries()
                .flat_map(|(workflow, bindings)| {
                    let projection_id: Box<str> = workflow.id().into();
                    let definition_version: Box<str> = workflow.definition_version().into();
                    let definition_schema_digest: Box<str> =
                        workflow.definition_schema_digest().into();
                    bindings
                        .iter()
                        .map(move |binding| ProjectionInputRegistration {
                            projection_id: projection_id.clone(),
                            definition_version: definition_version.clone(),
                            definition_schema_digest: definition_schema_digest.clone(),
                            source_domain: binding.domain().into(),
                            contract_id: binding.contract_id().into(),
                            contract_version: binding.version().into(),
                            schema_hash: binding.schema_hash().into(),
                            topic: binding.topic().into(),
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            Self {
                generation,
                registry: ProjectionWriteRegistry::from_capture(capture),
                inputs: inputs.into(),
            }
        })
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_selected(
        generation: &'static str,
        bindings: &[ProjectionInputBinding],
    ) -> Option<Self> {
        (!bindings.is_empty()).then(|| Self {
            generation,
            registry: ProjectionWriteRegistry::from_selected(bindings),
            inputs: bindings
                .iter()
                .map(|binding| ProjectionInputRegistration {
                    projection_id: binding.projection_id().into(),
                    definition_version: "v1".into(),
                    definition_schema_digest: binding.schema_hash().into(),
                    source_domain: binding.domain().into(),
                    contract_id: binding.contract_id().into(),
                    contract_version: binding.version().into(),
                    schema_hash: binding.schema_hash().into(),
                    topic: binding.topic().into(),
                })
                .collect::<Vec<_>>()
                .into(),
        })
    }

    pub(crate) fn generation(&self) -> &'static str {
        self.generation
    }

    fn inputs(&self) -> &[ProjectionInputRegistration] {
        &self.inputs
    }

    pub(crate) fn registry(&self) -> ProjectionWriteRegistry {
        self.registry.clone()
    }
}

impl PgStore {
    /// Add one deployment generation to the DB-side projection input registry.
    ///
    /// This runs only on the migration lane before serving starts. Runtime `rss_app` cannot
    /// register or retire bindings.
    #[cfg(any(test, feature = "test-support", feature = "fault-matrix-test-support"))]
    #[allow(dead_code)]
    // reason: integration fixtures use this raw selected-binding helper; runtime module tests
    // enable `test-support` without registering arbitrary bindings.
    pub(crate) async fn register_projection_input_bindings(
        &self,
        generation: &str,
        bindings: &[ProjectionInputBinding],
    ) -> Result<(), sqlx::Error> {
        validate_projection_input_generation_label(generation)?;
        let mut tx = self.pool.begin().await?;
        for binding in bindings {
            sqlx::query(
                r#"
                SELECT rss_register_projection_input_binding($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(generation)
            .bind(binding.projection_id())
            .bind("v1")
            .bind(binding.schema_hash())
            .bind(binding.domain())
            .bind(binding.contract_id())
            .bind(binding.version())
            .bind(binding.schema_hash())
            .bind(binding.topic())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await
    }

    #[cfg(any(test, feature = "test-support", feature = "fault-matrix-test-support"))]
    pub(crate) async fn register_projection_capture(
        &self,
        capture: &ProjectionCaptureRegistration,
    ) -> Result<(), sqlx::Error> {
        validate_projection_input_generation_label(capture.generation())?;
        let mut tx = self.pool.begin().await?;
        for input in capture.inputs() {
            sqlx::query(
                "SELECT rss_register_projection_input_binding($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(capture.generation())
            .bind(&input.projection_id)
            .bind(&input.definition_version)
            .bind(&input.definition_schema_digest)
            .bind(&input.source_domain)
            .bind(&input.contract_id)
            .bind(&input.contract_version)
            .bind(&input.schema_hash)
            .bind(&input.topic)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await
    }

    /// Verify that the runtime-owned global input generation exactly matches the database catalog.
    ///
    /// The serving role reaches the table only through the fixed-shape
    /// `rss_read_projection_input_generation` SECURITY DEFINER function. Missing selected rows
    /// return `Ok(false)` for missing, additional, or mutated rows in the selected generation;
    /// rows in other generations are irrelevant. Probe failures remain errors so startup/readiness
    /// fail closed.
    async fn projection_input_generation_contains(
        &self,
        generation: &str,
        expected: &[ProjectionInputRegistration],
    ) -> Result<bool, sqlx::Error> {
        validate_projection_input_generation_label(generation)?;
        let mut actual: Vec<ProjectionInputIdentityRow> = sqlx::query_as(
            "SELECT projection_id, projection_definition_version, \
                    projection_definition_schema_digest, source_domain, contract_id, \
                    contract_version, schema_hash, topic \
             FROM public.rss_read_projection_input_generation($1)",
        )
        .bind(generation)
        .fetch_all(&self.pool)
        .await?;
        actual.sort_unstable();
        let mut expected = expected
            .iter()
            .map(|input| {
                (
                    input.projection_id.to_string(),
                    input.definition_version.to_string(),
                    input.definition_schema_digest.to_string(),
                    input.source_domain.to_string(),
                    input.contract_id.to_string(),
                    input.contract_version.to_string(),
                    input.schema_hash.to_string(),
                    input.topic.to_string(),
                )
            })
            .collect::<Vec<_>>();
        expected.sort_unstable();
        expected.dedup();
        Ok(actual == expected)
    }

    pub(crate) async fn validate_projection_capture_registration(
        &self,
        capture: &ProjectionCaptureRegistration,
    ) -> Result<(), sqlx::Error> {
        if self
            .projection_input_generation_contains(capture.generation(), capture.inputs())
            .await?
        {
            Ok(())
        } else {
            Err(sqlx::Error::Protocol(
                "projection inputs do not exactly match the database generation".into(),
            ))
        }
    }
}

fn validate_projection_input_generation_label(generation: &str) -> Result<(), sqlx::Error> {
    let digest = generation.strip_prefix("sha256:");
    if digest.is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        Ok(())
    } else {
        Err(sqlx::Error::Protocol(
            "projection input generation is not a sha256 digest".into(),
        ))
    }
}

#[cfg(test)]
pub(crate) fn projection_input_generation(bindings: &[ProjectionInputBinding]) -> String {
    let mut tuples = bindings
        .iter()
        .map(|binding| {
            (
                binding.projection_id(),
                "v1",
                binding.schema_hash(),
                binding.domain(),
                binding.contract_id(),
                binding.version(),
                binding.schema_hash(),
                binding.topic(),
            )
        })
        .collect::<Vec<_>>();
    tuples.sort_unstable();

    let mut digest = Sha256::new();
    for tuple in tuples {
        for value in [
            tuple.0, tuple.1, tuple.2, tuple.3, tuple.4, tuple.5, tuple.6, tuple.7,
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
    }
    format!("sha256:{:x}", digest.finalize())
}

/// Mirror an inserted outbox fact when the compiled assembly workflow selection binds it.
///
/// This function accepts only [`TenantTx`], so it can run solely inside the same transaction as
/// the outbox insert. It intentionally returns `Ok(None)` for unbound facts.
pub(crate) async fn append_projection_event_if_bound<C: GeneratedOutboxConcern>(
    tx: &mut EventingTx<'_, ServingWriteLane, C>,
    entry: &consistency::EventEntry,
    env: &OutboxEnvelope,
    registry: &ProjectionWriteRegistry,
) -> Result<Option<Lsn>, sqlx::Error> {
    if !registry.is_bound(
        env.domain(),
        env.contract_id(),
        env.contract_version(),
        env.schema_hash(),
        entry.topic().as_str(),
    ) {
        return Ok(None);
    }

    let aggregate_id = env.partition_key().unwrap_or(entry.idem_key().as_str());
    let metadata_json = env.metadata_json();
    let id = tx
        .projection_append(ProjectionAppend {
            event_id: entry.idem_key().as_str(),
            domain: env.domain(),
            aggregate_id,
            topic: entry.topic().as_str(),
            payload: entry.payload(),
            correlation_id: env.causation_id(),
            contract_id: env.contract_id(),
            contract_version: env.contract_version(),
            schema_hash: env.schema_hash(),
            metadata_json: &metadata_json,
            partition_key: env.partition_key(),
            causation_id: env.causation_id(),
        })
        .await?;
    let lsn = u64::try_from(id).map_err(|err| sqlx::Error::Decode(Box::new(err)))?;
    Ok(Some(Lsn::new(lsn)))
}

pub(crate) struct ProjectionAppend<'a> {
    pub(crate) event_id: &'a str,
    pub(crate) domain: &'a str,
    pub(crate) aggregate_id: &'a str,
    pub(crate) topic: &'a str,
    pub(crate) payload: &'a [u8],
    pub(crate) correlation_id: Option<&'a str>,
    pub(crate) contract_id: &'a str,
    pub(crate) contract_version: &'a str,
    pub(crate) schema_hash: &'a str,
    pub(crate) metadata_json: &'a str,
    pub(crate) partition_key: Option<&'a str>,
    pub(crate) causation_id: Option<&'a str>,
}

impl PgProjectionSourceReader {
    pub(crate) fn new(
        operator: &VerifiedPgProjectionOperatorStore,
        store: &VerifiedPgProjectionSourceReadStore,
        scope: eventexec::ProjectionSourceScope,
    ) -> Self {
        Self {
            operator_pool: operator.store_arc().pool.clone(),
            pool: store.pool().clone(),
            scope,
        }
    }

    async fn issue_capability(
        &self,
    ) -> Result<ProjectionSourceCapability, ProjectionSourceReadError> {
        let issued: (String, String) = sqlx::query_as(
            "SELECT capability_first::text, capability_second::text \
             FROM public.rss_projection_operator_issue_source_capability(\
             $1::uuid, $2, $3, $4, $5)",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.projection().as_str())
        .bind(self.scope.definition_version())
        .bind(self.scope.definition_schema_digest())
        .bind(self.scope.input_generation())
        .fetch_one(&self.operator_pool)
        .await
        .map_err(map_projection_source_sqlx_error)?;
        let (first, second) = issued;
        let first = zeroize::Zeroizing::new(first);
        let second = zeroize::Zeroizing::new(second);
        ProjectionSourceCapability::from_uuid_halves(&first, &second)
            .map_err(|_| ProjectionSourceReadError::Invariant)
    }

    /// Read the committed high-water for this exact sealed source scope in one fixed SQL call.
    ///
    /// The database function validates tenant/projection/definition/generation membership before
    /// returning a position. Missing or mismatched scope therefore fails closed instead of being
    /// indistinguishable from an empty, valid source.
    pub(crate) async fn source_high_water(&self) -> Result<Option<Lsn>, ProjectionSourceReadError> {
        let capability = self.issue_capability().await?;
        let (capability_first, capability_second) = capability.uuid_halves();
        let high_water: Option<i64> = sqlx::query_scalar(
            "SELECT public.rss_projection_source_high_water_scoped(\
             $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)",
        )
        .bind(capability_first.as_str())
        .bind(capability_second.as_str())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.projection().as_str())
        .bind(self.scope.definition_version())
        .bind(self.scope.definition_schema_digest())
        .bind(self.scope.input_generation())
        .fetch_one(&self.pool)
        .await
        .map_err(map_projection_source_sqlx_error)?;

        high_water
            .map(|value| {
                u64::try_from(value)
                    .map(Lsn::new)
                    .map_err(|_| ProjectionSourceReadError::Invariant)
            })
            .transpose()
    }

    /// 读 `id > after` 的事件，按 id 升序，最多 `limit` 条（replay / tail 喂 harness）。
    ///
    /// Scope validation (`SQLSTATE 22023`) and persisted row decoding failures map to
    /// [`EngineErrorKind::Invariant`]; database availability errors map to
    /// [`EngineErrorKind::Transient`].
    ///
    /// `ProjectionBatchLimit` 在调用边界保证非零且不超过 1000；harness 应以小批 tail 循环调用
    /// （内存 + 延迟权衡）。
    pub async fn read_from(
        &self,
        after: Option<Lsn>,
        limit: ProjectionBatchLimit,
    ) -> Result<Vec<ProjectionEventRecord>, EngineError> {
        // projection_events.id 是 BIGSERIAL/IDENTITY 1-based；`None` 表示从起点读，映射到 DB
        // 函数的 exclusive `after=0`。
        let after_i64 = after
            .map(|lsn| lsn.get())
            .map(i64::try_from)
            .transpose()
            .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?
            .unwrap_or(0);
        let limit_i64 = i64::from(limit.get());

        let capability = self
            .issue_capability()
            .await
            .map_err(ProjectionSourceReadError::into_engine)?;
        let (capability_first, capability_second) = capability.uuid_halves();
        let rows: Vec<ProjectionEventRow> = sqlx::query_as(
            r#"
            SELECT id, event_id, domain, event_type, payload, contract_id, contract_version,
                   schema_hash, metadata, partition_key, causation_id
            FROM public.rss_read_projection_events_scoped(
                $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9::integer
            )
            "#,
        )
        .bind(capability_first.as_str())
        .bind(capability_second.as_str())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.projection().as_str())
        .bind(self.scope.definition_version())
        .bind(self.scope.definition_schema_digest())
        .bind(self.scope.input_generation())
        .bind(after_i64)
        .bind(limit_i64)
        .fetch_all(&self.pool)
        .await
        .map_err(map_projection_source_sqlx_error)
        .map_err(ProjectionSourceReadError::into_engine)?;

        rows.into_iter()
            .map(
                |(
                    id,
                    event_id,
                    domain,
                    event_type_str,
                    payload,
                    contract_id,
                    contract_version,
                    schema_hash,
                    metadata,
                    partition_key,
                    causation_id,
                )| {
                    let lsn_u64 = u64::try_from(id)
                        .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
                    let lsn = Lsn::new(lsn_u64);
                    let topic = EventTopic::parse(&event_type_str)
                        .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
                    let tenant = metadata
                        .get(diport::KEY_TENANT_ID)
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| EngineError::new(EngineErrorKind::Invariant))
                        .and_then(|raw| {
                            vocab::TenantId::parse(raw)
                                .map_err(|_| EngineError::new(EngineErrorKind::Invariant))
                        })?;
                    let metadata = ProjectionEventMetadata::new(
                        tenant,
                        event_id,
                        domain,
                        contract_id,
                        contract_version,
                        schema_hash,
                        metadata,
                        partition_key,
                        causation_id,
                    );
                    Ok(ProjectionEventRecord::with_metadata(
                        lsn, topic, payload, metadata,
                    ))
                },
            )
            .collect()
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectionSourceReadError {
    #[error("projection source authority or scope is invalid")]
    ScopeInvalid,
    #[error("projection source is temporarily unavailable")]
    Transient,
    #[error("projection source returned an invalid result")]
    Invariant,
}

impl ProjectionSourceReadError {
    pub(crate) fn into_engine(self) -> EngineError {
        let kind = match self {
            Self::ScopeInvalid | Self::Invariant => EngineErrorKind::Invariant,
            Self::Transient => EngineErrorKind::Transient,
        };
        EngineError::new(kind)
    }
}

pub(crate) fn projection_scope_sqlx_error(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == "22023")
}

fn map_projection_source_sqlx_error(error: sqlx::Error) -> ProjectionSourceReadError {
    if projection_scope_sqlx_error(&error) {
        ProjectionSourceReadError::ScopeInvalid
    } else {
        ProjectionSourceReadError::Transient
    }
}

type ProjectionEventRow = (
    i64,
    String,
    String,
    String,
    Vec<u8>,
    String,
    String,
    String,
    serde_json::Value,
    Option<String>,
    Option<String>,
);

/// `PgProjectionSourceReader` 是串行有序 source：`read_from` 以 `ORDER BY id ASC` 单调序逐行交付，
/// 满足 [`PartitionSerialDelivery`] 契约（消费方按此 bound 铸造 `SerialInOrder` witness）。
///
/// INVARIANT: ADAPTER-PORT-FREEZE-14 { level = "Medium", exec = "manual/opt-in", source = "code" }—— PartitionSerialDelivery on PgProjectionSourceReader；
/// 去掉 impl 或 read_from 改为非顺序查询即编译失败（smoke 测试 anti-vacuity）。
impl PartitionSerialDelivery for PgProjectionSourceReader {}

impl ProjectionEventSource for PgProjectionSourceReader {
    async fn read_from(
        &self,
        after: Option<Lsn>,
        limit: ProjectionBatchLimit,
    ) -> Result<Vec<ProjectionEventRecord>, EngineError> {
        PgProjectionSourceReader::read_from(self, after, limit).await
    }
}

// ── 错误 ──────────────────────────────────────────────────────────────────────

/// projection_events 操作失败（infra 故障）。
///
/// PII 边界（对标 [`diport::SagaDurableStoreError`] 范式）：`Display` 仅安全摘要常量；source 经
/// [`RedactedSource`] 脱敏（`Debug`/`Display` 固定 `<redacted>`、`Error::source()` 恒 `None`）。
/// 见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, thiserror::Error)]
#[error("projection_events operation failed")]
pub struct ProjectionEventsError {
    #[source]
    source: RedactedSource,
}

impl ProjectionEventsError {
    /// 把 adapter 内部错误包成 projection_events 操作失败。原始错误仅作 internal source 保留，
    /// 不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

// ── 单测 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod smoke {
    //! 编译期类型证明：projection event record 归 consistency，scoped reader 只实现事件源。

    use core::marker::PhantomData;

    use consistency::{
        PartitionSerialDelivery, ProjectionEvent, ProjectionEventRecord, ProjectionEventSource,
    };

    fn assert_projection_event<T: ProjectionEvent>(_: PhantomData<T>) {}

    #[test]
    fn projection_event_record_impl_frozen() {
        assert_projection_event(PhantomData::<ProjectionEventRecord>);
    }

    fn assert_projection_event_source<T: ProjectionEventSource>() {}

    #[test]
    fn pg_projection_events_source_impl_frozen() {
        assert_projection_event_source::<super::PgProjectionSourceReader>();
    }

    /// INVARIANT: ADAPTER-PORT-FREEZE-14 { level = "Medium", exec = "manual/opt-in", source = "code" }—— PartitionSerialDelivery on PgProjectionSourceReader；
    /// 去掉 impl 即编译失败（smoke anti-vacuity）。
    fn _assert_partition_serial<T: PartitionSerialDelivery>() {}

    #[test]
    fn pg_projection_events_partition_serial_impl_frozen() {
        _assert_partition_serial::<super::PgProjectionSourceReader>();
    }

    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn projection_source_capability_is_zeroized_and_uuid_shaped()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_zeroize_on_drop::<super::ProjectionSourceCapability>();
        let capability = super::ProjectionSourceCapability::from_uuid_halves(
            "00000000-0000-4000-8000-000000000001",
            "00000000-0000-4000-8000-000000000002",
        )?;
        let (first, second) = capability.uuid_halves();
        assert_eq!(first.as_str(), "00000000-0000-4000-8000-000000000001");
        assert_eq!(second.as_str(), "00000000-0000-4000-8000-000000000002");
        Ok(())
    }

    #[test]
    fn projection_generation_digest_requires_lowercase_hex() {
        let lower = format!("sha256:{}", "a".repeat(64));
        let upper = format!("sha256:{}", "A".repeat(64));
        assert!(super::validate_projection_input_generation_label(&lower).is_ok());
        assert!(super::validate_projection_input_generation_label(&upper).is_err());
    }

    #[test]
    fn projection_source_scope_error_remains_distinct_until_port_boundary() {
        assert_eq!(
            super::ProjectionSourceReadError::ScopeInvalid
                .into_engine()
                .kind(),
            consistency::EngineErrorKind::Invariant
        );
        assert_eq!(
            super::ProjectionSourceReadError::Transient
                .into_engine()
                .kind(),
            consistency::EngineErrorKind::Transient
        );
    }

    /// drift 测试：断言 0010 migration 含 append-only 强制（`REVOKE UPDATE, DELETE`）、
    /// 不含 `tenant_id` / `ENABLE ROW LEVEL SECURITY`（全局表，无 RLS）、
    /// **不含 `TO rss_app`**（全局 payload 表不授 tenant serving role，闭跨租读边界，#1122 F2）。
    ///
    /// INVARIANT: PROJECTION-APPEND-ONLY-01（DB 引擎 REVOKE serving-role 主守卫待 dual-pool；当前
    /// dylint Medium + 本 drift Medium 辅守卫）。
    #[test]
    #[allow(clippy::expect_used)]
    // reason: 测试解析编译期 include_str! 的已知 migration 文本，缺关键子句应 fail；
    // item-level carve-out（error-handling.md §Carve-out）。
    fn projection_events_migration_append_only_and_no_rls() {
        const MIGRATION: &str = include_str!("../migrations/0013_create_projection_events.sql");

        // append-only 强制：必须含 REVOKE UPDATE, DELETE（PROJECTION-APPEND-ONLY-01）。
        // anti-vacuity：migration 文本非空，此断言可失败（若去掉 REVOKE 子句即红）。
        assert!(
            MIGRATION.contains("REVOKE UPDATE, DELETE"),
            "migration 0010 必须含 REVOKE UPDATE, DELETE（PROJECTION-APPEND-ONLY-01）"
        );

        // 全局表：不含 tenant_id（对标 checkpoint；outbox/saga_journal 已 tenant-scoped）。
        assert!(
            !MIGRATION.contains("tenant_id"),
            "projection_events 是全局表，不应含 tenant_id"
        );

        // 全局表：不含 ENABLE ROW LEVEL SECURITY。
        assert!(
            !MIGRATION.contains("ENABLE ROW LEVEL SECURITY"),
            "projection_events 是全局表，不应含 ENABLE ROW LEVEL SECURITY"
        );

        // 跨租读边界（#1122 F2）：全局 payload 表不授 tenant serving role rss_app（对齐 outbox）。
        // anti-vacuity：migration 非空且含其它 GRANT/REVOKE 语义，此断言可失败（若误加 `TO rss_app` 即红）。
        assert!(
            !MIGRATION.contains("TO rss_app"),
            "projection_events 不得授 serving role rss_app（全局 payload 表跨租读边界，对齐 outbox；#1122 F2）"
        );
    }

    /// INVARIANT: PROJECTION-INPUT-GENERATION-01 { level = "Medium", exec = "manual/opt-in", source = "code", synthetic_red = "projection_input_registry_is_generation_bound_and_additive rejects destructive runtime replacement", anti_vacuity = "migration carrier and runtime source are both scanned" }.
    #[test]
    fn projection_input_registry_is_generation_bound_and_additive() {
        const MIGRATION: &str =
            include_str!("../migrations/0054_generation_bound_projection_registry.sql");
        const SOURCE: &str = include_str!("projection_events.rs");

        assert!(MIGRATION.contains("ADD COLUMN generation text"));
        assert!(MIGRATION.contains("ALTER COLUMN generation SET NOT NULL"));
        assert!(MIGRATION.contains("rss_register_projection_input_binding"));
        assert!(MIGRATION.contains("rss_retire_projection_input_generation"));
        assert!(MIGRATION.contains("PRIMARY KEY (generation,"));
        let destructive_replace = ["DELETE FROM", "projection_input_bindings"].join(" ");
        assert!(
            !SOURCE.contains(&destructive_replace),
            "runtime startup must never destructively replace the projection registry"
        );
    }

    #[test]
    fn projection_input_generation_is_order_independent_and_tuple_complete() {
        const HASH_A: &str =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const HASH_B: &str =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const A: vocab::ProjectionInputBinding = vocab::ProjectionInputBinding::from_static(
            "projection-a",
            "owner",
            "owner.contract-a",
            "v1",
            HASH_A,
            "owner.fact-a",
        );
        const B: vocab::ProjectionInputBinding = vocab::ProjectionInputBinding::from_static(
            "projection-b",
            "owner",
            "owner.contract-b",
            "v2",
            HASH_B,
            "owner.fact-b",
        );

        let forward = super::projection_input_generation(&[A, B]);
        let reversed = super::projection_input_generation(&[B, A]);
        assert_eq!(forward, reversed);
        assert!(forward.starts_with("sha256:"));
        assert_eq!(forward.len(), "sha256:".len() + 64);

        let changed_topic = vocab::ProjectionInputBinding::from_static(
            "projection-a",
            "owner",
            "owner.contract-a",
            "v1",
            HASH_A,
            "owner.fact-changed",
        );
        assert_ne!(
            forward,
            super::projection_input_generation(&[changed_topic, B])
        );
    }

    #[test]
    fn projection_write_registry_owns_the_selected_bindings() {
        const HASH: &str =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut selected = vec![vocab::ProjectionInputBinding::from_static(
            "projection-a",
            "owner",
            "owner.contract-a",
            "v1",
            HASH,
            "owner.fact-a",
        )];
        let registry = super::ProjectionWriteRegistry::from_selected(&selected);

        selected.clear();

        assert!(registry.is_bound("owner", "owner.contract-a", "v1", HASH, "owner.fact-a"));
        assert!(
            !registry.is_bound(
                "foreign-owner",
                "owner.contract-a",
                "v1",
                HASH,
                "owner.fact-a"
            ),
            "a contract tuple from another source domain must not be captured"
        );
    }
}
