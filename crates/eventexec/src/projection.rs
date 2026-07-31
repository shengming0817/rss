//! CQRS 投影 harness（L3）—— 断点续投 + CAS checkpoint。
//!
//! 对标 saga `advance_checkpoint`：apply + checkpoint CAS 分开两次 await，
//! 靠 `Projector::apply` 幂等（同 lsn no-op）+ checkpoint CAS 保证 effectively-once。
//! `projection_runner_once` / `projection_runner_loop` 把 durable `ProjectionEventSource` 接到 harness，
//! worker 重启只依赖持久 checkpoint，不保存内存游标。
//!
//! ref: oxidecomputer/steno（saga 进度 checkpoint）+ docs/rules/eventbus.md §Projection。
//!
//! INVARIANT 备注：apply 幂等由 `Projector` impl 保证（trait doc 已声明）；
//! CAS 由 `diport::OwnerCheckpointStore::save_checkpoint` 的 `expected` 版本参数保证（infra 层）。
//!
//! ## 故障语义与恢复
//!
//! - **apply 失败**：fail-closed 停批；checkpoint 仅到失败前 high-water。
//! - **Transient** 错误：建议 caller 限速重试，下轮从 checkpoint 续投（幂等重投 no-op）。
//! - **Permanent / Invariant** 错误：写入统一 DLQ 后停在 poison lsn；默认不自动 skip，须人工介入。
//! - **SkipPermanentAfterDlx**：显式 policy 仅可在 `Permanent` DLQ 写成功后把 checkpoint 推过该 poison。
//! - **CommitUnknown**：不写 poison DLQ、不自动 skip，checkpoint 不越过失败事件；worker 降级等待后
//!   自动重放同一事实，由 target receipt 收敛为 `Duplicate`。
//! - **RollbackFailed**：事务状态无法确认，worker 停止，禁止自动重试或推进 checkpoint。
//! - **OutOfOrder**：写入统一 DLQ 后停批，不把 checkpoint 推过乱序 poison lsn。
//! - **checkpoint 读失败**：fail-closed（[`ProjectionStop::CheckpointUnread`]）——**不** apply 任何事件、
//!   **不**降级为空 baseline 盲目重放；checkpoint 是恢复坐标，读失败让 caller 退避 / 报警 / 重试。
//! - **checkpoint 写失败**：apply 已生效（[`ProjectionStop::CheckpointUnsaved`]），幂等可重跑、不丢数据。

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use consistency::{
    EngineErrorKind, Lsn, ProjectionApplyError, ProjectionApplyErrorKind,
    ProjectionApplyErrorReason, ProjectionApplyOutcome, ProjectionBatchLimit,
    ProjectionDeadLetterReason, ProjectionEvent, ProjectionEventMetadata, ProjectionEventRecord,
    ProjectionEventSource, Projector, SerialInOrderGuarantor,
};
use diport::{
    CheckpointId, CheckpointOwner, CheckpointVersion, DeadLetterProvenance, DeadLetterRecord,
    DeadLetterStore, DeadLetterSummary, EnvelopeMetadata, KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION,
    KEY_TENANT_AUTHORITY, KEY_TENANT_ID, OwnerCheckpointStore, RedactedSource, SaveOutcome,
};
use futures::future::BoxFuture;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use vocab::ProjectionInputBinding;

use crate::ManagedBlockingWorker;
use crate::managed_blocking_worker::spawn_on_dedicated_runtime;
use crate::relay::WorkerHealth;

const SUMMARY_PROJECTION_APPLY_PERMANENT: DeadLetterSummary =
    DeadLetterSummary::new("projection apply permanent");
const SUMMARY_PROJECTION_APPLY_INVARIANT: DeadLetterSummary =
    DeadLetterSummary::new("projection apply invariant");
const SUMMARY_PROJECTION_APPLY_CONFLICT: DeadLetterSummary =
    DeadLetterSummary::new("projection apply conflict");
const SUMMARY_PROJECTION_APPLY_OUT_OF_ORDER: DeadLetterSummary =
    DeadLetterSummary::new("projection apply out of order");
const SUMMARY_PROJECTION_OUT_OF_ORDER: DeadLetterSummary =
    DeadLetterSummary::new("projection out of order");
const SUMMARY_PROJECTION_POISON: DeadLetterSummary = DeadLetterSummary::new("projection poison");

/// readyz probe 名：projection worker（无 `_ready` 后缀，对齐其它后台 worker probe 命名）。
pub const PROJECTION_WORKER_PROBE: &str = "projection_worker";

const PROJECTION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(45);
const MIN_PROJECTION_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_PROJECTION_POLL_INTERVAL: Duration = Duration::from_secs(300);

// ── Runner 配置 ──────────────────────────────────────────────────────────────

/// Projection poison 处理策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionPoisonPolicy {
    /// 默认隔离：poison 写 DLQ 后停止当前 projection，不推进 checkpoint 越过 poison。
    Isolate,
    /// 仅对 `Permanent` apply error：DLQ 写成功后把 checkpoint 推进到 poison LSN。
    SkipPermanentAfterDlx,
}

/// Projection runner 配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionRunnerConfig {
    batch_limit: ProjectionBatchLimit,
    poll_interval: Duration,
    poison_policy: ProjectionPoisonPolicy,
}

impl ProjectionRunnerConfig {
    /// 构造 projection runner 配置。`poll_interval` 在构造点拒绝 0 / 过大配置。
    pub fn new(
        batch_limit: ProjectionBatchLimit,
        poll_interval: Duration,
        poison_policy: ProjectionPoisonPolicy,
    ) -> Result<Self, ProjectionRunnerConfigError> {
        if poll_interval < MIN_PROJECTION_POLL_INTERVAL
            || poll_interval > MAX_PROJECTION_POLL_INTERVAL
        {
            return Err(ProjectionRunnerConfigError::PollIntervalOutOfRange {
                got: poll_interval,
                min: MIN_PROJECTION_POLL_INTERVAL,
                max: MAX_PROJECTION_POLL_INTERVAL,
            });
        }
        Ok(Self {
            batch_limit,
            poll_interval,
            poison_policy,
        })
    }

    pub fn batch_limit(self) -> ProjectionBatchLimit {
        self.batch_limit
    }

    pub fn poll_interval(self) -> Duration {
        self.poll_interval
    }

    pub fn poison_policy(self) -> ProjectionPoisonPolicy {
        self.poison_policy
    }
}

impl Default for ProjectionRunnerConfig {
    fn default() -> Self {
        Self {
            batch_limit: ProjectionBatchLimit::MAX,
            poll_interval: Duration::from_secs(1),
            poison_policy: ProjectionPoisonPolicy::Isolate,
        }
    }
}

/// Projection runner 配置错误。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProjectionRunnerConfigError {
    /// poll 间隔越界。
    #[error("projection poll_interval {got:?} out of range [{min:?}, {max:?}]")]
    PollIntervalOutOfRange {
        got: Duration,
        min: Duration,
        max: Duration,
    },
}

// ── Replay / shadow-swap control-plane types ────────────────────────────────

/// Projection id newtype. Only generated projection workflow ids and CLI selectors should enter
/// through this funnel.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectionId(String);

impl ProjectionId {
    pub fn parse(raw: &str) -> Result<Self, ProjectionSelectorError> {
        parse_projection_ident(raw, "projection id")?;
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProjectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProjectionId").field(&self.0).finish()
    }
}

impl fmt::Display for ProjectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl serde::Serialize for ProjectionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ProjectionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Projection shadow/active version newtype.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectionVersion(String);

impl ProjectionVersion {
    pub fn parse(raw: &str) -> Result<Self, ProjectionSelectorError> {
        parse_projection_ident(raw, "projection version")?;
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProjectionVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProjectionVersion").field(&self.0).finish()
    }
}

impl fmt::Display for ProjectionVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl serde::Serialize for ProjectionVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ProjectionVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Tenant + projection + version selector used by replay/status/swap commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionSelector {
    tenant: vocab::TenantId,
    projection: ProjectionId,
    version: ProjectionVersion,
}

impl ProjectionSelector {
    pub fn new(
        tenant: vocab::TenantId,
        projection: ProjectionId,
        version: ProjectionVersion,
    ) -> Self {
        Self {
            tenant,
            projection,
            version,
        }
    }

    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    pub fn projection(&self) -> &ProjectionId {
        &self.projection
    }

    pub fn version(&self) -> &ProjectionVersion {
        &self.version
    }

    pub fn shadow_checkpoint_owner(&self) -> CheckpointOwner {
        CheckpointOwner::new(format!("projection:{}", self.tenant))
    }

    pub fn shadow_checkpoint_id(&self) -> CheckpointId {
        CheckpointId::new(format!(
            "{}@{}:shadow",
            self.projection.as_str(),
            self.version.as_str()
        ))
    }

    pub fn active_pointer_key(&self) -> String {
        format!(
            "projection-active/{}/{}",
            self.tenant,
            self.projection.as_str()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectionSelectorError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is not canonical [a-z0-9._-]+")]
    Format { field: &'static str },
}

fn parse_projection_ident(raw: &str, field: &'static str) -> Result<(), ProjectionSelectorError> {
    if raw.is_empty() {
        return Err(ProjectionSelectorError::Empty { field });
    }
    if raw
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    {
        Ok(())
    } else {
        Err(ProjectionSelectorError::Format { field })
    }
}

/// Active projection pointer persisted through the CAS store.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProjectionActivePointer {
    tenant: String,
    projection: ProjectionId,
    version: ProjectionVersion,
    checkpoint_owner: String,
    checkpoint_id: String,
    high_water_lsn: Option<u64>,
}

impl ProjectionActivePointer {
    pub fn new(selector: &ProjectionSelector, high_water: Option<Lsn>) -> Self {
        Self {
            tenant: selector.tenant().to_string(),
            projection: selector.projection().clone(),
            version: selector.version().clone(),
            checkpoint_owner: selector.shadow_checkpoint_owner().as_str().to_string(),
            checkpoint_id: selector.shadow_checkpoint_id().as_str().to_string(),
            high_water_lsn: high_water.map(|lsn| lsn.get()),
        }
    }

    pub fn version(&self) -> &ProjectionVersion {
        &self.version
    }

    pub fn high_water_lsn(&self) -> Option<Lsn> {
        self.high_water_lsn.map(Lsn::new)
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionTargetStoreOutcome {
    /// mutation 与 receipt 已在同一事务首次提交。
    Applied,
    /// 同一 key 与 digest 的 receipt 已存在；必须在 persistent ordering 检查之前返回。
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionTargetStoreErrorKind {
    /// 同一 dedupe key 已对应不同 fact digest，禁止覆盖既有事实。
    Conflict,
    /// receipt 未命中且 LSN 低于 persistent high-water。
    OutOfOrder,
    /// 事务未提交且可安全重试。
    Transient,
    /// 事务已确认回滚的永久失败。
    Permanent,
    /// commit 可能成功但 ACK 丢失；重放须依 receipt 收敛。
    CommitUnknown,
    /// 无法确认事务已回滚；禁止自动 skip 或推进 checkpoint。
    RollbackFailed,
}

#[derive(Debug, thiserror::Error)]
#[error("projection target store apply failed")]
pub struct ProjectionTargetStoreError {
    kind: ProjectionTargetStoreErrorKind,
    #[source]
    source: RedactedSource,
}

impl ProjectionTargetStoreError {
    /// 从闭值 kind 与 provider cause 构造错误；cause 被类型层脱敏边界封存。
    pub fn new<E>(kind: ProjectionTargetStoreErrorKind, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind,
            source: RedactedSource::new(source),
        }
    }

    /// 返回 store 原始失败分类。
    pub const fn kind(&self) -> ProjectionTargetStoreErrorKind {
        self.kind
    }
}

/// 原子 receipt 的稳定去重键。字段私有，只能由 conforming funnel 创建。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectionDedupeKey {
    tenant: vocab::TenantId,
    projection: ProjectionId,
    generation: ProjectionVersion,
    event_id: String,
}

impl ProjectionDedupeKey {
    /// target tenant。
    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    /// projection workflow id。
    pub fn projection(&self) -> &ProjectionId {
        &self.projection
    }

    /// target generation/shadow version。
    pub fn generation(&self) -> &ProjectionVersion {
        &self.generation
    }

    /// source event stable id。
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
}

/// Store 可消费的唯一 validated input。所有字段私有，production source 无法直接构造。
#[derive(Clone)]
pub struct ValidatedProjectionApply {
    key: ProjectionDedupeKey,
    lsn: Lsn,
    topic: consistency::EventTopic,
    payload: Vec<u8>,
    metadata: ProjectionEventMetadata,
    fact_digest: [u8; 32],
}

impl ValidatedProjectionApply {
    /// 稳定 receipt key。
    pub fn key(&self) -> &ProjectionDedupeKey {
        &self.key
    }

    /// source journal LSN。
    pub fn lsn(&self) -> Lsn {
        self.lsn
    }

    /// exact-bound topic。
    pub fn topic(&self) -> &consistency::EventTopic {
        &self.topic
    }

    /// encoded business payload。
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// validated source envelope metadata。
    pub fn metadata(&self) -> &ProjectionEventMetadata {
        &self.metadata
    }

    /// canonical stable fact digest；同 key 不同 digest 必须返回 Conflict。
    pub fn fact_digest(&self) -> &[u8; 32] {
        &self.fact_digest
    }
}

impl fmt::Debug for ValidatedProjectionApply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedProjectionApply")
            .field("key", &self.key)
            .field("lsn", &self.lsn)
            .field("topic", &self.topic)
            .field("payload", &"<redacted>")
            .field("payload_len", &self.payload.len())
            .field("metadata", &self.metadata)
            .field("fact_digest", &"<redacted>")
            .finish()
    }
}

/// Adapter 唯一 SPI。mutation 与 receipt 必须由这一个调用在同一事务内原子完成。
///
/// 实现必须按 receipt duplicate/conflict → persistent ordering → mutation+receipt transaction 的顺序
/// 处理。`CommitUnknown` 不得谎报 rollback；`RollbackFailed` 不得自动重试。每个 production impl 必须
/// 通过 `testkit::projection_target_conformance!` 完整 enrollment，`runtime-baseline verify` 会拒绝旁路。
pub trait ProjectionTargetStore: Send + Sync + 'static {
    /// 原子 apply validated fact；不得拆成独立 mutation 与 receipt 调用。
    fn apply<'a>(
        &'a self,
        input: &'a ValidatedProjectionApply,
    ) -> BoxFuture<'a, Result<ProjectionTargetStoreOutcome, ProjectionTargetStoreError>>;
}

mod target_sealed {
    pub trait Sealed {}
}

/// Runtime target façade。sealed 后唯一实现形态是 [`ConformingProjectionTarget`].
pub trait ProjectionTarget: target_sealed::Sealed + Send + Sync {
    /// wrapper 绑定的 projection id。
    fn projection(&self) -> &ProjectionId;

    /// wrapper 的 exact generated input binding set。
    fn bindings(&self) -> &[ProjectionInputBinding];

    /// 分类并 apply 单条 raw projection event。
    fn apply<'a>(
        &'a self,
        selector: &'a ProjectionSelector,
        event: ProjectionEventRecord,
    ) -> BoxFuture<'a, Result<ProjectionApplyOutcome, ProjectionApplyError>>;
}

/// raw event 到 store input 的 canonical typed/private funnel。
pub struct ConformingProjectionTarget<S> {
    projection: ProjectionId,
    bindings: Vec<ProjectionInputBinding>,
    store: Arc<S>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
/// Canonical target 构造失败；任何错误都不得产生可注册 target。
pub enum ProjectionTargetConfigError {
    /// target 没有任何 generated input binding。
    #[error("projection target bindings must not be empty")]
    EmptyBindings,
    /// 至少一个 binding 的 projection id 与 target 不同。
    #[error("projection target binding belongs to another projection")]
    ProjectionMismatch,
    /// exact binding set 内存在重复项。
    #[error("projection target binding is duplicated")]
    DuplicateBinding,
}

impl<S: ProjectionTargetStore> ConformingProjectionTarget<S> {
    /// 构造 exact-bound target；空、错绑或重复 binding 均 fail-closed。
    pub fn new(
        projection: ProjectionId,
        bindings: Vec<ProjectionInputBinding>,
        store: Arc<S>,
    ) -> Result<Self, ProjectionTargetConfigError> {
        if bindings.is_empty() {
            return Err(ProjectionTargetConfigError::EmptyBindings);
        }
        if bindings
            .iter()
            .any(|binding| binding.projection_id() != projection.as_str())
        {
            return Err(ProjectionTargetConfigError::ProjectionMismatch);
        }
        if bindings
            .iter()
            .enumerate()
            .any(|(index, binding)| bindings[..index].contains(binding))
        {
            return Err(ProjectionTargetConfigError::DuplicateBinding);
        }
        Ok(Self {
            projection,
            bindings,
            store,
        })
    }

    fn validate(
        &self,
        selector: &ProjectionSelector,
        event: ProjectionEventRecord,
    ) -> Result<Option<ValidatedProjectionApply>, ProjectionApplyError> {
        if selector.projection() != &self.projection
            || event.metadata().tenant() != selector.tenant()
        {
            return Err(ProjectionApplyError::new(
                ProjectionApplyErrorKind::Invariant,
            ));
        }
        let exact = self.bindings.iter().any(|binding| {
            binding.domain() == event.metadata().domain()
                && binding.contract_id() == event.metadata().contract_id()
                && binding.version() == event.metadata().contract_version()
                && binding.schema_hash() == event.metadata().schema_hash()
                && binding.topic() == event.topic().as_str()
        });
        if !exact {
            let known_identity = self.bindings.iter().any(|binding| {
                binding.contract_id() == event.metadata().contract_id()
                    || binding.topic() == event.topic().as_str()
            });
            return if known_identity {
                Err(ProjectionApplyError::new(
                    ProjectionApplyErrorKind::Invariant,
                ))
            } else {
                Ok(None)
            };
        }

        let key = ProjectionDedupeKey {
            tenant: selector.tenant(),
            projection: selector.projection().clone(),
            generation: selector.version().clone(),
            event_id: event.metadata().event_id().to_string(),
        };
        let fact_digest = projection_fact_digest(selector, &event)?;
        Ok(Some(ValidatedProjectionApply {
            key,
            lsn: event.lsn(),
            topic: event.topic().clone(),
            payload: event.payload().to_vec(),
            metadata: event.metadata().clone(),
            fact_digest,
        }))
    }
}

fn projection_fact_digest(
    selector: &ProjectionSelector,
    event: &ProjectionEventRecord,
) -> Result<[u8; 32], ProjectionApplyError> {
    let mut digest = Sha256::new();
    let tenant = selector.tenant().to_string();
    for bytes in [
        tenant.as_bytes(),
        selector.projection().as_str().as_bytes(),
        selector.version().as_str().as_bytes(),
        event.metadata().event_id().as_bytes(),
        event.metadata().domain().as_bytes(),
        event.metadata().contract_id().as_bytes(),
        event.metadata().contract_version().as_bytes(),
        event.metadata().schema_hash().as_bytes(),
        event.topic().as_str().as_bytes(),
        event.payload(),
    ] {
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    let metadata_json = serde_json_canonicalizer::to_vec(event.metadata().metadata_json())
        .map_err(|_| ProjectionApplyError::new(ProjectionApplyErrorKind::Invariant))?;
    for optional in [
        Some(metadata_json.as_slice()),
        event.metadata().partition_key().map(str::as_bytes),
        event.metadata().causation_id().map(str::as_bytes),
    ] {
        match optional {
            Some(bytes) => {
                digest.update([1]);
                digest.update((bytes.len() as u64).to_be_bytes());
                digest.update(bytes);
            }
            None => digest.update([0]),
        }
    }
    Ok(digest.finalize().into())
}

impl<S: ProjectionTargetStore> target_sealed::Sealed for ConformingProjectionTarget<S> {}

impl<S: ProjectionTargetStore> ProjectionTarget for ConformingProjectionTarget<S> {
    fn projection(&self) -> &ProjectionId {
        &self.projection
    }

    fn bindings(&self) -> &[ProjectionInputBinding] {
        &self.bindings
    }

    fn apply<'a>(
        &'a self,
        selector: &'a ProjectionSelector,
        event: ProjectionEventRecord,
    ) -> BoxFuture<'a, Result<ProjectionApplyOutcome, ProjectionApplyError>> {
        Box::pin(async move {
            let Some(input) = self.validate(selector, event)? else {
                return Ok(ProjectionApplyOutcome::Filtered);
            };
            self.store
                .apply(&input)
                .await
                .map(|outcome| match outcome {
                    ProjectionTargetStoreOutcome::Applied => ProjectionApplyOutcome::Applied,
                    ProjectionTargetStoreOutcome::Duplicate => ProjectionApplyOutcome::Duplicate,
                })
                .map_err(|error| {
                    let reason = match error.kind() {
                        ProjectionTargetStoreErrorKind::Conflict => {
                            ProjectionApplyErrorReason::Conflict
                        }
                        ProjectionTargetStoreErrorKind::OutOfOrder => {
                            ProjectionApplyErrorReason::OutOfOrder
                        }
                        ProjectionTargetStoreErrorKind::Transient => {
                            ProjectionApplyErrorReason::Transient
                        }
                        ProjectionTargetStoreErrorKind::Permanent => {
                            ProjectionApplyErrorReason::Permanent
                        }
                        ProjectionTargetStoreErrorKind::CommitUnknown => {
                            ProjectionApplyErrorReason::CommitUnknown
                        }
                        ProjectionTargetStoreErrorKind::RollbackFailed => {
                            ProjectionApplyErrorReason::RollbackFailed
                        }
                    };
                    ProjectionApplyError::from_reason(reason)
                })
        })
    }
}

/// Projection targets selected by the sealed assembly runtime plan.
pub struct ProjectionTargetRegistry {
    planned: BTreeMap<ProjectionId, Vec<ProjectionInputBinding>>,
    targets: BTreeMap<ProjectionId, Arc<dyn ProjectionTarget>>,
}

impl ProjectionTargetRegistry {
    /// Build the exact target registry exposed by the assembly plan. Repository-wide generated
    /// inputs provide definition metadata only and cannot activate a projection by themselves.
    pub fn from_view(
        view: crate::ProjectionTargetView<'_>,
    ) -> Result<Self, ProjectionRegistryError> {
        let mut planned = BTreeMap::new();
        let mut targets = BTreeMap::new();
        for entry in view.entries() {
            let projection = ProjectionId::parse(entry.workflow().id())
                .map_err(|source| ProjectionRegistryError::InvalidProjectionId { source })?;
            let target = entry.target();
            if target.projection() != &projection || target.bindings() != entry.bindings() {
                return Err(ProjectionRegistryError::TargetIdentityMismatch { projection });
            }
            planned.insert(projection.clone(), entry.bindings().to_vec());
            targets.insert(projection, target);
        }
        Ok(Self { planned, targets })
    }

    #[cfg(test)]
    fn from_projection_ids<'a>(
        projection_ids: impl IntoIterator<Item = &'a str>,
        inputs: &'a [ProjectionInputBinding],
    ) -> Result<Self, ProjectionSelectorError> {
        let mut planned = BTreeMap::new();
        for id in projection_ids {
            let projection = ProjectionId::parse(id)?;
            let bindings = inputs
                .iter()
                .filter(|input| input.projection_id() == id)
                .cloned()
                .collect();
            planned.insert(projection, bindings);
        }
        Ok(Self {
            planned,
            targets: BTreeMap::new(),
        })
    }

    #[cfg(test)]
    fn register_target_for_test(
        &mut self,
        projection: ProjectionId,
        target: Arc<dyn ProjectionTarget>,
    ) -> Result<(), ProjectionRegistryError> {
        if !self.planned.contains_key(&projection) {
            return Err(ProjectionRegistryError::UnknownProjection { projection });
        }
        if self.targets.insert(projection.clone(), target).is_some() {
            return Err(ProjectionRegistryError::DuplicateProjection { projection });
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.planned.is_empty()
    }

    pub fn target(
        &self,
        projection: &ProjectionId,
    ) -> Result<Arc<dyn ProjectionTarget>, ProjectionRegistryError> {
        if !self.planned.contains_key(projection) {
            return Err(ProjectionRegistryError::UnknownProjection {
                projection: projection.clone(),
            });
        }
        self.targets.get(projection).cloned().ok_or_else(|| {
            ProjectionRegistryError::UncoveredProjection {
                projection: projection.clone(),
            }
        })
    }

    pub fn bindings_for(
        &self,
        projection: &ProjectionId,
    ) -> Result<Vec<ProjectionInputBinding>, ProjectionRegistryError> {
        self.planned.get(projection).cloned().ok_or_else(|| {
            ProjectionRegistryError::UnknownProjection {
                projection: projection.clone(),
            }
        })
    }

    pub fn validate_coverage(&self) -> Result<(), ProjectionRegistryError> {
        for projection in self.planned.keys() {
            if !self.targets.contains_key(projection) {
                return Err(ProjectionRegistryError::UncoveredProjection {
                    projection: projection.clone(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectionRegistryError {
    #[error("assembly-plan projection id is invalid")]
    InvalidProjectionId {
        #[source]
        source: ProjectionSelectorError,
    },
    #[error(
        "assembly-plan projection target identity does not match its generated bindings: {projection}"
    )]
    TargetIdentityMismatch { projection: ProjectionId },
    #[error("unknown projection target: {projection}")]
    UnknownProjection { projection: ProjectionId },
    #[error("assembly-plan projection target has no runtime target: {projection}")]
    UncoveredProjection { projection: ProjectionId },
    #[error("assembly-plan projection target is duplicated: {projection}")]
    DuplicateProjection { projection: ProjectionId },
}

/// Projector adapter that filters generated projection inputs and writes only matching events to
/// the selected shadow target.
pub struct ProjectionProjector {
    selector: ProjectionSelector,
    target: Arc<dyn ProjectionTarget>,
}

impl ProjectionProjector {
    pub fn new(selector: ProjectionSelector, target: Arc<dyn ProjectionTarget>) -> Self {
        Self { selector, target }
    }
}

impl Projector for ProjectionProjector {
    async fn apply<E: ProjectionEvent>(
        &self,
        event: &E,
    ) -> Result<ProjectionApplyOutcome, ProjectionApplyError> {
        let record = ProjectionEventRecord::with_metadata(
            event.lsn(),
            event.topic().clone(),
            event.payload().to_vec(),
            event.metadata().clone(),
        );
        self.target.apply(&self.selector, record).await
    }
}

// ── 公开结果类型 ──────────────────────────────────────────────────────────────

/// 单次 [`ProjectionHarness::run`] 的执行结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionRun {
    /// 本轮从 source 扫描并处理到结论的事件数（含 filtered/skipped/applied/duplicate，不含未处理尾部）。
    pub scanned: usize,
    /// 本轮成功写入投影目标的事件数（不含 filtered / skipped / failed）。
    pub applied: usize,
    /// 本轮由 target 确认为同一稳定事实已提交的事件数。
    pub duplicates: usize,
    /// 本轮属于同一 source stream 但不匹配当前投影 selector 的事件数。
    pub filtered: usize,
    /// 本轮跳过的事件数（lsn ≤ checkpoint baseline，或显式 poison skip）。
    pub skipped: usize,
    /// 本轮成功写入 projection DLQ 的事件数。
    pub dead_lettered: usize,
    /// 本轮停止原因。
    pub stop: ProjectionStop,
}

/// 投影批次停止原因。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProjectionStop {
    /// 全批完成，checkpoint 已推进（或无可推进事件）。
    Completed,
    /// apply 失败，fail-closed 停批（`failed_at` = 失败事件 lsn，`kind` = 错误种类）。
    ///
    /// 已成功 apply 的前缀已推进 checkpoint（high-water 到失败前一条）。
    ///
    /// - **Transient**：瞬时错误，建议 caller 限速重试（harness 下轮从 checkpoint 续投）。
    /// - **Permanent / Invariant**：写 projection DLQ 后停在同一 lsn（head-of-line blocking），
    ///   不自动 skip；须人工介入修复 projector 或显式处理 poison 事件。
    ApplyFailed {
        /// 失败事件的 lsn。
        failed_at: Lsn,
        /// projection apply 错误种类。
        kind: ProjectionApplyErrorKind,
        /// 可安全记录的精确 target failure reason。
        reason: ProjectionApplyErrorReason,
    },
    /// 事件 lsn 非升序——**release 也 fail-closed** 停批（`failed_at` = 首个乱序事件 lsn）。
    ///
    /// `SerialInOrderGuarantor` witness 只门禁 harness **构造**（编译期证上游声明串行）；运行期 batch
    /// 的实际顺序由此守：遇到 `lsn < 前一已处理 lsn` 即停，乱序事件**不 apply、不推进 checkpoint**
    /// 越过它（已成功前缀的 high-water 保留）。这把 witness 的「串行有序」声明从构造期延伸到 apply 期，
    /// 使非串行 source（伪造 witness 或乱序拼 slice）无法静默乱序投影（F1，#1211 review）。
    /// INVARIANT: PROJECTION-SERIAL-WITNESS-01 { level = "Medium", exec = "manual/opt-in", source = "code", facet = "runtime-fence" }（运行期半段）。
    OutOfOrder {
        /// 首个乱序事件的 lsn。
        failed_at: Lsn,
    },
    /// checkpoint CAS `StaleVersion`——并发投影实例已推进，本实例被 fence，停批。
    Fenced,
    /// apply 生效但 checkpoint 写 infra 故障（幂等可重跑，不丢数据）。
    CheckpointUnsaved,
    /// projection poison DLQ 写失败；本轮不推进 checkpoint，caller 应报警/退避后重试。
    DeadLetterUnsaved {
        /// DLQ 写失败对应的 poison lsn。
        failed_at: Lsn,
    },
    /// 显式 skip policy 已在 DLQ 写成功后把 checkpoint 推过 poison。
    PoisonSkipped {
        /// 被跳过的 poison lsn。
        skipped_at: Lsn,
        /// 被跳过的错误分类（当前只允许 `Permanent`）。
        kind: ProjectionApplyErrorKind,
    },
    /// projection event source 读取失败。
    SourceReadFailed {
        /// 事件源错误分类。
        kind: EngineErrorKind,
    },
    /// checkpoint **读** infra 故障——**fail-closed，不 apply 任何事件**。
    ///
    /// checkpoint 是恢复坐标：读失败时绝不降级为「空 baseline 从头重放」（会盲目全量重投、
    /// 掩盖 infra 故障），而是停批让 caller 退避 / 报警 / 重试（DB 恢复后重读得正确 offset 续投）。
    CheckpointUnread,
}

// ── ProjectionHarness ────────────────────────────────────────────────────────

/// CQRS 投影 harness：据 checkpoint 断点续投，apply 已按 lsn 升序排好的事件批，CAS 推进 offset。
///
/// `P: Projector` 必须保证 `apply` 幂等（同 lsn 重投 no-op）；`C: OwnerCheckpointStore` 提供
/// `(owner, projection_id)` 维度的断点续投 CAS。
pub struct ProjectionHarness<P, C, D> {
    projector: Arc<P>,
    checkpoint: Arc<C>,
    dlx: Arc<D>,
    owner: CheckpointOwner,
    projection_id: CheckpointId,
}

impl<P, C, D> ProjectionHarness<P, C, D>
where
    P: Projector + Send + Sync + 'static,
    C: OwnerCheckpointStore + Send + Sync + 'static,
    D: DeadLetterStore + Send + Sync + 'static,
{
    /// 构造投影 harness（必填参，缺失即编译错）。
    ///
    /// `_guarantor` 是串行有序 witness（[`consistency::SerialInOrderGuarantor`]）：非串行投递路径拿不到
    /// 此 witness ⇒ **编译期**挂不上 projection（fail-closed by absence，
    /// INVARIANT: PROJECTION-SERIAL-WITNESS-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary", facet = "witness-type" }）。witness 是 ZST，不占运行期成本（不存入 struct 字段，
    /// `run()` 签名不变）。唯一获取入口是 [`consistency::SerialInOrder::from_source`]，须传一个
    /// [`consistency::PartitionSerialDelivery`] source——非串行投递路径无该 impl ⇒ 编译期拒绝。
    ///
    /// ref: serverlesstechnology/cqrs src/cqrs.rs（events applied in order）
    pub fn new(
        projector: Arc<P>,
        checkpoint: Arc<C>,
        owner: CheckpointOwner,
        projection_id: CheckpointId,
        dlx: Arc<D>,
        _guarantor: impl SerialInOrderGuarantor,
    ) -> Self {
        Self {
            projector,
            checkpoint,
            dlx,
            owner,
            projection_id,
        }
    }

    /// 投影一批已按 lsn 升序排好的事件（前置：caller `read_from ORDER BY id ASC` 保证）。
    ///
    /// 流程：读 baseline → apply 批次（跳过 lsn ≤ baseline）→ 整批一次 CAS 到 high_water。
    /// apply 与 checkpoint CAS **分开两次 await**，靠幂等 + CAS 保证 effectively-once（对标 saga）。
    pub async fn run<E: ProjectionEvent>(&self, events: &[E]) -> ProjectionRun {
        self.run_with_poison_policy(events, ProjectionPoisonPolicy::Isolate)
            .await
    }

    async fn run_with_poison_policy<E: ProjectionEvent>(
        &self,
        events: &[E],
        poison_policy: ProjectionPoisonPolicy,
    ) -> ProjectionRun {
        // checkpoint 读失败 → fail-closed：不 apply，返回 CheckpointUnread 让 caller 退避 / 重试。
        let Some((baseline, version)) = self.read_baseline().await else {
            return ProjectionRun {
                scanned: 0,
                applied: 0,
                duplicates: 0,
                filtered: 0,
                skipped: 0,
                dead_lettered: 0,
                stop: ProjectionStop::CheckpointUnread,
            };
        };
        self.run_from_baseline(events, baseline, version, poison_policy)
            .await
    }

    async fn run_from_baseline<E: ProjectionEvent>(
        &self,
        events: &[E],
        baseline: Option<Lsn>,
        version: CheckpointVersion,
        poison_policy: ProjectionPoisonPolicy,
    ) -> ProjectionRun {
        let progress = self.apply_batch(events, baseline).await;
        let skipped_poison = skipped_poison(&progress.failure, poison_policy);
        let advance = self
            .advance_after_progress(&progress, baseline, version, skipped_poison)
            .await;
        let stop = stop_of(
            advance,
            progress.failure,
            progress.out_of_order,
            progress.dead_letter_write_failed,
            skipped_poison,
        );
        let result = ProjectionRun {
            scanned: progress.scanned,
            applied: progress.applied,
            duplicates: progress.duplicates,
            filtered: progress.filtered,
            skipped: progress.skipped
                + usize::from(matches!(stop, ProjectionStop::PoisonSkipped { .. })),
            dead_lettered: progress.dead_lettered,
            stop,
        };
        // debug 级 run 完成摘要（生产默认关闭）。
        tracing::debug!(
            owner = self.owner.as_str(),
            projection_id = self.projection_id.as_str(),
            scanned = result.scanned,
            applied = result.applied,
            duplicates = result.duplicates,
            filtered = result.filtered,
            skipped = result.skipped,
            dead_lettered = result.dead_lettered,
            stop = ?result.stop,
            "projection run complete"
        );
        result
    }

    async fn advance_after_progress(
        &self,
        progress: &BatchProgress,
        baseline: Option<Lsn>,
        version: CheckpointVersion,
        skipped_poison: Option<(Lsn, ProjectionApplyErrorKind)>,
    ) -> Advance {
        if progress.dead_letter_write_failed.is_some() || progress.out_of_order.is_some() {
            return Advance::NoChange;
        }
        if let Some((failed_at, _kind)) = skipped_poison {
            return self.advance_checkpoint(failed_at, version).await;
        }
        match progress.high_water {
            // 仅当 high_water 存在且 > baseline 时 CAS（有新进展才写 checkpoint）。
            Some(hw) if baseline != Some(hw) => self.advance_checkpoint(hw, version).await,
            // reason: 无新进展（空批 / 全跳过 / 首条即失败），不写 checkpoint（避免无效 CAS）。
            _ => Advance::NoChange,
        }
    }

    /// 读当前 checkpoint baseline。返回 `Some((baseline, version))` 进入 apply；`None` = 读 infra 故障，
    /// caller fail-closed 不 apply（[`ProjectionStop::CheckpointUnread`]）。
    ///
    /// - `Ok(Some(cp))` → `Some((Some(offset), version))`（续投）。
    /// - `Ok(None)`（从未保存，首轮）→ `Some((None, INITIAL))`（全量 replay，非故障）。
    /// - `Err(_)`（infra 故障）→ `None`：**不**降级为空 baseline 盲目重放——checkpoint 是恢复坐标，
    ///   读失败须 fail-closed 让 caller 退避 / 报警（DB 恢复后重读得正确 offset）。
    async fn read_baseline(&self) -> Option<(Option<Lsn>, CheckpointVersion)> {
        match self
            .checkpoint
            .get_checkpoint(&self.owner, &self.projection_id)
            .await
        {
            Ok(Some(cp)) => Some((Some(cp.offset), cp.version)),
            Ok(None) => Some((None, CheckpointVersion::INITIAL)),
            Err(err) => {
                self.error(
                    "projection: checkpoint read failed, fail-closed (no apply)",
                    &err,
                );
                None
            }
        }
    }

    /// apply 事件批：乱序 / 跳过 lsn ≤ baseline / 遇第一个失败均 fail-closed 停批。
    ///
    /// 顺序由运行期 `lsn < prev` 检查守（**release 也生效**，F1 #1211 review）——非仅前置假设。
    async fn apply_batch<E: ProjectionEvent>(
        &self,
        events: &[E],
        baseline: Option<Lsn>,
    ) -> BatchProgress {
        let mut progress = BatchProgress::default();
        let mut prev_lsn: Option<Lsn> = None;
        for event in events {
            let lsn = event.lsn();
            progress.scanned += 1;
            // 单调递增 release fail-closed：witness 只证构造期串行，运行期顺序由此守（INVARIANT PROJECTION-SERIAL-WITNESS-01）。
            if prev_lsn.is_some_and(|p| lsn < p) {
                self.log_out_of_order(lsn);
                if self
                    .write_projection_dead_letter(event, ProjectionDeadLetterReason::OutOfOrder)
                    .await
                    .is_err()
                {
                    progress.dead_letter_write_failed = Some(lsn);
                    break;
                }
                progress.dead_lettered += 1;
                progress.out_of_order = Some(lsn);
                break;
            }
            prev_lsn = Some(lsn);
            // 已在 baseline 以内的事件：已投过，跳过（断点续投语义）。
            if baseline.is_some_and(|b| lsn <= b) {
                progress.skipped += 1;
                continue;
            }
            match self.projector.apply(event).await {
                Ok(ProjectionApplyOutcome::Applied) => {
                    progress.applied += 1;
                    progress.high_water = Some(lsn);
                }
                Ok(ProjectionApplyOutcome::Duplicate) => {
                    progress.duplicates += 1;
                    progress.high_water = Some(lsn);
                }
                Ok(ProjectionApplyOutcome::Filtered) => {
                    progress.filtered += 1;
                    progress.high_water = Some(lsn);
                }
                Err(e) => {
                    self.log_apply_failed(lsn, e.kind(), e.reason(), event.topic().as_str());
                    if let Some(reason) =
                        ProjectionDeadLetterReason::from_apply_error_reason(e.reason())
                    {
                        if self
                            .write_projection_dead_letter(event, reason)
                            .await
                            .is_err()
                        {
                            progress.dead_letter_write_failed = Some(lsn);
                            break;
                        }
                        progress.dead_lettered += 1;
                    }
                    progress.failure = Some((lsn, e.kind(), e.reason()));
                    break;
                }
            }
        }
        progress
    }

    /// 结构化 warn：乱序 lsn 致 fail-closed 停批（仅元数据，无 payload/PII）。
    fn log_out_of_order(&self, lsn: Lsn) {
        tracing::warn!(
            owner = self.owner.as_str(),
            projection_id = self.projection_id.as_str(),
            lsn = lsn.get(),
            "projection: out-of-order lsn, stopping batch fail-closed"
        );
    }

    /// 结构化 warn：apply 失败致 fail-closed 停批（仅元数据，无 payload/PII）。
    fn log_apply_failed(
        &self,
        lsn: Lsn,
        kind: ProjectionApplyErrorKind,
        reason: ProjectionApplyErrorReason,
        topic: &str,
    ) {
        tracing::warn!(
            owner = self.owner.as_str(),
            projection_id = self.projection_id.as_str(),
            lsn = lsn.get(),
            kind = ?kind,
            reason = reason.as_label(),
            topic = topic,
            "projection: apply failed, stopping batch"
        );
    }

    async fn write_projection_dead_letter<E: ProjectionEvent>(
        &self,
        event: &E,
        reason: ProjectionDeadLetterReason,
    ) -> Result<(), ()> {
        let metadata = event.metadata();
        let record = DeadLetterRecord::new(
            metadata.tenant(),
            projection_dead_letter_message_id(&self.owner, &self.projection_id, event.lsn()),
            DeadLetterProvenance::projection(metadata.domain(), self.owner.as_str()),
            metadata.contract_id(),
            event.topic().as_str(),
            Some(self.projection_id.as_str().to_string()),
            event.payload().to_vec(),
            projection_dead_letter_summary(reason),
            1,
            projection_dead_letter_metadata(metadata),
        );
        self.dlx.write_dead_letter(record).await.map_err(|err| {
            tracing::error!(
                owner = self.owner.as_str(),
                projection_id = self.projection_id.as_str(),
                lsn = event.lsn().get(),
                reason = reason.as_label(),
                error = %err,
                "projection: dead-letter write failed, stopping without checkpoint advance"
            );
        })
    }

    /// CAS 推进 checkpoint 到 `hw`：`Saved` → Advanced；`StaleVersion` → warn + Fenced；
    /// infra 故障 → warn + Unsaved（apply 已生效，幂等可重跑）。
    async fn advance_checkpoint(&self, hw: Lsn, expected: CheckpointVersion) -> Advance {
        match self
            .checkpoint
            .save_checkpoint(&self.owner, &self.projection_id, hw, expected)
            .await
        {
            Ok(SaveOutcome::Saved) => Advance::Advanced,
            Ok(SaveOutcome::StaleVersion) => {
                self.warn("projection: checkpoint fenced by concurrent projector");
                Advance::Fenced
            }
            // reason: #[non_exhaustive] 未来变体——apply 已生效，保守记日志报 Unsaved（可重跑）。
            Ok(_) => {
                self.warn("projection: checkpoint not saved (unsupported outcome)");
                Advance::Unsaved
            }
            Err(err) => {
                // reason: projection checkpoint 是主要进度记录，持久化写失败 = error 级（observability.md
                // 持久化失败分级）；区别于 saga（checkpoint 仅快进游标非权威），projection 进度持久化失败
                // 需更高级别告警。
                self.error("projection: checkpoint save failed, replay is safe", &err);
                Advance::Unsaved
            }
        }
    }

    /// checkpoint 告警收口（结构化 tracing，控制各 caller 认知复杂度 ≤15）。
    fn warn(&self, msg: &'static str) {
        tracing::warn!(
            owner = self.owner.as_str(),
            projection_id = self.projection_id.as_str(),
            "{msg}"
        );
    }

    /// checkpoint 持久化错误收口（error 级；各 caller 认知复杂度 ≤15）。
    fn error(&self, msg: &'static str, err: &impl std::fmt::Display) {
        tracing::error!(
            owner = self.owner.as_str(),
            projection_id = self.projection_id.as_str(),
            error = %err,
            "{msg}"
        );
    }
}

// ── 内部辅助类型（crate 私有）────────────────────────────────────────────────

/// advance_checkpoint 结论（内部控制流；不出公开 API）。
#[derive(Clone, Copy)]
enum Advance {
    /// CAS 成功，checkpoint 已推进。
    Advanced,
    /// 无新进展（空批 / 全跳过 / 首条即失败），不写 checkpoint。
    NoChange,
    /// 并发实例 fence（StaleVersion）。
    Fenced,
    /// infra 故障未保存（apply 已生效，幂等可重跑）。
    Unsaved,
}

/// apply_batch 进度（内部；不出公开 API）。
#[derive(Default)]
struct BatchProgress {
    scanned: usize,
    applied: usize,
    duplicates: usize,
    filtered: usize,
    skipped: usize,
    dead_lettered: usize,
    /// 已成功 apply 的最高 lsn（None = 无任何新 apply）。
    high_water: Option<Lsn>,
    /// 第一个失败位点（lsn, kind）；None = 全批成功。
    failure: Option<(Lsn, ProjectionApplyErrorKind, ProjectionApplyErrorReason)>,
    /// 首个乱序事件 lsn（release fail-closed）；None = 顺序合法。与 `failure` 互斥（break 于首个命中）。
    out_of_order: Option<Lsn>,
    /// projection DLQ 写失败的 poison lsn；命中后不推进 checkpoint。
    dead_letter_write_failed: Option<Lsn>,
}

/// 把 advance 结论 + failure + 乱序停因组合成对外 `ProjectionStop`。
fn stop_of(
    advance: Advance,
    failure: Option<(Lsn, ProjectionApplyErrorKind, ProjectionApplyErrorReason)>,
    out_of_order: Option<Lsn>,
    dead_letter_write_failed: Option<Lsn>,
    skipped_poison: Option<(Lsn, ProjectionApplyErrorKind)>,
) -> ProjectionStop {
    if let Some(failed_at) = dead_letter_write_failed {
        return ProjectionStop::DeadLetterUnsaved { failed_at };
    }
    match advance {
        Advance::Fenced => ProjectionStop::Fenced,
        Advance::Unsaved => ProjectionStop::CheckpointUnsaved,
        // out_of_order 与 failure 互斥（apply_batch break 于首个命中）；乱序优先报 OutOfOrder。
        Advance::Advanced | Advance::NoChange => {
            if let Some((skipped_at, kind)) = skipped_poison {
                return ProjectionStop::PoisonSkipped { skipped_at, kind };
            }
            match (out_of_order, failure) {
                (Some(failed_at), _) => ProjectionStop::OutOfOrder { failed_at },
                (None, Some((failed_at, kind, reason))) => ProjectionStop::ApplyFailed {
                    failed_at,
                    kind,
                    reason,
                },
                (None, None) => ProjectionStop::Completed,
            }
        }
    }
}

fn skipped_poison(
    failure: &Option<(Lsn, ProjectionApplyErrorKind, ProjectionApplyErrorReason)>,
    policy: ProjectionPoisonPolicy,
) -> Option<(Lsn, ProjectionApplyErrorKind)> {
    match (policy, failure) {
        (
            ProjectionPoisonPolicy::SkipPermanentAfterDlx,
            Some((failed_at, ProjectionApplyErrorKind::Permanent, _)),
        ) => Some((*failed_at, ProjectionApplyErrorKind::Permanent)),
        _ => None,
    }
}

// ── Projection runner / worker ───────────────────────────────────────────────

/// 执行一轮 projection runner：读 checkpoint → 从 source 拉批次 → harness apply/checkpoint/DLX。
pub async fn projection_runner_once<S, P, C, D>(
    source: &S,
    harness: &ProjectionHarness<P, C, D>,
    config: ProjectionRunnerConfig,
) -> ProjectionRun
where
    S: ProjectionEventSource,
    P: Projector + Send + Sync + 'static,
    C: OwnerCheckpointStore + Send + Sync + 'static,
    D: DeadLetterStore + Send + Sync + 'static,
{
    let Some((baseline, version)) = harness.read_baseline().await else {
        return ProjectionRun {
            scanned: 0,
            applied: 0,
            duplicates: 0,
            filtered: 0,
            skipped: 0,
            dead_lettered: 0,
            stop: ProjectionStop::CheckpointUnread,
        };
    };
    let batch_limit = config.batch_limit();
    let after_lsn = baseline
        .map(|lsn| lsn.get().to_string())
        .unwrap_or_else(|| "source-start".to_string());
    let events = match source.read_from(baseline, batch_limit).await {
        Ok(events) => events,
        Err(err) => {
            let kind = err.kind();
            tracing::error!(
                owner = harness.owner.as_str(),
                projection_id = harness.projection_id.as_str(),
                after_lsn = after_lsn.as_str(),
                batch_limit = batch_limit.get(),
                kind = ?kind,
                error = %err,
                "projection: source read failed"
            );
            return ProjectionRun {
                scanned: 0,
                applied: 0,
                duplicates: 0,
                filtered: 0,
                skipped: 0,
                dead_lettered: 0,
                stop: ProjectionStop::SourceReadFailed { kind },
            };
        }
    };
    harness
        .run_from_baseline(&events, baseline, version, config.poison_policy())
        .await
}

/// Projection runner tail loop。取消后在当前批次结束处收敛。
pub async fn projection_runner_loop<S, P, C, D>(
    source: S,
    harness: ProjectionHarness<P, C, D>,
    config: ProjectionRunnerConfig,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
) where
    S: ProjectionEventSource,
    P: Projector + Send + Sync + 'static,
    C: OwnerCheckpointStore + Send + Sync + 'static,
    D: DeadLetterStore + Send + Sync + 'static,
{
    let mut ticker = tokio::time::interval(config.poll_interval());
    'outer: loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {}
        }
        loop {
            if token.is_cancelled() {
                break 'outer;
            }
            let run = projection_runner_once(&source, &harness, config).await;
            record_projection_health(&run, &health);
            match projection_loop_action(&run, config.batch_limit()) {
                ProjectionLoopAction::ContinueNow => continue,
                ProjectionLoopAction::Wait => break,
                ProjectionLoopAction::Stop => break 'outer,
            }
        }
    }
    health.mark_stopped();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionLoopAction {
    ContinueNow,
    Wait,
    Stop,
}

fn projection_loop_action(
    run: &ProjectionRun,
    batch_limit: ProjectionBatchLimit,
) -> ProjectionLoopAction {
    match run.stop {
        ProjectionStop::Completed => {
            if run.scanned >= batch_limit.get() as usize {
                ProjectionLoopAction::ContinueNow
            } else {
                ProjectionLoopAction::Wait
            }
        }
        ProjectionStop::PoisonSkipped { .. } => ProjectionLoopAction::ContinueNow,
        ProjectionStop::ApplyFailed {
            kind: ProjectionApplyErrorKind::Transient | ProjectionApplyErrorKind::CommitUnknown,
            ..
        }
        | ProjectionStop::CheckpointUnread
        | ProjectionStop::CheckpointUnsaved
        | ProjectionStop::DeadLetterUnsaved { .. }
        | ProjectionStop::SourceReadFailed {
            kind: EngineErrorKind::Transient,
        } => ProjectionLoopAction::Wait,
        _ => ProjectionLoopAction::Stop,
    }
}

fn record_projection_health(run: &ProjectionRun, health: &WorkerHealth) {
    match run.stop {
        ProjectionStop::Completed => health.mark_healthy(),
        _ => health.mark_degraded(),
    }
}

/// Spawn a supervised projection worker.
pub fn spawn_projection_worker<S, P, C, D>(
    name: String,
    source: S,
    harness: ProjectionHarness<P, C, D>,
    config: ProjectionRunnerConfig,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
) -> ManagedBlockingWorker
where
    S: ProjectionEventSource + Send + 'static,
    P: Projector + Send + Sync + 'static,
    C: OwnerCheckpointStore + Send + Sync + 'static,
    D: DeadLetterStore + Send + Sync + 'static,
{
    spawn_on_dedicated_runtime(
        name,
        token,
        Arc::clone(&health),
        PROJECTION_SHUTDOWN_TIMEOUT,
        move |token| async move {
            projection_runner_loop(source, harness, config, token, health).await;
            Ok(())
        },
    )
}

fn projection_dead_letter_message_id(
    owner: &CheckpointOwner,
    projection_id: &CheckpointId,
    lsn: Lsn,
) -> String {
    format!(
        "projection:{}:{}:{}",
        owner.as_str(),
        projection_id.as_str(),
        lsn.get()
    )
}

fn projection_dead_letter_summary(reason: ProjectionDeadLetterReason) -> DeadLetterSummary {
    match reason {
        ProjectionDeadLetterReason::ApplyPermanent => SUMMARY_PROJECTION_APPLY_PERMANENT,
        ProjectionDeadLetterReason::ApplyInvariant => SUMMARY_PROJECTION_APPLY_INVARIANT,
        ProjectionDeadLetterReason::ApplyConflict => SUMMARY_PROJECTION_APPLY_CONFLICT,
        ProjectionDeadLetterReason::ApplyOutOfOrder => SUMMARY_PROJECTION_APPLY_OUT_OF_ORDER,
        ProjectionDeadLetterReason::OutOfOrder => SUMMARY_PROJECTION_OUT_OF_ORDER,
        _ => SUMMARY_PROJECTION_POISON,
    }
}

fn projection_dead_letter_metadata(metadata: &ProjectionEventMetadata) -> EnvelopeMetadata {
    let mut out = EnvelopeMetadata::empty();
    if let serde_json::Value::Object(map) = metadata.metadata_json() {
        for (key, value) in map {
            if key == KEY_TENANT_AUTHORITY {
                continue;
            }
            if let Some(value) = projection_metadata_value(value) {
                insert_projection_dead_letter_metadata(&mut out, key.as_str(), value);
            }
        }
    }
    insert_projection_dead_letter_reserved_metadata(
        &mut out,
        KEY_TENANT_ID,
        metadata.tenant().to_string(),
    );
    insert_projection_dead_letter_reserved_metadata(
        &mut out,
        KEY_SCHEMA_VERSION,
        metadata.contract_version(),
    );
    insert_projection_dead_letter_reserved_metadata(
        &mut out,
        KEY_SCHEMA_HASH,
        metadata.schema_hash(),
    );
    if let Some(partition_key) = metadata.partition_key() {
        insert_projection_dead_letter_metadata(&mut out, "partitionKey", partition_key.to_string());
    }
    if let Some(causation_id) = metadata.causation_id() {
        insert_projection_dead_letter_metadata(&mut out, "causationId", causation_id.to_string());
    }
    out
}

fn insert_projection_dead_letter_metadata(
    metadata: &mut EnvelopeMetadata,
    key: impl Into<String>,
    value: impl Into<String>,
) {
    let _ = metadata.try_insert(key, value);
}

#[allow(unknown_lints, rss_diport_envelope_reserved_writer)]
// reason: projection DLX rehydrates typed projection system fields into persisted DLX metadata;
// the values come from ProjectionEventMetadata typed accessors, not user free-form metadata.
fn insert_projection_dead_letter_reserved_metadata(
    metadata: &mut EnvelopeMetadata,
    key: &'static str,
    value: impl Into<String>,
) {
    metadata.insert_wire_pair(key, value);
}

fn projection_metadata_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use std::time::Duration;

    use consistency::outbox::EventTopic;
    use consistency::{
        EngineError, EngineErrorKind, Lsn, ProjectionApplyError, ProjectionApplyErrorKind,
        ProjectionApplyErrorReason, ProjectionApplyOutcome, ProjectionBatchLimit, ProjectionEvent,
        ProjectionEventMetadata, ProjectionEventRecord, ProjectionEventSource, Projector,
    };
    use diport::{
        Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
        DeadLetterRecord, DeadLetterSource, DeadLetterStore, DeadLetterStoreError, KEY_SCHEMA_HASH,
        KEY_SCHEMA_VERSION, KEY_TENANT_AUTHORITY, KEY_TENANT_ID, OwnerCheckpointStore, SaveOutcome,
    };
    use primitives::healthz::HealthStatus;
    use tokio_util::sync::CancellationToken;

    use crate::relay::WorkerHealth;
    use consistency::PartitionSerialDelivery;

    use super::{
        ConformingProjectionTarget, ProjectionActivePointer, ProjectionHarness, ProjectionId,
        ProjectionLoopAction, ProjectionPoisonPolicy, ProjectionProjector, ProjectionRegistryError,
        ProjectionRun, ProjectionRunnerConfig, ProjectionSelector, ProjectionStop,
        ProjectionTarget, ProjectionTargetConfigError, ProjectionTargetRegistry,
        ProjectionTargetStore, ProjectionTargetStoreError, ProjectionTargetStoreErrorKind,
        ProjectionTargetStoreOutcome, ProjectionVersion, ValidatedProjectionApply,
        projection_loop_action, projection_runner_loop, projection_runner_once,
        record_projection_health,
    };

    type HarnessParts = (
        ProjectionHarness<RecordingProjector, FakeCheckpointStore, FakeDeadLetterStore>,
        Arc<RecordingProjector>,
        Arc<FakeCheckpointStore>,
        Arc<FakeDeadLetterStore>,
    );

    // ── FakeEvent ─────────────────────────────────────────────────────────────

    /// 测试用 fake 投影事件。
    struct FakeEvent {
        lsn: Lsn,
        topic: EventTopic,
        payload: Vec<u8>,
        metadata: ProjectionEventMetadata,
    }

    impl ProjectionEvent for FakeEvent {
        fn topic(&self) -> &EventTopic {
            &self.topic
        }
        fn lsn(&self) -> Lsn {
            self.lsn
        }
        fn payload(&self) -> &[u8] {
            &self.payload
        }
        fn metadata(&self) -> &ProjectionEventMetadata {
            &self.metadata
        }
    }

    /// 构造 seq 号 fake 事件（topic="proj.test"，payload=[]）。
    // reason: "proj.test" 是编译期常量，parse 必然成功，expect 用于测试断言。
    #[allow(clippy::expect_used)]
    fn ev(seq: u64) -> FakeEvent {
        FakeEvent {
            lsn: Lsn::new(seq),
            topic: EventTopic::parse("proj.test").expect("proj.test is valid topic"),
            payload: vec![],
            metadata: projection_metadata(),
        }
    }

    #[allow(clippy::expect_used)]
    // reason: test fixture literals are canonical; panic indicates fixture drift.
    fn projection_metadata() -> ProjectionEventMetadata {
        ProjectionEventMetadata::new(
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                .expect("canonical test tenant"),
            "projection-test-event",
            "test",
            "test.projection-event",
            "v1",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            serde_json::json!({ "tenantId": "f47ac10b-58cc-4372-a567-0e02b2c3d479" }),
            None,
            None,
        )
    }

    #[allow(clippy::expect_used)]
    fn projection_metadata_for(
        tenant: &str,
        domain: &str,
        contract_id: &str,
        contract_version: &str,
        schema_hash: &str,
    ) -> ProjectionEventMetadata {
        ProjectionEventMetadata::new(
            vocab::TenantId::parse(tenant).expect("canonical test tenant"),
            format!("projection-test-event-{contract_id}"),
            domain,
            contract_id,
            contract_version,
            schema_hash,
            serde_json::json!({ "tenantId": tenant }),
            None,
            None,
        )
    }

    /// 构造 seq 号批次 `start..=end`。
    fn evs(start: u64, end: u64) -> Vec<FakeEvent> {
        (start..=end).map(ev).collect()
    }

    #[allow(clippy::expect_used)]
    fn projection_record(seq: u64) -> ProjectionEventRecord {
        ProjectionEventRecord::with_metadata(
            Lsn::new(seq),
            EventTopic::parse("proj.test").expect("proj.test is valid topic"),
            vec![],
            projection_metadata(),
        )
    }

    fn projection_records(start: u64, end: u64) -> Vec<ProjectionEventRecord> {
        (start..=end).map(projection_record).collect()
    }

    #[allow(clippy::expect_used)]
    fn projection_record_with(
        seq: u64,
        topic: &str,
        metadata: ProjectionEventMetadata,
    ) -> ProjectionEventRecord {
        ProjectionEventRecord::with_metadata(
            Lsn::new(seq),
            EventTopic::parse(topic).expect("valid topic"),
            vec![],
            metadata,
        )
    }

    struct FakeProjectionSource {
        events: Vec<ProjectionEventRecord>,
        calls: Mutex<Vec<(Option<u64>, u32)>>,
        fail_kind: Option<EngineErrorKind>,
    }

    impl FakeProjectionSource {
        fn new(events: Vec<ProjectionEventRecord>) -> Self {
            Self {
                events,
                calls: Mutex::new(vec![]),
                fail_kind: None,
            }
        }

        fn fail(kind: EngineErrorKind) -> Self {
            Self {
                events: vec![],
                calls: Mutex::new(vec![]),
                fail_kind: Some(kind),
            }
        }

        fn read_calls(&self) -> Vec<(Option<u64>, u32)> {
            self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    impl PartitionSerialDelivery for FakeProjectionSource {}

    impl ProjectionEventSource for FakeProjectionSource {
        async fn read_from(
            &self,
            after: Option<Lsn>,
            limit: ProjectionBatchLimit,
        ) -> Result<Vec<ProjectionEventRecord>, EngineError> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((after.map(|lsn| lsn.get()), limit.get()));
            if let Some(kind) = self.fail_kind {
                return Err(EngineError::new(kind));
            }
            Ok(self
                .events
                .iter()
                .filter(|event| after.is_none_or(|after| event.lsn() > after))
                .take(limit.get() as usize)
                .cloned()
                .collect())
        }
    }

    struct CommitUnknownReplaySource {
        event: ProjectionEventRecord,
        token: CancellationToken,
        health: Arc<WorkerHealth>,
        baselines: Arc<Mutex<Vec<Option<u64>>>>,
        saw_degraded_retry: Arc<AtomicBool>,
    }

    impl PartitionSerialDelivery for CommitUnknownReplaySource {}

    impl ProjectionEventSource for CommitUnknownReplaySource {
        async fn read_from(
            &self,
            after: Option<Lsn>,
            _limit: ProjectionBatchLimit,
        ) -> Result<Vec<ProjectionEventRecord>, EngineError> {
            let mut baselines = self
                .baselines
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            baselines.push(after.map(|lsn| lsn.get()));
            let call = baselines.len();
            drop(baselines);
            if call == 2 {
                self.saw_degraded_retry.store(
                    self.health.status() == HealthStatus::Degraded,
                    Ordering::Release,
                );
            }
            if after.is_some() {
                self.token.cancel();
                Ok(vec![])
            } else {
                Ok(vec![self.event.clone()])
            }
        }
    }

    struct CommitUnknownThenDuplicate {
        attempts: Arc<AtomicUsize>,
    }

    impl Projector for CommitUnknownThenDuplicate {
        async fn apply<E: ProjectionEvent>(
            &self,
            _event: &E,
        ) -> Result<ProjectionApplyOutcome, ProjectionApplyError> {
            if self.attempts.fetch_add(1, Ordering::AcqRel) == 0 {
                Err(ProjectionApplyError::new(
                    ProjectionApplyErrorKind::CommitUnknown,
                ))
            } else {
                Ok(ProjectionApplyOutcome::Duplicate)
            }
        }
    }

    #[allow(clippy::expect_used)]
    fn runner_config(policy: ProjectionPoisonPolicy) -> ProjectionRunnerConfig {
        ProjectionRunnerConfig::new(
            ProjectionBatchLimit::MAX,
            Duration::from_millis(100),
            policy,
        )
        .expect("valid runner config")
    }

    const TEST_SCHEMA_HASH: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    static TEST_PROJECTION_INPUTS: &[vocab::ProjectionInputBinding] =
        &[vocab::ProjectionInputBinding::from_static(
            "audit.session-projection",
            "identity",
            "identity.session-created",
            "v1",
            TEST_SCHEMA_HASH,
            "identity.session.created",
        )];

    #[derive(Default)]
    struct RecordingTargetStore {
        applied: Mutex<Vec<u64>>,
        digests: Mutex<Vec<[u8; 32]>>,
    }

    impl RecordingTargetStore {
        fn applied_lsns(&self) -> Vec<u64> {
            self.applied
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        fn digests(&self) -> Vec<[u8; 32]> {
            self.digests
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone()
        }
    }

    impl ProjectionTargetStore for RecordingTargetStore {
        fn apply<'a>(
            &'a self,
            input: &'a ValidatedProjectionApply,
        ) -> futures::future::BoxFuture<
            'a,
            Result<ProjectionTargetStoreOutcome, ProjectionTargetStoreError>,
        > {
            Box::pin(async move {
                self.applied
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(input.lsn().get());
                self.digests
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push(*input.fact_digest());
                Ok(ProjectionTargetStoreOutcome::Applied)
            })
        }
    }

    #[allow(clippy::expect_used)]
    fn projection_selector(version: &str) -> ProjectionSelector {
        ProjectionSelector::new(
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                .expect("canonical test tenant"),
            ProjectionId::parse("audit.session-projection").expect("valid projection"),
            ProjectionVersion::parse(version).expect("valid version"),
        )
    }

    #[allow(clippy::expect_used)]
    fn conforming_target(store: Arc<RecordingTargetStore>) -> Arc<dyn ProjectionTarget> {
        Arc::new(
            ConformingProjectionTarget::new(
                ProjectionId::parse("audit.session-projection").expect("valid projection"),
                TEST_PROJECTION_INPUTS.to_vec(),
                store,
            )
            .expect("canonical target binding"),
        )
    }

    #[test]
    fn projection_selector_rejects_noncanonical_ids() {
        assert!(ProjectionId::parse("").is_err());
        assert!(ProjectionId::parse("Audit.Session").is_err());
        assert!(ProjectionId::parse("audit/session").is_err());
        assert!(ProjectionVersion::parse("v2").is_ok());
        assert!(ProjectionVersion::parse("v 2").is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn conforming_target_rejects_empty_mismatched_and_duplicate_bindings() {
        let projection = ProjectionId::parse("audit.session-projection").expect("valid projection");
        let store = Arc::new(RecordingTargetStore::default());
        assert!(matches!(
            ConformingProjectionTarget::new(projection.clone(), vec![], Arc::clone(&store)),
            Err(ProjectionTargetConfigError::EmptyBindings)
        ));
        let wrong = vocab::ProjectionInputBinding::from_static(
            "other.projection",
            "identity",
            "identity.session-created",
            "v1",
            TEST_SCHEMA_HASH,
            "identity.session.created",
        );
        assert!(matches!(
            ConformingProjectionTarget::new(projection.clone(), vec![wrong], Arc::clone(&store)),
            Err(ProjectionTargetConfigError::ProjectionMismatch)
        ));
        let binding = TEST_PROJECTION_INPUTS[0];
        assert!(matches!(
            ConformingProjectionTarget::new(projection, vec![binding, binding], store),
            Err(ProjectionTargetConfigError::DuplicateBinding)
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn fact_digest_covers_canonical_metadata_partition_and_causation() {
        let selector = projection_selector("v2");
        let store = Arc::new(RecordingTargetStore::default());
        let target = conforming_target(Arc::clone(&store));
        let metadata = |tier: &str, partition: &str, cause: &str| {
            ProjectionEventMetadata::new(
                vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                    .expect("canonical tenant"),
                "same-event",
                "identity",
                "identity.session-created",
                "v1",
                TEST_SCHEMA_HASH,
                serde_json::json!({"tier": tier, "tenantId": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}),
                Some(partition.to_string()),
                Some(cause.to_string()),
            )
        };
        for (lsn, tier, partition, cause) in
            [(1, "gold", "p-1", "c-1"), (2, "silver", "p-2", "c-2")]
        {
            let event = ProjectionEventRecord::with_metadata(
                Lsn::new(lsn),
                EventTopic::parse("identity.session.created").expect("canonical topic"),
                b"same-payload".to_vec(),
                metadata(tier, partition, cause),
            );
            assert!(matches!(
                target.apply(&selector, event).await,
                Ok(ProjectionApplyOutcome::Applied)
            ));
        }
        let digests = store.digests();
        assert_eq!(digests.len(), 2);
        assert_ne!(digests[0], digests[1]);
    }

    #[test]
    fn projection_registry_coverage_requires_target_for_each_plan_selected_projection()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut registry = ProjectionTargetRegistry::from_projection_ids(
            ["audit.session-projection"],
            TEST_PROJECTION_INPUTS,
        )?;
        assert!(matches!(
            registry.validate_coverage(),
            Err(ProjectionRegistryError::UncoveredProjection { .. })
        ));

        let projection = ProjectionId::parse("audit.session-projection")?;
        let first_store = Arc::new(RecordingTargetStore::default());
        registry.register_target_for_test(projection.clone(), conforming_target(first_store))?;
        assert!(registry.validate_coverage().is_ok());
        assert!(registry.target(&projection).is_ok());
        assert!(matches!(
            registry.register_target_for_test(
                projection.clone(),
                conforming_target(Arc::new(RecordingTargetStore::default()))
            ),
            Err(ProjectionRegistryError::DuplicateProjection { .. })
        ));

        let unknown = ProjectionId::parse("unknown.projection")?;
        assert!(matches!(
            registry.target(&unknown),
            Err(ProjectionRegistryError::UnknownProjection { .. })
        ));
        Ok(())
    }

    #[test]
    fn projection_registry_excludes_global_definitions_not_selected_by_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProjectionTargetRegistry::from_projection_ids(
            std::iter::empty::<&str>(),
            TEST_PROJECTION_INPUTS,
        )?;
        assert!(registry.is_empty());
        assert!(registry.validate_coverage().is_ok());
        assert!(matches!(
            registry.bindings_for(&ProjectionId::parse("audit.session-projection")?),
            Err(ProjectionRegistryError::UnknownProjection { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn replay_projector_filters_generated_projection_inputs_and_advances_shadow_checkpoint() {
        let selector = projection_selector("v2");
        let mut registry = ProjectionTargetRegistry::from_projection_ids(
            ["audit.session-projection"],
            TEST_PROJECTION_INPUTS,
        )
        .expect("plan-selected fixtures valid");
        let store = Arc::new(RecordingTargetStore::default());
        let target = conforming_target(Arc::clone(&store));
        registry
            .register_target_for_test(selector.projection().clone(), target.clone())
            .expect("known projection");
        registry.validate_coverage().expect("covered");

        let matching = projection_record_with(
            1,
            "identity.session.created",
            projection_metadata_for(
                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "identity",
                "identity.session-created",
                "v1",
                TEST_SCHEMA_HASH,
            ),
        );
        let wrong_tenant = projection_record_with(
            2,
            "identity.session.created",
            projection_metadata_for(
                "11111111-1111-4111-8111-111111111111",
                "identity",
                "identity.session-created",
                "v1",
                TEST_SCHEMA_HASH,
            ),
        );
        let wrong_domain = projection_record_with(
            3,
            "identity.session.created",
            projection_metadata_for(
                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "settings",
                "identity.session-created",
                "v1",
                TEST_SCHEMA_HASH,
            ),
        );
        let wrong_contract = projection_record_with(
            4,
            "billing.invoice.paid",
            projection_metadata_for(
                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "billing",
                "billing.invoice-paid",
                "v1",
                TEST_SCHEMA_HASH,
            ),
        );
        let wrong_version = projection_record_with(
            5,
            "identity.session.created",
            projection_metadata_for(
                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "identity",
                "identity.session-created",
                "v2",
                TEST_SCHEMA_HASH,
            ),
        );
        let wrong_schema_hash = projection_record_with(
            6,
            "identity.session.created",
            projection_metadata_for(
                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "identity",
                "identity.session-created",
                "v1",
                "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            ),
        );
        let wrong_topic = projection_record_with(
            7,
            "identity.role.assigned",
            projection_metadata_for(
                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "identity",
                "identity.session-created",
                "v1",
                TEST_SCHEMA_HASH,
            ),
        );
        for drift in [
            wrong_tenant,
            wrong_domain,
            wrong_version,
            wrong_schema_hash,
            wrong_topic,
        ] {
            let source = FakeProjectionSource::new(vec![drift]);
            let checkpoint = Arc::new(FakeCheckpointStore::empty());
            let harness = ProjectionHarness::new(
                Arc::new(ProjectionProjector::new(
                    selector.clone(),
                    Arc::clone(&target),
                )),
                Arc::clone(&checkpoint),
                selector.shadow_checkpoint_owner(),
                selector.shadow_checkpoint_id(),
                Arc::new(FakeDeadLetterStore::new()),
                consistency::SerialInOrder::from_source(&source),
            );
            let result = projection_runner_once(
                &source,
                &harness,
                runner_config(ProjectionPoisonPolicy::Isolate),
            )
            .await;
            assert!(matches!(
                result.stop,
                ProjectionStop::ApplyFailed {
                    kind: ProjectionApplyErrorKind::Invariant,
                    reason: ProjectionApplyErrorReason::Invariant,
                    ..
                }
            ));
            assert!(checkpoint.current().is_none());
            assert!(store.applied_lsns().is_empty());
        }
        let source = FakeProjectionSource::new(vec![matching, wrong_contract]);
        let checkpoint = Arc::new(FakeCheckpointStore::empty());
        let harness = ProjectionHarness::new(
            Arc::new(ProjectionProjector::new(selector.clone(), target)),
            Arc::clone(&checkpoint),
            selector.shadow_checkpoint_owner(),
            selector.shadow_checkpoint_id(),
            Arc::new(FakeDeadLetterStore::new()),
            consistency::SerialInOrder::from_source(&source),
        );

        let result = projection_runner_once(
            &source,
            &harness,
            runner_config(ProjectionPoisonPolicy::Isolate),
        )
        .await;

        assert_eq!(result.stop, ProjectionStop::Completed);
        assert_eq!(result.scanned, 2);
        assert_eq!(result.applied, 1);
        assert_eq!(result.filtered, 1);
        assert_eq!(result.skipped, 0);
        assert_eq!(store.applied_lsns(), vec![1]);
        assert_eq!(
            checkpoint.current().map(|checkpoint| checkpoint.offset),
            Some(Lsn::new(4)),
            "shadow checkpoint must advance through replay high-water even when target skips nonmatching events"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn shadow_replay_journey_keeps_active_pointer_until_swap_and_rollback() {
        let active_v1 = projection_selector("v1");
        let shadow_v2 = projection_selector("v2");
        let mut active = ProjectionActivePointer::new(&active_v1, Some(Lsn::new(10)));
        let mut registry = ProjectionTargetRegistry::from_projection_ids(
            ["audit.session-projection"],
            TEST_PROJECTION_INPUTS,
        )
        .expect("plan-selected fixtures valid");
        let store = Arc::new(RecordingTargetStore::default());
        let target = conforming_target(Arc::clone(&store));
        registry
            .register_target_for_test(shadow_v2.projection().clone(), target.clone())
            .expect("known projection");

        let event = projection_record_with(
            11,
            "identity.session.created",
            projection_metadata_for(
                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "identity",
                "identity.session-created",
                "v1",
                TEST_SCHEMA_HASH,
            ),
        );
        let source = FakeProjectionSource::new(vec![event]);
        let checkpoint = Arc::new(FakeCheckpointStore::empty());
        let harness = ProjectionHarness::new(
            Arc::new(ProjectionProjector::new(shadow_v2.clone(), target)),
            Arc::clone(&checkpoint),
            shadow_v2.shadow_checkpoint_owner(),
            shadow_v2.shadow_checkpoint_id(),
            Arc::new(FakeDeadLetterStore::new()),
            consistency::SerialInOrder::from_source(&source),
        );

        let result = projection_runner_once(
            &source,
            &harness,
            runner_config(ProjectionPoisonPolicy::Isolate),
        )
        .await;

        assert_eq!(result.stop, ProjectionStop::Completed);
        assert_eq!(result.scanned, 1);
        assert_eq!(result.applied, 1);
        assert_eq!(result.filtered, 0);
        assert_eq!(store.applied_lsns(), vec![11]);
        assert_eq!(active.version().as_str(), "v1", "replay must not promote");
        let shadow_high_water = checkpoint
            .current()
            .map(|checkpoint| checkpoint.offset)
            .expect("shadow checkpoint advanced");
        assert_eq!(shadow_high_water, Lsn::new(11));

        active = ProjectionActivePointer::new(&shadow_v2, Some(shadow_high_water));
        assert_eq!(active.version().as_str(), "v2");
        active = ProjectionActivePointer::new(&active_v1, Some(Lsn::new(10)));
        assert_eq!(active.version().as_str(), "v1");
    }

    // ── RecordingProjector ────────────────────────────────────────────────────

    /// 记录收到事件 lsn；可注入单点失败。
    struct RecordingProjector {
        applied: Arc<Mutex<Vec<u64>>>,
        /// 命中 `(lsn, kind)` 时返回 Err；None = 全成功。
        fail_at: Option<(u64, ProjectionApplyErrorKind)>,
    }

    impl RecordingProjector {
        fn new() -> Self {
            Self {
                applied: Arc::new(Mutex::new(vec![])),
                fail_at: None,
            }
        }
        fn failing_at(lsn: u64, kind: ProjectionApplyErrorKind) -> Self {
            Self {
                applied: Arc::new(Mutex::new(vec![])),
                fail_at: Some((lsn, kind)),
            }
        }
        fn applied_lsns(&self) -> Vec<u64> {
            // reason: Mutex 毒化只在 test panic 时触发，into_inner 安全恢复（MemCheckpointStore 同范式）。
            self.applied
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl Projector for RecordingProjector {
        async fn apply<E: ProjectionEvent>(
            &self,
            event: &E,
        ) -> Result<ProjectionApplyOutcome, ProjectionApplyError> {
            let lsn = event.lsn().get();
            // if-let chain 消除嵌套 if（collapsible_if 修复）。
            if let Some((_, kind)) = self.fail_at.filter(|&(fl, _)| fl == lsn) {
                return Err(ProjectionApplyError::new(kind));
            }
            self.applied
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(lsn);
            Ok(ProjectionApplyOutcome::Applied)
        }
    }

    // ── FakeCheckpointStore ───────────────────────────────────────────────────

    /// 内联 fake checkpoint store（复刻 MemCheckpointStore CAS 语义）。
    struct FakeCheckpointStore {
        /// `(offset, current_version)` 或 `None`（无记录）。
        state: Mutex<Option<(Lsn, CheckpointVersion)>>,
        /// 置 true → save 恒 StaleVersion（并发 fence 测试）。
        force_stale: bool,
        /// 置 true → get_checkpoint 返 Err（infra 故障测试）。
        fail_get: bool,
        /// 置 true → save_checkpoint 返 Err（infra 故障测试）。
        fail_save: bool,
    }

    impl FakeCheckpointStore {
        /// 空 store（无记录）。
        fn empty() -> Self {
            Self {
                state: Mutex::new(None),
                force_stale: false,
                fail_get: false,
                fail_save: false,
            }
        }

        /// 预置 offset + version（模拟前一轮已保存）。
        fn preset(offset: Lsn, version: CheckpointVersion) -> Self {
            Self {
                state: Mutex::new(Some((offset, version))),
                force_stale: false,
                fail_get: false,
                fail_save: false,
            }
        }

        /// 强制 save 返 StaleVersion。
        fn force_stale() -> Self {
            Self {
                force_stale: true,
                ..Self::empty()
            }
        }

        /// get 返 Err（infra 故障）。
        fn fail_get() -> Self {
            Self {
                fail_get: true,
                ..Self::empty()
            }
        }

        /// save 返 Err（infra 故障）。
        fn fail_save() -> Self {
            Self {
                fail_save: true,
                ..Self::empty()
            }
        }

        /// 读当前 checkpoint（测试断言用）。
        fn current(&self) -> Option<Checkpoint> {
            // reason: Mutex 毒化仅 test panic，into_inner 安全恢复。
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .map(|(offset, version)| Checkpoint { offset, version })
        }
    }

    /// FakeCheckpointStore 内部 Err 源（infra 故障 stub）。
    #[derive(Debug, thiserror::Error)]
    #[error("fake store error")]
    struct FakeStoreError;

    impl OwnerCheckpointStore for FakeCheckpointStore {
        async fn get_checkpoint(
            &self,
            _owner: &CheckpointOwner,
            _id: &CheckpointId,
        ) -> Result<Option<Checkpoint>, CheckpointStoreError> {
            if self.fail_get {
                return Err(CheckpointStoreError::new(FakeStoreError));
            }
            // reason: Mutex 毒化仅 test panic，into_inner 安全恢复。
            let g = self.state.lock().unwrap_or_else(|e| e.into_inner());
            Ok(g.map(|(offset, version)| Checkpoint { offset, version }))
        }

        async fn save_checkpoint(
            &self,
            _owner: &CheckpointOwner,
            _id: &CheckpointId,
            offset: Lsn,
            expected: CheckpointVersion,
        ) -> Result<SaveOutcome, CheckpointStoreError> {
            if self.fail_save {
                return Err(CheckpointStoreError::new(FakeStoreError));
            }
            if self.force_stale {
                return Ok(SaveOutcome::StaleVersion);
            }
            // reason: Mutex 毒化仅 test panic，into_inner 安全恢复。
            let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
            match *g {
                // 首存：expected == INITIAL（0）= 期望无既存行。
                None if expected == CheckpointVersion::INITIAL => {
                    *g = Some((offset, CheckpointVersion::INITIAL.next()));
                    Ok(SaveOutcome::Saved)
                }
                // CAS 更新：stored_version == expected → 推进版本。
                Some((_, stored_ver)) if stored_ver == expected => {
                    *g = Some((offset, expected.next()));
                    Ok(SaveOutcome::Saved)
                }
                // 其余：版本失配（并发写或不匹配首存）→ StaleVersion。
                _ => Ok(SaveOutcome::StaleVersion),
            }
        }

        async fn shutdown(&self) -> Result<(), CheckpointStoreError> {
            // reason: fake store 无 infra 资源，关闭无需操作。
            Ok(())
        }
    }

    // ── FakeDeadLetterStore ──────────────────────────────────────────────────

    #[derive(Default)]
    struct FakeDeadLetterStore {
        records: Mutex<Vec<DeadLetterRecord>>,
        fail_write: bool,
    }

    impl FakeDeadLetterStore {
        fn new() -> Self {
            Self::default()
        }

        fn fail_write() -> Self {
            Self {
                fail_write: true,
                ..Self::default()
            }
        }

        fn records(&self) -> Vec<DeadLetterRecord> {
            self.records
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl DeadLetterStore for FakeDeadLetterStore {
        async fn write_dead_letter(
            &self,
            record: DeadLetterRecord,
        ) -> Result<(), DeadLetterStoreError> {
            if self.fail_write {
                return Err(DeadLetterStoreError::new(std::io::Error::other(
                    "fake dlq unavailable",
                )));
            }
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            if !records
                .iter()
                .any(|existing| existing.message_id() == record.message_id())
            {
                records.push(record);
            }
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
    }

    // ── 测试辅助 ──────────────────────────────────────────────────────────────

    fn harness(projector: RecordingProjector, store: FakeCheckpointStore) -> HarnessParts {
        harness_with_dlx(projector, store, FakeDeadLetterStore::new())
    }

    fn harness_with_dlx(
        projector: RecordingProjector,
        store: FakeCheckpointStore,
        dlx: FakeDeadLetterStore,
    ) -> HarnessParts {
        // 测试 fake 串行 source（#[cfg(test)] 豁免 rss_partition_serial_allowlist dylint，
        // `cargo dylint --all` 默认不扫 test targets）。
        struct SerialFake;
        impl PartitionSerialDelivery for SerialFake {}

        let p = Arc::new(projector);
        let c = Arc::new(store);
        let d = Arc::new(dlx);
        let h = ProjectionHarness::new(
            Arc::clone(&p),
            Arc::clone(&c),
            CheckpointOwner::new("test-owner"),
            CheckpointId::new("test-proj"),
            Arc::clone(&d),
            consistency::SerialInOrder::from_source(&SerialFake),
        );
        (h, p, c, d)
    }

    fn assert_projection_dlx(record: &DeadLetterRecord, lsn: u64, summary: &str) {
        assert_eq!(record.source(), DeadLetterSource::Projection);
        assert_eq!(
            record.message_id(),
            format!("projection:test-owner:test-proj:{lsn}")
        );
        assert_eq!(record.consumer_group(), Some("test-proj"));
        assert_eq!(record.producer_domain(), "test");
        assert_eq!(record.consumer_domain(), Some("test-owner"));
        assert_eq!(record.contract_id(), "test.projection-event");
        assert_eq!(record.topic(), "proj.test");
        assert_eq!(record.error_summary(), summary);
        assert_eq!(record.num_attempts(), 1);
    }

    // ── 用例 ──────────────────────────────────────────────────────────────────

    /// 1. 无 ckpt 全量重放：events 1..=100 全部 apply，checkpoint 从 None 推进到 offset=100。
    // reason: 测试断言用 expect，checkpoint 必须存在（逻辑断言，非生产 error handling）。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn fresh_replay_applies_all() {
        let (h, p, c, _d) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());
        let events = evs(1, 100);
        let result = h.run(&events).await;

        assert_eq!(result.applied, 100);
        assert_eq!(result.skipped, 0);
        assert_eq!(result.stop, ProjectionStop::Completed);

        let ckpt = c.current().expect("checkpoint should be saved");
        assert_eq!(ckpt.offset, Lsn::new(100));
        assert_eq!(ckpt.version, CheckpointVersion::new(1));

        let lsns = p.applied_lsns();
        assert_eq!(lsns, (1u64..=100).collect::<Vec<_>>());
    }

    /// 2. 断点续投：预置 ckpt offset=50，跑 1..=100 → 跳过前 50，apply 51..=100。
    // reason: 测试断言用 expect。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn resume_skips_consumed_prefix() {
        let (h, p, c, _d) = harness(
            RecordingProjector::new(),
            FakeCheckpointStore::preset(Lsn::new(50), CheckpointVersion::new(1)),
        );
        let events = evs(1, 100);
        let result = h.run(&events).await;

        assert_eq!(result.applied, 50);
        assert_eq!(result.skipped, 50);
        assert_eq!(result.stop, ProjectionStop::Completed);

        let ckpt = c.current().expect("checkpoint should be updated");
        assert_eq!(ckpt.offset, Lsn::new(100));
        assert_eq!(ckpt.version, CheckpointVersion::new(2));

        let lsns = p.applied_lsns();
        assert_eq!(lsns, (51u64..=100).collect::<Vec<_>>());
    }

    /// 3. 全量重跑 no-op：预置 ckpt offset=100，再跑 1..=100 → 全跳过，checkpoint 不变。
    // reason: 测试断言用 expect。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn rerun_full_window_is_noop() {
        let (h, p, c, _d) = harness(
            RecordingProjector::new(),
            FakeCheckpointStore::preset(Lsn::new(100), CheckpointVersion::new(2)),
        );
        let events = evs(1, 100);
        let result = h.run(&events).await;

        assert_eq!(result.applied, 0);
        assert_eq!(result.skipped, 100);
        assert_eq!(result.stop, ProjectionStop::Completed);

        // checkpoint 未变（无 CAS 写）。
        let ckpt = c.current().expect("checkpoint should still exist");
        assert_eq!(ckpt.offset, Lsn::new(100));
        assert_eq!(ckpt.version, CheckpointVersion::new(2));

        assert!(
            p.applied_lsns().is_empty(),
            "projector should not be called"
        );
    }

    /// 4. lsn=0 首事件不跳过（None baseline 下 lsn=0 不满足 lsn<=b）。
    #[tokio::test]
    async fn lsn_zero_first_event_not_skipped() {
        let (h, _p, _c, _d) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());
        let events = vec![ev(0), ev(1), ev(2)];
        let result = h.run(&events).await;

        assert_eq!(result.applied, 3, "lsn=0 must not be skipped");
        assert_eq!(result.skipped, 0);
        assert_eq!(result.stop, ProjectionStop::Completed);
    }

    /// 5. 空批：applied=0, skipped=0, Completed，checkpoint 未写。
    #[tokio::test]
    async fn empty_batch_noop() {
        let (h, _p, c, _d) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());
        let result = h.run::<FakeEvent>(&[]).await;

        assert_eq!(
            result,
            ProjectionRun {
                scanned: 0,
                applied: 0,
                duplicates: 0,
                filtered: 0,
                skipped: 0,
                dead_lettered: 0,
                stop: ProjectionStop::Completed,
            }
        );
        assert!(c.current().is_none(), "no checkpoint should be written");
    }

    /// 6. 瞬时失败在第 3 条：apply 1,2 成功，3 失败停批；ckpt offset=2；projector 见 [1,2]。
    // reason: 测试断言用 expect。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn transient_failure_stops_keeps_prefix() {
        let (h, p, c, d) = harness(
            RecordingProjector::failing_at(3, ProjectionApplyErrorKind::Transient),
            FakeCheckpointStore::empty(),
        );
        let events = evs(1, 5);
        let result = h.run(&events).await;

        assert_eq!(result.applied, 2);
        assert_eq!(
            result.stop,
            ProjectionStop::ApplyFailed {
                failed_at: Lsn::new(3),
                kind: ProjectionApplyErrorKind::Transient,
                reason: ProjectionApplyErrorReason::Transient,
            }
        );

        let ckpt = c.current().expect("prefix checkpoint should be saved");
        assert_eq!(ckpt.offset, Lsn::new(2));

        assert_eq!(p.applied_lsns(), vec![1u64, 2]);
        assert!(
            d.records().is_empty(),
            "transient projection failure must not write DLQ"
        );
    }

    /// 7. 永久失败：写 projection DLQ 后 fail-closed，不自动 skip。
    // reason: 测试断言用 expect。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn permanent_failure_writes_projection_dlx_and_stops_without_auto_skip() {
        let (h, _p, c, d) = harness(
            RecordingProjector::failing_at(3, ProjectionApplyErrorKind::Permanent),
            FakeCheckpointStore::empty(),
        );
        let result = h.run(&evs(1, 5)).await;

        assert_eq!(
            result.stop,
            ProjectionStop::ApplyFailed {
                failed_at: Lsn::new(3),
                kind: ProjectionApplyErrorKind::Permanent,
                reason: ProjectionApplyErrorReason::Permanent,
            }
        );
        let ckpt = c.current().expect("prefix checkpoint should be saved");
        assert_eq!(ckpt.offset, Lsn::new(2));
        let records = d.records();
        assert_eq!(records.len(), 1);
        assert_projection_dlx(&records[0], 3, "projection apply permanent");

        let rerun = h.run(&evs(1, 5)).await;
        assert_eq!(
            rerun.stop,
            ProjectionStop::ApplyFailed {
                failed_at: Lsn::new(3),
                kind: ProjectionApplyErrorKind::Permanent,
                reason: ProjectionApplyErrorReason::Permanent,
            }
        );
        assert_eq!(
            d.records().len(),
            1,
            "projection DLQ message id must be idempotent"
        );
    }

    /// 8. Invariant 失败：写 projection DLQ，stop=ApplyFailed{kind:Invariant}。
    #[tokio::test]
    async fn invariant_failure_writes_projection_dlx_and_stops() {
        let (h, _p, _c, d) = harness(
            RecordingProjector::failing_at(3, ProjectionApplyErrorKind::Invariant),
            FakeCheckpointStore::empty(),
        );
        let result = h.run(&evs(1, 5)).await;

        assert_eq!(
            result.stop,
            ProjectionStop::ApplyFailed {
                failed_at: Lsn::new(3),
                kind: ProjectionApplyErrorKind::Invariant,
                reason: ProjectionApplyErrorReason::Invariant,
            }
        );
        let records = d.records();
        assert_eq!(records.len(), 1);
        assert_projection_dlx(&records[0], 3, "projection apply invariant");
    }

    /// 8b. poison DLQ 写失败：不推进 checkpoint。
    #[tokio::test]
    async fn projection_dlx_write_failure_does_not_advance_checkpoint() {
        let (h, _p, c, _d) = harness_with_dlx(
            RecordingProjector::failing_at(3, ProjectionApplyErrorKind::Permanent),
            FakeCheckpointStore::empty(),
            FakeDeadLetterStore::fail_write(),
        );
        let result = h.run(&evs(1, 5)).await;

        assert_eq!(
            result.stop,
            ProjectionStop::DeadLetterUnsaved {
                failed_at: Lsn::new(3)
            }
        );
        assert_eq!(result.applied, 2);
        assert!(
            c.current().is_none(),
            "DLQ write failure must not advance checkpoint"
        );
    }

    /// 9. 首条即失败：applied=0, checkpoint 未写（high_water=None → NoChange）。
    #[tokio::test]
    async fn first_event_fails_no_checkpoint_write() {
        let (h, _p, c, _d) = harness(
            RecordingProjector::failing_at(1, ProjectionApplyErrorKind::Transient),
            FakeCheckpointStore::empty(),
        );
        let result = h.run(&evs(1, 3)).await;

        assert_eq!(result.applied, 0);
        assert!(
            matches!(result.stop, ProjectionStop::ApplyFailed { .. }),
            "stop should be ApplyFailed"
        );
        assert!(c.current().is_none(), "checkpoint must not be written");
    }

    /// 10. CAS StaleVersion：projector 全部投完但 checkpoint 被 fence → Fenced。
    #[tokio::test]
    async fn stale_version_reports_fenced() {
        let (h, p, _c, _d) = harness(
            RecordingProjector::new(),
            FakeCheckpointStore::force_stale(),
        );
        let result = h.run(&evs(1, 3)).await;

        assert_eq!(result.stop, ProjectionStop::Fenced);
        // apply 已发生（投影写已生效）。
        assert_eq!(p.applied_lsns(), vec![1u64, 2, 3]);
    }

    /// 11. checkpoint save infra 故障：stop=CheckpointUnsaved，applied 计数正常。
    #[tokio::test]
    async fn checkpoint_save_infra_error_reports_unsaved() {
        let (h, p, _c, _d) = harness(RecordingProjector::new(), FakeCheckpointStore::fail_save());
        let result = h.run(&evs(1, 5)).await;

        assert_eq!(result.stop, ProjectionStop::CheckpointUnsaved);
        assert_eq!(result.applied, 5);
        assert_eq!(p.applied_lsns(), (1u64..=5).collect::<Vec<_>>());
    }

    /// 12. checkpoint get infra 故障：**fail-closed**——不 apply 任何事件，stop = CheckpointUnread
    ///     （不降级为空 baseline 盲目重放；caller 据此退避 / 报警 / 重试）。
    #[tokio::test]
    async fn checkpoint_read_infra_error_fails_closed() {
        let (h, p, _c, _d) = harness(RecordingProjector::new(), FakeCheckpointStore::fail_get());
        let events = evs(1, 5);
        let result = h.run(&events).await;

        // read 失败 → 零 apply、零 skip、CheckpointUnread；投影器从未被调用。
        assert_eq!(result.stop, ProjectionStop::CheckpointUnread);
        assert_eq!(result.applied, 0);
        assert_eq!(result.skipped, 0);
        assert!(
            p.applied_lsns().is_empty(),
            "fail-closed：checkpoint 读失败时投影器不应收到任何事件"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: tracing capture test uses Mutex/runtime construction as test assertions.
    fn projection_infra_errors_log_redacted_error_field() {
        use std::collections::HashMap;
        use tracing::field::{Field, Visit};
        use tracing::subscriber::Interest;
        use tracing::{Event, Id, Metadata, span};

        struct Captured {
            events: Mutex<Vec<HashMap<String, String>>>,
        }

        struct CapVisit {
            current: HashMap<String, String>,
        }

        impl Visit for CapVisit {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.current
                    .insert(field.name().to_string(), format!("{value:?}"));
            }

            fn record_str(&mut self, field: &Field, value: &str) {
                self.current
                    .insert(field.name().to_string(), value.to_string());
            }
        }

        struct CapSubscriber {
            captured: Arc<Captured>,
        }

        impl tracing::Subscriber for CapSubscriber {
            fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
                Interest::always()
            }

            fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
                true
            }

            fn new_span(&self, _span: &span::Attributes<'_>) -> Id {
                Id::from_u64(1)
            }

            fn record(&self, _span: &Id, _values: &span::Record<'_>) {}
            fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
            fn enter(&self, _span: &Id) {}
            fn exit(&self, _span: &Id) {}

            fn event(&self, event: &Event<'_>) {
                if *event.metadata().level() != tracing::Level::ERROR {
                    return;
                }
                let mut visitor = CapVisit {
                    current: HashMap::new(),
                };
                event.record(&mut visitor);
                self.captured.events.lock().unwrap().push(visitor.current);
            }
        }

        let captured = Arc::new(Captured {
            events: Mutex::new(vec![]),
        });
        let subscriber = CapSubscriber {
            captured: Arc::clone(&captured),
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        tracing::subscriber::with_default(subscriber, || {
            rt.block_on(async {
                let (read_harness, _p, _c, _d) =
                    harness(RecordingProjector::new(), FakeCheckpointStore::fail_get());
                let _ = read_harness.run(&evs(1, 1)).await;

                let source = FakeProjectionSource::fail(EngineErrorKind::Transient);
                let (source_harness, _p, _c, _d) = harness(
                    RecordingProjector::new(),
                    FakeCheckpointStore::preset(Lsn::new(10), CheckpointVersion::new(1)),
                );
                let _ = projection_runner_once(
                    &source,
                    &source_harness,
                    runner_config(ProjectionPoisonPolicy::Isolate),
                )
                .await;
            });
        });

        let events = captured.events.lock().unwrap();
        let error_fields: Vec<&str> = events
            .iter()
            .filter_map(|event| event.get("error").map(String::as_str))
            .collect();

        assert!(
            error_fields
                .iter()
                .any(|value| value.contains("transient engine error")),
            "source read log must preserve safe engine error summary: {error_fields:?}"
        );
        assert!(
            error_fields
                .iter()
                .all(|value| !value.contains("fake store")),
            "checkpoint logs must not expose redacted inner source: {error_fields:?}"
        );
        let source_event = events.iter().find(|event| {
            event
                .get("message")
                .is_some_and(|value| value.contains("projection: source read failed"))
        });
        assert!(
            source_event.is_some(),
            "must capture source read failure log: {events:?}"
        );
        let source_event = source_event.unwrap();
        assert!(
            source_event
                .get("kind")
                .is_some_and(|value| value.contains("Transient")),
            "source read log must include closed error kind field: {events:?}"
        );
        assert!(
            source_event
                .get("after_lsn")
                .is_some_and(|value| value == "10"),
            "source read log must include checkpoint cursor: {events:?}"
        );
        assert!(
            source_event
                .get("batch_limit")
                .is_some_and(|value| { value == &ProjectionBatchLimit::MAX.get().to_string() }),
            "source read log must include batch limit: {events:?}"
        );
    }

    /// 13. apply 失败 + checkpoint 被 fence：advance 主导，stop = Fenced（非 ApplyFailed）。
    ///
    /// lsn=1,2 成功，lsn=3 失败（high_water=2）→ CAS 推进到 2，但 force_stale → Fenced。
    /// stop_of(Fenced, Some(...)) = Fenced（fence 优先，advance 优先于 failure）。
    #[tokio::test]
    async fn apply_failure_during_fence_reports_fenced() {
        let (h, p, _c, _d) = harness(
            RecordingProjector::failing_at(3, ProjectionApplyErrorKind::Transient),
            FakeCheckpointStore::force_stale(),
        );
        let result = h.run(&evs(1, 5)).await;

        assert_eq!(
            result.stop,
            ProjectionStop::Fenced,
            "fence 优先于 apply 失败"
        );
        assert_eq!(result.applied, 2, "lsn=1,2 已成功 apply");
        assert_eq!(p.applied_lsns(), vec![1u64, 2]);
    }

    /// 14. apply 失败 + checkpoint save infra 故障：advance 主导，stop = CheckpointUnsaved。
    ///
    /// lsn=1,2 成功，lsn=3 失败（high_water=2）→ CAS 推进到 2，但 fail_save → Unsaved。
    /// stop_of(Unsaved, Some(...)) = CheckpointUnsaved（advance 优先于 failure）。
    #[tokio::test]
    async fn apply_failure_during_unsaved_reports_unsaved() {
        let (h, p, _c, _d) = harness(
            RecordingProjector::failing_at(3, ProjectionApplyErrorKind::Transient),
            FakeCheckpointStore::fail_save(),
        );
        let result = h.run(&evs(1, 5)).await;

        assert_eq!(
            result.stop,
            ProjectionStop::CheckpointUnsaved,
            "checkpoint save 故障优先于 apply 失败"
        );
        assert_eq!(result.applied, 2, "lsn=1,2 已成功 apply");
        assert_eq!(p.applied_lsns(), vec![1u64, 2]);
    }

    /// 15. 乱序事件 **release 也 fail-closed**（F1，#1211 review）：不 panic、不静默 apply 越过。
    ///
    /// 传入 [ev(1), ev(2), ev(5), ev(3)]：apply 1/2/5（high_water=5）后 ev(3) lsn < prev=5 →
    /// 停批，ev(3) 不 apply；stop=OutOfOrder{failed_at=3}，不把 checkpoint 推过 poison lsn=3。
    #[tokio::test]
    async fn out_of_order_events_stop_fail_closed() {
        let (h, p, c, d) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());
        let events = vec![ev(1), ev(2), ev(5), ev(3)];
        let result = h.run(&events).await;

        assert_eq!(
            result.stop,
            ProjectionStop::OutOfOrder {
                failed_at: Lsn::new(3)
            },
            "乱序 release 也 fail-closed 停批，报 OutOfOrder"
        );
        assert_eq!(result.applied, 3, "仅 lsn=1,2,5 已 apply（ev(3) 未 apply）");
        assert_eq!(p.applied_lsns(), vec![1u64, 2, 5], "ev(3) 不被 apply");
        assert!(
            c.current().is_none(),
            "out-of-order poison must not advance checkpoint past failed lsn"
        );
        let records = d.records();
        assert_eq!(records.len(), 1);
        assert_projection_dlx(&records[0], 3, "projection out of order");
        // anti-vacuity：合法升序批不触发 OutOfOrder（全 apply、Completed）。
        let (h2, p2, _c2, _d2) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());
        let ok = h2.run(&evs(1, 4)).await;
        assert_eq!(ok.stop, ProjectionStop::Completed, "升序批正常完成");
        assert_eq!(p2.applied_lsns(), vec![1u64, 2, 3, 4]);
    }

    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn runner_reads_from_checkpoint_offset_and_commits_high_water() {
        let source = FakeProjectionSource::new(projection_records(1, 100));
        let (h, p, c, _d) = harness(
            RecordingProjector::new(),
            FakeCheckpointStore::preset(Lsn::new(50), CheckpointVersion::new(1)),
        );

        let result =
            projection_runner_once(&source, &h, runner_config(ProjectionPoisonPolicy::Isolate))
                .await;

        assert_eq!(
            source.read_calls(),
            vec![(Some(50), ProjectionBatchLimit::MAX.get())]
        );
        assert_eq!(result.applied, 50);
        assert_eq!(result.skipped, 0);
        assert_eq!(result.stop, ProjectionStop::Completed);
        assert_eq!(p.applied_lsns(), (51u64..=100).collect::<Vec<_>>());
        let ckpt = c.current().expect("checkpoint should be updated");
        assert_eq!(ckpt.offset, Lsn::new(100));
    }

    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn runner_empty_batch_does_not_write_checkpoint() {
        let source = FakeProjectionSource::new(vec![]);
        let (h, _p, c, _d) = harness(
            RecordingProjector::new(),
            FakeCheckpointStore::preset(Lsn::new(10), CheckpointVersion::new(3)),
        );

        let result =
            projection_runner_once(&source, &h, runner_config(ProjectionPoisonPolicy::Isolate))
                .await;

        assert_eq!(
            source.read_calls(),
            vec![(Some(10), ProjectionBatchLimit::MAX.get())]
        );
        assert_eq!(result.stop, ProjectionStop::Completed);
        let ckpt = c.current().expect("checkpoint should remain unchanged");
        assert_eq!(ckpt.offset, Lsn::new(10));
        assert_eq!(ckpt.version, CheckpointVersion::new(3));
    }

    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn runner_empty_checkpoint_reads_from_source_start_including_lsn_zero() {
        let source = FakeProjectionSource::new(projection_records(0, 2));
        let (h, p, c, _d) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());

        let result =
            projection_runner_once(&source, &h, runner_config(ProjectionPoisonPolicy::Isolate))
                .await;

        assert_eq!(
            source.read_calls(),
            vec![(None, ProjectionBatchLimit::MAX.get())]
        );
        assert_eq!(result.stop, ProjectionStop::Completed);
        assert_eq!(result.applied, 3);
        assert_eq!(p.applied_lsns(), vec![0u64, 1, 2]);
        let ckpt = c.current().expect("checkpoint should advance");
        assert_eq!(ckpt.offset, Lsn::new(2));
    }

    #[tokio::test]
    async fn source_read_transient_waits_without_checkpoint_advance() {
        let source = FakeProjectionSource::fail(EngineErrorKind::Transient);
        let (h, p, c, _d) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());

        let result =
            projection_runner_once(&source, &h, runner_config(ProjectionPoisonPolicy::Isolate))
                .await;

        assert_eq!(
            result.stop,
            ProjectionStop::SourceReadFailed {
                kind: EngineErrorKind::Transient
            }
        );
        assert_eq!(
            projection_loop_action(&result, ProjectionBatchLimit::MAX),
            ProjectionLoopAction::Wait
        );
        assert_eq!(result.applied, 0);
        assert_eq!(result.skipped, 0);
        assert!(p.applied_lsns().is_empty());
        assert!(c.current().is_none());
    }

    #[test]
    fn commit_unknown_waits_but_rollback_failed_stops() {
        let failed = |kind, reason| ProjectionRun {
            scanned: 1,
            applied: 0,
            duplicates: 0,
            filtered: 0,
            skipped: 0,
            dead_lettered: 0,
            stop: ProjectionStop::ApplyFailed {
                failed_at: Lsn::new(1),
                kind,
                reason,
            },
        };
        assert_eq!(
            projection_loop_action(
                &failed(
                    ProjectionApplyErrorKind::CommitUnknown,
                    ProjectionApplyErrorReason::CommitUnknown,
                ),
                ProjectionBatchLimit::MAX,
            ),
            ProjectionLoopAction::Wait
        );
        assert_eq!(
            projection_loop_action(
                &failed(
                    ProjectionApplyErrorKind::RollbackFailed,
                    ProjectionApplyErrorReason::RollbackFailed,
                ),
                ProjectionBatchLimit::MAX,
            ),
            ProjectionLoopAction::Stop
        );
    }

    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn worker_loop_replays_commit_unknown_while_degraded_until_duplicate() {
        let token = CancellationToken::new();
        let health = Arc::new(WorkerHealth::healthy());
        let baselines = Arc::new(Mutex::new(vec![]));
        let saw_degraded_retry = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(AtomicUsize::new(0));
        let source = CommitUnknownReplaySource {
            event: projection_record(1),
            token: token.clone(),
            health: Arc::clone(&health),
            baselines: Arc::clone(&baselines),
            saw_degraded_retry: Arc::clone(&saw_degraded_retry),
        };
        let serial = consistency::SerialInOrder::from_source(&source);
        let checkpoint = Arc::new(FakeCheckpointStore::empty());
        let harness = ProjectionHarness::new(
            Arc::new(CommitUnknownThenDuplicate {
                attempts: Arc::clone(&attempts),
            }),
            Arc::clone(&checkpoint),
            CheckpointOwner::new("commit-unknown-loop"),
            CheckpointId::new("commit-unknown-loop"),
            Arc::new(FakeDeadLetterStore::new()),
            serial,
        );

        tokio::time::timeout(
            Duration::from_secs(2),
            projection_runner_loop(
                source,
                harness,
                runner_config(ProjectionPoisonPolicy::Isolate),
                token,
                health,
            ),
        )
        .await
        .expect("worker loop must converge and cancel");

        assert!(saw_degraded_retry.load(Ordering::Acquire));
        assert_eq!(attempts.load(Ordering::Acquire), 2);
        assert_eq!(
            baselines
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_slice(),
            &[None, None, Some(1)]
        );
        assert_eq!(
            checkpoint.current().map(|current| current.offset),
            Some(Lsn::new(1))
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: 断言 RedactedSource 链保留；Option 缺失即测试失败路径。
    fn target_store_error_redacts_provider_cause_chain() {
        let error = ProjectionTargetStoreError::new(
            ProjectionTargetStoreErrorKind::Transient,
            std::io::Error::other("postgres://admin:hunter2@db.internal/projection"),
        );
        assert_eq!(error.to_string(), "projection target store apply failed");
        let debug = format!("{error:?}");
        assert!(!debug.contains("hunter2") && !debug.contains("postgres://"));
        assert!(debug.contains("RedactedSource(<redacted>)"));
        let source = std::error::Error::source(&error).expect("redacted source must be retained");
        assert_eq!(source.to_string(), "<redacted>");
        assert!(
            source.source().is_none(),
            "raw provider cause must be sealed"
        );
    }

    #[tokio::test]
    async fn source_read_permanent_or_invariant_stops() {
        for kind in [EngineErrorKind::Permanent, EngineErrorKind::Invariant] {
            let source = FakeProjectionSource::fail(kind);
            let (h, _p, _c, _d) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());

            let result =
                projection_runner_once(&source, &h, runner_config(ProjectionPoisonPolicy::Isolate))
                    .await;

            assert_eq!(result.stop, ProjectionStop::SourceReadFailed { kind });
            assert_eq!(
                projection_loop_action(&result, ProjectionBatchLimit::MAX),
                ProjectionLoopAction::Stop
            );
        }
    }

    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn skip_policy_advances_permanent_poison_after_dlx() {
        let source = FakeProjectionSource::new(projection_records(1, 5));
        let (h, p, c, d) = harness(
            RecordingProjector::failing_at(3, ProjectionApplyErrorKind::Permanent),
            FakeCheckpointStore::empty(),
        );

        let result = projection_runner_once(
            &source,
            &h,
            runner_config(ProjectionPoisonPolicy::SkipPermanentAfterDlx),
        )
        .await;

        assert_eq!(
            result.stop,
            ProjectionStop::PoisonSkipped {
                skipped_at: Lsn::new(3),
                kind: ProjectionApplyErrorKind::Permanent,
            }
        );
        assert_eq!(result.applied, 2);
        assert_eq!(result.skipped, 1);
        let ckpt = c.current().expect("poison skip should commit checkpoint");
        assert_eq!(ckpt.offset, Lsn::new(3));
        assert_eq!(d.records().len(), 1);
        assert_projection_dlx(&d.records()[0], 3, "projection apply permanent");
        let health = WorkerHealth::healthy();
        record_projection_health(&result, &health);
        assert_eq!(
            health.status(),
            HealthStatus::Degraded,
            "skipping a poison event must surface degraded worker health"
        );

        let next = projection_runner_once(
            &source,
            &h,
            runner_config(ProjectionPoisonPolicy::SkipPermanentAfterDlx),
        )
        .await;
        assert_eq!(next.stop, ProjectionStop::Completed);
        assert_eq!(p.applied_lsns(), vec![1u64, 2, 4, 5]);
        let ckpt = c
            .current()
            .expect("checkpoint should advance past later events");
        assert_eq!(ckpt.offset, Lsn::new(5));
    }

    #[tokio::test]
    async fn skip_policy_does_not_skip_invariant() {
        let source = FakeProjectionSource::new(projection_records(1, 5));
        let (h, _p, c, d) = harness(
            RecordingProjector::failing_at(3, ProjectionApplyErrorKind::Invariant),
            FakeCheckpointStore::empty(),
        );

        let result = projection_runner_once(
            &source,
            &h,
            runner_config(ProjectionPoisonPolicy::SkipPermanentAfterDlx),
        )
        .await;

        assert_eq!(
            result.stop,
            ProjectionStop::ApplyFailed {
                failed_at: Lsn::new(3),
                kind: ProjectionApplyErrorKind::Invariant,
                reason: ProjectionApplyErrorReason::Invariant,
            }
        );
        assert_eq!(c.current().map(|cp| cp.offset), Some(Lsn::new(2)));
        assert_eq!(d.records().len(), 1);
    }

    #[tokio::test]
    async fn skip_policy_does_not_skip_out_of_order() {
        let source = FakeProjectionSource::new(vec![
            projection_record(1),
            projection_record(2),
            projection_record(5),
            projection_record(3),
        ]);
        let (h, _p, c, d) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());

        let result = projection_runner_once(
            &source,
            &h,
            runner_config(ProjectionPoisonPolicy::SkipPermanentAfterDlx),
        )
        .await;

        assert_eq!(
            result.stop,
            ProjectionStop::OutOfOrder {
                failed_at: Lsn::new(3)
            }
        );
        assert!(c.current().is_none());
        assert_eq!(d.records().len(), 1);
    }

    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn projection_dlx_preserves_reserved_envelope_headers_without_tenant_authority() {
        let tenant_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
        let schema_hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let event = ProjectionEventRecord::with_metadata(
            Lsn::new(7),
            EventTopic::parse("inventory.projected").expect("valid topic"),
            b"payload".to_vec(),
            ProjectionEventMetadata::new(
                vocab::TenantId::parse(tenant_id).expect("canonical tenant"),
                "event-reserved",
                "inventory",
                "contract-projection",
                "v2",
                schema_hash,
                serde_json::json!({
                    KEY_TENANT_ID: tenant_id,
                    KEY_SCHEMA_VERSION: "v2",
                    KEY_SCHEMA_HASH: schema_hash,
                    KEY_TENANT_AUTHORITY: "SECRET_AUTHORITY",
                    "customerTier": "gold"
                }),
                Some("inventory:sku-1".to_string()),
                Some("cause-1".to_string()),
            ),
        );
        let (h, _p, _c, d) = harness(
            RecordingProjector::failing_at(7, ProjectionApplyErrorKind::Permanent),
            FakeCheckpointStore::empty(),
        );

        let result = h.run(&[event]).await;

        assert_eq!(
            result.stop,
            ProjectionStop::ApplyFailed {
                failed_at: Lsn::new(7),
                kind: ProjectionApplyErrorKind::Permanent,
                reason: ProjectionApplyErrorReason::Permanent,
            }
        );
        let record = d
            .records()
            .pop()
            .expect("permanent projection error should write DLQ");
        let metadata = record.metadata();
        assert_eq!(metadata.get(KEY_TENANT_ID), Some(tenant_id));
        assert_eq!(metadata.get(KEY_SCHEMA_VERSION), Some("v2"));
        assert_eq!(metadata.get(KEY_SCHEMA_HASH), Some(schema_hash));
        assert_eq!(metadata.get("customerTier"), Some("gold"));
        assert_eq!(metadata.get("partitionKey"), Some("inventory:sku-1"));
        assert_eq!(metadata.get("causationId"), Some("cause-1"));
        assert!(
            metadata.get(KEY_TENANT_AUTHORITY).is_none(),
            "tenantAuthority must not be propagated to projection DLQ metadata"
        );
    }

    #[tokio::test]
    async fn skip_policy_dlx_write_failure_keeps_poison_unskipped() {
        let source = FakeProjectionSource::new(projection_records(1, 5));
        let (h, _p, c, _d) = harness_with_dlx(
            RecordingProjector::failing_at(3, ProjectionApplyErrorKind::Permanent),
            FakeCheckpointStore::empty(),
            FakeDeadLetterStore::fail_write(),
        );

        let result = projection_runner_once(
            &source,
            &h,
            runner_config(ProjectionPoisonPolicy::SkipPermanentAfterDlx),
        )
        .await;

        assert_eq!(
            result.stop,
            ProjectionStop::DeadLetterUnsaved {
                failed_at: Lsn::new(3)
            }
        );
        assert!(c.current().is_none());
    }
}
