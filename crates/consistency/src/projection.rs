//! CQRS 投影接缝（L3）—— 事件驱动重放投影读模型。
//!
//! `ProjectionEvent` 是投影事件载体 **sync trait**（outbox entry 与 saga journal event 都实现它）；
//! `Projector` 是 L3 引擎策略 trait（native AFIT，apply 单事件到读模型）。
//! ref: oxidecomputer/steno（saga journal 事件源对标）+ eventbus.md §Projection（双写 journal 接缝）。

use crate::error::EngineError;
use crate::outbox::EventTopic;
use vocab::TenantId;

/// 日志序号 newtype（私有字段；单调递增，checkpoint 用于断点续投）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lsn(u64);

impl Lsn {
    /// 由单调序号构造（受控 funnel；来源是 journal append 序）。
    ///
    /// infallible：单调性由 journal append 层保证，本 funnel 不校验——caller 是 harness（append 序源），
    /// 非外部输入，故无 [`vocab::StepName`] / [`EntityId`](crate::reconcile::EntityId) 那样的 fallible parse。
    pub fn new(seq: u64) -> Self {
        Self(seq)
    }

    /// 取底层序号。
    pub fn get(&self) -> u64 {
        self.0
    }
}

/// 单次投影事件源读取的批量上限（非零、受控最大值）。
///
/// 该类型是 projection source 资源边界的唯一 funnel：调用方必须在配置/启动期把外部 `u32`
/// 转成 `ProjectionBatchLimit`，避免把 0 或超大批量透传到 DB `LIMIT`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectionBatchLimit(u32);

impl ProjectionBatchLimit {
    /// 单次读取最多 1000 条，沿用现有 projection_events 小批建议的上界。
    pub const MAX: Self = Self(1_000);

    /// 构造批量限制；0 和超过 [`Self::MAX`] 的值 fail-closed。
    pub const fn new(limit: u32) -> Result<Self, ProjectionBatchLimitError> {
        if limit == 0 {
            Err(ProjectionBatchLimitError::Zero)
        } else if limit > Self::MAX.get() {
            Err(ProjectionBatchLimitError::TooLarge {
                max: Self::MAX.get(),
                attempted: limit,
            })
        } else {
            Ok(Self(limit))
        }
    }

    /// 取底层正整数批量值。
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for ProjectionBatchLimit {
    type Error = ProjectionBatchLimitError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// projection 批量限制构造错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectionBatchLimitError {
    /// 批量必须非零。
    #[error("projection batch limit must be non-zero")]
    Zero,
    /// 批量超过受控最大值。
    #[error("projection batch limit exceeds maximum")]
    TooLarge {
        /// 最大允许值。
        max: u32,
        /// 调用方尝试传入的值。
        attempted: u32,
    },
}

/// engine-owned 投影事件记录（adapter-agnostic）。
///
/// 字段私有：adapter 读出的 projection row 必须收敛成此类型再交给 projection harness / projector，
/// 避免上层 API 泄漏 adapter DTO。`payload` 可能含 PII，`Debug` 固定脱敏。
#[derive(Clone, PartialEq, Eq)]
pub struct ProjectionEventRecord {
    lsn: Lsn,
    topic: EventTopic,
    payload: Vec<u8>,
    metadata: ProjectionEventMetadata,
}

impl ProjectionEventRecord {
    /// 由已验证 topic + 单调 lsn + encoded payload + 持久化 envelope metadata 构造投影事件记录。
    pub fn with_metadata(
        lsn: Lsn,
        topic: EventTopic,
        payload: impl Into<Vec<u8>>,
        metadata: ProjectionEventMetadata,
    ) -> Self {
        Self {
            lsn,
            topic,
            payload: payload.into(),
            metadata,
        }
    }

    /// 事件 topic（投影路由键）。
    pub fn topic(&self) -> &EventTopic {
        &self.topic
    }

    /// 日志序号（断点续投 checkpoint）。
    pub fn lsn(&self) -> Lsn {
        self.lsn
    }

    /// 已编码 payload（投影器解码到读模型；解码不在本接缝）。
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// 投影事件持久化 metadata（用于 projection DLQ）。
    pub fn metadata(&self) -> &ProjectionEventMetadata {
        &self.metadata
    }
}

impl std::fmt::Debug for ProjectionEventRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectionEventRecord")
            .field("lsn", &self.lsn)
            .field("topic", &self.topic)
            .field("payload", &"<redacted>")
            .field("payload_len", &self.payload.len())
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl ProjectionEvent for ProjectionEventRecord {
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

/// Projection event metadata persisted alongside the encoded payload.
///
/// The metadata is copied from the outbox row when an event is mirrored into `projection_events`.
/// It lets the projection harness write a unified DLQ row without reaching back into adapter DTOs.
#[derive(Clone, PartialEq, Eq)]
pub struct ProjectionEventMetadata {
    tenant: TenantId,
    event_id: String,
    domain: String,
    contract_id: String,
    contract_version: String,
    schema_hash: String,
    metadata_json: serde_json::Value,
    partition_key: Option<String>,
    causation_id: Option<String>,
}

impl ProjectionEventMetadata {
    #[allow(clippy::too_many_arguments)]
    // reason: This is a stored envelope snapshot; splitting into a builder would introduce invalid
    // intermediate states for mandatory DLQ audit fields.
    pub fn new(
        tenant: TenantId,
        event_id: impl Into<String>,
        domain: impl Into<String>,
        contract_id: impl Into<String>,
        contract_version: impl Into<String>,
        schema_hash: impl Into<String>,
        metadata_json: serde_json::Value,
        partition_key: Option<String>,
        causation_id: Option<String>,
    ) -> Self {
        Self {
            tenant,
            event_id: event_id.into(),
            domain: domain.into(),
            contract_id: contract_id.into(),
            contract_version: contract_version.into(),
            schema_hash: schema_hash.into(),
            metadata_json,
            partition_key,
            causation_id,
        }
    }

    /// Test/default metadata for in-memory unit events.
    #[cfg(test)]
    #[allow(clippy::expect_used)]
    // reason: hard-coded canonical tenant fixture; panic would indicate the test fixture literal drifted.
    fn for_tests() -> Self {
        Self::new(
            TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("canonical test tenant"),
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

    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn schema_hash(&self) -> &str {
        &self.schema_hash
    }

    pub fn metadata_json(&self) -> &serde_json::Value {
        &self.metadata_json
    }

    pub fn partition_key(&self) -> Option<&str> {
        self.partition_key.as_deref()
    }

    pub fn causation_id(&self) -> Option<&str> {
        self.causation_id.as_deref()
    }
}

impl std::fmt::Debug for ProjectionEventMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let partition_key = self.partition_key.as_ref().map(|_| "<redacted>");
        let causation_id = self.causation_id.as_ref().map(|_| "<redacted>");
        f.debug_struct("ProjectionEventMetadata")
            .field("tenant", &self.tenant)
            .field("event_id", &self.event_id)
            .field("domain", &self.domain)
            .field("contract_id", &self.contract_id)
            .field("contract_version", &self.contract_version)
            .field("schema_hash", &self.schema_hash)
            .field("metadata_json", &"<redacted>")
            .field("partition_key", &partition_key)
            .field("causation_id", &causation_id)
            .finish()
    }
}

/// 投影事件载体（sync trait；outbox entry / saga journal event 共同实现 —— eventbus.md §Projection）。
///
/// 投影器据 `topic` 路由、`lsn` 断点续投、`payload` 解码。纯查询 trait（无 async / 无 dyn 注入）——
/// 泛型 `<E: ProjectionEvent>` 消费，非 trait object。
pub trait ProjectionEvent {
    /// 事件 topic（投影路由键）。
    fn topic(&self) -> &crate::outbox::EventTopic;

    /// 日志序号（断点续投 checkpoint）。
    fn lsn(&self) -> Lsn;

    /// 已编码 payload（投影器解码到读模型；解码不在本接缝）。
    fn payload(&self) -> &[u8];

    /// Persisted projection event metadata used for unified projection DLQ rows.
    fn metadata(&self) -> &ProjectionEventMetadata;
}

/// 投影器策略（L3 引擎策略 trait，native AFIT）。
///
/// 把单条投影事件 apply 到读模型（重放 / tail 驱动）。native AFIT ⇒ 非 object-safe，
/// 投影 harness 泛型 `<P: Projector>` 消费，禁 `Box<dyn>`。投影事件经泛型 `<E: ProjectionEvent>` 入。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionApplyOutcome {
    /// 事件匹配当前投影目标并已写入目标 read-model。
    Applied,
    /// 同一稳定事实已由目标原子提交；业务效果与 receipt 均未重复创建。
    Duplicate,
    /// 事件属于同一 source stream，但不属于当前投影 selector；checkpoint 仍可推进。
    Filtered,
}

/// 投影 apply 的闭值错误分类。
///
/// `CommitUnknown` 与 `RollbackFailed` 明确表达事务结果不确定性：它们既不能进入 poison DLQ，
/// 也不能被 harness 自动跳过或推进 checkpoint。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionApplyErrorKind {
    /// 后端暂时不可用，可在不推进 checkpoint 的前提下重试。
    Transient,
    /// 已确认的永久业务失败，可由显式 poison policy 处置。
    Permanent,
    /// target identity、binding 或 ordering 不变量被破坏。
    Invariant,
    /// 原子提交可能已成功，但确认 ACK 丢失，必须以同一事实重放判定。
    CommitUnknown,
    /// 事务回滚未能得到确认，禁止自动重试、skip 或 dead-letter。
    RollbackFailed,
}

impl ProjectionApplyErrorKind {
    /// 稳定、低基数且不含运行期数据的错误消息。
    pub const fn message(self) -> &'static str {
        match self {
            Self::Transient => "transient projection apply error",
            Self::Permanent => "permanent projection apply error",
            Self::Invariant => "projection apply invariant violated",
            Self::CommitUnknown => "projection apply commit outcome unknown",
            Self::RollbackFailed => "projection apply rollback failed",
        }
    }
}

/// 投影失败的精确、低基数原因。
///
/// [`ProjectionApplyErrorKind`] 决定重试/结算控制流；本类型保留 store 的 conflict 与 persistent
/// ordering 事实，供 DLQ、CLI 与 conformance 在不暴露 provider message 的前提下诊断根因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionApplyErrorReason {
    /// 后端暂时不可用。
    Transient,
    /// assembly-selected target definition 与输入不一致。
    TargetDefinitionDrift,
    /// generated source binding/version/schema/topic 与 target 不一致。
    InputBindingDrift,
    /// selector、envelope 或 payload tenant 不一致。
    TenantDrift,
    /// 合法 binding 下的 payload 无法解码。
    PayloadMalformed,
    /// payload 或 metadata 值不满足 target 约束。
    PayloadValueInvalid,
    /// domain version 未严格单调递增。
    VersionRegression,
    /// provider 返回违反固定协议的结果或不可分类的永久错误。
    ProviderInvariant,
    /// provider 永久拒绝操作且事务已确认回滚。
    ProviderPermanent,
    /// 同一 dedupe key 已绑定到不同事实。
    Conflict,
    /// 未见过的事件低于 target 持久 high-water。
    OutOfOrder,
    /// 原子提交可能成功，但确认 ACK 丢失。
    CommitUnknown,
    /// 事务回滚未得到确认。
    RollbackFailed,
}

impl ProjectionApplyErrorReason {
    /// 返回控制流使用的闭值错误分类。
    pub const fn kind(self) -> ProjectionApplyErrorKind {
        match self {
            Self::Transient => ProjectionApplyErrorKind::Transient,
            Self::PayloadMalformed
            | Self::PayloadValueInvalid
            | Self::VersionRegression
            | Self::ProviderPermanent => ProjectionApplyErrorKind::Permanent,
            Self::TargetDefinitionDrift
            | Self::InputBindingDrift
            | Self::TenantDrift
            | Self::ProviderInvariant
            | Self::Conflict
            | Self::OutOfOrder => ProjectionApplyErrorKind::Invariant,
            Self::CommitUnknown => ProjectionApplyErrorKind::CommitUnknown,
            Self::RollbackFailed => ProjectionApplyErrorKind::RollbackFailed,
        }
    }

    /// 返回供日志、CLI 与测试使用的稳定低基数标签。
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::TargetDefinitionDrift => "target_definition_drift",
            Self::InputBindingDrift => "input_binding_drift",
            Self::TenantDrift => "tenant_drift",
            Self::PayloadMalformed => "payload_malformed",
            Self::PayloadValueInvalid => "payload_value_invalid",
            Self::VersionRegression => "version_regression",
            Self::ProviderInvariant => "provider_invariant",
            Self::ProviderPermanent => "provider_permanent",
            Self::Conflict => "conflict",
            Self::OutOfOrder => "out_of_order",
            Self::CommitUnknown => "commit_unknown",
            Self::RollbackFailed => "rollback_failed",
        }
    }
}

/// projection 专属 apply 错误；字段私有，避免恢复宽泛 `EngineError` 通道。
#[derive(Debug, thiserror::Error)]
#[error("{}", .reason.kind().message())]
pub struct ProjectionApplyError {
    reason: ProjectionApplyErrorReason,
}

impl ProjectionApplyError {
    /// 从精确、低基数原因构造错误。
    pub const fn from_reason(reason: ProjectionApplyErrorReason) -> Self {
        Self { reason }
    }

    /// 返回闭值错误分类。
    pub const fn kind(&self) -> ProjectionApplyErrorKind {
        self.reason.kind()
    }

    /// 返回精确、低基数错误原因。
    pub const fn reason(&self) -> ProjectionApplyErrorReason {
        self.reason
    }
}

#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait Projector {
    /// apply 单事件到读模型。幂等（同 lsn 重投 no-op）由实现保证，行为 PR 兑现。
    async fn apply<E: ProjectionEvent>(
        &self,
        event: &E,
    ) -> Result<ProjectionApplyOutcome, ProjectionApplyError>;
}

/// 投影 checkpoint（已成功 apply 的最高 LSN）。
///
/// 单调性由 [`ProjectionCheckpoint::advance_to`] 的受控 funnel 保证：只能原地不动或向前推进，不能回退。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionCheckpoint {
    last_applied: Lsn,
}

impl ProjectionCheckpoint {
    /// 由已知 high-water LSN 构造 checkpoint。
    pub fn new(last_applied: Lsn) -> Self {
        Self { last_applied }
    }

    /// 已成功 apply 的最高 LSN。
    pub fn last_applied(&self) -> Lsn {
        self.last_applied
    }

    /// 推进 checkpoint；`next < current` 时 fail-closed 拒绝回退。
    pub fn advance_to(&mut self, next: Lsn) -> Result<(), ProjectionCheckpointError> {
        if next < self.last_applied {
            return Err(ProjectionCheckpointError::Regression {
                current: self.last_applied,
                attempted: next,
            });
        }
        self.last_applied = next;
        Ok(())
    }
}

/// projection checkpoint 单调性错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectionCheckpointError {
    /// 尝试把 checkpoint 从 `current` 回退到 `attempted`。
    #[error("projection checkpoint regression")]
    Regression {
        /// 当前 high-water。
        current: Lsn,
        /// 尝试写入的回退 high-water。
        attempted: Lsn,
    },
}

/// projection poison-event 进入 dead-letter 的闭值原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionDeadLetterReason {
    reason: ProjectionApplyErrorReason,
}

impl ProjectionDeadLetterReason {
    /// 从 apply 错误分类映射到 projection DLX 原因；瞬态错误不进 projection dead-letter。
    pub fn from_apply_error_reason(reason: ProjectionApplyErrorReason) -> Option<Self> {
        match reason {
            ProjectionApplyErrorReason::Transient
            | ProjectionApplyErrorReason::CommitUnknown
            | ProjectionApplyErrorReason::RollbackFailed => None,
            reason => Some(Self { reason }),
        }
    }

    /// 为事件源交付乱序构造受控 DLQ 原因。
    pub const fn source_out_of_order() -> Self {
        Self {
            reason: ProjectionApplyErrorReason::OutOfOrder,
        }
    }

    /// 返回与 stop/CLI 共用的精确 action reason。
    pub const fn reason(self) -> ProjectionApplyErrorReason {
        self.reason
    }

    /// 稳定低基数 label。
    pub const fn as_label(self) -> &'static str {
        self.reason.as_label()
    }
}

/// projection dead-letter 输入模型（provider-agnostic）。
///
/// 只建模 poison event + reason；持久化端口仍归 `diport::DeadLetterStore` / 后续 projection runtime wiring，
/// 本类型不新增 provider port。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionDeadLetter {
    event: ProjectionEventRecord,
    reason: ProjectionDeadLetterReason,
}

impl ProjectionDeadLetter {
    /// 由投影事件与闭值 dead-letter 原因构造。
    pub fn new(event: ProjectionEventRecord, reason: ProjectionDeadLetterReason) -> Self {
        Self { event, reason }
    }

    /// 原始投影事件（payload Debug 仍脱敏）。
    pub fn event(&self) -> &ProjectionEventRecord {
        &self.event
    }

    /// dead-letter 原因。
    pub fn reason(&self) -> ProjectionDeadLetterReason {
        self.reason
    }
}

// ── 串行有序投递 marker（fail-closed by absence）─────────────────────────────────

mod sealed {
    /// sealed 私有 supertrait——外部 crate 无法命名 ⇒ witness 类型宇宙对本 crate 封闭（Hard）。
    pub trait Sealed {}
}

/// 类型级 witness：上游投递 per-`(domain, partition_key)` 串行有序（outbox head-of-partition gating）。
///
/// `ProjectionHarness::new`（eventexec）必填一枚此 witness——非串行投递路径拿不到 witness ⇒ **编译期**
/// 挂不上 projection（fail-closed by absence）。sealed supertrait ⇒ witness 类型集对外封闭（外部 crate
/// 不能定义自己的 guarantor 类型，Hard）；唯一 blessed witness 是 [`SerialInOrder`]，唯一获取入口是
/// [`SerialInOrder::from_source`]。
///
/// 评级切分：attach 门禁（无 witness 不可构造 harness）+ witness 类型封闭 = **Hard**；witness「真实性」
/// （铸造它的 source 真是串行）= **Medium**（见 [`PartitionSerialDelivery`]）。
///
/// # INVARIANT: PROJECTION-SERIAL-WITNESS-01 { level = "Hard", exec = "native-compile", source = "code", native = "sealed witness trait boundary" }
pub trait SerialInOrderGuarantor: sealed::Sealed + Copy {}

/// 唯一 blessed 串行有序 witness（ZST，零运行期成本）。
///
/// 私有字段 `()` ⇒ 外部 crate 无法 struct-literal 构造；唯一获取入口是 [`SerialInOrder::from_source`]
/// （须传一个 [`PartitionSerialDelivery`] 串行 source）。in-memory 非串行 bus 无 `PartitionSerialDelivery`
/// impl ⇒ 拿不到 witness ⇒ 无法构造 projection harness。
#[derive(Clone, Copy, Debug)]
pub struct SerialInOrder(());

impl sealed::Sealed for SerialInOrder {}
impl SerialInOrderGuarantor for SerialInOrder {}

/// 串行有序投递契约 trait：impl 者的 read/poll 路径保证 per-`(domain, partition_key)` 串行有序投递。
///
/// **NOT sealed**——真实 adapter（`adapters/postgres`，外部 crate）须能 impl 来铸造 witness。这层 open 是
/// witness「真实性」的 **Medium** 边界（类型系统看不进 SQL head-of-partition gating，「此投递串行」是
/// 实现的语义属性、非结构属性）：哪些类型可 impl 由 dylint `rss_partition_serial_allowlist`（AST 级，
/// 仅放行 allowlist adapter/组合根类型，INVARIANT: PARTITION-SERIAL-IMPL-ALLOWLIST-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）守，`#[cfg(test)]`
/// 测试 fake 豁免。**in-memory 非串行 fake 禁止 impl 本 trait**。
///
/// **projection 用途下的全局 lsn 升序要求**：per-partition 串行是 outbox relay 的 head-of-partition
/// gating（OUTBOX-PARTITION-ORDER-01）属性，**不是**本 trait impl 的职责。projection harness（`apply_batch`，
/// eventexec）实际要求**跨所有 domain/partition 的全局单调 lsn 升序交付**——上游 caller 须以
/// `ORDER BY id ASC`（或等价全局 lsn 升序）读取 `projection_events`，再交付给 harness；本 trait
/// impl 仅声明「per-partition 串行已满足」，全局升序由读侧 SQL ORDER BY 保证，两层职责正交。
pub trait PartitionSerialDelivery {}

/// 投影事件源（L3 引擎策略 trait，native AFIT）。
///
/// 事件源返回 engine-owned [`ProjectionEventRecord`]，不向上泄漏 adapter DTO。supertrait
/// [`PartitionSerialDelivery`] 把「可作为 projection source」和「能铸造 [`SerialInOrder`] witness」
/// 结构性绑定：非串行 source 无法实现本 trait。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费；这是 ADR-003 既定范式，禁 dynosaur/Box<dyn>。
pub trait ProjectionEventSource: PartitionSerialDelivery {
    /// 读 `after` 之后至多 `limit` 条投影事件；`None` 表示从事件源起点读取。
    ///
    /// 返回必须按全局 LSN 升序排列。调用方不得用具体 LSN 值兼作“起点前”哨兵：`Lsn(0)`
    /// 对内存/测试 source 仍是合法事件坐标，持久化 adapter 若天然 1-based 可在实现内把 `None`
    /// 映射为自身的起点前游标。
    async fn read_from(
        &self,
        after: Option<Lsn>,
        limit: ProjectionBatchLimit,
    ) -> Result<Vec<ProjectionEventRecord>, EngineError>;
}

impl SerialInOrder {
    /// 从一个串行有序 source 铸造 witness——`S: PartitionSerialDelivery` bound 即门。
    ///
    /// 不读 `_source` 任何运行期状态（witness 是纯类型级证明）：bound 满足即证「此 source 声明自己
    /// per-partition 串行有序」，故安全铸 ZST witness 喂 projection harness。非串行类型无该 impl ⇒ 编译期
    /// 拿不到 witness。
    pub fn from_source<S: PartitionSerialDelivery>(_source: &S) -> Self {
        SerialInOrder(())
    }
}

#[cfg(test)]
mod tests {
    use crate::outbox::EventTopic;

    use super::{
        Lsn, ProjectionApplyError, ProjectionApplyErrorKind, ProjectionApplyErrorReason,
        ProjectionApplyOutcome, ProjectionBatchLimit, ProjectionBatchLimitError,
        ProjectionCheckpoint, ProjectionCheckpointError, ProjectionDeadLetter,
        ProjectionDeadLetterReason, ProjectionEventMetadata, ProjectionEventRecord,
    };

    #[allow(clippy::expect_used)]
    // reason: test fixture uses a compile-time known canonical topic.
    fn topic() -> EventTopic {
        EventTopic::parse("projection.test.event").expect("valid projection topic")
    }

    fn record(lsn: Lsn, payload: impl Into<Vec<u8>>) -> ProjectionEventRecord {
        ProjectionEventRecord::with_metadata(
            lsn,
            topic(),
            payload,
            ProjectionEventMetadata::for_tests(),
        )
    }

    // Lsn new/get 多值往返（含边界 0 / u64::MAX）。
    #[test]
    fn lsn_new_get_round_trips() {
        let cases: &[u64] = &[0, 1, 42, u64::MAX];
        for &seq in cases {
            assert_eq!(Lsn::new(seq).get(), seq, "seq={seq}");
        }
    }

    // Lsn 单调序：Ord / Eq 烟测（断点续投 checkpoint 比较语义）。
    #[test]
    fn lsn_ordering() {
        assert!(Lsn::new(1) < Lsn::new(2));
        assert_eq!(Lsn::new(7), Lsn::new(7));
        assert!(Lsn::new(u64::MAX) > Lsn::new(0));
    }

    #[test]
    fn projection_event_record_round_trips_through_trait() {
        let record = record(Lsn::new(9), b"secret-payload".to_vec());

        assert_eq!(record.lsn(), Lsn::new(9));
        assert_eq!(record.topic().as_str(), "projection.test.event");
        assert_eq!(record.payload(), b"secret-payload");
    }

    #[test]
    fn projection_event_record_debug_redacts_payload() {
        let record = record(Lsn::new(9), b"secret-payload".to_vec());
        let debug = format!("{record:?}");

        assert!(
            debug.contains("<redacted>"),
            "Debug must include redaction marker: {debug}"
        );
        assert!(
            !debug.contains("secret-payload"),
            "Debug leaked projection payload: {debug}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: test fixture uses a compile-time known canonical tenant.
    fn projection_event_metadata_debug_redacts_partition_key_and_causation_id() {
        let metadata = ProjectionEventMetadata::new(
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                .expect("canonical test tenant"),
            "projection-test-event",
            "test",
            "test.projection-event",
            "v1",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            serde_json::json!({ "tenantId": "f47ac10b-58cc-4372-a567-0e02b2c3d479" }),
            Some("tenant-7:session-secret".to_string()),
            Some("SECRET-CAUSATION".to_string()),
        );
        let record = ProjectionEventRecord::with_metadata(
            Lsn::new(9),
            topic(),
            b"secret-payload".to_vec(),
            metadata,
        );
        let debug = format!("{record:?}");

        assert!(
            debug.contains("Some"),
            "presence should stay visible: {debug}"
        );
        assert!(
            debug.contains("<redacted>"),
            "Debug must include redaction marker: {debug}"
        );
        assert!(
            !debug.contains("session-secret"),
            "Debug leaked projection partition_key: {debug}"
        );
        assert!(
            !debug.contains("SECRET-CAUSATION"),
            "Debug leaked projection causation_id: {debug}"
        );
        assert!(
            !debug.contains("secret-payload"),
            "Debug leaked projection payload: {debug}"
        );
    }

    #[test]
    fn projection_checkpoint_rejects_regression() {
        let mut checkpoint = ProjectionCheckpoint::new(Lsn::new(5));

        assert_eq!(checkpoint.last_applied(), Lsn::new(5));
        assert_eq!(checkpoint.advance_to(Lsn::new(7)), Ok(()));
        assert_eq!(checkpoint.last_applied(), Lsn::new(7));
        assert_eq!(checkpoint.advance_to(Lsn::new(7)), Ok(()));
        assert_eq!(
            checkpoint.advance_to(Lsn::new(6)),
            Err(ProjectionCheckpointError::Regression {
                current: Lsn::new(7),
                attempted: Lsn::new(6),
            })
        );
        assert_eq!(checkpoint.last_applied(), Lsn::new(7));
    }

    #[test]
    fn projection_dead_letter_reason_maps_poison_errors_only() {
        assert_eq!(
            ProjectionDeadLetterReason::from_apply_error_reason(
                ProjectionApplyErrorReason::Transient
            ),
            None
        );
        assert_eq!(
            ProjectionDeadLetterReason::from_apply_error_reason(
                ProjectionApplyErrorReason::PayloadMalformed
            )
            .map(ProjectionDeadLetterReason::reason),
            Some(ProjectionApplyErrorReason::PayloadMalformed)
        );
        assert_eq!(
            ProjectionDeadLetterReason::from_apply_error_reason(
                ProjectionApplyErrorReason::ProviderInvariant
            )
            .map(ProjectionDeadLetterReason::reason),
            Some(ProjectionApplyErrorReason::ProviderInvariant)
        );
        assert_eq!(
            ProjectionDeadLetterReason::from_apply_error_reason(
                ProjectionApplyErrorReason::CommitUnknown
            ),
            None
        );
        assert_eq!(
            ProjectionDeadLetterReason::from_apply_error_reason(
                ProjectionApplyErrorReason::RollbackFailed
            ),
            None
        );
        assert_eq!(
            ProjectionDeadLetterReason::from_apply_error_reason(
                ProjectionApplyErrorReason::Conflict
            )
            .map(ProjectionDeadLetterReason::reason),
            Some(ProjectionApplyErrorReason::Conflict)
        );
        assert_eq!(
            ProjectionDeadLetterReason::from_apply_error_reason(
                ProjectionApplyErrorReason::OutOfOrder
            )
            .map(ProjectionDeadLetterReason::reason),
            Some(ProjectionApplyErrorReason::OutOfOrder)
        );
        assert_eq!(
            ProjectionDeadLetterReason::source_out_of_order().as_label(),
            "out_of_order"
        );
    }

    #[test]
    fn projection_action_reasons_preserve_operator_diagnostics() {
        let cases = [
            (
                ProjectionApplyErrorReason::TargetDefinitionDrift,
                "target_definition_drift",
            ),
            (ProjectionApplyErrorReason::TenantDrift, "tenant_drift"),
            (
                ProjectionApplyErrorReason::PayloadMalformed,
                "payload_malformed",
            ),
            (
                ProjectionApplyErrorReason::VersionRegression,
                "version_regression",
            ),
        ];
        for (reason, expected) in cases {
            assert_eq!(reason.as_label(), expected);
        }
    }

    #[test]
    fn projection_apply_contract_is_closed_and_stable() {
        let outcomes = [
            ProjectionApplyOutcome::Applied,
            ProjectionApplyOutcome::Duplicate,
            ProjectionApplyOutcome::Filtered,
        ];
        assert_eq!(outcomes.len(), 3);

        let cases = [
            (
                ProjectionApplyErrorReason::Transient,
                ProjectionApplyErrorKind::Transient,
                "transient projection apply error",
            ),
            (
                ProjectionApplyErrorReason::PayloadValueInvalid,
                ProjectionApplyErrorKind::Permanent,
                "permanent projection apply error",
            ),
            (
                ProjectionApplyErrorReason::ProviderInvariant,
                ProjectionApplyErrorKind::Invariant,
                "projection apply invariant violated",
            ),
            (
                ProjectionApplyErrorReason::ProviderPermanent,
                ProjectionApplyErrorKind::Permanent,
                "permanent projection apply error",
            ),
            (
                ProjectionApplyErrorReason::CommitUnknown,
                ProjectionApplyErrorKind::CommitUnknown,
                "projection apply commit outcome unknown",
            ),
            (
                ProjectionApplyErrorReason::RollbackFailed,
                ProjectionApplyErrorKind::RollbackFailed,
                "projection apply rollback failed",
            ),
        ];
        for (reason, kind, message) in cases {
            let error = ProjectionApplyError::from_reason(reason);
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), message);
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn projection_dead_letter_wraps_event_and_reason() {
        let event = record(Lsn::new(11), b"bad-event".to_vec());
        let reason = ProjectionDeadLetterReason::from_apply_error_reason(
            ProjectionApplyErrorReason::PayloadMalformed,
        )
        .expect("payload malformed is controlled poison");
        let dead_letter = ProjectionDeadLetter::new(event, reason);

        assert_eq!(dead_letter.event().lsn(), Lsn::new(11));
        assert_eq!(
            dead_letter.reason().reason(),
            ProjectionApplyErrorReason::PayloadMalformed
        );
        assert_eq!(dead_letter.reason().as_label(), "payload_malformed");
        assert!(
            !format!("{dead_letter:?}").contains("bad-event"),
            "dead-letter Debug must not leak payload"
        );
    }

    #[test]
    fn projection_batch_limit_rejects_zero_and_over_max() {
        assert_eq!(
            ProjectionBatchLimit::new(0),
            Err(ProjectionBatchLimitError::Zero)
        );
        assert_eq!(
            ProjectionBatchLimit::new(ProjectionBatchLimit::MAX.get() + 1),
            Err(ProjectionBatchLimitError::TooLarge {
                max: ProjectionBatchLimit::MAX.get(),
                attempted: ProjectionBatchLimit::MAX.get() + 1,
            })
        );

        assert_eq!(
            ProjectionBatchLimit::new(ProjectionBatchLimit::MAX.get())
                .map(ProjectionBatchLimit::get),
            Ok(ProjectionBatchLimit::MAX.get())
        );
    }

    // 串行有序 witness：从 PartitionSerialDelivery source 铸造，满足 SerialInOrderGuarantor bound。
    // 编译过即证「门禁可被串行 source 满足」+「witness 是 Copy（喂 harness 后仍可复用）」。
    #[test]
    fn serial_in_order_witness_mints_from_partition_serial_source() {
        // 测试 fake：声明自己串行（#[cfg(test)] 豁免 allowlist dylint）。
        struct SerialSrc;
        impl super::PartitionSerialDelivery for SerialSrc {}

        // 模拟 projection harness 的 witness bound——只接受 SerialInOrderGuarantor。
        fn requires<G: super::SerialInOrderGuarantor>(_g: G) {}

        let w = super::SerialInOrder::from_source(&SerialSrc);
        requires(w);
        // Copy 语义 anti-vacuity：witness 传值后仍可再用（ZST Copy）。
        requires(w);
    }
}
