//! CQRS 投影接缝（L3）—— 事件驱动重放投影读模型。
//!
//! `ProjectionEvent` 是投影事件载体 **sync trait**（outbox entry 与 saga journal event 都实现它）；
//! `Projector` 是 L3 引擎策略 trait（native AFIT，apply 单事件到读模型）。
//! ref: oxidecomputer/steno（saga journal 事件源对标）+ eventbus.md §Projection（双写 journal 接缝）。

use crate::error::{EngineError, EngineErrorKind};
use crate::outbox::Topic;

/// 日志序号 newtype（私有字段；单调递增，checkpoint 用于断点续投）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lsn(u64);

impl Lsn {
    /// 由单调序号构造（受控 funnel；来源是 journal append 序）。
    ///
    /// infallible：单调性由 journal append 层保证，本 funnel 不校验——caller 是 harness（append 序源），
    /// 非外部输入，故无 [`StepName`](crate::saga::StepName) / [`EntityId`](crate::reconcile::EntityId) 那样的 fallible parse。
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
    topic: Topic,
    payload: Vec<u8>,
}

impl ProjectionEventRecord {
    /// 由已验证 topic + 单调 lsn + encoded payload 构造投影事件记录。
    pub fn new(lsn: Lsn, topic: Topic, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            lsn,
            topic,
            payload: payload.into(),
        }
    }

    /// 事件 topic（投影路由键）。
    pub fn topic(&self) -> &Topic {
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
}

impl std::fmt::Debug for ProjectionEventRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectionEventRecord")
            .field("lsn", &self.lsn)
            .field("topic", &self.topic)
            .field("payload", &"<redacted>")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl ProjectionEvent for ProjectionEventRecord {
    fn topic(&self) -> &Topic {
        &self.topic
    }

    fn lsn(&self) -> Lsn {
        self.lsn
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// 投影事件载体（sync trait；outbox entry / saga journal event 共同实现 —— eventbus.md §Projection）。
///
/// 投影器据 `topic` 路由、`lsn` 断点续投、`payload` 解码。纯查询 trait（无 async / 无 dyn 注入）——
/// 泛型 `<E: ProjectionEvent>` 消费，非 trait object。
pub trait ProjectionEvent {
    /// 事件 topic（投影路由键）。
    fn topic(&self) -> &crate::outbox::Topic;

    /// 日志序号（断点续投 checkpoint）。
    fn lsn(&self) -> Lsn;

    /// 已编码 payload（投影器解码到读模型；解码不在本接缝）。
    fn payload(&self) -> &[u8];
}

/// 投影器策略（L3 引擎策略 trait，native AFIT）。
///
/// 把单条投影事件 apply 到读模型（重放 / tail 驱动）。native AFIT ⇒ 非 object-safe，
/// 投影 harness 泛型 `<P: Projector>` 消费，禁 `Box<dyn>`。投影事件经泛型 `<E: ProjectionEvent>` 入。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait Projector {
    /// apply 单事件到读模型。幂等（同 lsn 重投 no-op）由实现保证，行为 PR 兑现。
    async fn apply<E: ProjectionEvent>(&self, event: &E) -> Result<(), EngineError>;
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
#[non_exhaustive]
pub enum ProjectionDeadLetterReason {
    /// projector 返回永久错误，重试无意义。
    ApplyPermanent,
    /// projector 破坏引擎不变量，需要人工修复或跳过。
    ApplyInvariant,
    /// 事件源交付乱序，不能安全继续投影。
    OutOfOrder,
}

impl ProjectionDeadLetterReason {
    /// 从 apply 错误分类映射到 projection DLX 原因；瞬态错误不进 projection dead-letter。
    pub fn from_engine_error_kind(kind: EngineErrorKind) -> Option<Self> {
        match kind {
            EngineErrorKind::Transient => None,
            EngineErrorKind::Permanent => Some(Self::ApplyPermanent),
            EngineErrorKind::Invariant => Some(Self::ApplyInvariant),
        }
    }

    /// 稳定低基数 label。
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::ApplyPermanent => "apply_permanent",
            Self::ApplyInvariant => "apply_invariant",
            Self::OutOfOrder => "out_of_order",
        }
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
    /// 读 `after` 之后至多 `limit` 条投影事件；返回必须按全局 LSN 升序排列。
    async fn read_from(
        &self,
        after: Lsn,
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
    use crate::EngineErrorKind;
    use crate::outbox::Topic;

    use super::{
        Lsn, ProjectionBatchLimit, ProjectionBatchLimitError, ProjectionCheckpoint,
        ProjectionCheckpointError, ProjectionDeadLetter, ProjectionDeadLetterReason,
        ProjectionEventRecord,
    };

    #[allow(clippy::expect_used)]
    // reason: test fixture uses a compile-time known canonical topic.
    fn topic() -> Topic {
        Topic::parse("projection.test.event").expect("valid projection topic")
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
        let record = ProjectionEventRecord::new(Lsn::new(9), topic(), b"secret-payload".to_vec());

        assert_eq!(record.lsn(), Lsn::new(9));
        assert_eq!(record.topic().as_str(), "projection.test.event");
        assert_eq!(record.payload(), b"secret-payload");
    }

    #[test]
    fn projection_event_record_debug_redacts_payload() {
        let record = ProjectionEventRecord::new(Lsn::new(9), topic(), b"secret-payload".to_vec());
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
            ProjectionDeadLetterReason::from_engine_error_kind(EngineErrorKind::Transient),
            None
        );
        assert_eq!(
            ProjectionDeadLetterReason::from_engine_error_kind(EngineErrorKind::Permanent),
            Some(ProjectionDeadLetterReason::ApplyPermanent)
        );
        assert_eq!(
            ProjectionDeadLetterReason::from_engine_error_kind(EngineErrorKind::Invariant),
            Some(ProjectionDeadLetterReason::ApplyInvariant)
        );
        assert_eq!(
            ProjectionDeadLetterReason::OutOfOrder.as_label(),
            "out_of_order"
        );
    }

    #[test]
    fn projection_dead_letter_wraps_event_and_reason() {
        let event = ProjectionEventRecord::new(Lsn::new(11), topic(), b"bad-event".to_vec());
        let dead_letter =
            ProjectionDeadLetter::new(event, ProjectionDeadLetterReason::ApplyPermanent);

        assert_eq!(dead_letter.event().lsn(), Lsn::new(11));
        assert_eq!(
            dead_letter.reason(),
            ProjectionDeadLetterReason::ApplyPermanent
        );
        assert_eq!(dead_letter.reason().as_label(), "apply_permanent");
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
