//! CQRS 投影接缝（L3）—— 事件驱动重放投影读模型。
//!
//! `ProjectionEvent` 是投影事件载体 **sync trait**（outbox entry 与 saga journal event 都实现它）；
//! `Projector` 是 L3 引擎策略 trait（native AFIT，apply 单事件到读模型）。
//! ref: oxidecomputer/steno（saga journal 事件源对标）+ eventbus.md §Projection（双写 journal 接缝）。

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
    async fn apply<E: ProjectionEvent>(&self, event: &E) -> Result<(), crate::error::EngineError>;
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
    use super::Lsn;

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
