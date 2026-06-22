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
    pub fn new(_seq: u64) -> Self {
        todo!()
    }

    /// 取底层序号。
    pub fn get(&self) -> u64 {
        todo!()
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
