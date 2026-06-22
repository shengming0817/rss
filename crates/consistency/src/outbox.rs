//! Outbox 投递接缝（L1）—— 纯类型 disposition + relay 策略。
//!
//! `Disposition`/`HandleResult`/`PermanentError`/`Entry`/`Topic` 是 **纯态机类型**（sync，穷尽闭值集）；
//! `OutboxRelay` 是 L1 引擎策略 trait（native AFIT，把已持久化 entry 中继到 broker）。
//! 真实 broker I/O（AMQP）与 in-memory bus 在 `eventexec`/adapters，consistency 只冻类型 + 策略接缝。
//! 语义见 `docs/rules/eventbus.md` §Disposition / §ConsumerBase。
//! ref: ThreeDotsLabs/watermill message/router.go@master（Ack/Requeue/Reject disposition 概念对标）。

/// 消费处置（穷尽闭值集，Hard 冻结；漏 case 编不过）。eventbus.md §Disposition 表。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Disposition {
    /// 成功：broker ack + receipt commit。
    Ack,
    /// 瞬态失败：退避重试，预算耗尽后转 Reject。
    Requeue,
    /// 永久失败：broker nack/reject，进入 DLX。
    Reject,
}

impl Disposition {
    /// 稳定 metrics/log label（crate-owned 闭映射；下游无需 match non_exhaustive enum）。
    pub fn as_label(self) -> &'static str {
        todo!()
    }
}

/// 永久（不可重试）失败种类——**排除** `Transient`（类型层杜绝把瞬态误标永久）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PermanentErrorKind {
    /// 永久失败（重试无意义）。
    Permanent,
    /// 引擎不变量被破坏（编程错误）。
    Invariant,
}

impl PermanentErrorKind {
    /// 稳定 message（`&'static str` const literal）。
    pub fn message(self) -> &'static str {
        todo!()
    }
}

/// 永久错误标记（私有字段；只是分类，不自动把 Requeue 改 Reject —— eventbus.md）。
///
/// 持 [`PermanentErrorKind`]（排除 `Transient`），类型层杜绝把瞬态误标永久（codex F5）。
#[derive(Debug, thiserror::Error)]
#[error("{}", .0.message())]
pub struct PermanentError(PermanentErrorKind);

impl PermanentError {
    /// 由永久错误种类构造（`Transient` 类型层不可表达）。
    pub fn new(_kind: PermanentErrorKind) -> Self {
        todo!()
    }

    /// 永久错误种类（供 DLX 细分类）。
    pub fn kind(&self) -> PermanentErrorKind {
        todo!()
    }
}

/// 业务 handler 结果（私有字段；禁裸 struct literal，经 `ack`/`requeue`/`reject` 构造器 —— eventbus.md）。
#[derive(Debug)]
pub struct HandleResult {
    #[allow(dead_code)]
    // reason: 冻结期 accessor body = todo!()，字段暂未被读；行为 PR 兑现访问器实现后移除。
    disposition: Disposition,
}

impl HandleResult {
    /// 成功。
    pub fn ack() -> Self {
        todo!()
    }

    /// 瞬态失败 → 退避重试（携因由进引擎错误通道）。
    pub fn requeue(_error: crate::error::EngineError) -> Self {
        todo!()
    }

    /// 永久失败 → DLX。
    pub fn reject(_error: PermanentError) -> Self {
        todo!()
    }

    /// 处置（subscriber/relay 穷尽 match）。
    pub fn disposition(&self) -> Disposition {
        todo!()
    }
}

/// 事件 topic newtype（私有字段；稳定 dotted 名称 —— eventbus.md §命名）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Topic(String);

/// `Topic` 解析错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TopicError {
    #[error("topic name is empty")]
    Empty,
    #[error("topic name is not a canonical dotted name")]
    Format,
}

impl Topic {
    /// 解析稳定 dotted topic 名；拒绝空/非 canonical（fail-closed）。
    pub fn parse(_raw: &str) -> Result<Self, TopicError> {
        todo!()
    }

    /// 借出底层字符串视图。
    pub fn as_str(&self) -> &str {
        todo!()
    }
}

/// 持久化 outbox 条目（私有字段；payload 是已编码字节，由 emit 期写入 —— eventbus.md §命名与 payload）。
///
/// engine 类型——**不** derive serde（ADR-004 C6）；wire 编解码在 generated/eventexec 边界完成。
#[derive(Debug, Clone)]
pub struct Entry {
    #[allow(dead_code)]
    // reason: 冻结期 accessor body = todo!()，字段暂未被读；行为 PR 兑现访问器实现后移除。
    topic: Topic,
    #[allow(dead_code)]
    idem_key: crate::idempotency::IdemKey,
    #[allow(dead_code)]
    payload: Vec<u8>,
}

impl Entry {
    /// 由 topic + 幂等 key + 已编码 payload 构造（受控 funnel；命令 topic 构造收口于此 —— eventbus.md）。
    pub fn new(_topic: Topic, _idem_key: crate::idempotency::IdemKey, _payload: Vec<u8>) -> Self {
        todo!()
    }

    /// 目标 topic。
    pub fn topic(&self) -> &Topic {
        todo!()
    }

    /// 幂等 key。
    pub fn idem_key(&self) -> &crate::idempotency::IdemKey {
        todo!()
    }

    /// 已编码 payload。
    pub fn payload(&self) -> &[u8] {
        todo!()
    }
}

/// Outbox 中继策略（L1 引擎策略 trait，native AFIT）。
///
/// 把**已持久化**的 outbox entry 中继到 broker（demo=进程内 bus / postgres=真实 broker，eventbus.md
/// topology-gated）。native AFIT ⇒ 非 object-safe，消费方泛型 `<R: OutboxRelay>`，禁 `Box<dyn>`。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait OutboxRelay {
    /// 中继单条已持久化 entry。返回处置驱动 receipt commit / DLX / 退避（穷尽 `Disposition`）。
    async fn relay(&self, entry: &Entry) -> Result<Disposition, crate::error::EngineError>;
}
