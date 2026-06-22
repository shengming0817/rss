//! 幂等去重接缝（L0 引擎策略）—— ADR-004 C1 native AFIT 样板源。
//!
//! `IdempotencyStore` 是 **L0 引擎策略 trait**（native AFIT + 泛型静态分发，零 box，不引 dynosaur）：
//! 消费方写 `fn run<S: IdempotencyStore>(s: &S)` 单态消费。**非** DI infra port——provider-可换的持久化
//! claimer（Redis/PG）由组合根经 `bootstrap::replaydeps` 选型注入，那是 diport 的 dyn 端。
//! ref: kube-rs kube-runtime/src/watcher.rs@main（内部 native AFIT trait `ApiMode` + 泛型 `step<A>` 消费）。

/// 幂等键 newtype（私有字段，构造经 fallible funnel）。
///
/// 命令 dispatch / outbox 消费两阶段去重的稳定 key。空 key 非法——重放时 key 漂移会退化成新消费者，
/// 故冻结为可失败构造。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdemKey(String);

/// `IdemKey` 解析错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdemKeyError {
    #[error("idempotency key is empty")]
    Empty,
}

impl IdemKey {
    /// 解析稳定幂等 key；拒绝空 key（fail-closed）。
    pub fn parse(_raw: &str) -> Result<Self, IdemKeyError> {
        todo!()
    }

    /// 借出底层字符串视图。
    pub fn as_str(&self) -> &str {
        todo!()
    }
}

/// 首见判定结果（穷尽闭值集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SeenState {
    /// 首次见到此 key（应执行副作用）。
    Fresh,
    /// 已见过（应跳过，幂等短路）。
    Duplicate,
}

/// 幂等去重策略（L0 引擎策略 trait，native AFIT）。
///
/// trait 内直接 `async fn`——**不** object-safe，故消费方用泛型 `<S: IdempotencyStore>` 静态分发，
/// 禁 `Box<dyn IdempotencyStore>`。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait IdempotencyStore {
    /// 标记并查询 key 是否首见（claim-or-skip）。`Fresh` ⇒ 执行；`Duplicate` ⇒ 幂等短路。
    async fn check(&self, key: &IdemKey) -> Result<SeenState, crate::error::EngineError>;
}
