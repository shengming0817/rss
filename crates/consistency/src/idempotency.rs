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
    pub fn parse(raw: &str) -> Result<Self, IdemKeyError> {
        if raw.is_empty() {
            return Err(IdemKeyError::Empty);
        }
        Ok(Self(raw.to_string()))
    }

    /// 借出底层字符串视图。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 消费者组 newtype（私有字段，构造经 fallible funnel）。
///
/// 幂等 claim 的第二维度（PK = `(IdemKey, ConsumerGroup)`）：同一 key 在不同组各自首见。组名是**稳定**
/// 标识——漂移即等价新组、去重失效，故与 [`IdemKey`] 同款冻结为可失败构造（拒空 fail-closed），让组名
/// 在边界统一经此 funnel，杜绝裸 `String` 在三处 claimer（pg / redis / in-mem）各自拼装。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConsumerGroup(String);

/// `ConsumerGroup` 解析错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConsumerGroupError {
    #[error("consumer group is empty")]
    Empty,
}

impl ConsumerGroup {
    /// 解析稳定消费者组名；拒绝空名（fail-closed）。
    pub fn parse(raw: &str) -> Result<Self, ConsumerGroupError> {
        if raw.is_empty() {
            return Err(ConsumerGroupError::Empty);
        }
        Ok(Self(raw.to_string()))
    }

    /// 借出底层字符串视图。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 首见判定结果（穷尽闭值集）。
///
/// # Claim-only draft 注意
///
/// 当前仅支持 `Fresh`/`Duplicate` 两态（absent→claimed）；
/// `Done`/`Released` 等完整生命周期态属 T007 ConsumerBase 阶段（跟踪 `#1120`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SeenState {
    /// 首次见到此 key（应执行副作用）。
    ///
    /// **注意（claim-only draft）**：副作用执行前崩溃时，key 仍留 claimed，
    /// 重放永久返回 `Duplicate`（crash-after-claim 丢失风险）；完整闭环见 T007。
    Fresh,
    /// 已见过（应跳过，幂等短路）。
    Duplicate,
}

/// 幂等去重策略（L0 引擎策略 trait，native AFIT）。
///
/// trait 内直接 `async fn`——**不** object-safe，故消费方用泛型 `<S: IdempotencyStore>` 静态分发，
/// 禁 `Box<dyn IdempotencyStore>`。
///
/// # Claim-only draft（当前阶段语义限制）
///
/// 当前实现是 **claim-only draft**——`check` 只做 absent→claimed 的 claim-or-skip；
/// **无 commit/release/done/claimed-timeout 闭环**。这意味着：
/// - consumer 收到 `Fresh` 后若在执行副作用前崩溃，Redis/PG 中仍留有 claimed 记录。
/// - 重放时该 key 永久被判 `Duplicate`，副作用**永不执行**（crash-after-claim 丢失风险）。
///
/// 完整的 absent→claimed→done + commit/release 闭环属 **T007 ConsumerBase 阶段**（跟踪 `#1120`）。
///
/// **ConsumerBase 落地前，不得把本 store 复用于「Fresh 后副作用崩溃会造成不可接受丢失」的场景。**
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait IdempotencyStore {
    /// 标记并查询 key 是否首见（claim-or-skip）。`Fresh` ⇒ 执行；`Duplicate` ⇒ 幂等短路。
    ///
    /// # Claim-only draft
    ///
    /// 当前是 **claim-only**：`Fresh` 返回后无 commit/release 闭环；
    /// crash-after-claim 会导致该 key 永久 `Duplicate`（丢失风险）。
    /// 完整闭环属 T007 ConsumerBase 阶段（跟踪 `#1120`）。
    async fn check(&self, key: &IdemKey) -> Result<SeenState, crate::error::EngineError>;
}

#[cfg(test)]
mod tests {
    use super::{ConsumerGroup, ConsumerGroupError, IdemKey, IdemKeyError};

    // 任意非空 key 接受（opaque，不限字符集、不 trim）；as_str 往返。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果，item-level carve-out（error-handling.md §Carve-out）。
    fn idem_key_parse_accepts_non_empty_and_round_trips() {
        let cases: &[&str] = &[
            "a",
            "some-key-123",
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "session.created:tenant-42:evt-1",
        ];
        for &raw in cases {
            assert!(IdemKey::parse(raw).is_ok(), "expected Ok for raw={raw:?}");
            let key = IdemKey::parse(raw).unwrap();
            assert_eq!(key.as_str(), raw, "raw={raw:?}");
        }
    }

    // 空 key fail-closed → Empty（重放时 key 漂移退化成新消费者，故拒空）。
    #[test]
    fn idem_key_parse_rejects_empty() {
        assert!(matches!(IdemKey::parse(""), Err(IdemKeyError::Empty)));
    }

    // 纯空白是合法 opaque key（只拒空、不 trim——caller 负责构造稳定 key，漂移在边界即暴露而非被掩盖）。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果，item-level carve-out（error-handling.md §Carve-out）。
    fn idem_key_parse_accepts_whitespace_only_opaque() {
        for &raw in &[" ", "\t", "  x  "] {
            assert!(IdemKey::parse(raw).is_ok(), "expected Ok for raw={raw:?}");
            assert_eq!(IdemKey::parse(raw).unwrap().as_str(), raw, "raw={raw:?}");
        }
    }

    // 任意非空组名接受（opaque）；as_str 往返。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果，item-level carve-out（error-handling.md §Carve-out）。
    fn consumer_group_parse_accepts_non_empty_and_round_trips() {
        for &raw in &["audit", "audit.session-created", "grp-1", " "] {
            assert!(
                ConsumerGroup::parse(raw).is_ok(),
                "expected Ok for raw={raw:?}"
            );
            assert_eq!(
                ConsumerGroup::parse(raw).unwrap().as_str(),
                raw,
                "raw={raw:?}"
            );
        }
    }

    // 空组名 fail-closed → Empty（漂移成空组会静默吞去重维度，故拒空）。
    #[test]
    fn consumer_group_parse_rejects_empty() {
        assert!(matches!(
            ConsumerGroup::parse(""),
            Err(ConsumerGroupError::Empty)
        ));
    }
}
