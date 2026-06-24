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
///
/// # 状态机（absent → claimed → done）
///
/// - `check`：absent→claimed（首见 `Fresh`，已 claimed/done 返 `Duplicate`）。
/// - `commit`：claimed→done（幂等永久去重，副作用执行成功后调用）。
/// - `release`：claimed→absent（释放 claim，使后续重放可重新 `Fresh`；用于放弃处理/重投前释放）。
///
/// commit/release 闭环在 #1120 兑现，消除 crash-after-claim 时 key 永久 `Duplicate` 的丢失风险。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait IdempotencyStore {
    /// 标记并查询 key 是否首见（claim-or-skip）。`Fresh` ⇒ 执行；`Duplicate` ⇒ 幂等短路。
    async fn check(&self, key: &IdemKey) -> Result<SeenState, crate::error::EngineError>;

    /// claimed→done：标记副作用已成功执行（幂等永久去重）。
    ///
    /// 对 absent key 为幂等 no-op（`Ok(())`）。
    async fn commit(&self, key: &IdemKey) -> Result<(), crate::error::EngineError>;

    /// claimed→absent：释放 claim（删除 claimed 记录），使后续重放可重新得到 `Fresh`。
    ///
    /// 用于放弃处理或重投前释放。对 absent key 为幂等 no-op（`Ok(())`）。
    async fn release(&self, key: &IdemKey) -> Result<(), crate::error::EngineError>;
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::{
        ConsumerGroup, ConsumerGroupError, IdemKey, IdemKeyError, IdempotencyStore, SeenState,
    };
    use crate::error::EngineError;

    // ─── in-mem fake（测试专用，覆盖完整状态机）────────────────────────────────────

    /// 三态内存 store：absent / claimed / done。
    struct FakeStore {
        /// `true` = claimed，`false` = done（absent 时 key 不存在）。
        state: Mutex<HashMap<String, bool>>,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                state: Mutex::new(HashMap::new()),
            }
        }
    }

    impl IdempotencyStore for FakeStore {
        async fn check(&self, key: &IdemKey) -> Result<SeenState, EngineError> {
            let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
            // reason: in-mem 操作恒成功，unwrap_or_else 处理 poisoned lock 后继续。
            match map.get(key.as_str()) {
                None => {
                    // absent → claimed
                    map.insert(key.as_str().to_string(), true);
                    Ok(SeenState::Fresh)
                }
                Some(_) => Ok(SeenState::Duplicate),
            }
        }

        async fn commit(&self, key: &IdemKey) -> Result<(), EngineError> {
            // reason: in-mem commit 恒 Ok；claimed→done（absent 时幂等 no-op）。
            let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if map.contains_key(key.as_str()) {
                map.insert(key.as_str().to_string(), false); // false = done
            }
            Ok(())
        }

        async fn release(&self, key: &IdemKey) -> Result<(), EngineError> {
            // reason: in-mem release 恒 Ok；claimed→absent（absent 时幂等 no-op）。
            let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
            map.remove(key.as_str());
            Ok(())
        }
    }

    // ─── 状态机测试（TDD）────────────────────────────────────────────────────────

    #[allow(clippy::unwrap_used)]
    // reason: 测试用 parse — 已知非空 key，item-level carve-out（error-handling.md §Carve-out）。
    fn k(raw: &str) -> IdemKey {
        IdemKey::parse(raw).unwrap()
    }

    /// claim → commit → 再 check = Duplicate（done 永久去重）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store.check/commit 在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn state_machine_claim_commit_then_duplicate() {
        let store = FakeStore::new();
        let key = k("evt-commit-1");
        assert_eq!(store.check(&key).await.unwrap(), SeenState::Fresh);
        store.commit(&key).await.unwrap();
        assert_eq!(store.check(&key).await.unwrap(), SeenState::Duplicate);
    }

    /// claim → release → 再 check = Fresh（释放后可重领）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn state_machine_claim_release_then_fresh() {
        let store = FakeStore::new();
        let key = k("evt-release-1");
        assert_eq!(store.check(&key).await.unwrap(), SeenState::Fresh);
        store.release(&key).await.unwrap();
        assert_eq!(store.check(&key).await.unwrap(), SeenState::Fresh);
    }

    /// commit 对 absent key 幂等 no-op（不 panic，Ok）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn commit_on_absent_key_is_noop() {
        let store = FakeStore::new();
        let key = k("evt-absent-commit");
        // 直接 commit，未 claim
        assert!(store.commit(&key).await.is_ok());
        // 之后 check 仍可 Fresh（absent 状态未被写入 done）
        assert_eq!(store.check(&key).await.unwrap(), SeenState::Fresh);
    }

    /// release 对 absent key 幂等 no-op（不 panic，Ok）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn release_on_absent_key_is_noop() {
        let store = FakeStore::new();
        let key = k("evt-absent-release");
        // 直接 release，未 claim
        assert!(store.release(&key).await.is_ok());
        // 之后 check 仍可 Fresh
        assert_eq!(store.check(&key).await.unwrap(), SeenState::Fresh);
    }

    /// 表驱动：多条 key 各自独立状态机，互不干扰。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn multiple_keys_independent_state_machines() {
        let store = FakeStore::new();
        let keys: &[&str] = &["evt-A", "evt-B", "evt-C"];
        // 全部 claim
        for &raw in keys {
            assert_eq!(
                store.check(&k(raw)).await.unwrap(),
                SeenState::Fresh,
                "raw={raw}"
            );
        }
        // A commit，B release，C 留 claimed
        store.commit(&k("evt-A")).await.unwrap();
        store.release(&k("evt-B")).await.unwrap();
        // A：done → Duplicate
        assert_eq!(
            store.check(&k("evt-A")).await.unwrap(),
            SeenState::Duplicate
        );
        // B：absent → Fresh
        assert_eq!(store.check(&k("evt-B")).await.unwrap(), SeenState::Fresh);
        // C：still claimed → Duplicate
        assert_eq!(
            store.check(&k("evt-C")).await.unwrap(),
            SeenState::Duplicate
        );
    }

    // ─── IdemKey / ConsumerGroup 原有测试（保留）────────────────────────────────

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
