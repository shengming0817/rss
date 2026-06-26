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
    /// 首次见到此 key（应执行副作用）；本消费者持有以传入 [`LeaseToken`] 标记的 claim。
    Fresh,
    /// 已见过（应跳过，幂等短路）：claim 仍被他人持有或已 `done`。
    Duplicate,
}

/// 租约令牌（opaque newtype，私有字段 + funnel 构造，#1213）。
///
/// 消费方每次 claim 前铸出（uuid v4 文本），随 [`IdempotencyStore::check`] 传入；store 在 claimed 行
/// stamp 此 token。后续 `extend`/`commit`/`release` 凭它做 **CAS 围栏**——令牌不符即判
/// [`LeaseOutcome::Lost`]（claim 已被 TTL 重捞、他人接管），触发 hard-fence。
///
/// # Enforcement 分级
///
/// - **调用方无法在 call-site 传裸 `String`**（须经 `LeaseToken::new` 构造后才符合
///   `check`/`extend`/`commit`/`release` 形参类型）——类型系统强制（**Hard**）。
/// - **不同消费者持有不同 token 而无法冒用**——依赖 uuid v4 熵与 token 不跨消费者传输的协议约定
///   （**Medium**），非类型封闭；类型层不阻止同一进程构造任意 `LeaseToken`。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LeaseToken(String);

impl LeaseToken {
    /// 由调用方铸出的不透明令牌构造（消费方传 uuid v4 文本）。
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// 借出底层字符串视图（adapter 绑定到后端 CAS 谓词）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `extend` / `commit` 的租约 CAS 结果（穷尽闭值集，#1213）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaseOutcome {
    /// 令牌仍匹配持有的 claimed 行（CAS 命中）：续租 / 提交成功。
    Held,
    /// 令牌不符（claim 已被 TTL 重捞、他人接管或已 done）：**hard-fence**——消费方须把 Ack 降级为
    /// Requeue、**不** commit，避免 stale holder 双写。
    Lost,
}

/// 幂等去重 + 租约策略（L0 引擎策略 trait，native AFIT）。
///
/// trait 内直接 `async fn`——**不** object-safe，故消费方用泛型 `<S: IdempotencyStore>` 静态分发，
/// 禁 `Box<dyn IdempotencyStore>`。
///
/// # 状态机（absent → claimed(token) → done）
///
/// - `check`：absent / **TTL 过期的 claimed** → claimed(传入 token)（`Fresh`）；fresh-claimed / done →
///   `Duplicate`。过期 claim 经 TTL 重捞（claimed 超 `lease_ttl` 未续租即可被新 token 接管），修
///   crash-after-claim 时 key 永久 `Duplicate` 的丢消息风险（硬崩溃下 `release` 走不到，#1213）。
/// - `extend`：claimed(token) 续租（刷新 lease 到期点）；token 匹配 → `Held`，不符 → `Lost`（已被重捞）。
/// - `commit`：claimed(token)→done（CAS）；token 匹配 → `Held`（永久去重），不符 → `Lost`（**hard-fence**）。
/// - `release`：claimed(token)→absent（CAS）；token 不符为 no-op（不误删他人 claim）。
///
/// 长 handler 由消费方后台按 `lease_ttl/3` 周期调 `extend` 续租；租约丢失（`Lost`）触发 cancel + hard-fence
/// （#1213，对标 gocell ConsumerBase runWithRenewal + leaseLost）。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait IdempotencyStore {
    /// 铸 claim 并查询首见（claim-or-skip + TTL 重捞）。`lease` 是本次 claim 的令牌（消费方铸，uuid v4）。
    ///
    /// **写副作用（`Fresh` 路径）**：`check` 在 `Fresh` 路径上执行 `INSERT ... ON CONFLICT` / `SET NX`
    /// 原子操作，将 `lease` token stamp 到后端——**不是只读谓词**（后续 issue 跟踪重命名为 `try_claim`）。
    ///
    /// `Fresh` ⇒ 本消费者持有以 `lease` 标记的 claim，应执行副作用；`Duplicate` ⇒ 幂等短路（他人持有或已 done）。
    ///
    /// **`Duplicate` 路径**：传入的 `lease` **不会**写入后端——claim-or-reclaim 是单一原子操作，token 必须
    /// 在调用前铸出；若返回 `Duplicate`，调用方可丢弃该 token。
    async fn check(
        &self,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<SeenState, crate::error::EngineError>;

    /// 续租：刷新 `lease` 标记的 claimed 行到期点。`Held` 仍持有 / `Lost` 已被重捞（hard-fence 信号）。
    ///
    /// 对 absent / 他人持有 / 已 done 的行返回 `Lost`（无匹配 CAS）。
    async fn extend(
        &self,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<LeaseOutcome, crate::error::EngineError>;

    /// claimed→done（CAS）：仅当 `lease` 仍匹配时标记永久去重。`Held` 提交成功 / `Lost` 租约已失（勿 Ack）。
    ///
    /// 对 absent / 已被重捞的行返回 `Lost`（hard-fence：消费方降级 Requeue、不移除 broker 投递）。
    async fn commit(
        &self,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<LeaseOutcome, crate::error::EngineError>;

    /// claimed→absent（CAS）：仅当 `lease` 仍匹配时释放 claim，使后续重放可重新得到 `Fresh`。
    ///
    /// 令牌不符（已被重捞）为幂等 no-op（`Ok(())`，不误删他人 claim）；对 absent key 同样 no-op。
    async fn release(
        &self,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<(), crate::error::EngineError>;
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::{
        ConsumerGroup, ConsumerGroupError, IdemKey, IdemKeyError, IdempotencyStore, LeaseOutcome,
        LeaseToken, SeenState,
    };
    use crate::error::EngineError;

    // ─── in-mem fake（测试专用，覆盖完整 token CAS 状态机）──────────────────────────

    /// claimed 行内容：lease token + 是否已 done。
    struct Entry {
        token: String,
        done: bool,
    }

    /// 三态内存 store：absent / claimed(token) / done(token)。token CAS 围栏忠实实现；
    /// **不**含 TTL 重捞（无时间源）——重捞正确性由 PG 集成测试守，本 fake 只验 CAS 语义。
    struct FakeStore {
        state: Mutex<HashMap<String, Entry>>,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                state: Mutex::new(HashMap::new()),
            }
        }
    }

    impl IdempotencyStore for FakeStore {
        async fn check(&self, key: &IdemKey, lease: &LeaseToken) -> Result<SeenState, EngineError> {
            let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
            // reason: in-mem 操作恒成功，unwrap_or_else 处理 poisoned lock 后继续。
            if map.contains_key(key.as_str()) {
                // 已 claimed/done（无 TTL 重捞）→ Duplicate。
                Ok(SeenState::Duplicate)
            } else {
                map.insert(
                    key.as_str().to_string(),
                    Entry {
                        token: lease.as_str().to_string(),
                        done: false,
                    },
                );
                Ok(SeenState::Fresh)
            }
        }

        async fn extend(
            &self,
            key: &IdemKey,
            lease: &LeaseToken,
        ) -> Result<LeaseOutcome, EngineError> {
            // reason: in-mem 恒 Ok；仅 claimed 且 token 匹配 → Held，否则 Lost。
            let map = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let held = matches!(
                map.get(key.as_str()),
                Some(e) if !e.done && e.token == lease.as_str()
            );
            Ok(if held {
                LeaseOutcome::Held
            } else {
                LeaseOutcome::Lost
            })
        }

        async fn commit(
            &self,
            key: &IdemKey,
            lease: &LeaseToken,
        ) -> Result<LeaseOutcome, EngineError> {
            // reason: in-mem commit 恒 Ok；token 匹配 → done(Held)，不符/absent → Lost（hard-fence）。
            let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
            match map.get_mut(key.as_str()) {
                Some(e) if e.token == lease.as_str() => {
                    e.done = true;
                    Ok(LeaseOutcome::Held)
                }
                _ => Ok(LeaseOutcome::Lost),
            }
        }

        async fn release(&self, key: &IdemKey, lease: &LeaseToken) -> Result<(), EngineError> {
            // reason: in-mem release 恒 Ok；仅 token 匹配的 claimed 行删除（CAS），否则 no-op。
            let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if matches!(map.get(key.as_str()), Some(e) if !e.done && e.token == lease.as_str()) {
                map.remove(key.as_str());
            }
            Ok(())
        }
    }

    // ─── 状态机测试（TDD）────────────────────────────────────────────────────────

    #[allow(clippy::unwrap_used)]
    // reason: 测试用 parse — 已知非空 key，item-level carve-out（error-handling.md §Carve-out）。
    fn k(raw: &str) -> IdemKey {
        IdemKey::parse(raw).unwrap()
    }

    /// 测试令牌 helper。
    fn tok(raw: &str) -> LeaseToken {
        LeaseToken::new(raw)
    }

    /// claim → commit(Held) → 再 check = Duplicate（done 永久去重）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store.check/commit 在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn state_machine_claim_commit_then_duplicate() {
        let store = FakeStore::new();
        let key = k("evt-commit-1");
        let t = tok("lease-1");
        assert_eq!(store.check(&key, &t).await.unwrap(), SeenState::Fresh);
        assert_eq!(store.commit(&key, &t).await.unwrap(), LeaseOutcome::Held);
        assert_eq!(
            store.check(&key, &tok("lease-2")).await.unwrap(),
            SeenState::Duplicate
        );
    }

    /// claim → release(CAS) → 再 check = Fresh（释放后可重领）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn state_machine_claim_release_then_fresh() {
        let store = FakeStore::new();
        let key = k("evt-release-1");
        let t = tok("lease-1");
        assert_eq!(store.check(&key, &t).await.unwrap(), SeenState::Fresh);
        store.release(&key, &t).await.unwrap();
        assert_eq!(
            store.check(&key, &tok("lease-2")).await.unwrap(),
            SeenState::Fresh
        );
    }

    /// commit 对 absent key 返 Lost（hard-fence；不创建行，check 仍 Fresh）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn commit_on_absent_key_is_lost() {
        let store = FakeStore::new();
        let key = k("evt-absent-commit");
        // 直接 commit，未 claim → Lost（无匹配 CAS）
        assert_eq!(
            store.commit(&key, &tok("lease-1")).await.unwrap(),
            LeaseOutcome::Lost
        );
        // 之后 check 仍可 Fresh（absent 状态未被写入 done）
        assert_eq!(
            store.check(&key, &tok("lease-2")).await.unwrap(),
            SeenState::Fresh
        );
    }

    /// release 对 absent key 幂等 no-op（不 panic，Ok）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn release_on_absent_key_is_noop() {
        let store = FakeStore::new();
        let key = k("evt-absent-release");
        // 直接 release，未 claim
        assert!(store.release(&key, &tok("lease-1")).await.is_ok());
        // 之后 check 仍可 Fresh
        assert_eq!(
            store.check(&key, &tok("lease-2")).await.unwrap(),
            SeenState::Fresh
        );
    }

    /// 续租：持有期间 extend = Held；token 不符 = Lost（已被重捞）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn extend_held_while_owned_lost_on_token_mismatch() {
        let store = FakeStore::new();
        let key = k("evt-extend-1");
        let mine = tok("lease-mine");
        assert_eq!(store.check(&key, &mine).await.unwrap(), SeenState::Fresh);
        // 持有者续租成功
        assert_eq!(store.extend(&key, &mine).await.unwrap(), LeaseOutcome::Held);
        // 他人令牌续租 → Lost
        assert_eq!(
            store.extend(&key, &tok("lease-other")).await.unwrap(),
            LeaseOutcome::Lost
        );
    }

    /// hard-fence：stale token commit = Lost；正确 token commit = Held。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn commit_with_stale_token_is_lost_hard_fence() {
        let store = FakeStore::new();
        let key = k("evt-fence-1");
        let mine = tok("lease-mine");
        assert_eq!(store.check(&key, &mine).await.unwrap(), SeenState::Fresh);
        // stale holder（错误 token）commit → Lost（不可降级为 done）
        assert_eq!(
            store.commit(&key, &tok("lease-stale")).await.unwrap(),
            LeaseOutcome::Lost
        );
        // 真持有者 commit → Held
        assert_eq!(store.commit(&key, &mine).await.unwrap(), LeaseOutcome::Held);
    }

    /// commit 后再 extend = Lost（done 行不可续租）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn extend_after_commit_is_lost() {
        let store = FakeStore::new();
        let key = k("evt-extend-done");
        let t = tok("lease-1");
        assert_eq!(store.check(&key, &t).await.unwrap(), SeenState::Fresh);
        assert_eq!(store.commit(&key, &t).await.unwrap(), LeaseOutcome::Held);
        assert_eq!(store.extend(&key, &t).await.unwrap(), LeaseOutcome::Lost);
    }

    /// release token CAS：他人 token release 为 no-op（不误删，仍 Duplicate）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn release_with_stale_token_is_noop() {
        let store = FakeStore::new();
        let key = k("evt-release-cas");
        let mine = tok("lease-mine");
        assert_eq!(store.check(&key, &mine).await.unwrap(), SeenState::Fresh);
        // stale token release → no-op
        store.release(&key, &tok("lease-stale")).await.unwrap();
        // claim 仍在（未被误删）→ Duplicate
        assert_eq!(
            store.check(&key, &tok("lease-x")).await.unwrap(),
            SeenState::Duplicate
        );
    }

    /// 表驱动：多条 key 各自独立状态机，互不干扰。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn multiple_keys_independent_state_machines() {
        let store = FakeStore::new();
        let keys: &[&str] = &["evt-A", "evt-B", "evt-C"];
        let t = tok("lease-shared");
        // 全部 claim
        for &raw in keys {
            assert_eq!(
                store.check(&k(raw), &t).await.unwrap(),
                SeenState::Fresh,
                "raw={raw}"
            );
        }
        // A commit，B release，C 留 claimed
        assert_eq!(
            store.commit(&k("evt-A"), &t).await.unwrap(),
            LeaseOutcome::Held
        );
        store.release(&k("evt-B"), &t).await.unwrap();
        // A：done → Duplicate
        assert_eq!(
            store.check(&k("evt-A"), &t).await.unwrap(),
            SeenState::Duplicate
        );
        // B：absent → Fresh
        assert_eq!(
            store.check(&k("evt-B"), &t).await.unwrap(),
            SeenState::Fresh
        );
        // C：still claimed → Duplicate
        assert_eq!(
            store.check(&k("evt-C"), &t).await.unwrap(),
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
