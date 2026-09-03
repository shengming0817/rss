//! 幂等去重词汇类型（L0）。
//!
//! 本模块只冻结消费侧 inbox 去重所需的稳定 key / group / lease token / CAS outcome 词汇。
//! 持久化 claim 接缝归 [`crate::inbox::InboxStore`]，避免把 consumer inbox 的存储端口继续挂在
//! `idempotency` 模块名下。
//! ref: kube-rs kube-runtime/src/watcher.rs@main（内部 native AFIT trait `ApiMode` + 泛型 `step<A>` 消费）。

use sha2::{Digest as _, Sha256};

const EXTERNAL_EFFECT_KEY_DOMAIN: &str = "rss-consumer-external-effect-v1";

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

/// Crate-private stable provider key reserved for the inactive idempotent ConsumerTx policy.
///
/// The raw value cannot be parsed or supplied by business code. It is derived only from the same
/// tenant, event id, and consumer group that identify the durable Inbox receipt, so retries reuse
/// one provider key without creating a second Inbox identity.
///
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct ExternalEffectIdempotencyKey(String);

impl std::fmt::Debug for ExternalEffectIdempotencyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExternalEffectIdempotencyKey(<redacted>)")
    }
}

/// Crate-owned proof that key material came through the verified Inbox claim boundary.
///
/// The type and its fields are not public API, so public `InboxReceiptContext`/`IdemKey` values
/// cannot be combined by application code to mint provider keys.
#[allow(dead_code)]
// reason: frozen for the inactive IdempotencyKey policy; only internal conformance tests activate it.
pub(crate) struct VerifiedExternalEffectInboxIdentity<'a> {
    context: &'a crate::inbox::InboxReceiptContext,
    event_id: &'a IdemKey,
}

#[allow(dead_code)]
// reason: frozen for the inactive IdempotencyKey policy; the future engine claim funnel is its consumer.
impl<'a> VerifiedExternalEffectInboxIdentity<'a> {
    pub(crate) fn from_verified_claim(
        context: &'a crate::inbox::InboxReceiptContext,
        event_id: &'a IdemKey,
    ) -> Self {
        Self { context, event_id }
    }
}

#[allow(dead_code)]
// reason: frozen derivation has no production caller until the IdempotencyKey policy is activated.
impl ExternalEffectIdempotencyKey {
    /// Derive the provider key from a crate-owned verified Inbox identity.
    #[must_use]
    pub(crate) fn derive(identity: &VerifiedExternalEffectInboxIdentity<'_>) -> Self {
        let mut hasher = Sha256::new();
        hash_component(&mut hasher, EXTERNAL_EFFECT_KEY_DOMAIN);
        hash_component(&mut hasher, &identity.context.tenant_id().to_string());
        hash_component(&mut hasher, identity.event_id.as_str());
        hash_component(&mut hasher, identity.context.consumer_group().as_str());
        Self(format!("sha256:{:x}", hasher.finalize()))
    }

    /// Borrow the stable provider representation.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

fn hash_component(hasher: &mut Sha256, value: &str) {
    hasher.update(value.len().to_string().as_bytes());
    hasher.update(b":");
    hasher.update(value.as_bytes());
    hasher.update(b"\0");
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
pub enum SeenState {
    /// 首次见到此 key（应执行副作用）；本消费者持有以传入 [`LeaseToken`] 标记的 claim。
    Fresh,
    /// Another consumer currently owns an active claim lease.
    ///
    /// This is expected contention, not a backend failure. The consumer must retain the broker
    /// delivery, wait according to the provider-bound lease policy, then requeue it without
    /// invoking the handler.
    InProgress,
    /// 已持久完成（应跳过，幂等短路）。
    ///
    /// 活跃 `claimed` 不属于 Duplicate：store 必须返回 [`Self::InProgress`]，使 broker 保留并重投消息。
    Duplicate,
}

impl SeenState {
    /// Stable low-cardinality metrics/log label.
    pub fn as_label(self) -> &'static str {
        match self {
            SeenState::Fresh => "fresh",
            SeenState::InProgress => "in_progress",
            SeenState::Duplicate => "duplicate",
        }
    }
}

/// 租约令牌（uuid v4 newtype，私有字段 + 唯一构造入口 [`LeaseToken::mint`]，#1213 / #1354 F4）。
///
/// 消费方每次 claim 前 [`mint`](LeaseToken::mint) 一枚（内部铸 uuid v4 文本），随
/// [`crate::inbox::InboxStore::try_claim`] 传入；store 在 claimed 行 stamp 此 token。后续
/// `extend`/`commit`/`release` 凭它做 **CAS 围栏**——令牌不符即判 [`LeaseOutcome::Lost`]
/// （claim 已被 TTL 重捞、他人接管），触发 hard-fence。
///
/// # Enforcement 分级
///
/// - **token 必为 uuid v4**——唯一构造入口 `mint()` 内铸 `uuid::Uuid::new_v4()`，类型层**无**裸 `String`
///   入口（已删 `new(raw)`，#1354 F4）；调用方无法构造非-uuid-v4 / 低熵 token——类型系统强制（**Hard**）。
/// - **不同消费者持有不同 token 而无法冒用**——`mint()` 每次铸全新随机 uuid v4 + token 不跨消费者传输的
///   协议约定（**Medium**）：类型层不阻止同进程再 `mint()` 别的 token，但无法**选定**特定值冒用他人持有的 token。
///
/// `Debug` 脱敏：token 是 lease TTL 窗口内的 CAS 围栏令牌，泄漏即可被 stale holder 冒用劫持 fence；
/// 照 codebase 敏感 token 惯例（如 `VaultToken`）`Debug` 固定 `<redacted>`，不随结构化日志外泄。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LeaseToken(String);

impl std::fmt::Debug for LeaseToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: 围栏令牌脱敏，杜绝 `{:?}` 误入日志泄漏可劫持 CAS 的 token 文本。
        f.write_str("LeaseToken(<redacted>)")
    }
}

impl LeaseToken {
    /// 铸一枚新租约令牌（内部 `uuid::Uuid::new_v4()`）——唯一构造入口，uuid v4 由此构造保证（#1354 F4）。
    pub fn mint() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
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

impl LeaseOutcome {
    /// Stable low-cardinality metrics/log label.
    pub fn as_label(self) -> &'static str {
        match self {
            LeaseOutcome::Held => "held",
            LeaseOutcome::Lost => "lost",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    use super::{
        ConsumerGroup, ConsumerGroupError, ExternalEffectIdempotencyKey, IdemKey, IdemKeyError,
        LeaseOutcome, LeaseToken, SeenState, VerifiedExternalEffectInboxIdentity,
    };
    use crate::error::EngineError;
    use crate::inbox::{InboxReceiptContext, InboxStore};

    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d480";
    const SCHEMA_HASH: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[allow(clippy::expect_used)]
    // reason: fixed valid fixtures make setup failure a test-construction bug.
    fn receipt(tenant: &str, group: &str) -> InboxReceiptContext {
        InboxReceiptContext::new(
            rss_request_context::TenantId::parse(tenant).expect("tenant"),
            ConsumerGroup::parse(group).expect("group"),
            "runtime",
            "runtime.fact-recorded",
            "runtime.fact-recorded",
            "v1",
            SCHEMA_HASH,
            None,
            None,
        )
        .expect("receipt")
    }

    fn external_effect_key(
        context: &InboxReceiptContext,
        event_id: &IdemKey,
    ) -> ExternalEffectIdempotencyKey {
        let identity = VerifiedExternalEffectInboxIdentity::from_verified_claim(context, event_id);
        ExternalEffectIdempotencyKey::derive(&identity)
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: fixed non-empty event fixtures make parse failure a test-construction bug.
    fn external_effect_key_is_stable_and_bound_to_verified_inbox_identity() {
        let event_a = IdemKey::parse("event-1").expect("event");
        let event_b = IdemKey::parse("event-2").expect("event");
        let context = receipt(TENANT_A, "audit-consumer");

        let key = external_effect_key(&context, &event_a);
        assert_eq!(
            key.as_str(),
            "sha256:f38b4e73be55986b8ac0c51fbc6164da0175f93c3191950b4768f55e9a2a04f1"
        );
        assert_eq!(key, external_effect_key(&context, &event_a));
        assert_ne!(key, external_effect_key(&context, &event_b));
        assert_ne!(
            key,
            external_effect_key(&receipt(TENANT_B, "audit-consumer"), &event_a)
        );
        assert_ne!(
            key,
            external_effect_key(&receipt(TENANT_A, "audit-consumer-v2"), &event_a)
        );
    }

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

    impl InboxStore for FakeStore {
        async fn try_claim(
            &self,
            _ctx: &InboxReceiptContext,
            key: &IdemKey,
            lease: &LeaseToken,
        ) -> Result<SeenState, EngineError> {
            let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
            // reason: in-mem 操作恒成功，unwrap_or_else 处理 poisoned lock 后继续。
            if let Some(entry) = map.get(key.as_str()) {
                if entry.done {
                    Ok(SeenState::Duplicate)
                } else {
                    Ok(SeenState::InProgress)
                }
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
            _ctx: &InboxReceiptContext,
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
            _ctx: &InboxReceiptContext,
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

        async fn release(
            &self,
            _ctx: &InboxReceiptContext,
            key: &IdemKey,
            lease: &LeaseToken,
        ) -> Result<(), EngineError> {
            // reason: in-mem release 恒 Ok；仅 token 匹配的 claimed 行删除（CAS），否则 no-op。
            let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if matches!(map.get(key.as_str()), Some(e) if !e.done && e.token == lease.as_str()) {
                map.remove(key.as_str());
            }
            Ok(())
        }
    }

    // ─── 状态机测试（TDD）────────────────────────────────────────────────────────

    #[test]
    fn seen_state_labels_are_stable_and_distinct() {
        let cases = [
            (SeenState::Fresh, "fresh"),
            (SeenState::InProgress, "in_progress"),
            (SeenState::Duplicate, "duplicate"),
        ];
        for (state, expected) in cases {
            assert_eq!(state.as_label(), expected);
        }
        assert_ne!(SeenState::Fresh.as_label(), SeenState::Duplicate.as_label());
        assert_ne!(
            SeenState::InProgress.as_label(),
            SeenState::Duplicate.as_label()
        );
    }

    #[test]
    fn lease_outcome_labels_are_stable_and_distinct() {
        let cases = [(LeaseOutcome::Held, "held"), (LeaseOutcome::Lost, "lost")];
        for (outcome, expected) in cases {
            assert_eq!(outcome.as_label(), expected);
        }
        assert_ne!(LeaseOutcome::Held.as_label(), LeaseOutcome::Lost.as_label());
    }

    #[allow(clippy::unwrap_used)]
    // reason: 测试用 parse — 已知非空 key，item-level carve-out。
    fn k(raw: &str) -> IdemKey {
        IdemKey::parse(raw).unwrap()
    }

    /// 测试令牌 helper：每次铸一枚新 uuid v4（绑定变量复用同 token；内联调用得不同 token）。
    fn tok() -> LeaseToken {
        LeaseToken::mint()
    }

    #[allow(clippy::unwrap_used)]
    // reason: 测试 fixture 使用固定合法值，构造失败即测试本身配置错误。
    fn ctx() -> &'static InboxReceiptContext {
        static CTX: OnceLock<InboxReceiptContext> = OnceLock::new();
        CTX.get_or_init(|| {
            InboxReceiptContext::new(
                rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                    .unwrap(),
                ConsumerGroup::parse("test-consumer").unwrap(),
                "runtime",
                "runtime.fact-recorded",
                "runtime.fact-recorded",
                "v1",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                None,
                None,
            )
            .unwrap()
        })
    }

    /// claim → commit(Held) → 再 try_claim = Duplicate（该 state 中 done 为 terminal；durable provider 可按
    /// 自身 retention 策略回收 receipt）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store.try_claim/commit 在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn state_machine_claim_commit_then_duplicate() {
        let store = FakeStore::new();
        let key = k("evt-commit-1");
        let t = tok();
        assert_eq!(
            store.try_claim(ctx(), &key, &t).await.unwrap(),
            SeenState::Fresh
        );
        assert_eq!(
            store.commit(ctx(), &key, &t).await.unwrap(),
            LeaseOutcome::Held
        );
        assert_eq!(
            store.try_claim(ctx(), &key, &tok()).await.unwrap(),
            SeenState::Duplicate
        );
    }

    /// claim → release(CAS) → 再 try_claim = Fresh（释放后可重领）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn state_machine_claim_release_then_fresh() {
        let store = FakeStore::new();
        let key = k("evt-release-1");
        let t = tok();
        assert_eq!(
            store.try_claim(ctx(), &key, &t).await.unwrap(),
            SeenState::Fresh
        );
        store.release(ctx(), &key, &t).await.unwrap();
        assert_eq!(
            store.try_claim(ctx(), &key, &tok()).await.unwrap(),
            SeenState::Fresh
        );
    }

    /// commit 对 absent key 返 Lost（hard-fence；不创建行，try_claim 仍 Fresh）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn commit_on_absent_key_is_lost() {
        let store = FakeStore::new();
        let key = k("evt-absent-commit");
        // 直接 commit，未 claim → Lost（无匹配 CAS）
        assert_eq!(
            store.commit(ctx(), &key, &tok()).await.unwrap(),
            LeaseOutcome::Lost
        );
        // 之后 try_claim 仍可 Fresh（absent 状态未被写入 done）
        assert_eq!(
            store.try_claim(ctx(), &key, &tok()).await.unwrap(),
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
        assert!(store.release(ctx(), &key, &tok()).await.is_ok());
        // 之后 try_claim 仍可 Fresh
        assert_eq!(
            store.try_claim(ctx(), &key, &tok()).await.unwrap(),
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
        let mine = tok();
        assert_eq!(
            store.try_claim(ctx(), &key, &mine).await.unwrap(),
            SeenState::Fresh
        );
        // 持有者续租成功
        assert_eq!(
            store.extend(ctx(), &key, &mine).await.unwrap(),
            LeaseOutcome::Held
        );
        // 他人令牌续租 → Lost
        assert_eq!(
            store.extend(ctx(), &key, &tok()).await.unwrap(),
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
        let mine = tok();
        assert_eq!(
            store.try_claim(ctx(), &key, &mine).await.unwrap(),
            SeenState::Fresh
        );
        // stale holder（错误 token）commit → Lost（不可降级为 done）
        assert_eq!(
            store.commit(ctx(), &key, &tok()).await.unwrap(),
            LeaseOutcome::Lost
        );
        // 真持有者 commit → Held
        assert_eq!(
            store.commit(ctx(), &key, &mine).await.unwrap(),
            LeaseOutcome::Held
        );
    }

    /// commit 后再 extend = Lost（done 行不可续租）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn extend_after_commit_is_lost() {
        let store = FakeStore::new();
        let key = k("evt-extend-done");
        let t = tok();
        assert_eq!(
            store.try_claim(ctx(), &key, &t).await.unwrap(),
            SeenState::Fresh
        );
        assert_eq!(
            store.commit(ctx(), &key, &t).await.unwrap(),
            LeaseOutcome::Held
        );
        assert_eq!(
            store.extend(ctx(), &key, &t).await.unwrap(),
            LeaseOutcome::Lost
        );
    }

    /// release token CAS：他人 token release 为 no-op（不误删，active claim 仍 in-progress）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn release_with_stale_token_is_noop() {
        let store = FakeStore::new();
        let key = k("evt-release-cas");
        let mine = tok();
        assert_eq!(
            store.try_claim(ctx(), &key, &mine).await.unwrap(),
            SeenState::Fresh
        );
        // stale token release → no-op
        store.release(ctx(), &key, &tok()).await.unwrap();
        // claim 仍在（未被误删）→ typed in-progress
        assert_eq!(
            store.try_claim(ctx(), &key, &tok()).await.unwrap(),
            SeenState::InProgress
        );
    }

    /// 表驱动：多条 key 各自独立状态机，互不干扰。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 状态机断言测试——store 方法在 in-mem 实现中恒 Ok，item-level carve-out。
    async fn multiple_keys_independent_state_machines() {
        let store = FakeStore::new();
        let keys: &[&str] = &["evt-A", "evt-B", "evt-C"];
        let t = tok();
        // 全部 claim
        for &raw in keys {
            assert_eq!(
                store.try_claim(ctx(), &k(raw), &t).await.unwrap(),
                SeenState::Fresh,
                "raw={raw}"
            );
        }
        // A commit，B release，C 留 claimed
        assert_eq!(
            store.commit(ctx(), &k("evt-A"), &t).await.unwrap(),
            LeaseOutcome::Held
        );
        store.release(ctx(), &k("evt-B"), &t).await.unwrap();
        // A：done → Duplicate
        assert_eq!(
            store.try_claim(ctx(), &k("evt-A"), &t).await.unwrap(),
            SeenState::Duplicate
        );
        // B：absent → Fresh
        assert_eq!(
            store.try_claim(ctx(), &k("evt-B"), &t).await.unwrap(),
            SeenState::Fresh
        );
        // C：still claimed → typed in-progress，不得伪装 durable done 或后端故障。
        assert_eq!(
            store.try_claim(ctx(), &k("evt-C"), &t).await.unwrap(),
            SeenState::InProgress
        );
    }

    // ─── LeaseToken mint 硬化（F4：uuid v4 由构造保证，非协议约定）──────────────────

    /// mint() 产出合法 uuid v4（version == Random）——uuid v4 从「协议约定」上移为「构造保证」。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 断言已知由 mint 铸出的 uuid 文本可解析，item-level carve-out。
    fn mint_produces_valid_uuid_v4() {
        let token = LeaseToken::mint();
        let parsed = uuid::Uuid::parse_str(token.as_str()).unwrap();
        assert_eq!(
            parsed.get_version(),
            Some(uuid::Version::Random),
            "token={token:?}"
        );
    }

    /// 两次 mint() 产出不同 token（uuid v4 熵——token CAS 围栏依赖唯一性）。
    #[test]
    fn two_mints_are_distinct() {
        assert_ne!(LeaseToken::mint(), LeaseToken::mint());
    }

    // ─── IdemKey / ConsumerGroup 原有测试（保留）────────────────────────────────

    // 任意非空 key 接受（opaque，不限字符集、不 trim）；as_str 往返。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果，item-level carve-out。
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
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果，item-level carve-out。
    fn idem_key_parse_accepts_whitespace_only_opaque() {
        for &raw in &[" ", "\t", "  x  "] {
            assert!(IdemKey::parse(raw).is_ok(), "expected Ok for raw={raw:?}");
            assert_eq!(IdemKey::parse(raw).unwrap().as_str(), raw, "raw={raw:?}");
        }
    }

    // 任意非空组名接受（opaque）；as_str 往返。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果，item-level carve-out。
    fn consumer_group_parse_accepts_non_empty_and_round_trips() {
        for &raw in &["observer", "observer.fact-recorded", "grp-1", " "] {
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
