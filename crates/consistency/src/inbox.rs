//! Inbox semantic model and engine ports for consumer-side idempotency.
//!
//! This module freezes the pure state machine and native AFIT engine ports behind durable inbox
//! implementations. It deliberately does not own clocks, broker settle, DLX, or runtime renewal
//! loops; those stay in adapters and `eventexec`. The storage shape is absent row -> `claimed` ->
//! `done`, while `absent` exists only as an engine state, not as a persisted status label.
//!
//! ref: MassTransit/MassTransit src/Persistence/MassTransit.EntityFrameworkCoreIntegration/EntityFrameworkCoreIntegration/InboxState.cs@62ab339afa3bac2e9b3fe1769d0d35d7e44778e9

use crate::error::EngineError;
use crate::idempotency::{IdemKey, LeaseOutcome, LeaseToken, SeenState};
use crate::outbox::BacklogSample;

/// Persisted inbox row status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboxStatus {
    /// A consumer currently owns the claim lease.
    Claimed,
    /// The message has reached a terminal dedup state.
    Done,
}

impl InboxStatus {
    /// Stable storage/metrics label for persisted statuses.
    pub fn as_label(self) -> &'static str {
        match self {
            InboxStatus::Claimed => "claimed",
            InboxStatus::Done => "done",
        }
    }

    /// Parse a persisted inbox status label.
    pub fn parse_label(raw: &str) -> Result<Self, InboxStatusError> {
        match raw {
            "claimed" => Ok(Self::Claimed),
            "done" => Ok(Self::Done),
            _ => Err(InboxStatusError::Unknown),
        }
    }
}

/// Inbox status parse error.
///
/// The unknown input is intentionally not retained: status labels can be sourced from durable
/// storage and should not be reflected into logs/errors as runtime strings.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboxStatusError {
    /// The status label is not in the closed inbox status set.
    #[error("unknown inbox status label")]
    Unknown,
}

/// Lease freshness as evaluated by the storage adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboxLeaseFreshness {
    /// Lease is still valid; another claim must be treated as duplicate.
    Active,
    /// Lease is stale enough to be reclaimed.
    Expired,
}

impl InboxLeaseFreshness {
    /// Stable low-cardinality label for freshness observations.
    pub fn as_label(self) -> &'static str {
        match self {
            InboxLeaseFreshness::Active => "active",
            InboxLeaseFreshness::Expired => "expired",
        }
    }
}

/// A claimed inbox row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxClaim {
    lease: LeaseToken,
    freshness: InboxLeaseFreshness,
}

impl InboxClaim {
    /// Build an active claim held by `lease`.
    pub fn active(lease: LeaseToken) -> Self {
        Self {
            lease,
            freshness: InboxLeaseFreshness::Active,
        }
    }

    /// Build an expired claim held by `lease`.
    pub fn expired(lease: LeaseToken) -> Self {
        Self {
            lease,
            freshness: InboxLeaseFreshness::Expired,
        }
    }

    /// Borrow the lease token associated with this claim.
    pub fn lease(&self) -> &LeaseToken {
        &self.lease
    }

    /// Current lease freshness observation.
    pub fn freshness(&self) -> InboxLeaseFreshness {
        self.freshness
    }

    fn lease_matches(&self, lease: &LeaseToken) -> bool {
        &self.lease == lease
    }
}

/// Pure inbox state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboxState {
    /// No durable inbox row exists.
    Absent,
    /// A claimed row exists and carries a lease token.
    Claimed(InboxClaim),
    /// Terminal dedup row exists.
    Done,
}

impl InboxState {
    /// Persisted status for this state, if any.
    pub fn status(&self) -> Option<InboxStatus> {
        match self {
            Self::Absent => None,
            Self::Claimed(_) => Some(InboxStatus::Claimed),
            Self::Done => Some(InboxStatus::Done),
        }
    }

    /// Claim or reclaim the state with `lease`.
    pub fn try_claim(self, lease: LeaseToken) -> (SeenState, Self) {
        match self {
            Self::Absent => (SeenState::Fresh, Self::Claimed(InboxClaim::active(lease))),
            Self::Claimed(claim) if claim.freshness() == InboxLeaseFreshness::Expired => {
                (SeenState::Fresh, Self::Claimed(InboxClaim::active(lease)))
            }
            Self::Claimed(claim) => (SeenState::Duplicate, Self::Claimed(claim)),
            Self::Done => (SeenState::Duplicate, Self::Done),
        }
    }

    /// Extend the matching claim lease.
    pub fn extend(&self, lease: &LeaseToken) -> LeaseOutcome {
        match self {
            Self::Claimed(claim) if claim.lease_matches(lease) => LeaseOutcome::Held,
            _ => LeaseOutcome::Lost,
        }
    }

    /// Commit a matching claim into the terminal dedup state.
    pub fn commit(self, lease: &LeaseToken) -> (LeaseOutcome, Self) {
        match self {
            Self::Claimed(claim) if claim.lease_matches(lease) => (LeaseOutcome::Held, Self::Done),
            state => (LeaseOutcome::Lost, state),
        }
    }

    /// Release a matching claim back to absent.
    pub fn release(self, lease: &LeaseToken) -> Self {
        match self {
            Self::Claimed(claim) if claim.lease_matches(lease) => Self::Absent,
            state => state,
        }
    }
}

/// 消费方 inbox claim + lease CAS 策略（L0 引擎策略 trait，native AFIT）。
///
/// trait 内直接 `async fn`——**不** object-safe，故消费方用泛型 `<S: InboxStore>` 静态分发，
/// 禁 `Box<dyn InboxStore>`。这是 consistency 引擎策略端口，**非** `diport` dyn port。
///
/// # 状态机（absent → claimed(token) → done）
///
/// - `try_claim`：absent / **TTL 过期的 claimed** → claimed(传入 token)（`Fresh`）；fresh-claimed / done →
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
pub trait InboxStore {
    /// 铸 claim 并查询首见（claim-or-skip + TTL 重捞）。`lease` 由 [`LeaseToken::mint`] 铸出（uuid v4）。
    ///
    /// **写副作用（`Fresh` 路径）**：`try_claim` 在 `Fresh` 路径上执行 `INSERT ... ON CONFLICT` / `SET NX`
    /// 原子操作，将 `lease` token stamp 到后端——**不是只读谓词**；方法名 `try_claim` 即点明 claim 写语义（#1354）。
    ///
    /// `Fresh` ⇒ 本消费者持有以 `lease` 标记的 claim，应执行副作用；`Duplicate` ⇒ 幂等短路（他人持有或已 done）。
    ///
    /// **`Duplicate` 路径**：传入的 `lease` **不会**写入后端——claim-or-reclaim 是单一原子操作，token 必须
    /// 在调用前铸出；若返回 `Duplicate`，调用方可丢弃该 token。
    async fn try_claim(&self, key: &IdemKey, lease: &LeaseToken) -> Result<SeenState, EngineError>;

    /// 续租：刷新 `lease` 标记的 claimed 行到期点。`Held` 仍持有 / `Lost` 已被重捞（hard-fence 信号）。
    ///
    /// 对 absent / 他人持有 / 已 done 的行返回 `Lost`（无匹配 CAS）。
    async fn extend(&self, key: &IdemKey, lease: &LeaseToken) -> Result<LeaseOutcome, EngineError>;

    /// claimed→done（CAS）：仅当 `lease` 仍匹配时标记永久去重。`Held` 提交成功 / `Lost` 租约已失（勿 Ack）。
    ///
    /// 对 absent / 已被重捞的行返回 `Lost`（hard-fence：消费方降级 Requeue、不移除 broker 投递）。
    async fn commit(&self, key: &IdemKey, lease: &LeaseToken) -> Result<LeaseOutcome, EngineError>;

    /// claimed→absent（CAS）：仅当 `lease` 仍匹配时释放 claim，使后续重放可重新得到 `Fresh`。
    ///
    /// 令牌不符（已被重捞）为幂等 no-op（`Ok(())`，不误删他人 claim）；对 absent key 同样 no-op。
    async fn release(&self, key: &IdemKey, lease: &LeaseToken) -> Result<(), EngineError>;
}

/// Inbox backlog sampler scoped to the consumer group bound by the store handle.
///
/// Implementations count only stale `claimed` rows that can block replay visibility for this group.
/// Active claims and terminal `done` rows are excluded. When clear, implementations return
/// [`BacklogSample::empty`] (`depth=0`, `oldest_age_seconds=0`). Native AFIT keeps this port generic
/// and non-object-safe; do not add a `diport` dyn wrapper.
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费；与 InboxStore/OutboxBacklog 同范式。
pub trait InboxBacklog {
    /// Sample stale claimed inbox rows for the handle's bound consumer group.
    async fn sample_backlog(&self) -> Result<BacklogSample, EngineError>;
}

#[cfg(test)]
mod tests {
    use super::{InboxClaim, InboxLeaseFreshness, InboxState, InboxStatus, InboxStatusError};
    use crate::{LeaseOutcome, LeaseToken, SeenState};

    fn token_pair() -> (LeaseToken, LeaseToken) {
        (LeaseToken::mint(), LeaseToken::mint())
    }

    #[test]
    fn inbox_status_labels_are_stable_and_parseable() {
        let cases = [
            (InboxStatus::Claimed, "claimed"),
            (InboxStatus::Done, "done"),
        ];
        for (status, expected) in cases {
            assert_eq!(status.as_label(), expected);
            assert_eq!(InboxStatus::parse_label(expected), Ok(status));
        }
        assert_ne!(
            InboxStatus::Claimed.as_label(),
            InboxStatus::Done.as_label()
        );
        assert_eq!(
            InboxStatus::parse_label("absent"),
            Err(InboxStatusError::Unknown)
        );
        assert_eq!(
            InboxStatus::parse_label("CLAIMED"),
            Err(InboxStatusError::Unknown)
        );
    }

    #[test]
    fn inbox_lease_freshness_labels_are_stable_and_distinct() {
        assert_eq!(InboxLeaseFreshness::Active.as_label(), "active");
        assert_eq!(InboxLeaseFreshness::Expired.as_label(), "expired");
        assert_ne!(
            InboxLeaseFreshness::Active.as_label(),
            InboxLeaseFreshness::Expired.as_label()
        );
    }

    #[test]
    fn inbox_claim_constructors_set_freshness_and_redact_debug() {
        let lease = LeaseToken::mint();
        let active = InboxClaim::active(lease.clone());
        let expired = InboxClaim::expired(lease.clone());

        assert_eq!(active.lease(), &lease);
        assert_eq!(active.freshness(), InboxLeaseFreshness::Active);
        assert_eq!(expired.lease(), &lease);
        assert_eq!(expired.freshness(), InboxLeaseFreshness::Expired);

        let debug = format!("{active:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(lease.as_str()));
    }

    #[test]
    fn inbox_state_status_maps_only_persisted_states() {
        let (lease, _) = token_pair();
        assert_eq!(InboxState::Absent.status(), None);
        assert_eq!(
            InboxState::Claimed(InboxClaim::active(lease)).status(),
            Some(InboxStatus::Claimed)
        );
        assert_eq!(InboxState::Done.status(), Some(InboxStatus::Done));
    }

    #[test]
    fn claim_absent_returns_fresh_and_active_claim() {
        let (lease, _) = token_pair();
        let (seen, state) = InboxState::Absent.try_claim(lease.clone());

        assert_eq!(seen, SeenState::Fresh);
        assert!(matches!(state, InboxState::Claimed(_)));
        if let InboxState::Claimed(claim) = state {
            assert_eq!(claim.lease(), &lease);
            assert_eq!(claim.freshness(), InboxLeaseFreshness::Active);
        }
    }

    #[test]
    fn claim_active_claim_is_duplicate_and_preserves_lease() {
        let (held, contender) = token_pair();
        let state = InboxState::Claimed(InboxClaim::active(held.clone()));

        let (seen, state) = state.try_claim(contender);

        assert_eq!(seen, SeenState::Duplicate);
        assert!(matches!(state, InboxState::Claimed(_)));
        if let InboxState::Claimed(claim) = state {
            assert_eq!(claim.lease(), &held);
        }
    }

    #[test]
    fn claim_expired_claim_reclaims_with_new_active_lease() {
        let (stale, new_lease) = token_pair();
        let state = InboxState::Claimed(InboxClaim::expired(stale));

        let (seen, state) = state.try_claim(new_lease.clone());

        assert_eq!(seen, SeenState::Fresh);
        assert!(matches!(state, InboxState::Claimed(_)));
        if let InboxState::Claimed(claim) = state {
            assert_eq!(claim.lease(), &new_lease);
            assert_eq!(claim.freshness(), InboxLeaseFreshness::Active);
        }
    }

    #[test]
    fn claim_done_is_duplicate_and_preserves_done() {
        let (lease, _) = token_pair();

        let (seen, state) = InboxState::Done.try_claim(lease);

        assert_eq!(seen, SeenState::Duplicate);
        assert_eq!(state, InboxState::Done);
    }

    #[test]
    fn extend_requires_matching_claim_lease_even_when_expired() {
        let (held, other) = token_pair();
        let claimed = InboxState::Claimed(InboxClaim::active(held.clone()));
        let expired = InboxState::Claimed(InboxClaim::expired(held.clone()));

        assert_eq!(claimed.extend(&held), LeaseOutcome::Held);
        assert_eq!(claimed.extend(&other), LeaseOutcome::Lost);
        assert_eq!(expired.extend(&held), LeaseOutcome::Held);
        assert_eq!(expired.extend(&other), LeaseOutcome::Lost);
        assert_eq!(InboxState::Absent.extend(&held), LeaseOutcome::Lost);
        assert_eq!(InboxState::Done.extend(&held), LeaseOutcome::Lost);
    }

    #[test]
    fn commit_requires_matching_claim_lease_even_when_expired() {
        let (held, other) = token_pair();
        let claimed = InboxState::Claimed(InboxClaim::active(held.clone()));

        let (outcome, state) = claimed.commit(&held);
        assert_eq!(outcome, LeaseOutcome::Held);
        assert_eq!(state, InboxState::Done);

        let claimed = InboxState::Claimed(InboxClaim::active(held.clone()));
        let (outcome, state) = claimed.commit(&other);
        assert_eq!(outcome, LeaseOutcome::Lost);
        assert_eq!(state.status(), Some(InboxStatus::Claimed));

        let expired = InboxState::Claimed(InboxClaim::expired(held.clone()));
        let (outcome, state) = expired.commit(&held);
        assert_eq!(outcome, LeaseOutcome::Held);
        assert_eq!(state, InboxState::Done);

        let expired = InboxState::Claimed(InboxClaim::expired(held.clone()));
        let (outcome, state) = expired.commit(&other);
        assert_eq!(outcome, LeaseOutcome::Lost);
        assert_eq!(state.status(), Some(InboxStatus::Claimed));

        assert_eq!(
            InboxState::Absent.commit(&held),
            (LeaseOutcome::Lost, InboxState::Absent)
        );
        assert_eq!(
            InboxState::Done.commit(&held),
            (LeaseOutcome::Lost, InboxState::Done)
        );
    }

    #[test]
    fn release_requires_matching_claim_lease_even_when_expired() {
        let (held, other) = token_pair();
        let claimed = InboxState::Claimed(InboxClaim::active(held.clone()));
        let expired = InboxState::Claimed(InboxClaim::expired(held.clone()));

        assert_eq!(claimed.clone().release(&held), InboxState::Absent);
        assert_eq!(claimed.clone().release(&other), claimed);
        assert_eq!(expired.clone().release(&held), InboxState::Absent);
        assert_eq!(expired.clone().release(&other), expired);
        assert_eq!(InboxState::Absent.release(&held), InboxState::Absent);
        assert_eq!(InboxState::Done.release(&held), InboxState::Done);
    }
}
