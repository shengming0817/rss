//! distributed — RSS 分布式原语（provider-agnostic 值类型）与 global maintenance coordination。
//!
//! 提供 fencing token 单调性、分布式锁 key、共识传输消息和节点角色。distlock / CAS DI port trait
//! 集中在 `diport`；本 crate 公开 [`Locker`]（分布式互斥锁）facade，state-CAS 仅服务于内部 sealed
//! maintenance lane，不暴露无 tenant/scope 义务的通用 facade。
//!
//! ref: databendlabs/openraft openraft/src/lib.rs@main
//!   LogId/Vote 单调性 = fencing 语义；ServerState = NodeRole。
//!
//! state-CAS 是 crate-private 的 global maintenance implementation detail；外部 consumer
//! 不能恢复旧的无 scope facade：
//!
//! ```compile_fail
//! use distributed::CasKey;
//! ```
//!
//! ```compile_fail
//! use distributed::StateCas;
//! ```
//!
//! ```compile_fail
//! use distributed::CasRequest;
//! ```
//!
//! ```compile_fail
//! use distributed::CasOutcome;
//! ```
//!
//! ```compile_fail
//! use distributed::GlobalCasKey;
//! ```
//!
//! ```compile_fail
//! use distributed::MaintenanceLane;
//! ```

mod cas;
mod locker;
mod maintenance;
mod transport;
pub use locker::Locker;
pub use maintenance::{
    CoordinatedRetentionSweeper, InboxBacklogMaintenance, MaintenanceCoordinator,
    MaintenanceCoordinatorError, MaintenanceObservation, OutboxBacklogMaintenance,
    OutboxRetentionMaintenance,
};
pub use transport::{
    HttpContractMethod, HttpContractRequest, HttpContractResponse, HttpContractTarget,
    HttpContractTransport, HttpContractTransportError, HttpContractTransportErrorKind,
    InstrumentedHttpContractTransport, TransportMode, TransportOutcome,
};

/// Fencing token（单调递增；对齐 openraft LogId/Vote 单调语义，防止脑裂写入）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FencingToken(u64);

impl FencingToken {
    /// 构造 fencing token。
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// 返回底层 u64 值。
    pub fn value(&self) -> u64 {
        self.0
    }
}

/// 分布式锁 key（newtype，不与裸 `String` 混用）。经 [`LockKey::parse`] **fail-closed** 构造
/// （拒空 / 空白 / 控制字符）——分布式互斥维度是全局协调面，非法 key 不得进入（照 `diport::LeaderId::parse`）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LockKey(String);

impl LockKey {
    /// 解析锁 key：非空 + canonical（fail-closed）。空 → [`LockKeyError::Empty`]；纯空白 / 含控制字符 →
    /// [`LockKeyError::NotCanonical`]。其余形态（如 `tenant-42/reconcile/cert-3`）保持 opaque——
    /// 租户命名空间约定由调用方按 grammar 组装。
    pub fn parse(raw: &str) -> Result<Self, LockKeyError> {
        if raw.is_empty() {
            return Err(LockKeyError::Empty);
        }
        if raw.trim().is_empty() || raw.chars().any(char::is_control) {
            return Err(LockKeyError::NotCanonical);
        }
        Ok(Self(raw.to_string()))
    }

    /// 返回底层字符串切片。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// [`LockKey`] 解析错误（canonical funnel fail-closed，照 `diport::LeaderIdError`）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LockKeyError {
    /// 锁 key 为空。
    #[error("lock key is empty")]
    Empty,
    /// 锁 key 纯空白或含控制字符。
    #[error("lock key is blank or contains control characters")]
    NotCanonical,
}

/// 分布式锁授权凭据 —— **不可伪造的 opaque capability**。字段私有 + 仅 crate 内 [`LockGrant::new`] 构造，
/// 故仅 [`Locker`] 能从 provider outcome mint；外部 crate 无法构造 ⇒ token-as-capability 由**类型系统封闭**
/// （非运行期约定）：无法伪造 grant 调 `release`/`renew` 顶替持有者。外部经 getter 只读。
///
/// INVARIANT: DISTLOCK-GRANT-UNFORGEABLE-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }（Hard：private 字段 + crate-only 构造 funnel；外部 crate
/// 编译期无法 mint `LockGrant`。`FencingToken::new` 虽 pub（CAS 复用），但无 `LockGrant` 构造面即无法组合成持锁凭据）。
#[derive(Debug, Clone)]
pub struct LockGrant {
    key: LockKey,
    token: FencingToken,
    ttl: std::time::Duration,
}

impl LockGrant {
    /// crate 内 mint（仅 [`Locker`] 从 `LockStore` outcome 构造；外部 crate 不可达 ⇒ grant 不可伪造）。
    pub(crate) fn new(key: LockKey, token: FencingToken, ttl: std::time::Duration) -> Self {
        Self { key, token, ttl }
    }

    /// 被授予锁的资源 key。
    pub fn key(&self) -> &LockKey {
        &self.key
    }

    /// 单调 fencing token（持锁凭据）：`renew`/`release` 经此向 provider 证明持有权；token 不匹配
    /// （已易手 / 过期被接管）则 renew 失败、release no-op。
    pub fn token(&self) -> FencingToken {
        self.token
    }

    /// 锁的租约时长（holder 须在过期前 `renew` 续租；超时未续 ⇒ 他者可接管，token 单调递增）。
    pub fn ttl(&self) -> std::time::Duration {
        self.ttl
    }
}

/// 节点传输消息（provider-agnostic；adapter 映射到 openraft RPC）。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TransportMessage {
    AppendEntries {
        term: u64,
        leader_id: u64,
        prev_log_index: u64,
        entries: Vec<Vec<u8>>,
    },
    AppendEntriesResponse {
        term: u64,
        success: bool,
    },
    Vote {
        term: u64,
        candidate_id: u64,
        last_log_index: u64,
    },
    VoteResponse {
        term: u64,
        vote_granted: bool,
    },
}

/// 节点角色（对齐 openraft ServerState）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeRole {
    Learner,
    Follower,
    Candidate,
    Leader,
}

/// distributed crate 错误类型。
///
/// `#[non_exhaustive]` 含**预留扩展点**：当前 facade 把「已持有」表达为 typed outcome
///（`Locker::acquire→Ok(None)`，非 error），
/// 故下列 variant 当前不由任一 facade 返回；保留供未来生产 provider（raft transport / etcd-lock 等）的
/// **error 路径**使用，删除前须确认无 provider 需要：
/// - [`DistError::NotLeader`]：共识 provider 非 leader（raft transport）。
/// - [`DistError::FencingMismatch`]：fencing 失配的预留 provider error 形态。
/// - [`DistError::LockAlreadyHeld`]：锁已被持有（`Locker::acquire` 现以 `Ok(None)` 表达，预留 provider error 形态）。
///
/// 当前 facade 实际返回的是 [`DistError::Transport`]（infra 故障，可重试）与 [`DistError::Fatal`]（不可恢复 /
/// 未知 outcome 变体 fail-safe）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DistError {
    /// 预留：共识 provider 非 leader（当前无 facade 返回，见枚举级文档）。
    #[error("not leader")]
    NotLeader,
    /// 预留：fencing 失配（当前无公开 facade 返回此 error）。
    #[error("fencing token mismatch")]
    FencingMismatch,
    /// 预留：锁已被持有（当前 `Locker::acquire` 以 `Ok(None)` 表达，无 facade 返回此 error）。
    #[error("lock already held")]
    LockAlreadyHeld,
    /// infra 故障（provider 端口返回错误），可重试。内部 maintenance CAS / [`Locker`] 返回此变体。
    #[error("transport error")]
    Transport,
    /// 不可恢复错误 / 未知 typed-outcome 变体的 fail-safe 兜底。
    #[error("fatal error")]
    Fatal,
}

#[cfg(test)]
mod smoke {
    use super::*;

    /// 证明 NodeRole::Leader 可构造、穷尽 match。
    /// 注意：#[non_exhaustive] 在同 crate 内不启用，同 crate 内 match 不需要 `_` arm。
    #[test]
    fn node_role_leader_and_exhaustive_match() {
        let role = NodeRole::Leader;
        let _desc = match role {
            NodeRole::Learner => "learner",
            NodeRole::Follower => "follower",
            NodeRole::Candidate => "candidate",
            NodeRole::Leader => "leader",
        };
    }

    /// 证明 TransportMessage 全部 4 个 variant 可字面构造，且穷尽 match 通过编译。
    /// 同 crate 内 #[non_exhaustive] 不启用，穷尽列全部变体、不加 `_` 臂。
    #[test]
    fn transport_message_all_variants_constructible_and_exhaustive_match() {
        let msgs = [
            TransportMessage::AppendEntries {
                term: 2,
                leader_id: 1,
                prev_log_index: 5,
                entries: vec![vec![0u8, 1u8]],
            },
            TransportMessage::AppendEntriesResponse {
                term: 2,
                success: true,
            },
            TransportMessage::Vote {
                term: 1,
                candidate_id: 42,
                last_log_index: 0,
            },
            TransportMessage::VoteResponse {
                term: 1,
                vote_granted: true,
            },
        ];
        for msg in &msgs {
            let _kind = match msg {
                TransportMessage::AppendEntries { .. } => "append_entries",
                TransportMessage::AppendEntriesResponse { .. } => "append_entries_response",
                TransportMessage::Vote { .. } => "vote",
                TransportMessage::VoteResponse { .. } => "vote_response",
            };
        }
    }

    /// 证明 DistError 全部 5 个 variant 可构造，且穷尽 match 通过编译。
    /// 同 crate 内 #[non_exhaustive] 不启用，不加 `_` 臂。
    #[test]
    fn dist_error_all_variants_constructible_and_exhaustive_match() {
        let errors = [
            DistError::NotLeader,
            DistError::FencingMismatch,
            DistError::LockAlreadyHeld,
            DistError::Transport,
            DistError::Fatal,
        ];
        for err in &errors {
            let _msg = match err {
                DistError::NotLeader => "not_leader",
                DistError::FencingMismatch => "fencing_mismatch",
                DistError::LockAlreadyHeld => "lock_already_held",
                DistError::Transport => "transport",
                DistError::Fatal => "fatal",
            };
        }
    }

    /// 证明 FencingToken 往返正确 + LockKey fail-closed parse（接受 canonical、拒空/空白/控制字符）。
    #[test]
    #[allow(clippy::expect_used)]
    // reason: 测试用 canonical literal 解析 LockKey，item-level carve-out。
    fn fencing_token_and_lock_key_round_trip() {
        // FencingToken 真实调用。
        let t = FencingToken::new(42);
        assert_eq!(t.value(), 42);
        let t0 = FencingToken::new(0);
        assert_eq!(t0.value(), 0);

        // LockKey fail-closed parse：canonical 接受。
        let lk = LockKey::parse("tenant-2/reconcile/cert-9").expect("canonical");
        assert_eq!(lk.as_str(), "tenant-2/reconcile/cert-9");
        let lk2 = LockKey::parse("owned-lock-key").expect("canonical");
        assert_eq!(lk2, lk2.clone()); // Eq / Hash / Clone 派生行为。
        assert_ne!(lk, lk2);
        // 拒空 / 纯空白 / 控制字符（fail-closed funnel）。
        assert!(matches!(LockKey::parse(""), Err(LockKeyError::Empty)));
        for raw in [" ", "\t", "a\nb", "x\0y"] {
            assert!(
                matches!(LockKey::parse(raw), Err(LockKeyError::NotCanonical)),
                "raw={raw:?}"
            );
        }
    }

    /// FencingToken 单调全序（对齐 openraft LogId.index derive Ord）：较大值「更晚」、可排序 / max。
    #[test]
    fn fencing_token_is_monotonic_ordered() {
        assert!(FencingToken::new(1) < FencingToken::new(2));
        let mut tokens = [
            FencingToken::new(3),
            FencingToken::new(1),
            FencingToken::new(2),
        ];
        tokens.sort();
        assert_eq!(
            tokens,
            [
                FencingToken::new(1),
                FencingToken::new(2),
                FencingToken::new(3)
            ]
        );
        assert_eq!(
            tokens.iter().max().copied(),
            Some(FencingToken::new(3)),
            "max 取最晚 token"
        );
    }

    /// 证明 LockGrant crate 内 mint（`new`）+ getter 读回（字段私有，外部不可伪造）。
    #[test]
    #[allow(clippy::expect_used)]
    // reason: 测试用 canonical literal 解析 LockKey，item-level carve-out。
    fn lock_grant_mint_and_getters() {
        let grant = LockGrant::new(
            LockKey::parse("tenant-3/lock").expect("canonical"),
            FencingToken::new(5),
            std::time::Duration::from_secs(15),
        );
        assert_eq!(grant.key().as_str(), "tenant-3/lock");
        assert_eq!(grant.token().value(), 5);
        assert_eq!(grant.ttl(), std::time::Duration::from_secs(15));
    }

    /// 证明 LockGrant 实现 Send + Sync。
    #[test]
    fn lock_grant_send_sync() {
        fn _assert_send_sync<T: Send + Sync>() {}
        _assert_send_sync::<LockGrant>();
    }
}
