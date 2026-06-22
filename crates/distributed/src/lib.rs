//! distributed — RSS 分布式原语（provider-agnostic 值类型）。
//!
//! 提供 fencing token 单调性、分布式锁 key、CAS 请求/结果、共识传输消息和节点角色。
//! distlock / CAS DI port trait 集中在 `diport`；本 crate 只定义值类型，不依赖 openraft / dynosaur。
//!
//! ref: databendlabs/openraft openraft/src/lib.rs@main
//!   LogId/Vote 单调性 = fencing 语义；ServerState = NodeRole。
//!
//! ADR-004 C8：签名冻结阶段所有函数体为 `todo!()`，覆盖率豁免。

/// Fencing token（单调递增；对齐 openraft LogId/Vote 单调语义，防止脑裂写入）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FencingToken(u64);

impl FencingToken {
    /// 构造 fencing token。
    pub fn new(_value: u64) -> Self {
        todo!()
    }

    /// 返回底层 u64 值。
    pub fn value(&self) -> u64 {
        todo!()
    }
}

/// 分布式锁 key（newtype，不与裸 `String` 混用）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LockKey(String);

impl LockKey {
    /// 构造 lock key。
    pub fn new(_key: impl Into<String>) -> Self {
        todo!()
    }

    /// 返回底层字符串切片。
    pub fn as_str(&self) -> &str {
        todo!()
    }
}

/// CAS 操作 key（newtype，不与 `LockKey` 或裸 `String` 混用）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CasKey(String);

impl CasKey {
    /// 构造 CAS key。
    pub fn new(_key: impl Into<String>) -> Self {
        todo!()
    }

    /// 返回底层字符串切片。
    pub fn as_str(&self) -> &str {
        todo!()
    }
}

/// 分布式锁授权凭据（持锁凭证，携带 fencing token + TTL）。
#[derive(Debug, Clone)]
pub struct LockGrant {
    pub key: LockKey,
    pub token: FencingToken,
    pub ttl: std::time::Duration,
}

/// CAS 请求（对齐 openraft client_write typed AppData）。
#[derive(Debug, Clone)]
pub struct CasRequest<T> {
    pub key: CasKey,
    pub expected: Option<T>,
    pub new_value: T,
    pub token: Option<FencingToken>,
}

/// CAS 操作结果。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum CasOutcome<T> {
    /// CAS 成功应用，返回新 fencing token。
    Applied { token: FencingToken },
    /// CAS 冲突，当前值与 expected 不符。
    Conflict { current: Option<T> },
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
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DistError {
    #[error("not leader")]
    NotLeader,
    #[error("fencing token mismatch")]
    FencingMismatch,
    #[error("lock already held")]
    LockAlreadyHeld,
    #[error("transport error")]
    Transport,
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

    /// 证明 CasOutcome::<u64> 各 variant 可构造；FencingToken::new 只绑定 fn 指针，不调用。
    /// Applied variant 需要 FencingToken——因 new() 是 todo!()，改为构造 Conflict variant
    /// 并同时验证 Applied 的类型签名（绑定 fn ptr 即可，不需运行时调用）。
    #[test]
    fn cas_outcome_constructible() {
        // 绑定函数指针只验证签名，不调用（避免触发 todo!()）。
        let _fn_ptr: fn(u64) -> FencingToken = FencingToken::new;
        let _lock_key_fn: fn(&str) -> LockKey = |s| LockKey::new(s);

        // Conflict variant 不依赖 FencingToken::new，可直接构造。
        let outcome: CasOutcome<u64> = CasOutcome::Conflict { current: Some(42) };
        assert!(matches!(
            outcome,
            CasOutcome::Conflict { current: Some(42) }
        ));
    }

    /// 证明 CasOutcome::Applied 的 token 字段类型为 FencingToken（通过 if let 类型推断）。
    #[test]
    fn cas_outcome_applied_signature() {
        // 验证 Applied { token: FencingToken } 字段类型在类型系统中成立——
        // 通过构造函数引用而非运行时值，完成编译期类型检查。
        type AppliedMaker = fn(FencingToken) -> CasOutcome<u64>;
        let _: AppliedMaker = |t| CasOutcome::Applied { token: t };
    }

    /// 证明 CasRequest 字段布局可在类型系统中构造（不调用 todo!() 函数体）。
    #[test]
    fn cas_request_field_layout() {
        // 绑定 CasKey::new 函数指针，验证签名而不调用（避免触发 todo!()）。
        let _cas_key_fn: fn(&str) -> CasKey = |s| CasKey::new(s);
        // 验证 token 字段为 Option<FencingToken>，key 字段为 CasKey，value 类型正确。
        let _make: fn(CasKey, Option<FencingToken>) -> CasRequest<u32> = |k, t| CasRequest {
            key: k,
            expected: None,
            new_value: 1u32,
            token: t,
        };
        // 构造不依赖 todo!() 的字段验证——仅检查 expected/new_value/token 类型。
        let _check_types: fn(CasKey) -> CasRequest<u32> = |k| CasRequest {
            key: k,
            expected: Some(0u32),
            new_value: 1u32,
            token: None,
        };
    }

    /// 证明 LockGrant 字段布局正确（不调用 todo!() 构造器）。
    #[test]
    fn lock_grant_field_layout() {
        // LockGrant 是普通 struct，字段均为公开且无 todo!() 函数依赖。
        // 通过闭包绑定验证字段类型：key: LockKey, token: FencingToken, ttl: Duration。
        type LockGrantMaker = fn(LockKey, FencingToken, std::time::Duration) -> LockGrant;
        let _make: LockGrantMaker = |key, token, ttl| LockGrant { key, token, ttl };
    }

    /// 证明 LockGrant 实现 Send + Sync。
    #[test]
    fn lock_grant_send_sync() {
        fn _assert_send_sync<T: Send + Sync>() {}
        _assert_send_sync::<LockGrant>();
    }
}
