//! distributed — RSS 分布式原语（provider-agnostic 值类型）+ typed state-CAS facade。
//!
//! 提供 fencing token 单调性、分布式锁 key、CAS 请求/结果、共识传输消息和节点角色。
//! distlock / CAS DI port trait 集中在 `diport`；本 crate 定义值类型并实现 [`StateCas`] facade。
//!
//! ref: databendlabs/openraft openraft/src/lib.rs@main
//!   LogId/Vote 单调性 = fencing 语义；ServerState = NodeRole。
//!
//! ADR-004 C8：签名冻结阶段所有函数体为 `todo!()`，覆盖率豁免（distlock 切片仍冻结）。

mod cas;
pub use cas::StateCas;

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
/// typed facade key，经 `StateCas` 映射为 `diport::CasStoreKey` 下沉端口。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CasKey(String);

impl CasKey {
    /// 构造 CAS key。
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// 返回底层字符串切片。
    pub fn as_str(&self) -> &str {
        &self.0
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
#[derive(Clone)]
pub struct CasRequest<T> {
    pub key: CasKey,
    pub expected: Option<T>,
    pub new_value: T,
    pub token: Option<FencingToken>,
}

/// CAS 操作结果。
#[derive(Clone)]
#[non_exhaustive]
pub enum CasOutcome<T> {
    /// CAS 成功应用，返回新 fencing token。
    Applied { token: FencingToken },
    /// CAS 冲突，当前值与 expected 不符。
    Conflict { current: Option<T> },
    /// CAS 被 fence：`expected_token` 低于该 key 当前 token（旧 leader stale 写被挡）。返回当前 token
    /// 供调用方重读 / 停写重选举——fence 是**预期控制流**（与 [`CasOutcome::Conflict`] 同档、非 error），
    /// 对齐 diport 端口层 `CasStoreOutcome::Fenced`，不把高水位 token 压扁进无字段错误。
    Fenced { token: FencingToken },
}

/// PII 边界：手写 `Debug` 对 payload 字段（`expected`/`new_value`，可能含敏感 MDM 设备状态/凭据）输出
/// `<redacted>`；`key`/`token` 是路由/版本元数据，可观测。与 diport 端口层 `CasStoreRequest` 脱敏纪律一致
/// （INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 同源）。
impl<T> std::fmt::Debug for CasRequest<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CasRequest")
            .field("key", &self.key)
            .field("expected", &"<redacted>")
            .field("new_value", &"<redacted>")
            .field("token", &self.token)
            .finish()
    }
}

/// PII 边界：`Conflict.current`（当前状态 payload）输出 `<redacted>`；`Applied.token` / `Fenced.token`
/// 是版本元数据，可观测。
impl<T> std::fmt::Debug for CasOutcome<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CasOutcome::Applied { token } => {
                f.debug_struct("Applied").field("token", token).finish()
            }
            CasOutcome::Conflict { .. } => f
                .debug_struct("Conflict")
                .field("current", &"<redacted>")
                .finish(),
            CasOutcome::Fenced { token } => f.debug_struct("Fenced").field("token", token).finish(),
        }
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

    /// 证明 FencingToken 和 CasKey 往返正确；LockKey::new 仍是 todo!() 仅绑定 fn 指针。
    #[test]
    fn fencing_token_and_cas_key_round_trip() {
        // FencingToken 真实调用。
        let t = FencingToken::new(42);
        assert_eq!(t.value(), 42);
        let t0 = FencingToken::new(0);
        assert_eq!(t0.value(), 0);

        // CasKey 真实调用。
        let k = CasKey::new("tenant-1/state");
        assert_eq!(k.as_str(), "tenant-1/state");
        let k2 = CasKey::new(String::from("owned-string"));
        assert_eq!(k2.as_str(), "owned-string");

        // LockKey::new 仍是 todo!()——只绑 fn-ptr 验证签名，不调用。
        let _lock_key_fn: fn(&str) -> LockKey = |s| LockKey::new(s);
    }

    /// 证明 CasOutcome::<u64> Applied / Conflict 各 variant 可在运行时构造。
    #[test]
    fn cas_outcome_constructible() {
        let applied: CasOutcome<u64> = CasOutcome::Applied {
            token: FencingToken::new(1),
        };
        assert!(matches!(applied, CasOutcome::Applied { token } if token.value() == 1));

        let conflict: CasOutcome<u64> = CasOutcome::Conflict { current: Some(42) };
        assert!(matches!(
            conflict,
            CasOutcome::Conflict { current: Some(42) }
        ));
    }

    /// 证明 CasRequest 字段布局正确，key/expected/new_value/token 可构造。
    #[test]
    fn cas_request_field_layout() {
        let key = CasKey::new("req-key");
        let req: CasRequest<u32> = CasRequest {
            key,
            expected: Some(0u32),
            new_value: 1u32,
            token: Some(FencingToken::new(3)),
        };
        assert_eq!(req.key.as_str(), "req-key");
        assert_eq!(req.expected, Some(0u32));
        assert_eq!(req.new_value, 1u32);
        assert_eq!(req.token.map(|t| t.value()), Some(3));
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

    /// PII 边界：CasRequest<T>/CasOutcome<T> 手写 Debug 对 expected/new_value/Conflict.current 输出
    /// `<redacted>`；key/token 可观测（INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 同源）。
    #[test]
    fn cas_request_and_outcome_debug_redacts_payload() {
        // anti-vacuity：裸 &str 的 Debug 包含原始值。
        assert!(format!("{:?}", "topsecret").contains("topsecret"));

        let req: CasRequest<String> = CasRequest {
            key: CasKey::new("device-1/state"),
            expected: Some("topsecret".into()),
            new_value: "new-secret".into(),
            token: Some(FencingToken::new(7)),
        };
        let dbg = format!("{req:?}");
        assert!(
            !dbg.contains("topsecret"),
            "expected 不应在 Debug 输出中: {dbg}"
        );
        assert!(
            !dbg.contains("new-secret"),
            "new_value 不应在 Debug 输出中: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "Debug 输出应含 <redacted>: {dbg}"
        );
        assert!(
            dbg.contains("device-1/state"),
            "key 应在 Debug 输出中: {dbg}"
        );
        assert!(dbg.contains('7'), "token 值应在 Debug 输出中: {dbg}");

        let conflict: CasOutcome<String> = CasOutcome::Conflict {
            current: Some("topsecret".into()),
        };
        let dbg = format!("{conflict:?}");
        assert!(
            !dbg.contains("topsecret"),
            "Conflict.current 不应在 Debug 输出中: {dbg}"
        );
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
    }
}
