//! `RateLimiter` —— 限流 provider DI port（可替换：in-mem governor / 未来 redis-distributed）。
//!
//! 对标 GoCell `middleware.RateLimiter`（Go `x/time/rate` token bucket）。provider 各自管理单调时钟
//! （in-mem governor 用 QuantaClock，redis 用服务端 TTL）——**不**经 [`crate::Clock`]（wall-clock，错的
//! 时间基）。
//!
//! async 而非 sync：未来 redis-distributed provider 走网络 I/O 须 async；provider 互换要求统一最宽签名
//! （与 [`crate::Signer`] / [`crate::Publisher`] 同，区别于纯计算的 sync [`crate::Clock`]）。in-mem governor
//! provider 内部同步即返，经 `async fn` 包裹零额外开销。
//!
//! 对标：**port 形状**照 [`crate::signer`]（ADR-003 dynosaur Send-变体范式，本 crate 的 async DI port 单一对标）；
//! **限流算法**无单一 Rust 工业对标 trait——概念源自 GCRA（Generic Cell Rate Algorithm）/ Go `x/time/rate`
//! token bucket，provider 落地见 `adapters/ratelimit`（governor `ref:` 在该 crate）。

use std::time::Duration;

use dynosaur::dynosaur;

use crate::redacted::RedactedSource;

/// 限流判定失败（provider 后端不可用等；**非** over-limit——over-limit 是 `Ok(RateLimitDecision::Limited)`）。
///
/// PII 边界（**类型层 Hard**，与 [`crate::ShutdownError`] 同范式）：`Display` 仅 provider 无关安全
/// 摘要常量；source 经 [`RedactedSource`] 脱敏（`Debug`/`Display` 固定 `<redacted>`、`{err:?}` 与
/// `%err` 同样不泄漏 source 凭据——把原 Soft 消费侧约定上移为类型层保证）。adapter 原始错误经
/// [`RateLimitError::new`] 由 [`RedactedSource`] **owned 但 write-only** 保留（redis-distributed provider 的
/// source 可能携网络细节，如 Redis URL）：`RedactedSource::source()` 恒 `None`，原始 source **不经标准
/// `Error` 链暴露**（fail-closed）；安全摘要走统一脱敏 funnel `secure::redact_error`（顶层 `Display`、不遍历 source 链）。
///
/// INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（source 经 `RedactedSource` 脱敏；回归见 `redacted.rs`
/// `redacted_source` 单测）。
#[derive(Debug, thiserror::Error)]
#[error("rate limit check failed")]
pub struct RateLimitError {
    #[source]
    source: RedactedSource,
}

impl RateLimitError {
    /// 把 adapter 内部错误包成限流检查失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

/// 限流 key——per tenant / principal / route 的配额桶标识。newtype funnel（私有字段，单一构造入口），
/// 不裸传 `&str`。opaque：key 组合策略随消费域（httpserve middleware，#1106）派生，不在 DI-infra 层冻结。
///
/// `Hash + Eq + Clone`：provider 据此分桶（governor keyed store 的 key 约束）。
///
/// `Debug` 经字段级脱敏，避免 per-principal key（tenant/principal/route）随 `?key` / `{key:?}` 泄漏主体标识。
#[derive(Clone, PartialEq, Eq, Hash, secure::Redact)]
pub struct RateLimitKey(#[redact(sensitivity = pii)] String);

impl RateLimitKey {
    /// 由字符串构造限流 key。
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }
    /// 借出底层 key。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 限流判定结果。`Limited` 携带建议的 `retry_after`（对标 HTTP `Retry-After` / GCRA `NotUntil`）。
///
/// `#[non_exhaustive]`（对齐 [`crate::AuditOutcome`]）：跨 crate 公开判定枚举，后续可能新增状态
/// （如 shadow-only / quota-missing / degraded-allow），外部消费方（httpserve middleware #1106 / 组合根）
/// 必须保留 wildcard 分支，使限流结果集可演进而不破坏下游穷尽 match。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RateLimitDecision {
    /// 在配额内，放行。
    Allowed,
    /// 超配额，建议 `retry_after` 后重试。
    Limited {
        /// 距下一次允许通过的最短等待时长（**亚秒精度**）。映射 HTTP `Retry-After`（整数秒）时消费侧
        /// （httpserve middleware，#1106）须 **ceil**（`(d.as_millis() + 999) / 1000`），floor 会让客户端过早重试仍被拒。
        retry_after: Duration,
    },
}

/// 限流 provider DI port（async）。
///
/// 公开 [`RateLimiter`] 是 **Send 变体**（adapters `impl RateLimiter for ...`），[`DynRateLimiter`] 是其
/// dyn-compatible wrapper（组合根经 `Box<DynRateLimiter>` / `Arc<DynRateLimiter>` 注入）。非 Send 基 trait
/// `RateLimiterLocal` 不在 crate 根 re-export（见 crate rustdoc）。
///
/// dyn-safe 约束（ADR-003 §4.6）：方法 `&self`、参数 / 返回为具体类型、supertrait 仅 Send、带 `async fn shutdown`
/// （无 async Drop）。
#[trait_variant::make(RateLimiter: Send)]
#[dynosaur(pub DynRateLimiter = dyn(box) RateLimiter, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `RateLimiter` 变体 +
// dynosaur `DynRateLimiter` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait RateLimiterLocal {
    /// 对 `key` 消费一个配额单位并判定。`Ok(Allowed)`=放行；`Ok(Limited{retry_after})`=超配额（**非**错误）；
    /// `Err`=provider 后端故障。
    ///
    /// `key` 取**所有权**（非 `&RateLimitKey`）：async DI port 经 dynosaur `dyn(box)` 派发，dyn-compatible
    /// 要求方法签名无生命周期参数（引用参数会引入 `'_`，破坏 wrapper 生成）——与 [`crate::Signer::sign`] 同范式。
    /// 消费侧（httpserve middleware #1106）每请求构造一个 key move 进来即可（`RateLimitKey` 是廉价 String 包装）。
    async fn check(&self, key: RateLimitKey) -> Result<RateLimitDecision, RateLimitError>;

    /// 异步释放 provider 资源（无 async Drop）。有 infra 资源的 adapter 应**同时** `impl ManagedResource`
    /// 由 `bootstrap::ShutdownStack` 统一编排；本方法是 port-local 关闭路径（参 [`crate::Signer::shutdown`]）。
    async fn shutdown(&self) -> Result<(), RateLimitError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynRateLimiter>` 动态注入，
    //! 且 mockall mock（native-AFIT）可装入 `DynRateLimiter` 跨 spawn（PORT-SHAPE-03，与 `signer.rs` 对称）。
    use super::{DynRateLimiter, RateLimitDecision, RateLimitError, RateLimitKey, RateLimiter};

    struct AllowAll;
    impl RateLimiter for AllowAll {
        async fn check(&self, _key: RateLimitKey) -> Result<RateLimitDecision, RateLimitError> {
            Ok(RateLimitDecision::Allowed)
        }
        async fn shutdown(&self) -> Result<(), RateLimitError> {
            Ok(())
        }
    }

    // multi_thread + spawn：boxed future 须 Send（trait_variant Send 变体）才能跨 worker 调度——
    // current-thread 不暴露 Send 违规，故用 multi_thread 真正验证 dyn 注入的 Send 语义。
    #[tokio::test(flavor = "multi_thread")]
    async fn rate_limiter_is_dyn_injectable() {
        let limiter: Box<DynRateLimiter> = DynRateLimiter::new_box(AllowAll);
        let joined = tokio::spawn(async move {
            matches!(
                limiter.check(RateLimitKey::new("tenant-1")).await,
                Ok(RateLimitDecision::Allowed)
            ) && limiter.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }

    // PORT-SHAPE-03（#1049，与 signer.rs:mockall_mock_loads_into_dyn_signer 对称）：mockall mock 是 native-AFIT
    // trait impl，可经 `new_box` 装入 dynosaur Send 变体 `DynRateLimiter` 并跨 spawn（Send future）——
    // 预验证 httpserve middleware（#1106）单测可 mock 本 port。
    mockall::mock! {
        TestRateLimiter {}
        impl RateLimiter for TestRateLimiter {
            async fn check(&self, key: RateLimitKey) -> Result<RateLimitDecision, RateLimitError>;
            async fn shutdown(&self) -> Result<(), RateLimitError>;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mockall_mock_loads_into_dyn_rate_limiter() {
        let mut mock = MockTestRateLimiter::new();
        mock.expect_check()
            .returning(|_| Ok(RateLimitDecision::Allowed));
        let limiter: Box<DynRateLimiter> = DynRateLimiter::new_box(mock);
        let joined = tokio::spawn(async move { limiter.check(RateLimitKey::new("k")).await }).await;
        assert!(matches!(joined, Ok(Ok(RateLimitDecision::Allowed))));
    }
}

#[cfg(test)]
mod smoke_error {
    //! `RateLimitError` wrapper 集成 `RedactedSource` 冒烟：Display 为常量安全摘要，source() 首层 =
    //! `RedactedSource`（其自身 `source()` 恒 `None`，fail-closed）。
    //! `Debug` / `Display` 不展开 source 回归见 `redacted.rs` `redacted_source` 单测
    //! （INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）。
    use super::RateLimitError;

    #[test]
    fn display_is_constant_safe_summary() {
        let err = RateLimitError::new(std::io::Error::other("leak-marker-rl"));
        assert_eq!(err.to_string(), "rate limit check failed");
        assert!(std::error::Error::source(&err).is_some());
        // 端到端：derive(Debug) 经 RedactedSource 脱敏、不展开内层 source（anti-vacuity 前置）。
        assert!(
            format!("{:?}", std::io::Error::other("leak-marker-rl")).contains("leak-marker-rl"),
            "前提失效：内层 Debug 未携 marker"
        );
        assert!(
            !format!("{err:?}").contains("leak-marker-rl"),
            "wrapper Debug 泄漏 source: {err:?}"
        );
    }
}

#[cfg(test)]
mod pii_debug {
    //! `RateLimitKey` Debug 脱敏回归：key 可能含 per-principal 标识（email / sub / route）。
    //! INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }.
    use super::RateLimitKey;

    #[test]
    fn rate_limit_key_debug_redacts_inner_key() {
        let key = RateLimitKey::new("tenant-a:alice@corp.example:/admin");
        let dbg = format!("{key:?}");
        assert!(!dbg.contains("alice@corp.example"), "principal 泄漏: {dbg}");
        assert!(!dbg.contains("/admin"), "route/key 原文泄漏: {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
    }
}
