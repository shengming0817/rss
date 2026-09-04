//! ratelimit — in-mem keyed 限流 DI port provider（W 阶段，#1011）。
//!
//! impl `diport::RateLimiter`（GCRA keyed 限流，对标 GoCell `middleware.RateLimiter` / Go `x/time/rate`
//! token bucket）+ `rss_runtime::ManagedResource`（in-mem 无 infra 资源，shutdown=Ok，对标 `adapters/memory`）。
//! crate 保持 `forbid(unsafe_code)`（继承 workspace lints；不 invoke dynosaur 宏——只 import diport trait）。
//!
//! 时钟：用 governor 自带 monotonic 时钟（`DefaultClock`=QuantaClock），**不**经 `diport::Clock`
//! （wall-clock SystemTime，错的时间基）；我们不直调 `Instant::now`/`SystemTime::now`，不触 clippy
//! disallowed-methods。测试经 `FakeRelativeClock` 注入确定性时间。
//! ref: antifuchs/governor src/state/keyed.rs@v0.8.1

use diport::{RateLimitDecision, RateLimitError, RateLimitKey, RateLimitQuota, RateLimiter};
use governor::Quota;
use governor::RateLimiter as GovRateLimiter;
use governor::clock::{Clock, DefaultClock};
use governor::middleware::NoOpMiddleware;
use governor::state::keyed::DashMapStateStore;
use rss_runtime::{ManagedResource, ShutdownError};

/// keyed governor 限流器（DashMap 状态 + per-clock NoOp 中间件）。MW 须显式 `NoOpMiddleware<C::Instant>`
/// （struct 默认 `NoOpMiddleware<QuantaInstant>` 不满足泛型 `C` 的 `RateLimitingMiddleware<C::Instant>` 约束）。
type KeyedGov<C> = GovRateLimiter<
    RateLimitKey,
    DashMapStateStore<RateLimitKey>,
    C,
    NoOpMiddleware<<C as Clock>::Instant>,
>;

fn to_governor_quota(quota: RateLimitQuota) -> Quota {
    // RateLimitQuota rejects zero before reaching adapters.
    let per_second = std::num::NonZeroU32::new(quota.per_second())
        .unwrap_or_else(|| unreachable!("validated quota is non-zero"));
    let burst = std::num::NonZeroU32::new(quota.burst())
        .unwrap_or_else(|| unreachable!("validated quota is non-zero"));
    Quota::per_second(per_second).allow_burst(burst)
}

/// in-mem keyed 限流 provider（governor GCRA）。每个 [`RateLimitKey`] 独立配额桶（per-key 隔离），用
/// governor `DashMapStateStore`（lock-free 并发）。
///
/// 泛型 `C: Clock` 默认 governor monotonic `DefaultClock`；测试经 `FakeRelativeClock` 注入确定性时钟。
pub struct GovernorLimiter<C: Clock = DefaultClock> {
    inner: KeyedGov<C>,
    clock: C,
}

impl GovernorLimiter<DefaultClock> {
    /// 由配额配置构造（生产路径，monotonic 时钟）。
    pub fn new(quota: RateLimitQuota) -> Self {
        Self::with_clock(quota, DefaultClock::default())
    }
}

impl<C> GovernorLimiter<C>
where
    C: Clock + Clone,
{
    /// 由配额配置 + 显式时钟构造（测试经 `FakeRelativeClock` 注入确定性时间）。
    ///
    /// clock 同时交给 governor 限流器与本类型留存（`check` 取 `clock.now()` 算 `retry_after`）；二者须同源，
    /// 故 clone 注入。
    pub fn with_clock(quota: RateLimitQuota, clock: C) -> Self {
        let inner = GovRateLimiter::dashmap_with_clock(to_governor_quota(quota), clock.clone());
        Self { inner, clock }
    }
}

impl<C> RateLimiter for GovernorLimiter<C>
where
    C: Clock + Clone + Send + Sync,
{
    async fn check(&self, key: RateLimitKey) -> Result<RateLimitDecision, RateLimitError> {
        // 内存 GCRA 检查同步即返、不产生 backend 错误（`Err(NotUntil)` = over-limit，不是 provider 故障）；
        // 本测试 provider 不产生 RateLimitError；production Redis provider 负责网络故障映射。
        match self.inner.check_key(&key) {
            Ok(()) => Ok(RateLimitDecision::Allowed),
            Err(not_until) => Ok(RateLimitDecision::Limited {
                retry_after: not_until.wait_time_from(self.clock.now()),
            }),
        }
    }

    async fn shutdown(&self) -> Result<(), RateLimitError> {
        // reason: in-mem 限流器无 infra 资源（连接 / 句柄 / 后台 task），状态随 drop 回收，关闭无需显式释放。
        Ok(())
    }
}

/// INVARIANT: ADAPTER-PORT-FREEZE-08 { level = "Hard", exec = "native-compile", source = "code", native = "sealed ManagedResource implementation on the production provider" }.
impl<C> ManagedResource for GovernorLimiter<C>
where
    C: Clock + Clone + Send + Sync,
{
    fn name(&self) -> &str {
        "ratelimit"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // reason: in-mem 限流器无 infra 资源（连接 / 句柄 / 后台 task），状态随 drop 回收，关闭无需显式释放。
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! 限流行为矩阵（表驱动 + FakeRelativeClock）+ dyn-injection smoke + 生命周期 + anti-vacuity。
    //! ADAPTER-PORT-FREEZE-08 support：sealed-marker impl 冻结的 diport DI port trait（ManagedResource
    //! + RateLimiter）；去掉任一 impl 即编译失败（anti-vacuity，见 `impls_frozen_ports`）。
    use super::*;
    use core::marker::PhantomData;
    use core::time::Duration;
    use diport::DynRateLimiter;
    use governor::clock::FakeRelativeClock;

    // 测试构造用 expect：item-level carve-out。
    #[allow(clippy::expect_used)]
    fn quota(per_second: u32, burst: u32) -> RateLimitQuota {
        RateLimitQuota::try_new(per_second, burst).expect("valid test quota")
    }

    fn limiter(
        per_second: u32,
        burst: u32,
        clock: FakeRelativeClock,
    ) -> GovernorLimiter<FakeRelativeClock> {
        GovernorLimiter::with_clock(quota(per_second, burst), clock)
    }

    // 断言判定为 Limited 并取出 retry_after。panic 的 item-level carve-out 集中于此 helper，
    // 测试体不再散落 `panic!`。
    #[allow(clippy::panic)]
    fn expect_retry_after(decision: RateLimitDecision) -> Duration {
        match decision {
            RateLimitDecision::Limited { retry_after } => retry_after,
            // RateLimitDecision 现为 #[non_exhaustive]：跨 crate 须 wildcard 分支（覆盖 Allowed + 未来新状态）。
            other => panic!("expected RateLimitDecision::Limited, got {other:?}"),
        }
    }

    // 取 `key` 判定。in-mem 实现 `check` 永不 `Err`，故 `unwrap` 的 item-level carve-out 集中于此 helper，
    // 测试体不再散落 `#[allow(clippy::unwrap_used)]`。同一 `&str` →
    // 同一 `RateLimitKey`（Hash/Eq），重复调用命中同一配额桶。
    #[allow(clippy::unwrap_used)]
    async fn decide(rl: &GovernorLimiter<FakeRelativeClock>, key: &str) -> RateLimitDecision {
        rl.check(RateLimitKey::new(key)).await.unwrap()
    }

    // 1 / 2：allow 在 burst 内、deny 超 burst（同一时刻不推进时钟）。
    #[tokio::test]
    async fn allow_within_burst_then_deny_over_burst() {
        let rl = limiter(10, 2, FakeRelativeClock::default());
        assert_eq!(decide(&rl, "tenant-a").await, RateLimitDecision::Allowed);
        assert_eq!(decide(&rl, "tenant-a").await, RateLimitDecision::Allowed);
        assert!(matches!(
            decide(&rl, "tenant-a").await,
            RateLimitDecision::Limited { .. }
        ));
    }

    // 5：per-key 隔离。
    #[tokio::test]
    async fn per_key_isolation() {
        let rl = limiter(10, 1, FakeRelativeClock::default());
        // 耗尽 a 的桶。
        assert_eq!(decide(&rl, "tenant-a").await, RateLimitDecision::Allowed);
        assert!(matches!(
            decide(&rl, "tenant-a").await,
            RateLimitDecision::Limited { .. }
        ));
        // b 不受 a 影响。
        assert_eq!(decide(&rl, "tenant-b").await, RateLimitDecision::Allowed);
    }

    // 3：retry_after 正确（per_second=1 ⇒ 补一个令牌约需 1s）。
    #[tokio::test]
    async fn retry_after_is_positive_and_bounded() {
        let rl = limiter(1, 1, FakeRelativeClock::default());
        assert_eq!(decide(&rl, "t").await, RateLimitDecision::Allowed);
        let retry_after = expect_retry_after(decide(&rl, "t").await);
        assert!(retry_after > Duration::ZERO, "retry_after must be positive");
        assert!(
            retry_after <= Duration::from_secs(1),
            "retry_after must be <= replenish interval, got {retry_after:?}"
        );
    }

    // 4：时钟推进后令牌补充，重新放行。
    #[tokio::test]
    async fn refills_after_clock_advance() {
        let clock = FakeRelativeClock::default();
        let rl = limiter(1, 1, clock.clone());
        assert_eq!(decide(&rl, "t").await, RateLimitDecision::Allowed);
        assert!(matches!(
            decide(&rl, "t").await,
            RateLimitDecision::Limited { .. }
        ));
        clock.advance(Duration::from_secs(2));
        assert_eq!(decide(&rl, "t").await, RateLimitDecision::Allowed);
    }

    // 6：时钟部分推进，retry_after 单调缩短。
    #[tokio::test]
    async fn retry_after_shrinks_as_clock_advances() {
        let clock = FakeRelativeClock::default();
        let rl = limiter(1, 1, clock.clone());
        let _ = decide(&rl, "t").await;
        let first = expect_retry_after(decide(&rl, "t").await);
        clock.advance(Duration::from_millis(400));
        let second = expect_retry_after(decide(&rl, "t").await);
        assert!(
            second < first,
            "retry_after should shrink: {second:?} < {first:?}"
        );
    }

    // 8（边界）：时钟推进恰好等于 retry_after 后放行——验证 GCRA `NotUntil` 与 FakeRelativeClock 纳秒精度对齐
    // （推进 = 建议等待时长即满足 conformance，非 off-by-one）。
    #[tokio::test]
    async fn refills_exactly_at_retry_after() {
        let clock = FakeRelativeClock::default();
        let rl = limiter(1, 1, clock.clone());
        let _ = decide(&rl, "t").await;
        let wait = expect_retry_after(decide(&rl, "t").await);
        clock.advance(wait);
        assert_eq!(decide(&rl, "t").await, RateLimitDecision::Allowed);
    }

    // 7：dyn-injection（multi_thread spawn，Send 证明）。
    #[tokio::test(flavor = "multi_thread")]
    async fn dyn_injectable_across_spawn() {
        let rl: Box<DynRateLimiter> = DynRateLimiter::new_box(GovernorLimiter::new(quota(5, 5)));
        let joined = tokio::spawn(async move {
            matches!(
                rl.check(RateLimitKey::new("k")).await,
                Ok(RateLimitDecision::Allowed)
            ) && rl.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }

    // 8 / 9 / 10：ManagedResource name / shutdown + RateLimiter shutdown。
    #[tokio::test]
    async fn lifecycle_name_and_shutdowns() {
        let rl = GovernorLimiter::new(quota(1, 1));
        assert_eq!(ManagedResource::name(&rl), "ratelimit");
        assert!(ManagedResource::shutdown(&rl).await.is_ok());
        assert!(RateLimiter::shutdown(&rl).await.is_ok());
    }

    // 11：anti-vacuity——编译期断言两个冻结 diport port 均已 impl（去掉任一 impl 即编译失败）。
    fn assert_managed_resource<T: ManagedResource>(_: PhantomData<T>) {}
    fn assert_rate_limiter<T: RateLimiter>(_: PhantomData<T>) {}

    #[test]
    fn impls_frozen_ports() {
        assert_managed_resource(PhantomData::<GovernorLimiter>);
        assert_rate_limiter(PhantomData::<GovernorLimiter>);
    }
}
