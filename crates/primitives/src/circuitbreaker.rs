//! 三态熔断纯状态机（ADR-004 C1：L0 纯计算 → sync 静态分发，非 DI port）。
//!
//! 仅纯数据 + 纯 transition 函数；调度 / 锁 / 时钟读取在 adapter（时钟为 DI port，归 diport）。
//! 对标 sony/gobreaker 三态 + Counts + ReadyToTrip，剥离 goroutine/mutex/时钟。
//! ref: sony/gobreaker v2/gobreaker.go@master。

use std::time::Duration;

/// 熔断态（闭值集；Copy）。Closed=放行、Open=快速失败、HalfOpen=探测。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitState {
    /// 稳定 metrics label（crate-owned 闭映射；下游无需 match non_exhaustive enum）。
    pub fn as_label(self) -> &'static str {
        match self {
            CircuitState::Closed => "closed",
            CircuitState::Open => "open",
            CircuitState::HalfOpen => "half_open",
        }
    }
}

/// 滚动窗口计数（纯值；transition 的唯一输入之一）。对标 gobreaker `Counts`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CircuitCounts {
    requests: u32,
    total_successes: u32,
    total_failures: u32,
    consecutive_successes: u32,
    consecutive_failures: u32,
}

impl CircuitCounts {
    /// 空计数（窗口起点 / reset 后）。
    pub fn new() -> Self {
        Self {
            requests: 0,
            total_successes: 0,
            total_failures: 0,
            consecutive_successes: 0,
            consecutive_failures: 0,
        }
    }

    /// 记一次成功（纯函数，返回新值；不内部可变）。
    pub fn record_success(self) -> Self {
        Self {
            requests: self.requests + 1,
            total_successes: self.total_successes + 1,
            consecutive_successes: self.consecutive_successes + 1,
            consecutive_failures: 0,
            ..self
        }
    }

    /// 记一次失败（纯函数，返回新值）。
    pub fn record_failure(self) -> Self {
        Self {
            requests: self.requests + 1,
            total_failures: self.total_failures + 1,
            consecutive_failures: self.consecutive_failures + 1,
            consecutive_successes: 0,
            ..self
        }
    }

    /// 窗口内请求总数。
    pub fn requests(self) -> u32 {
        self.requests
    }

    /// 连续失败数。
    pub fn consecutive_failures(self) -> u32 {
        self.consecutive_failures
    }

    /// 连续成功数。
    pub fn consecutive_successes(self) -> u32 {
        self.consecutive_successes
    }

    /// 窗口内累计成功数（adapter 上报 success rate metrics）。
    pub fn total_successes(self) -> u32 {
        self.total_successes
    }

    /// 窗口内累计失败数（adapter 上报 failure rate metrics）。
    pub fn total_failures(self) -> u32 {
        self.total_failures
    }
}

/// 熔断阈值配置（纯值类型；构造经 fallible funnel 拒非法阈值）。
///
/// INVARIANT: BREAKER-CONFIG-01 —— `max_half_open_requests >= 1`、`interval`/`timeout` 非零（fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerConfig {
    failure_threshold: u32,
    max_half_open_requests: u32,
    interval: Duration,
    timeout: Duration,
}

/// `BreakerConfig` 构造错误（message const literal）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BreakerConfigError {
    #[error("failure threshold must be non-zero")]
    ZeroThreshold,
    #[error("max half-open requests must be non-zero")]
    ZeroHalfOpen,
    #[error("breaker durations must be non-zero")]
    ZeroDuration,
}

impl BreakerConfig {
    /// 构造并校验阈值（fail-closed：零阈值 / 零时长拒）。
    pub fn new(
        failure_threshold: u32,
        max_half_open_requests: u32,
        interval: Duration,
        timeout: Duration,
    ) -> Result<Self, BreakerConfigError> {
        if failure_threshold < 1 {
            return Err(BreakerConfigError::ZeroThreshold);
        }
        if max_half_open_requests < 1 {
            return Err(BreakerConfigError::ZeroHalfOpen);
        }
        if interval.is_zero() || timeout.is_zero() {
            return Err(BreakerConfigError::ZeroDuration);
        }
        Ok(Self {
            failure_threshold,
            max_half_open_requests,
            interval,
            timeout,
        })
    }

    /// 触发跳闸的失败阈值。
    pub fn failure_threshold(self) -> u32 {
        self.failure_threshold
    }

    /// half-open 探测期允许的并发请求上限。
    pub fn max_half_open_requests(self) -> u32 {
        self.max_half_open_requests
    }

    /// 滚动窗口长度。
    pub fn interval(self) -> Duration {
        self.interval
    }

    /// open→half-open 的冷却时长。
    pub fn timeout(self) -> Duration {
        self.timeout
    }
}

/// 调用结果（transition 输入；避免把业务 error 类型泄进纯状态机）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallOutcome {
    Success,
    Failure,
}

/// 触发态迁移的事件（纯输入；时钟由调用方读取后以 `TimeoutElapsed` 传入，时钟本身是 DI port）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BreakerEvent {
    /// 一次受保护调用完成。
    Call(CallOutcome),
    /// open 计时已到（调用方读时钟判定后传入；纯状态机不读时钟）。
    TimeoutElapsed,
}

/// 纯状态机：给定当前态 + 计数 + 配置 + 事件，算出下一态。无副作用、无时钟、无锁。
///
/// # Caller 契约
///
/// caller 先把本次结果 `record_*` 进 counts、再调 `next_state`（counts 含本次事件；event 仅选转移臂）。
/// 阈值在 counts 含本次后判 `>=`，故 `threshold=N` 时第 N 次失败即 Open。
///
/// reason: 时钟读取（`now >= opened_at + timeout`）留在 adapter；此处只接 `TimeoutElapsed`
/// 已判定的纯输入，使熔断决策可单测、可被泛型消费而零运行时依赖。
pub fn next_state(
    state: CircuitState,
    counts: CircuitCounts,
    config: BreakerConfig,
    event: BreakerEvent,
) -> CircuitState {
    match (state, event) {
        (CircuitState::Closed, BreakerEvent::Call(CallOutcome::Failure)) => {
            if counts.consecutive_failures >= config.failure_threshold {
                CircuitState::Open
            } else {
                CircuitState::Closed
            }
        }
        (CircuitState::Closed, BreakerEvent::Call(CallOutcome::Success)) => CircuitState::Closed,
        (CircuitState::Open, BreakerEvent::TimeoutElapsed) => CircuitState::HalfOpen,
        (CircuitState::HalfOpen, BreakerEvent::Call(CallOutcome::Success)) => {
            if counts.consecutive_successes >= config.max_half_open_requests {
                CircuitState::Closed
            } else {
                CircuitState::HalfOpen
            }
        }
        (CircuitState::HalfOpen, BreakerEvent::Call(CallOutcome::Failure)) => CircuitState::Open,
        // 其余组合幂等返回原态
        _ => state,
    }
}

/// 纯判定：当前态是否允许放行一次新调用（Closed=是、Open=否、HalfOpen=受 max_half_open 限）。
pub fn allows_request(state: CircuitState, counts: CircuitCounts, config: BreakerConfig) -> bool {
    match state {
        CircuitState::Closed => true,
        CircuitState::Open => false,
        CircuitState::HalfOpen => counts.requests < config.max_half_open_requests,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BreakerConfig {
        #[allow(clippy::unwrap_used)]
        BreakerConfig::new(3, 2, Duration::from_secs(10), Duration::from_secs(5)).unwrap()
    }

    // ── as_label ──────────────────────────────────────────────────────────────
    #[test]
    fn as_label_closed() {
        assert_eq!(CircuitState::Closed.as_label(), "closed");
    }

    #[test]
    fn as_label_open() {
        assert_eq!(CircuitState::Open.as_label(), "open");
    }

    #[test]
    fn as_label_half_open() {
        assert_eq!(CircuitState::HalfOpen.as_label(), "half_open");
    }

    // ── CircuitCounts ─────────────────────────────────────────────────────────
    #[test]
    fn counts_new_all_zero() {
        let c = CircuitCounts::new();
        assert_eq!(c.requests(), 0);
        assert_eq!(c.total_successes(), 0);
        assert_eq!(c.total_failures(), 0);
        assert_eq!(c.consecutive_successes(), 0);
        assert_eq!(c.consecutive_failures(), 0);
    }

    #[test]
    fn counts_record_success_increments_and_resets_failures() {
        let c = CircuitCounts::new()
            .record_failure()
            .record_failure()
            .record_success();
        assert_eq!(c.requests(), 3);
        assert_eq!(c.total_successes(), 1);
        assert_eq!(c.total_failures(), 2);
        assert_eq!(c.consecutive_successes(), 1);
        assert_eq!(c.consecutive_failures(), 0);
    }

    #[test]
    fn counts_record_failure_increments_and_resets_successes() {
        let c = CircuitCounts::new()
            .record_success()
            .record_success()
            .record_failure();
        assert_eq!(c.requests(), 3);
        assert_eq!(c.total_successes(), 2);
        assert_eq!(c.total_failures(), 1);
        assert_eq!(c.consecutive_successes(), 0);
        assert_eq!(c.consecutive_failures(), 1);
    }

    #[test]
    fn counts_consecutive_accumulate() {
        let c = CircuitCounts::new()
            .record_failure()
            .record_failure()
            .record_failure();
        assert_eq!(c.consecutive_failures(), 3);
        assert_eq!(c.consecutive_successes(), 0);
    }

    // ── BreakerConfig::new ────────────────────────────────────────────────────
    #[test]
    fn config_new_ok() {
        #[allow(clippy::unwrap_used)]
        let c = BreakerConfig::new(1, 1, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        assert_eq!(c.failure_threshold(), 1);
        assert_eq!(c.max_half_open_requests(), 1);
        assert_eq!(c.interval(), Duration::from_secs(1));
        assert_eq!(c.timeout(), Duration::from_secs(1));
    }

    #[test]
    fn config_new_zero_threshold_err() {
        let r = BreakerConfig::new(0, 1, Duration::from_secs(1), Duration::from_secs(1));
        assert!(matches!(r, Err(BreakerConfigError::ZeroThreshold)));
    }

    #[test]
    fn config_new_zero_half_open_err() {
        let r = BreakerConfig::new(1, 0, Duration::from_secs(1), Duration::from_secs(1));
        assert!(matches!(r, Err(BreakerConfigError::ZeroHalfOpen)));
    }

    #[test]
    fn config_new_zero_interval_err() {
        let r = BreakerConfig::new(1, 1, Duration::ZERO, Duration::from_secs(1));
        assert!(matches!(r, Err(BreakerConfigError::ZeroDuration)));
    }

    #[test]
    fn config_new_zero_timeout_err() {
        let r = BreakerConfig::new(1, 1, Duration::from_secs(1), Duration::ZERO);
        assert!(matches!(r, Err(BreakerConfigError::ZeroDuration)));
    }

    // ── next_state 六路转移矩阵 ───────────────────────────────────────────────

    // (Closed, Failure) consecutive_failures < threshold → Closed
    #[test]
    fn next_state_closed_failure_below_threshold_stays_closed() {
        let counts = CircuitCounts::new().record_failure(); // consecutive=1, threshold=3
        let s = next_state(
            CircuitState::Closed,
            counts,
            cfg(),
            BreakerEvent::Call(CallOutcome::Failure),
        );
        assert_eq!(s, CircuitState::Closed);
    }

    // (Closed, Failure) consecutive_failures == threshold → Open
    #[test]
    fn next_state_closed_failure_at_threshold_opens() {
        let counts = CircuitCounts::new()
            .record_failure()
            .record_failure()
            .record_failure(); // consecutive=3, threshold=3
        let s = next_state(
            CircuitState::Closed,
            counts,
            cfg(),
            BreakerEvent::Call(CallOutcome::Failure),
        );
        assert_eq!(s, CircuitState::Open);
    }

    // (Closed, Failure) consecutive_failures just below threshold → stays Closed
    #[test]
    fn next_state_closed_failure_one_below_threshold_stays_closed() {
        let counts = CircuitCounts::new().record_failure().record_failure(); // consecutive=2, threshold=3
        let s = next_state(
            CircuitState::Closed,
            counts,
            cfg(),
            BreakerEvent::Call(CallOutcome::Failure),
        );
        assert_eq!(s, CircuitState::Closed);
    }

    // (Closed, Success) → Closed
    #[test]
    fn next_state_closed_success_stays_closed() {
        let counts = CircuitCounts::new().record_success();
        let s = next_state(
            CircuitState::Closed,
            counts,
            cfg(),
            BreakerEvent::Call(CallOutcome::Success),
        );
        assert_eq!(s, CircuitState::Closed);
    }

    // (Open, TimeoutElapsed) → HalfOpen
    #[test]
    fn next_state_open_timeout_elapsed_to_half_open() {
        let s = next_state(
            CircuitState::Open,
            CircuitCounts::new(),
            cfg(),
            BreakerEvent::TimeoutElapsed,
        );
        assert_eq!(s, CircuitState::HalfOpen);
    }

    // (HalfOpen, Success) consecutive_successes == max_half_open → Closed
    #[test]
    fn next_state_half_open_success_at_max_closes() {
        let counts = CircuitCounts::new().record_success().record_success(); // consecutive=2, max=2
        let s = next_state(
            CircuitState::HalfOpen,
            counts,
            cfg(),
            BreakerEvent::Call(CallOutcome::Success),
        );
        assert_eq!(s, CircuitState::Closed);
    }

    // (HalfOpen, Success) consecutive_successes < max_half_open → HalfOpen
    #[test]
    fn next_state_half_open_success_below_max_stays_half_open() {
        let counts = CircuitCounts::new().record_success(); // consecutive=1, max=2
        let s = next_state(
            CircuitState::HalfOpen,
            counts,
            cfg(),
            BreakerEvent::Call(CallOutcome::Success),
        );
        assert_eq!(s, CircuitState::HalfOpen);
    }

    // (HalfOpen, Failure) → Open
    #[test]
    fn next_state_half_open_failure_opens() {
        let counts = CircuitCounts::new().record_failure();
        let s = next_state(
            CircuitState::HalfOpen,
            counts,
            cfg(),
            BreakerEvent::Call(CallOutcome::Failure),
        );
        assert_eq!(s, CircuitState::Open);
    }

    // 幂等：其余组合返回原态
    #[test]
    fn next_state_closed_timeout_is_idempotent() {
        let s = next_state(
            CircuitState::Closed,
            CircuitCounts::new(),
            cfg(),
            BreakerEvent::TimeoutElapsed,
        );
        assert_eq!(s, CircuitState::Closed);
    }

    #[test]
    fn next_state_half_open_timeout_is_idempotent() {
        let s = next_state(
            CircuitState::HalfOpen,
            CircuitCounts::new(),
            cfg(),
            BreakerEvent::TimeoutElapsed,
        );
        assert_eq!(s, CircuitState::HalfOpen);
    }

    #[test]
    fn next_state_open_call_is_idempotent() {
        let s = next_state(
            CircuitState::Open,
            CircuitCounts::new(),
            cfg(),
            BreakerEvent::Call(CallOutcome::Success),
        );
        assert_eq!(s, CircuitState::Open);
    }

    // ── allows_request 三态 ───────────────────────────────────────────────────
    #[test]
    fn allows_request_closed_always_true() {
        assert!(allows_request(
            CircuitState::Closed,
            CircuitCounts::new(),
            cfg()
        ));
    }

    #[test]
    fn allows_request_open_always_false() {
        assert!(!allows_request(
            CircuitState::Open,
            CircuitCounts::new(),
            cfg()
        ));
    }

    #[test]
    fn allows_request_half_open_below_max_true() {
        // max=2, requests=1
        let counts = CircuitCounts::new().record_success();
        assert!(allows_request(CircuitState::HalfOpen, counts, cfg()));
    }

    #[test]
    fn allows_request_half_open_at_max_false() {
        // max=2, requests=2
        let counts = CircuitCounts::new().record_success().record_success();
        assert!(!allows_request(CircuitState::HalfOpen, counts, cfg()));
    }
}
