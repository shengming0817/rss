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
        todo!()
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
        todo!()
    }

    /// 记一次成功（纯函数，返回新值；不内部可变）。
    pub fn record_success(self) -> Self {
        todo!()
    }

    /// 记一次失败（纯函数，返回新值）。
    pub fn record_failure(self) -> Self {
        todo!()
    }

    /// 窗口内请求总数。
    pub fn requests(self) -> u32 {
        todo!()
    }

    /// 连续失败数。
    pub fn consecutive_failures(self) -> u32 {
        todo!()
    }

    /// 连续成功数。
    pub fn consecutive_successes(self) -> u32 {
        todo!()
    }

    /// 窗口内累计成功数（adapter 上报 success rate metrics）。
    pub fn total_successes(self) -> u32 {
        todo!()
    }

    /// 窗口内累计失败数（adapter 上报 failure rate metrics）。
    pub fn total_failures(self) -> u32 {
        todo!()
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
        _failure_threshold: u32,
        _max_half_open_requests: u32,
        _interval: Duration,
        _timeout: Duration,
    ) -> Result<Self, BreakerConfigError> {
        todo!()
    }

    /// 触发跳闸的失败阈值。
    pub fn failure_threshold(self) -> u32 {
        todo!()
    }

    /// half-open 探测期允许的并发请求上限。
    pub fn max_half_open_requests(self) -> u32 {
        todo!()
    }

    /// 滚动窗口长度。
    pub fn interval(self) -> Duration {
        todo!()
    }

    /// open→half-open 的冷却时长。
    pub fn timeout(self) -> Duration {
        todo!()
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
/// reason: 时钟读取（`now >= opened_at + timeout`）留在 adapter；此处只接 `TimeoutElapsed`
/// 已判定的纯输入，使熔断决策可单测、可被泛型消费而零运行时依赖。
pub fn next_state(
    _state: CircuitState,
    _counts: CircuitCounts,
    _config: BreakerConfig,
    _event: BreakerEvent,
) -> CircuitState {
    todo!()
}

/// 纯判定：当前态是否允许放行一次新调用（Closed=是、Open=否、HalfOpen=受 max_half_open 限）。
pub fn allows_request(
    _state: CircuitState,
    _counts: CircuitCounts,
    _config: BreakerConfig,
) -> bool {
    todo!()
}
