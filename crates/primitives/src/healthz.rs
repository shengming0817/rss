//! 健康聚合纯计算（ADR-004 C1：L0 sync 纯计算，非 DI port）。
//!
//! 三态严重度 + typed `ProbeName`。探针求值本身（I/O、背景并发）是 DI port → diport；
//! 此处只冻**纯聚合**：单条 report 的合成 + 多条 worst-of。
//! 生命周期 Hook（fx lifecycle，LIFO stop）是 `ManagedResource` DI port，**不在 primitives**。
//! ref: uber-go/fx lifecycle.go@master（生命周期边界——确认 Hook 是 DI port 故排除）。

/// 健康严重度（三态闭值集；Copy）。worst-of 聚合用全序：Healthy < Degraded < Unhealthy。
///
/// INVARIANT: HEALTHZ-SEVERITY-ORD-01 —— variant 声明顺序即严重度全序（Healthy<Degraded<Unhealthy），worst-of 聚合依赖此序；新增 variant 须精确插位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

impl HealthStatus {
    /// 稳定 metrics/health label（crate-owned 闭映射；下游无需 match non_exhaustive enum）。
    pub fn as_label(self) -> &'static str {
        todo!()
    }
}

/// 探针名 newtype（私有字段；构造经 fallible funnel）。
///
/// INVARIANT: HEALTHZ-PROBE-NAME-01 —— 非空、无控制字符（fail-closed；校验在行为 PR 兑现）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProbeName(String);

/// `ProbeName` 解析错误（message const literal）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeNameError {
    #[error("probe name is empty")]
    Empty,
    #[error("probe name has invalid format")]
    Format,
}

impl ProbeName {
    /// 解析探针名；拒空 / 非法字符（fail-closed）。
    pub fn parse(_raw: &str) -> Result<Self, ProbeNameError> {
        todo!()
    }

    /// 借出底层字符串视图。
    pub fn as_str(&self) -> &str {
        todo!()
    }
}

/// 单条探针报告（纯值；detail 为 `&'static str` const，禁夹带 runtime PII）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCheck {
    name: ProbeName,
    status: HealthStatus,
    detail: &'static str,
}

impl HealthCheck {
    /// 由探针名 + 状态 + 稳定 detail 构造（detail 为 const literal，无 runtime 数据）。
    pub fn new(_name: ProbeName, _status: HealthStatus, _detail: &'static str) -> Self {
        todo!()
    }

    /// 探针名。
    pub fn name(&self) -> &ProbeName {
        todo!()
    }

    /// 严重度。
    pub fn status(&self) -> HealthStatus {
        todo!()
    }

    /// 稳定 detail（const，无 PII）。
    pub fn detail(&self) -> &'static str {
        todo!()
    }
}

/// 聚合健康报告（纯值；多条 check 的 worst-of 合成结果）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    overall: HealthStatus,
    checks: Vec<HealthCheck>,
}

impl HealthReport {
    /// 纯聚合：取所有 check 的最坏 `HealthStatus` 为 overall。无 I/O、无背景并发——探针求值在 adapter（DI port）。
    pub fn aggregate(_checks: Vec<HealthCheck>) -> Self {
        todo!()
    }

    /// 聚合严重度。
    pub fn overall(&self) -> HealthStatus {
        todo!()
    }

    /// 明细。
    pub fn checks(&self) -> &[HealthCheck] {
        todo!()
    }
}
