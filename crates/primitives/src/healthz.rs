//! 健康聚合纯计算（ADR-004 C1：L0 sync 纯计算，非 DI port）。
//!
//! 三态严重度 + typed `ProbeName`。探针求值本身（I/O、背景并发）是 DI port → diport；
//! 此处只冻**纯聚合**：单条 report 的合成 + 多条 worst-of。
//! 生命周期 Hook（fx lifecycle，LIFO stop）是 `ManagedResource` DI port，**不在 primitives**。
//! ref: uber-go/fx lifecycle.go@master（生命周期边界——确认 Hook 是 DI port 故排除）。

/// 健康严重度（三态闭值集；Copy）。worst-of 聚合用全序：Healthy < Degraded < Unhealthy。
///
/// INVARIANT: HEALTHZ-SEVERITY-ORD-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— variant 声明顺序即严重度全序（Healthy<Degraded<Unhealthy），worst-of 聚合依赖此序；新增 variant 须精确插位。
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
        match self {
            HealthStatus::Healthy => "healthy",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Unhealthy => "unhealthy",
        }
    }
}

/// 探针名 newtype（私有字段；构造经 fallible funnel）。
///
/// INVARIANT: HEALTHZ-PROBE-NAME-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— 非空、无控制字符（fail-closed）。
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
    pub fn parse(raw: &str) -> Result<Self, ProbeNameError> {
        if raw.is_empty() {
            return Err(ProbeNameError::Empty);
        }
        if raw.chars().any(|c| c.is_control()) {
            return Err(ProbeNameError::Format);
        }
        Ok(Self(raw.to_string()))
    }

    /// 借出底层字符串视图。
    pub fn as_str(&self) -> &str {
        self.0.as_str()
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
    pub fn new(name: ProbeName, status: HealthStatus, detail: &'static str) -> Self {
        Self {
            name,
            status,
            detail,
        }
    }

    /// 探针名。
    pub fn name(&self) -> &ProbeName {
        &self.name
    }

    /// 严重度。
    pub fn status(&self) -> HealthStatus {
        self.status
    }

    /// 稳定 detail（const，无 PII）。
    pub fn detail(&self) -> &'static str {
        self.detail
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
    ///
    /// **fail-closed**：空 checks（未注册任何 probe）聚合为 `Unhealthy`——readyz 不得因「没探针」
    /// 误放行（fail-open）。类型/registry 级「至少一 probe」上线门随 readyz 接线落地（W-services）。
    pub fn aggregate(checks: Vec<HealthCheck>) -> Self {
        let overall = if checks.is_empty() {
            HealthStatus::Unhealthy
        } else {
            // HealthStatus derives Ord with Healthy < Degraded < Unhealthy (declaration order).
            checks
                .iter()
                .fold(HealthStatus::Healthy, |acc, c| acc.max(c.status()))
        };
        Self { overall, checks }
    }

    /// 聚合严重度。
    pub fn overall(&self) -> HealthStatus {
        self.overall
    }

    /// 明细。
    pub fn checks(&self) -> &[HealthCheck] {
        &self.checks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── as_label ──────────────────────────────────────────────────────────────
    #[test]
    fn status_as_label_healthy() {
        assert_eq!(HealthStatus::Healthy.as_label(), "healthy");
    }

    #[test]
    fn status_as_label_degraded() {
        assert_eq!(HealthStatus::Degraded.as_label(), "degraded");
    }

    #[test]
    fn status_as_label_unhealthy() {
        assert_eq!(HealthStatus::Unhealthy.as_label(), "unhealthy");
    }

    // ── ProbeName::parse ──────────────────────────────────────────────────────
    #[test]
    fn probe_name_parse_ok() {
        #[allow(clippy::unwrap_used)]
        let n = ProbeName::parse("db-check").unwrap();
        assert_eq!(n.as_str(), "db-check");
    }

    #[test]
    fn probe_name_parse_empty_err() {
        assert!(matches!(ProbeName::parse(""), Err(ProbeNameError::Empty)));
    }

    #[test]
    fn probe_name_parse_control_char_err() {
        // \t is a control character
        assert!(matches!(
            ProbeName::parse("bad\tname"),
            Err(ProbeNameError::Format)
        ));
    }

    #[test]
    fn probe_name_parse_newline_err() {
        assert!(matches!(
            ProbeName::parse("bad\nname"),
            Err(ProbeNameError::Format)
        ));
    }

    // ── HealthCheck getters ───────────────────────────────────────────────────
    #[test]
    fn health_check_getters() {
        #[allow(clippy::unwrap_used)]
        let name = ProbeName::parse("cache").unwrap();
        let check = HealthCheck::new(name.clone(), HealthStatus::Degraded, "cache slow");
        assert_eq!(check.name(), &name);
        assert_eq!(check.status(), HealthStatus::Degraded);
        assert_eq!(check.detail(), "cache slow");
    }

    // ── HealthReport::aggregate worst-of ─────────────────────────────────────
    #[test]
    fn aggregate_empty_checks_is_unhealthy() {
        // fail-closed：未注册任何 probe 不得返回 Healthy（堵 readyz fail-open）。
        let report = HealthReport::aggregate(vec![]);
        assert_eq!(report.overall(), HealthStatus::Unhealthy);
        assert!(report.checks().is_empty());
    }

    #[test]
    fn aggregate_all_healthy_is_healthy() {
        #[allow(clippy::unwrap_used)]
        let checks = vec![
            HealthCheck::new(ProbeName::parse("a").unwrap(), HealthStatus::Healthy, "ok"),
            HealthCheck::new(ProbeName::parse("b").unwrap(), HealthStatus::Healthy, "ok"),
        ];
        let report = HealthReport::aggregate(checks);
        assert_eq!(report.overall(), HealthStatus::Healthy);
    }

    #[test]
    fn aggregate_with_degraded_is_degraded() {
        #[allow(clippy::unwrap_used)]
        let checks = vec![
            HealthCheck::new(ProbeName::parse("a").unwrap(), HealthStatus::Healthy, "ok"),
            HealthCheck::new(
                ProbeName::parse("b").unwrap(),
                HealthStatus::Degraded,
                "slow",
            ),
        ];
        let report = HealthReport::aggregate(checks);
        assert_eq!(report.overall(), HealthStatus::Degraded);
    }

    #[test]
    fn aggregate_with_unhealthy_is_unhealthy() {
        #[allow(clippy::unwrap_used)]
        let checks = vec![
            HealthCheck::new(ProbeName::parse("a").unwrap(), HealthStatus::Healthy, "ok"),
            HealthCheck::new(
                ProbeName::parse("b").unwrap(),
                HealthStatus::Degraded,
                "slow",
            ),
            HealthCheck::new(
                ProbeName::parse("c").unwrap(),
                HealthStatus::Unhealthy,
                "down",
            ),
        ];
        let report = HealthReport::aggregate(checks);
        assert_eq!(report.overall(), HealthStatus::Unhealthy);
    }

    #[test]
    fn aggregate_preserves_checks_order() {
        #[allow(clippy::unwrap_used)]
        let checks = vec![
            HealthCheck::new(ProbeName::parse("x").unwrap(), HealthStatus::Healthy, "ok"),
            HealthCheck::new(
                ProbeName::parse("y").unwrap(),
                HealthStatus::Unhealthy,
                "down",
            ),
        ];
        let report = HealthReport::aggregate(checks.clone());
        assert_eq!(report.checks(), checks.as_slice());
    }
}
