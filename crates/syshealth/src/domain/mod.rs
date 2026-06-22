//! syshealth 域类型与纯逻辑。
//!
//! 薄域——最大化复用 `primitives::healthz`；禁止重定义 `HealthStatus` / `HealthCheck` /
//! `HealthReport`（破坏 INVARIANT HEALTHZ-SEVERITY-ORD-01 全序）。
//! 所有类型 `pub(crate)`，字段私有，只经显式构造 funnel 创建（ADR-001）。
//! 域类型**严禁** derive `Serialize`/`Deserialize`（dylint 守护区，ADR-004 C6）。
//!
//! # 签名冻结（ADR-004 C8 豁免覆盖率）
//!
//! 函数体全为 `todo!()`；smoke test 只绑函数指针 / 构造类型，不触 body。
//!
//! ref: aegis-monitoring docs.rs/aegis-monitoring/0.1.3/aegis_monitoring/health/@0.1.3
//!      （critical/non-critical 分级聚合语义）。

use primitives::healthz::{HealthCheck, HealthStatus, ProbeName};

// ---------------------------------------------------------------------------
// ProbeDescriptor
// ---------------------------------------------------------------------------

/// 探针描述符（私有字段；区分 critical / non-critical 分级聚合）。
///
/// - `critical: true`  → 失败时聚合结果退化为 `HealthStatus::Unhealthy`。
/// - `critical: false` → 失败时聚合结果退化为 `HealthStatus::Degraded`。
// reason: 签名冻结期字段已声明但 accessor body 全为 todo!()（ADR-004 C8）。
#[allow(dead_code)]
pub(crate) struct ProbeDescriptor {
    name: ProbeName,
    critical: bool,
}

// reason: 签名冻结期方法尚无调用方，dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
impl ProbeDescriptor {
    /// 构造探针描述符（位置参必填）。
    pub(crate) fn new(_name: ProbeName, _critical: bool) -> Self {
        todo!()
    }

    /// 探针名。
    pub(crate) fn name(&self) -> &ProbeName {
        todo!()
    }

    /// 是否关键探针（关键探针失败 → `Unhealthy`）。
    pub(crate) fn critical(&self) -> bool {
        todo!()
    }
}

impl std::fmt::Debug for ProbeDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeDescriptor")
            .field("name", &self.name)
            .field("critical", &self.critical)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ProbeRegistry
// ---------------------------------------------------------------------------

/// 探针注册表（私有字段；运行时持有所有已注册 `ProbeDescriptor`）。
// reason: 签名冻结期字段已声明但方法 body 全为 todo!()（ADR-004 C8）。
#[allow(dead_code)]
pub(crate) struct ProbeRegistry {
    descriptors: Vec<ProbeDescriptor>,
}

// reason: 签名冻结期方法尚无调用方，dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
impl ProbeRegistry {
    /// 构造空注册表。
    pub(crate) fn new() -> Self {
        todo!()
    }

    /// 注册探针描述符（重复名称 → `SyshealthError::DuplicateProbe`）。
    pub(crate) fn register(&mut self, _descriptor: ProbeDescriptor) -> Result<(), SyshealthError> {
        todo!()
    }

    /// 返回所有已注册探针描述符（按注册顺序）。
    pub(crate) fn descriptors(&self) -> &[ProbeDescriptor] {
        todo!()
    }
}

impl std::fmt::Debug for ProbeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeRegistry")
            .field("descriptors", &self.descriptors)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// 纯逻辑（签名冻结，body=todo!()）
// ---------------------------------------------------------------------------

/// 基于探针 criticality 分级聚合健康状态。
///
/// INVARIANT: HEALTHZ-EMPTY-FAIL-OPEN-01
///
/// - 探针未在 `registry` 中注册 → 视为 non-critical 处理（fail-open 降级，不 panic）。
/// - critical 探针 check 状态 != `Healthy` → 返回 `HealthStatus::Unhealthy`。
/// - non-critical 探针 check 状态 != `Healthy` → 返回 `HealthStatus::Degraded`（当无 critical 失败时）。
/// - 所有探针 `Healthy` → 返回 `HealthStatus::Healthy`。
/// - `checks` 为空 → 返回 `HealthStatus::Healthy`（fail-open，无探针即认为健康）。
///
/// 使用 `primitives::healthz::HealthStatus` 的全序（INVARIANT HEALTHZ-SEVERITY-ORD-01）。
// reason: checks 为空时返回 Healthy（fail-open）——无探针注册是初始化阶段容忍行为；
//         组合根须在上线 readiness gate 前强制注册 ≥1 探针。本函数非 readiness 唯一裁决点。
// reason: 签名冻结期函数尚无调用方，dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
pub(crate) fn aggregate_with_criticality(
    _checks: &[HealthCheck],
    _registry: &ProbeRegistry,
) -> HealthStatus {
    todo!()
}

// ---------------------------------------------------------------------------
// 错误枚举
// ---------------------------------------------------------------------------

/// syshealth 域错误（库枚举；`thiserror`；message 为 `&'static str` const literal）。
// reason: 签名冻结期枚举尚无调用方，dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum SyshealthError {
    // reason: 预留给独立 probe 查询 API（按名查未注册探针），非 aggregate_with_criticality 产生；
    //         当前无调用路径，保留以避免行为 PR 误判签名漂移。
    #[error("probe name is not registered in registry")]
    ProbeNotRegistered,
    #[error("probe name is already registered")]
    DuplicateProbe,
}
