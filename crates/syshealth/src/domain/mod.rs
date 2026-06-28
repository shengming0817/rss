//! syshealth 域类型与纯逻辑。
//!
//! 薄域——最大化复用 `primitives::healthz`；禁止重定义 `HealthStatus` / `HealthCheck` /
//! `HealthReport`（破坏 INVARIANT HEALTHZ-SEVERITY-ORD-01 全序）。
//! 所有类型 `pub(crate)`，字段私有，只经显式构造 funnel 创建（ADR-001）。
//! 域类型**严禁** derive `Serialize`/`Deserialize`（dylint 守护区 `rss_domain_no_serialize`，ADR-004 C6）。
//!
//! 本模块全为同步纯 L0 计算（无 I/O、无背景并发）；探针求值本身（I/O）是 diport 的 DI port，不在此。
//! 当前域 API 仅测试消费——生产消费方（readyz / info 端点接线）在 W-services 阶段引入，故未接线
//! 的 `pub(crate)` 项带 item-level `#[allow(dead_code)]`（库 crate 无 `pub` root ⇒ 普通构建里全部不可达）。
//!
//! ref: aegis-monitoring docs.rs/aegis-monitoring/0.1.3/aegis_monitoring/health/@0.1.3
//!      （critical/non-critical 分级聚合语义）。
//! ref: danielschemmel/build-info build-info-common/src/lib.rs@master
//!      （`SystemInfo` 字段结构对标 `CrateInfo.name`/`CrateInfo.version`/`GitInfo.commit_short_id`；
//!       偏离点：不用 build.rs 自采集，值由组合根启动时注入——契合「无状态」）。

use primitives::healthz::{HealthCheck, HealthStatus, ProbeName};

// ---------------------------------------------------------------------------
// ProbeDescriptor
// ---------------------------------------------------------------------------

/// 探针描述符（私有字段；区分 critical / non-critical 分级聚合）。
///
/// - `critical: true`  → 失败时聚合结果退化为 `HealthStatus::Unhealthy`。
/// - `critical: false` → 失败时聚合结果退化为 `HealthStatus::Degraded`。
// reason: `new` 当前无生产消费方（探针注册接线在 W-services），仅测试消费；库 crate 无 pub root ⇒ dead_code。
#[allow(dead_code)]
pub(crate) struct ProbeDescriptor {
    name: ProbeName,
    critical: bool,
}

impl ProbeDescriptor {
    /// 构造探针描述符（位置参必填）。
    // reason: 仅测试 / 未来组合根消费；普通构建不可达（库 crate 无 pub root）。
    #[allow(dead_code)]
    pub(crate) fn new(name: ProbeName, critical: bool) -> Self {
        Self { name, critical }
    }

    /// 探针名。
    pub(crate) fn name(&self) -> &ProbeName {
        &self.name
    }

    /// 是否关键探针（关键探针失败 → `Unhealthy`）。
    pub(crate) fn critical(&self) -> bool {
        self.critical
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

/// 探针注册表（私有字段；运行时持有所有已注册 `ProbeDescriptor`，按注册顺序）。
// reason: 注册 / 查询接线在 W-services；当前仅测试消费 ⇒ dead_code（库 crate 无 pub root）。
#[allow(dead_code)]
pub(crate) struct ProbeRegistry {
    descriptors: Vec<ProbeDescriptor>,
}

impl ProbeRegistry {
    /// 构造空注册表。
    // reason: 仅测试 / 未来组合根消费；普通构建不可达。
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {
            descriptors: Vec::new(),
        }
    }

    /// 注册探针描述符（重复名称 → `SyshealthError::DuplicateProbe`，原表不变）。
    // reason: 注册接线在 W-services；当前仅测试消费 ⇒ dead_code。
    #[allow(dead_code)]
    pub(crate) fn register(&mut self, descriptor: ProbeDescriptor) -> Result<(), SyshealthError> {
        if self
            .descriptors
            .iter()
            .any(|d| d.name() == descriptor.name())
        {
            return Err(SyshealthError::DuplicateProbe);
        }
        self.descriptors.push(descriptor);
        Ok(())
    }

    /// 返回所有已注册探针描述符（按注册顺序）。
    // reason: 快照读取接线在 W-services；当前仅测试消费 ⇒ dead_code。
    #[allow(dead_code)]
    pub(crate) fn descriptors(&self) -> &[ProbeDescriptor] {
        &self.descriptors
    }

    /// 严格查询探针 criticality：未注册 → `SyshealthError::ProbeNotRegistered`（**fail-closed** 查询）。
    ///
    /// 供 [`aggregate_with_criticality`] 与「按名严格判级」的独立 probe 查询路径使用；返回 `Err`
    /// 时 aggregate 按 fail-closed 兜底（未注册失败探针计为 critical）。
    // reason: 严格查询路径接线在 W-services；当前仅 aggregate（match Err→fail-closed）与测试消费 ⇒ dead_code。
    #[allow(dead_code)]
    pub(crate) fn criticality_of(&self, name: &ProbeName) -> Result<bool, SyshealthError> {
        self.descriptors
            .iter()
            .find(|d| d.name() == name)
            .map(|d| d.critical())
            .ok_or(SyshealthError::ProbeNotRegistered)
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
// SystemInfo（系统元信息：无状态注入值对象）
// ---------------------------------------------------------------------------

/// 系统元信息（无状态值对象；私有字段，只经构造 funnel 注入）。
///
/// gocell `syscore` 的「系统元信息」slice 在 Rust 侧的薄域映射：服务名 + 版本 + git 短修订号，
/// 全部由组合根启动时**注入**（无 DB、无 build.rs 自采集），故为纯值、`Clone`/`Eq`。
/// 域类型**不** derive `Serialize`——wire 化经 contract/DTO（W-services info 端点）。
///
/// ref: danielschemmel/build-info build-info-common/src/lib.rs@master
///      （字段对标 `CrateInfo.name` / `CrateInfo.version` / `GitInfo.commit_short_id`）。
// reason: info 端点接线在 W-services；当前仅测试消费 ⇒ dead_code（库 crate 无 pub root）。
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SystemInfo {
    service: String,
    version: String,
    revision: String,
}

impl SystemInfo {
    /// 由组合根注入服务名 / 版本 / git 短修订号构造（受信注入，infallible）。
    //
    // reason: infallible（不返回 Result）——这三个字段是**构建期常量**（`CARGO_PKG_*` / git 短 sha），
    //         由组合根在启动时一次性注入，非 config / wire 派生的不可信输入；其非空 / 格式校验是组合根
    //         的职责，不在此薄域重复（区别于 `ProbeName::parse` 这类可信边界外输入的 fail-closed funnel）。
    //         W-services info 端点 wire 化时经 contract/DTO 校验出站。
    // reason: 仅测试 / 未来组合根消费；普通构建不可达。
    #[allow(dead_code)]
    pub(crate) fn new(
        service: impl Into<String>,
        version: impl Into<String>,
        revision: impl Into<String>,
    ) -> Self {
        Self {
            service: service.into(),
            version: version.into(),
            revision: revision.into(),
        }
    }

    /// 服务名。
    // reason: info 端点接线在 W-services；当前仅测试消费 ⇒ dead_code。
    #[allow(dead_code)]
    pub(crate) fn service(&self) -> &str {
        &self.service
    }

    /// 服务版本（semver 形态字符串）。
    // reason: 同上 ⇒ dead_code。
    #[allow(dead_code)]
    pub(crate) fn version(&self) -> &str {
        &self.version
    }

    /// git 短修订号（无 VCS 时由组合根注入占位值）。
    // reason: 同上 ⇒ dead_code。
    #[allow(dead_code)]
    pub(crate) fn revision(&self) -> &str {
        &self.revision
    }
}

// ---------------------------------------------------------------------------
// 纯逻辑：分级聚合
// ---------------------------------------------------------------------------

/// 基于探针 criticality 分级聚合健康状态（**fail-closed**，对齐仓库 readiness 单源）。
///
/// INVARIANT: HEALTHZ-EMPTY-FAIL-CLOSED-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
///
/// - `checks` 为空（无任何探针结果）→ 返回 `HealthStatus::Unhealthy`（fail-closed，对齐
///   `primitives::HealthReport::aggregate`：无探针即不可服务，不得放行）。
/// - 探针**未在 `registry` 中注册**且 check 状态 != `Healthy` → 视为 critical 处理（fail-closed，
///   注册缺失 = 配置错误，不静默放行）→ 计入 critical 失败。
/// - critical 探针 check 状态 != `Healthy` → 返回 `HealthStatus::Unhealthy`。
/// - non-critical 探针 check 状态 != `Healthy` → 返回 `HealthStatus::Degraded`（当无 critical/未注册失败时）。
/// - 全部 check `Healthy`（且非空）→ 返回 `HealthStatus::Healthy`。
///
/// 使用 `primitives::healthz::HealthStatus` 的全序（INVARIANT HEALTHZ-SEVERITY-ORD-01）。
// reason: fail-closed 与仓库 readiness 单源一致（primitives::HealthReport::aggregate 空→Unhealthy、
//         httpserve::readyz Unhealthy→503、bootstrap readyz）；零信任默认——注册缺失 / 无探针
//         不得误判为可服务（review #228 F1/F2 修正原 fail-open 设计）。non-critical 失败仍封顶
//         Degraded 是有意的严重度分级（aegis-monitoring critical/non-critical 模型），非 fail-open。
// reason: readyz 聚合接线在 W-services；当前仅测试消费 ⇒ dead_code（库 crate 无 pub root）。
#[allow(dead_code)]
pub(crate) fn aggregate_with_criticality(
    checks: &[HealthCheck],
    registry: &ProbeRegistry,
) -> HealthStatus {
    // fail-closed：无任何探针结果即不可服务（对齐 primitives::HealthReport::aggregate）。
    if checks.is_empty() {
        return HealthStatus::Unhealthy;
    }

    let mut critical_fail = false;
    let mut noncritical_fail = false;

    for check in checks {
        if check.status() == HealthStatus::Healthy {
            continue;
        }
        match registry.criticality_of(check.name()) {
            // critical 失败 OR 未注册失败（fail-closed：注册缺失视为 critical，不静默放行）。
            Ok(true) | Err(SyshealthError::ProbeNotRegistered) => critical_fail = true,
            // 已注册 non-critical 失败 → 封顶 Degraded（有意的严重度分级）。
            Ok(false) => noncritical_fail = true,
            // reason: criticality_of 仅产 ProbeNotRegistered；其它变体（DuplicateProbe）非查询路径，
            //         fail-closed 兜底为 critical（不可达，防未来变体漂移成静默放行）。
            Err(_) => critical_fail = true,
        }
    }

    if critical_fail {
        HealthStatus::Unhealthy
    } else if noncritical_fail {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    }
}

// ---------------------------------------------------------------------------
// 错误枚举
// ---------------------------------------------------------------------------

/// syshealth 域错误（库枚举；`thiserror`；message 为 `&'static str` const literal）。
// reason: 错误构造在 register / criticality_of（当前仅测试可达）；库 crate 无 pub root ⇒ dead_code。
#[allow(dead_code)]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum SyshealthError {
    #[error("probe name is not registered in registry")]
    ProbeNotRegistered,
    #[error("probe name is already registered")]
    DuplicateProbe,
}

// ---------------------------------------------------------------------------
// 行为测试（表式 #[test]；纯 L0、无 async）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        ProbeDescriptor, ProbeRegistry, SyshealthError, SystemInfo, aggregate_with_criticality,
    };
    use primitives::healthz::{HealthCheck, HealthStatus, ProbeName};

    /// 测试辅助：解析探针名（测试输入恒合法）。
    #[allow(clippy::unwrap_used)]
    fn probe(name: &str) -> ProbeName {
        ProbeName::parse(name).unwrap()
    }

    fn check(name: &str, status: HealthStatus) -> HealthCheck {
        HealthCheck::new(probe(name), status, "test-detail")
    }

    #[allow(clippy::unwrap_used)]
    fn registry(entries: &[(&str, bool)]) -> ProbeRegistry {
        let mut reg = ProbeRegistry::new();
        for (name, critical) in entries {
            reg.register(ProbeDescriptor::new(probe(name), *critical))
                .unwrap();
        }
        reg
    }

    // ── ProbeDescriptor ───────────────────────────────────────────────────
    #[test]
    fn probe_descriptor_accessors() {
        let d = ProbeDescriptor::new(probe("db"), true);
        assert_eq!(d.name(), &probe("db"));
        assert!(d.critical());

        let d2 = ProbeDescriptor::new(probe("cache"), false);
        assert!(!d2.critical());
    }

    // ── ProbeRegistry ─────────────────────────────────────────────────────
    #[test]
    fn registry_new_is_empty() {
        let reg = ProbeRegistry::new();
        assert!(reg.descriptors().is_empty());
    }

    #[test]
    fn registry_register_ok_and_preserves_order() {
        let reg = registry(&[("db", true), ("cache", false), ("queue", true)]);
        let names: Vec<&str> = reg
            .descriptors()
            .iter()
            .map(|d| d.name().as_str())
            .collect();
        assert_eq!(names, vec!["db", "cache", "queue"]);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn registry_register_duplicate_is_err() {
        let mut reg = ProbeRegistry::new();
        reg.register(ProbeDescriptor::new(probe("db"), true))
            .unwrap();
        let err = reg.register(ProbeDescriptor::new(probe("db"), false));
        assert!(matches!(err, Err(SyshealthError::DuplicateProbe)));
        // 重复注册不入表（保持单条）。
        assert_eq!(reg.descriptors().len(), 1);
    }

    // ── criticality_of（fail-closed 查询）─────────────────────────────────
    #[test]
    fn criticality_of_registered_critical() {
        let reg = registry(&[("db", true)]);
        assert_eq!(reg.criticality_of(&probe("db")), Ok(true));
    }

    #[test]
    fn criticality_of_registered_noncritical() {
        let reg = registry(&[("cache", false)]);
        assert_eq!(reg.criticality_of(&probe("cache")), Ok(false));
    }

    #[test]
    fn criticality_of_unregistered_is_err() {
        let reg = registry(&[("db", true)]);
        assert!(matches!(
            reg.criticality_of(&probe("missing")),
            Err(SyshealthError::ProbeNotRegistered)
        ));
    }

    // ── aggregate_with_criticality（fail-closed 分级）─────────────────────
    #[test]
    fn aggregate_empty_checks_is_unhealthy_fail_closed() {
        // INVARIANT: HEALTHZ-EMPTY-FAIL-CLOSED-01 { level = "Medium", exec = "manual/opt-in", source = "code" }        // fail-closed：无探针结果即不可服务（对齐 primitives::HealthReport::aggregate）。
        let reg = ProbeRegistry::new();
        assert_eq!(
            aggregate_with_criticality(&[], &reg),
            HealthStatus::Unhealthy
        );
    }

    #[test]
    fn aggregate_all_healthy_is_healthy() {
        let reg = registry(&[("db", true), ("cache", false)]);
        let checks = [
            check("db", HealthStatus::Healthy),
            check("cache", HealthStatus::Healthy),
        ];
        assert_eq!(
            aggregate_with_criticality(&checks, &reg),
            HealthStatus::Healthy
        );
    }

    #[test]
    fn aggregate_critical_degraded_is_unhealthy() {
        // critical 探针仅 Degraded 也升 Unhealthy。
        let reg = registry(&[("db", true)]);
        let checks = [check("db", HealthStatus::Degraded)];
        assert_eq!(
            aggregate_with_criticality(&checks, &reg),
            HealthStatus::Unhealthy
        );
    }

    #[test]
    fn aggregate_critical_unhealthy_is_unhealthy() {
        let reg = registry(&[("db", true)]);
        let checks = [check("db", HealthStatus::Unhealthy)];
        assert_eq!(
            aggregate_with_criticality(&checks, &reg),
            HealthStatus::Unhealthy
        );
    }

    #[test]
    fn aggregate_noncritical_unhealthy_caps_at_degraded() {
        // non-critical 探针即便 Unhealthy 也只降到 Degraded。
        let reg = registry(&[("cache", false)]);
        let checks = [check("cache", HealthStatus::Unhealthy)];
        assert_eq!(
            aggregate_with_criticality(&checks, &reg),
            HealthStatus::Degraded
        );
    }

    #[test]
    fn aggregate_noncritical_degraded_is_degraded() {
        let reg = registry(&[("cache", false)]);
        let checks = [check("cache", HealthStatus::Degraded)];
        assert_eq!(
            aggregate_with_criticality(&checks, &reg),
            HealthStatus::Degraded
        );
    }

    #[test]
    fn aggregate_unregistered_failing_probe_is_failclosed_unhealthy() {
        // INVARIANT: HEALTHZ-EMPTY-FAIL-CLOSED-01 { level = "Medium", exec = "manual/opt-in", source = "code" }        // 未注册失败探针 → 视为 critical（fail-closed，注册缺失=配置错误，不静默放行）→ Unhealthy。
        let reg = ProbeRegistry::new();
        let checks = [check("ghost", HealthStatus::Unhealthy)];
        assert_eq!(
            aggregate_with_criticality(&checks, &reg),
            HealthStatus::Unhealthy
        );
    }

    #[test]
    fn aggregate_unregistered_healthy_probe_is_healthy() {
        // INVARIANT: HEALTHZ-EMPTY-FAIL-CLOSED-01 { level = "Medium", exec = "manual/opt-in", source = "code" }        // 未注册但 Healthy 的 check 不触发 fail-closed（只有失败探针才按注册缺失判 critical）→ Healthy。
        let reg = registry(&[("db", true)]);
        let checks = [
            check("db", HealthStatus::Healthy),
            check("ghost", HealthStatus::Healthy),
        ];
        assert_eq!(
            aggregate_with_criticality(&checks, &reg),
            HealthStatus::Healthy
        );
    }

    #[test]
    fn aggregate_two_critical_probes_both_fail_is_unhealthy() {
        // 多个 critical 同时失败仍聚合为 Unhealthy（回归护栏）。
        let reg = registry(&[("db", true), ("queue", true)]);
        let checks = [
            check("db", HealthStatus::Unhealthy),
            check("queue", HealthStatus::Unhealthy),
        ];
        assert_eq!(
            aggregate_with_criticality(&checks, &reg),
            HealthStatus::Unhealthy
        );
    }

    #[test]
    fn aggregate_critical_healthy_noncritical_unhealthy_is_degraded() {
        let reg = registry(&[("db", true), ("cache", false)]);
        let checks = [
            check("db", HealthStatus::Healthy),
            check("cache", HealthStatus::Unhealthy),
        ];
        assert_eq!(
            aggregate_with_criticality(&checks, &reg),
            HealthStatus::Degraded
        );
    }

    #[test]
    fn aggregate_critical_unhealthy_noncritical_healthy_is_unhealthy() {
        let reg = registry(&[("db", true), ("cache", false)]);
        let checks = [
            check("db", HealthStatus::Unhealthy),
            check("cache", HealthStatus::Healthy),
        ];
        assert_eq!(
            aggregate_with_criticality(&checks, &reg),
            HealthStatus::Unhealthy
        );
    }

    #[test]
    fn aggregate_critical_degraded_noncritical_unhealthy_critical_wins() {
        // critical 失败胜过 non-critical 失败 → Unhealthy。
        let reg = registry(&[("db", true), ("cache", false)]);
        let checks = [
            check("db", HealthStatus::Degraded),
            check("cache", HealthStatus::Unhealthy),
        ];
        assert_eq!(
            aggregate_with_criticality(&checks, &reg),
            HealthStatus::Unhealthy
        );
    }

    // ── SystemInfo ────────────────────────────────────────────────────────
    #[test]
    fn system_info_accessors() {
        let info = SystemInfo::new("rss", "1.2.3", "abc1234");
        assert_eq!(info.service(), "rss");
        assert_eq!(info.version(), "1.2.3");
        assert_eq!(info.revision(), "abc1234");
    }

    #[test]
    fn system_info_clone_eq() {
        let a = SystemInfo::new("rss", "1.0.0", "deadbee");
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ── Debug / Display 覆盖 ─────────────────────────────────────────────
    #[test]
    fn debug_impls_render_fields() {
        let d = ProbeDescriptor::new(probe("db"), true);
        let s = format!("{d:?}");
        assert!(s.contains("ProbeDescriptor"));
        assert!(s.contains("db"));

        let reg = registry(&[("db", true)]);
        let rs = format!("{reg:?}");
        assert!(rs.contains("ProbeRegistry"));

        let info = SystemInfo::new("rss", "1.0.0", "abc");
        assert!(format!("{info:?}").contains("SystemInfo"));
    }

    #[test]
    fn error_display_messages() {
        assert_eq!(
            SyshealthError::ProbeNotRegistered.to_string(),
            "probe name is not registered in registry"
        );
        assert_eq!(
            SyshealthError::DuplicateProbe.to_string(),
            "probe name is already registered"
        );
    }
}
