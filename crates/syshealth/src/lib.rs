//! syshealth — RSS 系统健康聚合域。
//!
//! 本 crate 是薄域——最大化复用 `primitives::healthz` 的 `HealthStatus` / `HealthCheck` /
//! `HealthReport`，在此基础上叠加 critical / non-critical 探针分级聚合语义。
//! 严禁重定义 `HealthStatus`（破坏 INVARIANT HEALTHZ-SEVERITY-ORD-01 全序不变量）。
//! DI port（探针 I/O 求值）归 `diport`（ADR-003）；`ManagedResource` 生命周期 Hook 亦在 diport。
//!
//! # 模块布局
//!
//! - `domain` —— 域类型与纯逻辑（dylint 守护区，禁 derive Serialize）
//!
//! # 签名冻结（ADR-004 C8 豁免覆盖率）
//!
//! 本 crate 当前只冻结签名（函数体 = `todo!()`）；smoke test 只绑函数指针 / 构造类型，
//! 不执行任何 `todo!()` body。
//!
//! ref: aegis-monitoring docs.rs/aegis-monitoring/0.1.3/aegis_monitoring/health/@0.1.3
//!      （critical/non-critical 分级聚合）。

#![forbid(unsafe_code)]

pub(crate) mod domain;

// ---------------------------------------------------------------------------
// smoke test（ADR-004 C8 豁免：只绑函数指针 / 构造类型，不触 todo!() body）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod smoke {
    //! build smoke：证明签名可被引用消费 + 错误 enum 可构造 + Send 约束。
    //! **不调用** `todo!()` body。

    use crate::domain::{
        ProbeDescriptor, ProbeRegistry, SyshealthError, aggregate_with_criticality,
    };
    use primitives::healthz::{HealthCheck, HealthStatus, ProbeName};

    fn _assert_send<T: Send>() {}

    #[test]
    fn error_enum_is_send() {
        _assert_send::<SyshealthError>();
    }

    #[test]
    fn syshealth_error_enum_is_exhaustive() {
        let e = SyshealthError::ProbeNotRegistered;
        match e {
            SyshealthError::ProbeNotRegistered => {}
            SyshealthError::DuplicateProbe => {}
        }
    }

    #[test]
    fn health_status_from_primitives_is_reachable() {
        // 验证复用 primitives 的 HealthStatus（不重定义）；
        // non_exhaustive 要求外部 crate 穷举 match 必须含 `_` 分支。
        let _status = HealthStatus::Degraded;
        match _status {
            HealthStatus::Healthy => {}
            HealthStatus::Degraded => {}
            HealthStatus::Unhealthy => {}
            // reason: HealthStatus 为 #[non_exhaustive]，外部 crate 必须覆盖未来可能新增的 variant（编译期约束）。
            _ => {}
        }
    }

    #[test]
    fn aggregate_with_criticality_signature_is_consumable() {
        // 绑定函数指针（不调用 → 不触 todo!()）
        let _f: fn(&[HealthCheck], &ProbeRegistry) -> HealthStatus = aggregate_with_criticality;
        let _ = _f;
    }

    #[test]
    fn probe_descriptor_and_registry_signatures_are_consumable() {
        // 绑定函数指针（不调用 → 不触 todo!()）
        let _new_desc: fn(ProbeName, bool) -> ProbeDescriptor = ProbeDescriptor::new;
        let _ = _new_desc;

        let _new_reg: fn() -> ProbeRegistry = ProbeRegistry::new;
        let _ = _new_reg;

        let _register: fn(&mut ProbeRegistry, ProbeDescriptor) -> Result<(), SyshealthError> =
            ProbeRegistry::register;
        let _ = _register;
    }

    #[test]
    fn probe_descriptor_accessor_signatures_are_consumable() {
        // 绑定 ProbeDescriptor accessor（不调用 → 不触 todo!()）
        let _name: fn(&ProbeDescriptor) -> &ProbeName = ProbeDescriptor::name;
        let _ = _name;

        let _critical: fn(&ProbeDescriptor) -> bool = ProbeDescriptor::critical;
        let _ = _critical;
    }

    #[test]
    fn probe_registry_accessor_signatures_are_consumable() {
        // 绑定 ProbeRegistry accessor（不调用 → 不触 todo!()）
        let _descriptors: fn(&ProbeRegistry) -> &[ProbeDescriptor] = ProbeRegistry::descriptors;
        let _ = _descriptors;
    }
}
