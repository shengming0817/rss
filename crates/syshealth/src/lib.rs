//! syshealth — RSS 系统健康聚合域。
//!
//! 本 crate 是薄域——最大化复用 `primitives::healthz` 的 `HealthStatus` / `HealthCheck` /
//! `HealthReport`，在此基础上叠加 critical / non-critical 探针分级聚合语义，并提供一个无状态的
//! 系统元信息（`SystemInfo`）值对象。严禁重定义 `HealthStatus`（破坏 INVARIANT
//! HEALTHZ-SEVERITY-ORD-01 全序不变量）。
//! DI port（探针 I/O 求值）归 `diport`（ADR-003）；`ManagedResource` 生命周期 Hook 亦在 diport。
//! 本 crate 全为同步纯 L0 计算，无 I/O / 无状态。
//!
//! # 模块布局
//!
//! - `domain` —— 域类型与纯逻辑（dylint 守护区 `rss_domain_no_serialize`，禁 derive Serialize）：
//!   `ProbeDescriptor` / `ProbeRegistry`（注册 + criticality 查询）、`aggregate_with_criticality`
//!   分级聚合、`SystemInfo` 系统元信息、`SyshealthError`。
//!
//! # 接线状态
//!
//! 域逻辑已写实；生产消费方（readyz / info 端点接线）在 W-services 阶段引入。在此之前域 API 仅由
//! crate 内行为测试消费——库 crate 无 `pub` root，故未接线的 `pub(crate)` 项带 item-level
//! `#[allow(dead_code)]`（见各 item `// reason:`）。
//!
//! ref: aegis-monitoring docs.rs/aegis-monitoring/0.1.3/aegis_monitoring/health/@0.1.3
//!      （critical/non-critical 分级聚合）。
//! ref: danielschemmel/build-info build-info-common/src/lib.rs@master
//!      （`SystemInfo` 字段结构对标；偏离点：不用 build.rs 自采集，值由组合根注入）。

#![forbid(unsafe_code)]

pub(crate) mod domain;
