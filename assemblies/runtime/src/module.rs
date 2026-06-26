//! 运行时层共享基础设施依赖（[PERSIST-001] #1422，ADR-010 §2.6 step 2）。
//!
//! [`SharedRuntimeDeps`]（parameter object）把共享基础设施**流入**每个域 `wire_X`。它持
//! `PgRuntimeDeps`（postgres 适配器 capability bundle）等 adapter 类型，故必须落组合根层
//! （`assemblies/runtime`），不能进 `bootstrap`（服务层不依赖适配器）。配对的产物出口
//! [`bootstrap::DomainModuleResult`]（probes / resources / workers 可聚合产物）按 ADR-010 §2.2 归属
//! `bootstrap`，组合根经 `merge` 聚合后排空到 sink。
//!
//! # 不变式
//!
//! - **INVARIANT: WIRING-DEPS-NO-HANDOFF-01（Hard，签名强制）**：域接线函数签名为
//!   `wire_X(deps: &SharedRuntimeDeps) -> anyhow::Result<bootstrap::DomainModuleResult>`——只收
//!   `&SharedRuntimeDeps`，无参数可塞别域的 `DomainModuleResult`，故 A 域产物喂进 B 域 wiring 编译期不可表达
//!   （type-system 一档载体）。
//! - 「`SharedRuntimeDeps` 字段仅基础设施」是**约定、非 INVARIANT**（当前无机器门）；升 Medium 机器门见
//!   follow-up #1448。
//!
//! # 开源对标
//!
//! `SharedRuntimeDeps`（infra 流入）对标 omicron `Arc<ServerContext>` clone 进各 server；产物侧
//! `DomainModuleResult` + `merge`（bootstrap）对标 shaku `HasComponents::resolve_all() -> &[Arc<I>]`；概念出处
//! uber-go/dig 的 `Out` + value group（已被 `bootstrap::domain` 引用的 fx 谱系）。RSS 用具体 struct + 手工 `merge`，
//! 无运行时 container / 无反射 / 无 macro——dig/shaku 的运行时解析全部上移编译期。
//!
//! ref: oxidecomputer/omicron nexus/src/context.rs@8eb92537bd12598dfd2c861f897a88962fabf684

use postgres::PgRuntimeDeps;

/// 共享基础设施依赖，流入每个域的 `wire_X`（parameter object，[`bootstrap::DomainModuleResult`] 的入向配对）。
///
/// 设计意图：每个字段是框架 / 适配器基础设施类型，不放域 service 类型（`settings` / `identity` / …），否则等于
/// 经 deps bag 重开「跨 module value handoff」。**但这不是 `INVARIANT:`——当前无机器门**：`assemblies/runtime`
/// 物理可命名域 service 类型，新增 `pub settings: SettingsService` 字段在类型层不会被拒，仅靠 review 约定守（Soft）。
/// 按 `ai-robust.md` 新增 enforcement 不得停留 Soft，故此处**不**声明为现行 INVARIANT / 架构规则；升 Medium 机器门
/// （`cargo xtask` / `dylint` 字段类型扫描断言 infra crate 白名单、禁域 crate + synthetic red + 接入 `verify`）见
/// follow-up #1448，落地后再以 `INVARIANT: WIRING-DEPS-INFRA-ONLY-01` 收口。
#[derive(Clone)]
pub struct SharedRuntimeDeps {
    /// 共享 postgres capability bundle；各域经 `for_domain::<caps::X>()` 投影受控 durable 能力句柄。
    ///
    /// 不暴露 `Arc<PgStore>` / `PgPool`，保持 PG-BUNDLE-FUNNEL-01/03：repo、readiness、sampler、pool guard
    /// 均经 `PgRuntimeDeps` 方法派发。
    pub pg: PgRuntimeDeps,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SharedRuntimeDeps` 必须 `Send`（组合根跨 await 持有传入各 `wire_X`）。
    #[test]
    fn shared_runtime_deps_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<SharedRuntimeDeps>();
    }
}
