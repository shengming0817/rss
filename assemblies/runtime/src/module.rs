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
//! - **INVARIANT: WIRING-DEPS-NO-HANDOFF-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }（Hard，签名强制）**：域接线入口
//!   `domains::X::module(source: &impl XModuleSource) -> Future<Result<DomainBinding>>` 统一为 async；
//!   每个 source trait 均 sealed，生产实现仅 [`SharedRuntimeDeps`]，测试实现仅提供同域 provider，且签名
//!   无参数可塞别域的 `DomainModuleResult`，故 A 域产物喂进 B 域 wiring 编译期不可表达
//!   （type-system 一档载体）。
//! - **INVARIANT: WIRING-DEPS-INFRA-ONLY-01 { level = "Medium", exec = "verify", source = "code" }（Medium，xtask 字段扫描）**：
//!   `SharedRuntimeDeps` 字段类型只允许 provider bundle / infra value object 允许列表，以及精确例外
//!   `Arc<dyn distributed::DomainTransport>`；域 service / repo 类型不得经 deps bag 跨 module handoff。
//!
//! # 开源对标
//!
//! `SharedRuntimeDeps`（infra 流入）对标 omicron `Arc<ServerContext>` clone 进各 server；产物侧
//! `DomainModuleResult` + `merge`（bootstrap）对标 shaku `HasComponents::resolve_all() -> &[Arc<I>]`；概念出处
//! uber-go/dig 的 `Out` + value group（已被 `bootstrap::domain` 引用的 fx 谱系）。RSS 用具体 struct + 手工 `merge`，
//! 无运行时 container / 无反射 / 无 macro——dig/shaku 的运行时解析全部上移编译期。
//!
//! ref: oxidecomputer/omicron nexus/src/context.rs@8eb92537bd12598dfd2c861f897a88962fabf684

use std::sync::Arc;

use diport::KeyName;
use postgres::PgRuntimeDeps;
use redis::RedisRuntimeDeps;
use s3::S3RuntimeDeps;
use vault::VaultRuntimeDeps;

/// 共享基础设施依赖，流入每个域的 `wire_X`（parameter object，[`bootstrap::DomainModuleResult`] 的入向配对）。
///
/// 设计意图：每个字段是框架 / 适配器基础设施类型，不放域 service 类型（`settings` / `identity` / …），否则等于
/// 经 deps bag 重开「跨 module value handoff」。该边界由 `cargo xtask runtime-deps guard` 承载：
/// 允许 provider bundle / infra value object 类型根，拒绝域 service / repo 类型，并接入 `verify`。
#[derive(Clone)]
pub struct SharedRuntimeDeps {
    /// 共享 postgres capability bundle；各域经 `for_domain::<caps::X>()` 投影受控 durable 能力句柄。
    ///
    /// 不暴露 `Arc<PgStore>` / `PgPool`，保持 PG-BUNDLE-FUNNEL-01/03：repo、readiness、sampler、pool guard
    /// 均经 `PgRuntimeDeps` 方法派发。
    pub pg: PgRuntimeDeps,

    /// 共享 redis capability bundle，生产必配；distributed runtime 通过此唯一入口取得 lock provider。
    ///
    /// 不暴露 `deadpool_redis::Pool`，保持 REDIS-BUNDLE-FUNNEL-01：pool guard、distlock、CAS、idempotency
    /// 均经 `RedisRuntimeDeps::infra()` / `runtime_resources()` 派发。
    pub redis: RedisRuntimeDeps,

    /// 共享 S3 object-store capability bundle。runtime canary 与后续对象消费方只能经此 bundle 取得
    /// `S3Store`，endpoint/TLS/credentials 仍由组合根启动期 fail-fast 构造。
    pub s3: S3RuntimeDeps,

    /// 共享 vault capability bundle（#1498）；settings 域经 `vault.for_domain::<caps::Settings>().secret_resolver()`
    /// / `key_provider()` 投影受控 Vault 句柄，拿不到 signer 或裸 `reqwest::Client`（VAULT-BUNDLE-RESOLVER-02）。
    /// 其 `runtime_resources()` 单源派生 resolver/key-provider guard，组合根 `merge` 进 `DomainModuleResult.resources`。
    pub vault: VaultRuntimeDeps,

    /// settings `ConfigValue` 加密使用的 Vault Transit key name。组合根启动期从
    /// `RSS_SETTINGS_CONFIG_VALUE_KEY_NAME` fail-fast 解析，wire_settings 只消费 typed 值。
    pub settings_config_value_key_name: KeyName,

    /// 共享 outbound domain transport dispatch seam。组合根构造真实 provider 并注入 typed trait
    /// object，后续域/运行时消费者只能经 `distributed::DomainTransport` 发起跨域同步调用；底层 HTTP
    /// adapter 的 mTLS source 生命周期另由 `DomainModuleResult.resources` 托管。
    pub domain_transport: Arc<dyn distributed::DomainTransport>,
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
