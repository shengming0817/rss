//! runtime — RSS library 组合根（Root 层）：从配置构造验签 provider，按 listener 装配
//! `finalize_routes → finalize_auth → .layer(verify_bridge)` 的认证接线接缝，并驱动运行时入口
//! （tokio 运行时 + per-listener socket bind + `axum::serve` + 信号优雅关停 + generated domain wiring，#1320）。
//!
//! 运行时入口（[`run`]，#1320 Join）：从 fingerprint-verified `RuntimePlan` 投影 listener execution plan
//! → 构造 plan 要求的 provider bundle → generated domains → `compose_bindings`
//! → 聚合 `DomainModuleResult` → 按 plan 唯一 finalizer 产出 `FinalizedListenerSet`
//! + `FinalizedProbeReceipt` → runtime adapter 完成 bind-all/preflight-all，再交由
//!   `runtimeexec::LaunchPlan` 唯一编排 serve、SIGTERM/SIGINT 和 LIFO drain。Health 只由 plan 中的
//!   `Health + NoAuth` 项创建，没有手写 append 旁路。各域 typed handle 经 Registry 的 route/subscriber
//!   funnel 一次性交接，不进入共享依赖或生命周期输出。JWT 验签 key 经本地
//!   JWKS 文件源 + 外部 agent 轮转注入；Internal listener 默认走 SPIFFE/mTLS，service-token 仅保留 loopback
//!   本地测试路径。
//!
//! 安全同批门（ADR-006 §5）：依赖图引真 verifier（`oidc` backend）、不引 stub Pdp（`memory` 经 deny.toml 禁
//! runtime；`rss_pdp_impl_adapter_only` dylint 守 +
//! `cargo xtask verify` 的 pdp-allow 计数门守逃生门用量）。`OidcProvider` 必填 `VerifierConfig` + `Box<dyn Clock>`
//! ⇒ 无 key/clock 不可构造（编译期守）。
//!
pub mod auth_bridge;
mod config;
#[cfg(test)]
mod config_tests;
pub mod distributed_runtime;
#[cfg(test)]
mod domain_placement_tests;
mod domains;
pub mod event_transport;
pub mod infra;
pub(crate) mod launch;
mod lifecycle;
mod listeners;
mod module;
#[path = "generated/modules_gen.rs"]
mod modules_gen;
pub mod operator;
mod phase;
pub mod plan;
mod provider_catalog;
mod provider_output;
#[path = "generated/providers_gen.rs"]
mod providers_gen;
mod routes;
mod runtime_inventory;
pub mod saga_runtime;
mod secret_config;
pub mod support;
mod telemetry;
#[cfg(test)]
mod telemetry_tests;
#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
pub(crate) use secret_config::EnvSecret;
#[cfg(test)]
use telemetry::{
    OTEL_ENDPOINT_ENV, build_trace_export, build_trace_export_from_value,
    prepare_local_before_external,
};

pub use distributed_runtime::DistributedRuntimeDeps;
pub use domains::settings::{CONFIGS_READY_PROBE_NAME, ConfigsReadyProbe};
pub use infra::oidc::{
    KeyedEs256StaticKey, RssAccessStaticProviderConfig, rss_access_provider_from_static_config,
};
pub use settings_composition::KEYPROVIDER_READY_PROBE_NAME;

/// Explicit integration-only seams for exercising typed domain wiring with hermetic providers.
///
/// Production callers cannot reach the concrete domain constructors; live assembly always enters
/// through the committed generated module list.
#[cfg(feature = "integration")]
pub mod test_support;
pub use lifecycle::{
    activate_structured_panic_observation, install_redacted_panic_hook, prepare_runtime,
    report_process_error, run, shutdown_runtime,
};
pub(crate) use lifecycle::{
    prepare_operator_local, prepare_runtime_kernel, shutdown_prepared_runtime,
};
pub(crate) use module::LocalDomainProviderCatalog;
pub use module::SharedRuntimeDeps;
pub use phase::ServingRuntimeInputs;

#[cfg(test)]
pub(crate) use lifecycle::{RuntimeLifecycleOwner, prepare_serving_local, safe_process_error_line};

#[cfg(test)]
use crypto::RustCryptoMacVerifier;
#[cfg(test)]
use infra::oidc::{
    FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME, RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME,
};
#[cfg(test)]
use infra::redis::REDIS_READY_PROBE_NAME;
#[cfg(test)]
use infra::s3::{S3RuntimeConfig, S3RuntimeConfigParts};
#[cfg(test)]
use phase::{RuntimePhase, after_required_preflight, validate_domain_listener_evidence};
#[cfg(test)]
use primitives::MacKey;
