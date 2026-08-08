//! runtime — RSS 生产组合根（Root 层，#1309 抽离自 bins 双写）：从配置构造生产验签 provider，按 listener 装配
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
//! server/rss/runtime；bins 生产 `src/` 无内联 `impl diport::Pdp`，`rss_pdp_impl_adapter_only` dylint 守 +
//! `cargo xtask verify` 的 pdp-allow 计数门守逃生门用量）。`OidcProvider` 必填 `VerifierConfig` + `Box<dyn Clock>`
//! ⇒ 无 key/clock 不可构造（编译期守）。
//!
//! INVARIANT: BINS-AUTH-SYNC-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }(Hard, #1309) — `bins/server` 是 serving-only thin entry；`bins/rss` 先
//! dispatch 显式 operator CLI（0067 reader-lane migration、audit ledger verify、settings ConfigValue maintenance、projection/DLQ/
//! reconcile-target maintenance），未知参数 fail-closed，未命中 CLI 时再调用同一份 `runtime::run()` serving 组合根。auth wiring
//! 一致性由「单一 `run()` 源」编译期保证，原
//! xtask Medium 守卫 `bins_auth_sync.rs` 退役（双写消除、无第二副本可漂移）。

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
mod listeners;
mod module;
#[path = "generated/modules_gen.rs"]
mod modules_gen;
pub mod operator;
#[path = "generated/providers_gen.rs"]
mod providers_gen;
#[cfg(test)]
mod telemetry_tests;
#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
const _: () = assert!(!providers_gen::PROVIDER_CATALOG.is_empty());
mod phase;
pub mod plan;
mod provider_output;
mod routes;
mod runtime_inventory;
pub mod saga_runtime;
mod secret_config;
pub mod support;
mod telemetry;
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
pub use module::SharedRuntimeDeps;
pub use phase::ServingRuntimeInputs;

#[cfg(test)]
use infra::oidc::{
    FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME, RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME,
};
#[cfg(test)]
use infra::redis::REDIS_READY_PROBE_NAME;
#[cfg(test)]
use infra::s3::{S3RuntimeConfig, S3RuntimeConfigParts};
use phase::PreparedRuntimeInputs;
#[cfg(test)]
use phase::{RuntimePhase, after_required_preflight, validate_domain_listener_evidence};

use anyhow::Context as _;
use config::{RuntimeConfigSnapshot, SnapshotConfig};
#[cfg(test)]
use crypto::RustCryptoMacVerifier;
use diport::ManagedResource as _;
#[cfg(test)]
use primitives::MacKey;
use std::sync::Arc;

fn prepare_serving_local(
    config: SnapshotConfig<'_>,
) -> anyhow::Result<Arc<secure::DigestPasswordBlocklist>> {
    domains::identity::load_password_blocklist(config)
}

fn prepare_operator_local(_: SnapshotConfig<'_>) -> anyhow::Result<()> {
    Ok(())
}

/// Capture one process snapshot, run profile-local preparation, then build external tracing.
///
/// The local closure always runs before the OTLP builder. Serving uses it to seal the mandatory
/// password policy; operators use the same snapshot/tracing lifecycle without receiving that
/// serving-only capability.
fn prepare_runtime_kernel<Local>(
    prepare_local: impl FnOnce(SnapshotConfig<'_>) -> anyhow::Result<Local>,
) -> anyhow::Result<(PreparedRuntimeInputs, Local, phase::PreparedTelemetryPlan)> {
    let runtime_config = RuntimeConfigSnapshot::capture_process_snapshot()
        .context("capture process runtime configuration")?;
    let config = runtime_config.view();
    let telemetry_plan = phase::PreparedTelemetryPlan::prepare(config)?;
    let (local, trace_export) =
        telemetry::prepare_local_before_external(config, prepare_local, || {
            telemetry::build_trace_export(config, telemetry_plan.resource())
        })?;
    telemetry::install_runtime_subscriber(
        telemetry_plan.filter(),
        telemetry_plan.resource().clone(),
        trace_export.as_ref(),
    )?;
    Ok((
        PreparedRuntimeInputs::new(runtime_config, trace_export),
        local,
        telemetry_plan,
    ))
}

/// Prepare serving inputs, sealing the local password policy before any external provider.
///
/// 组合根 binary 入口在 [`run`] **之前**调用——否则运行时入口的全部结构化日志
/// （bind / serve / shutdown / fail-fast）皆为 no-op。`RUST_LOG`、[`telemetry::OTEL_ENDPOINT_ENV`] 与后续
/// serving consumer 全部来自这个 snapshot，不再读取 ambient environment。密码 blocklist 在
/// snapshot 后立即加载并成为必填 [`ServingRuntimeInputs`] typestate，任何 OTLP/外部 provider 都晚于它。
///
/// Only this type can enter [`run`] or [`shutdown_runtime`].
pub fn prepare_runtime() -> anyhow::Result<ServingRuntimeInputs> {
    let (prepared, password_blocklist, telemetry_plan) =
        prepare_runtime_kernel(prepare_serving_local)?;
    Ok(ServingRuntimeInputs::new(
        prepared,
        password_blocklist,
        telemetry_plan,
    ))
}

/// Emit a process-terminal failure through the installed JSON subscriber.
///
/// Preparation failures before subscriber installation use one safe CLI line; a process can
/// therefore emit either pre-runtime CLI text or the versioned JSON stream, never both.
pub fn report_process_error(error: &anyhow::Error) {
    if !telemetry::report_process_error(error) {
        eprintln!("{}", safe_process_error_line(error));
    }
}

fn safe_process_error_line(error: &anyhow::Error) -> String {
    let single_line: String = error
        .to_string()
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    secure::redact_observation_field("process_error", &single_line).to_string()
}

/// Flush the trace exporter when a prepared runtime exits before serving launch.
pub async fn shutdown_runtime(mut runtime_inputs: ServingRuntimeInputs) -> anyhow::Result<()> {
    shutdown_prepared_runtime(runtime_inputs.prepared_mut()).await
}

async fn shutdown_prepared_runtime(
    runtime_inputs: &mut PreparedRuntimeInputs,
) -> anyhow::Result<()> {
    if let Some(trace_export) = runtime_inputs.take_trace_export() {
        trace_export
            .shutdown()
            .await
            .context("shutdown trace exporter")?;
    }
    Ok(())
}

/// Owns resources prepared before startup until the inner startup body moves them into launch.
struct RuntimeLifecycleOwner {
    inputs: ServingRuntimeInputs,
}

impl RuntimeLifecycleOwner {
    fn new(inputs: ServingRuntimeInputs) -> Self {
        Self { inputs }
    }

    async fn run(mut self) -> anyhow::Result<()> {
        let startup_result = run_startup(&mut self.inputs).await;
        self.finish(startup_result).await
    }

    async fn finish(mut self, startup_result: anyhow::Result<()>) -> anyhow::Result<()> {
        let cleanup_result = shutdown_prepared_runtime(self.inputs.prepared_mut()).await;
        match (startup_result, cleanup_result) {
            (Ok(()), cleanup_result) => cleanup_result,
            (Err(startup_error), Ok(())) => Err(startup_error),
            (Err(startup_error), Err(cleanup_error)) => {
                tracing::error!(
                    cleanup_error = %cleanup_error,
                    "runtime startup failed and trace cleanup also failed; preserving startup error"
                );
                Err(startup_error)
            }
        }
    }
}

/// 生产组合根入口：构造共享基础设施 → generated domains → `compose_bindings`
/// → 聚合 readiness/lifecycle outputs → 装配认证接线 → 挂 Health listener
/// → bind + serve + 信号优雅关停。
///
/// 缺配 / 连不上 / migration 失败均 **fail-fast**（不静默 ready）。各域业务 handler ↔ service 接线
/// 由 manifest-derived domain list 驱动，禁止回退为手写 per-domain wiring。
/// tracing subscriber 与配置 snapshot 由 [`prepare_runtime`] 在 `main` 中先于本 fn 装配。
// reason: 组合根入口顺序编排（infra setup → provider setup → generated domains → compose → finalize → serve）
// 多条 tracing 宏展开在 cognitive_complexity 计数贡献额外节点——item-level carve-out（error-handling.md §Carve-out）。
#[allow(clippy::cognitive_complexity)]
pub async fn run(runtime_inputs: ServingRuntimeInputs) -> anyhow::Result<()> {
    RuntimeLifecycleOwner::new(runtime_inputs).run().await
}

async fn run_startup(runtime_inputs: &mut ServingRuntimeInputs) -> anyhow::Result<()> {
    phase::execute(runtime_inputs).await.map(|_| ())
}
