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
pub(crate) use secret_config::EnvSecret;

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

use config::{RuntimeConfigSnapshot, SnapshotConfig};
use std::sync::Arc;

use anyhow::Context as _;
#[cfg(test)]
use crypto::RustCryptoMacVerifier;
use diport::ManagedResource as _;
#[cfg(test)]
use primitives::MacKey;

/// otel OTLP/gRPC 导出端点环境变量（**按需开启**：未设 → 不导出 trace，仅 fmt 日志；设了 → 按 scheme 派发 typed endpoint）。
const OTEL_ENDPOINT_ENV: &str = "RSS_OTEL_ENDPOINT";

/// 从进程配置快照构建可选 otel trace 导出 exporter。
fn build_trace_export(config: SnapshotConfig<'_>) -> anyhow::Result<Option<otel::OtelExporter>> {
    build_trace_export_from_value(config.value(OTEL_ENDPOINT_ENV))
}

/// 从显式原始值构建可选 exporter（纯解析内核，**不**触碰配置源或全局 subscriber）。
///
/// **按需开启**：[`OTEL_ENDPOINT_ENV`] 未设 → `Ok(None)`（仅 fmt 日志，不导出 trace）。设了则按 scheme 派发
/// typed [`otel::OtelEndpoint`]——`https://` → TLS（生产默认）；`http://` → 仅 loopback host 显式明文 opt-in
/// （非 loopback 即 `Err`，零信任 fail-closed）；其它 scheme → `Err`。**fail-fast**：误配在组合根接线期即暴露，
/// 不静默退回 fmt（值非法 ≠ 未配）。Exporter 由 [`run`] 交给 `runtimeexec` 的唯一 shutdown owner 并在关停时 flush。
fn build_trace_export_from_value(raw: Option<&str>) -> anyhow::Result<Option<otel::OtelExporter>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let endpoint = if raw.starts_with("https://") {
        otel::OtelEndpoint::tls(raw).context("RSS_OTEL_ENDPOINT https (TLS) endpoint")?
    } else if raw.starts_with("http://") {
        otel::OtelEndpoint::insecure_localhost(raw)
            .context("RSS_OTEL_ENDPOINT http endpoint must target a loopback host")?
    } else {
        // 错误只含变量名、不含 raw 值（endpoint 可携 userinfo/token，避免明文进启动日志；调试细节经
        // OtelEndpoint::{tls,insecure_localhost} 的 error chain 上层已足够）。
        anyhow::bail!("{OTEL_ENDPOINT_ENV} must be https:// (TLS) or http:// to a loopback host");
    };
    let provider = otel::build_otlp_provider(endpoint).context("build OTLP/gRPC trace provider")?;
    Ok(Some(otel::OtelExporter::new(provider)))
}

fn prepare_local_before_external<Local, External>(
    config: SnapshotConfig<'_>,
    prepare_local: impl FnOnce(SnapshotConfig<'_>) -> anyhow::Result<Local>,
    build_external: impl FnOnce() -> anyhow::Result<External>,
) -> anyhow::Result<(Local, External)> {
    let local = prepare_local(config)?;
    let external = build_external()?;
    Ok((local, external))
}

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
) -> anyhow::Result<(PreparedRuntimeInputs, Local)> {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let runtime_config = RuntimeConfigSnapshot::capture_process_snapshot()
        .context("capture process runtime configuration")?;
    let config = runtime_config.view();
    let (local, trace_export) =
        prepare_local_before_external(config, prepare_local, || build_trace_export(config))?;
    let filter = config
        .value("RUST_LOG")
        .and_then(|raw| EnvFilter::try_new(raw).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));
    let otel_layer = trace_export.as_ref().map(|exporter| exporter.layer());
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(otel_layer)
        .init();
    Ok((
        PreparedRuntimeInputs::new(runtime_config, trace_export),
        local,
    ))
}

/// Prepare serving inputs, sealing the local password policy before any external provider.
///
/// 组合根 binary 入口在 [`run`] **之前**调用——否则运行时入口的全部结构化日志
/// （bind / serve / shutdown / fail-fast）皆为 no-op。`RUST_LOG`、[`OTEL_ENDPOINT_ENV`] 与后续
/// serving consumer 全部来自这个 snapshot，不再读取 ambient environment。密码 blocklist 在
/// snapshot 后立即加载并成为必填 [`ServingRuntimeInputs`] typestate，任何 OTLP/外部 provider 都晚于它。
///
/// Only this type can enter [`run`] or [`shutdown_runtime`].
pub fn prepare_runtime() -> anyhow::Result<ServingRuntimeInputs> {
    let (prepared, password_blocklist) = prepare_runtime_kernel(prepare_serving_local)?;
    ServingRuntimeInputs::from_prepared(prepared, password_blocklist)
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
