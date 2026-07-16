//! runtime — RSS 生产组合根（Root 层，#1309 抽离自 bins 双写）：从配置构造生产验签 provider，按 listener 装配
//! `finalize_routes → finalize_auth → .layer(verify_bridge)` 的认证接线接缝，并驱动运行时入口
//! （tokio 运行时 + per-listener socket bind + `axum::serve` + 信号优雅关停 + generated domain wiring，#1320）。
//!
//! 运行时入口（[`run`]，#1320 Join）：构造 provider bundle → generated domains → `compose_bindings`
//! → 聚合 `DomainModuleResult` → `assemble_authed_routers`
//! → 组合根挂 Health listener（healthz/readyz）→ 逐 listener bind socket + serve（经 `httpd::HttpServer`
//! + `bootstrap::ShutdownStack`）→ SIGTERM/SIGINT 优雅 drain。各域 typed handle 经 Registry 的 route/subscriber
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
mod domains;
pub mod event_transport;
pub mod infra;
pub(crate) mod launch;
pub mod listeners;
pub mod module;
#[path = "generated/modules_gen.rs"]
mod modules_gen;
pub mod phase;
pub mod plan;
mod provider_output;
pub mod routes;
pub mod saga_runtime;

pub use distributed_runtime::{DistributedRuntimeDeps, wire_distributed};
pub use domains::settings::{CONFIGS_READY_PROBE_NAME, ConfigsReadyProbe};
pub use infra::oidc::{build_provider, provider_from_b64};
pub use infra::s3::build_s3_runtime_deps_from;
pub use infra::vault::{
    build_settings_config_value_key_name_from, build_vault_runtime_deps,
    is_oidc_jwks_export_command, run_oidc_jwks_export_command,
};
pub use settings_composition::KEYPROVIDER_READY_PROBE_NAME;

/// Explicit integration-only seams for exercising typed domain wiring with hermetic providers.
///
/// Production callers cannot reach the concrete domain constructors; live assembly always enters
/// through the committed generated module list.
#[cfg(feature = "integration")]
pub mod test_support {
    use super::{DistributedRuntimeDeps, SharedRuntimeDeps};

    /// Builds the production Redis capability bundle from explicit integration-test values.
    ///
    /// The default production API exposes only the snapshot-backed typed constructor; this seam is
    /// compiled solely for the container-backed integration lane.
    pub async fn build_redis_runtime_deps_from_values(
        url: String,
        allow_plaintext: Option<&str>,
    ) -> anyhow::Result<redis::RedisRuntimeDeps> {
        crate::infra::redis::build_redis_runtime_deps_from_values(url, allow_plaintext).await
    }

    /// Wires the production event transport through an integration-only seam.
    pub async fn wire_event_transport(
        pg: &postgres::PgRuntimeHandle,
        distributed: DistributedRuntimeDeps,
        subscribers: Vec<crate::event_transport::BridgedSubscription>,
        cfg: crate::event_transport::EventTransportConfig,
    ) -> anyhow::Result<bootstrap::DomainModuleResult> {
        crate::event_transport::wire_event_transport(pg, distributed, subscribers, cfg).await
    }

    /// Builds the settings binding for container-backed integration tests.
    pub async fn wire_settings(
        deps: &SharedRuntimeDeps,
    ) -> anyhow::Result<bootstrap::DomainBinding> {
        crate::domains::settings::integration_binding(deps).await
    }

    /// Builds the identity binding with a hermetic configuration source for integration tests.
    pub fn wire_identity_with(
        deps: &SharedRuntimeDeps,
        get: impl Fn(&str) -> Option<String>,
        vault_allow_http: bool,
    ) -> anyhow::Result<bootstrap::DomainBinding> {
        crate::domains::identity::wire_identity_with(deps, get, vault_allow_http)
    }
}
pub use module::SharedRuntimeDeps;

use bootstrap::DomainModuleResult;
use infra::oidc::{
    OIDC_JWKS_READY_PROBE_NAME, OidcJwksReadyProbe, build_provider_with_replay_guard,
    build_runtime_oidc_provider,
};
use infra::pg::{
    PgRuntimeConfig, PgRuntimeConfigParts, build_pg_audit_maintenance_config,
    build_pg_migrator_config,
};
use infra::redis::{
    REDIS_READY_PROBE_NAME, RedisReadyProbe, RedisRuntimeConfig, build_redis_runtime_deps,
    spawn_redis_readiness_sampler,
};
use infra::s3::{build_s3_canary_config_from, build_s3_dlx_archive_store_from, wire_s3_canary};
use infra::vault::build_vault_key_provider_from;
use phase::{RuntimeInputs, RuntimeOutputs, RuntimePhase, phase_result};

#[cfg(test)]
use config::DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV;
use config::{
    EnvConfigSource, RuntimeConfigSnapshot, SnapshotConfig, domain_transport_mtls_allow_set_env,
    domain_transport_required_domains_from, domain_transport_url_env,
};

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use audit::ports::{AuditAdminRepo as _, AuditLedgerVerifyReport};
use base64::Engine as _;
use consistency::{EngineErrorKind, IdemKey, ProjectionBatchLimit, SerialInOrder};
#[cfg(test)]
use crypto::RustCryptoMacVerifier;
use diport::{
    DynKeyProvider, DynManagedResource, KeyProvider, ManagedResource, RedactedBytes, ShutdownError,
};
use eventexec::{
    DeadLetterId, DlqCursor, DlqEntrySummary, DlqInspectRequest, DlqInspectTarget, DlqListQuery,
    DlqRedriveOutcome, DlqRedriveRequest, DlqReplayRequest, DlqStore, OperatorDlqCapability,
    OperatorReconcileCapability, OutboxExpiredResolutionKind, OutboxExpiredResolutionOutcome,
    OutboxExpiredResolutionRequest, OutboxResolutionChangeTicket, ProjectionHarness, ProjectionId,
    ProjectionReplayProjector, ProjectionSelector, ProjectionStop, ProjectionTargetRegistry,
    ProjectionVersion, ReconcileOperatorStore, ReconcileTargetSummary, VerifiedOperatorSubject,
    projection_runner_once,
};
use postgres::{
    ConfigValueMaintenanceCapability, ConfigValueMaintenanceOperation,
    ConfigValueMaintenanceOptions, ConfigValueProtection, MaintenanceAuditOutcome, PgDlqStore,
    PgDlxLifecycleRuntime, PgMaintenanceDeps, PgReconcileStore, PgRuntimeDeps, PgRuntimeHandle,
    ProjectionPointerPrecondition, caps,
};
#[cfg(test)]
use primitives::MacKey;
use primitives::{HealthCheck, HealthStatus, ProbeName};
use tokio_util::sync::CancellationToken;

/// SPIFFE Workload API endpoint env var consumed by the upstream `spiffe` source.
const SPIFFE_ENDPOINT_SOCKET_ENV: &str = "SPIFFE_ENDPOINT_SOCKET";
/// Shared remote domain transport endpoint fallback (`durable-shared` only).
const DOMAIN_TRANSPORT_SHARED_URL_ENV: &str = "RSS_DOMAIN_TRANSPORT_URL";
/// Local workload SPIFFE ID expected from the outbound SPIRE source.
const DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV: &str = "RSS_DOMAIN_TRANSPORT_MTLS_LOCAL_SPIFFE_ID";

/// Composition-root validation wrapper around the shared zeroizing secret carrier. Selected
/// credentials transfer the same `String` allocation to the provider's own secret owner.
#[derive(secure::Redact)]
pub(crate) struct EnvSecret(#[redact(sensitivity = secret)] secure::SecretText);

impl EnvSecret {
    pub(crate) fn required(
        get: &impl Fn(&str) -> Option<String>,
        name: &'static str,
    ) -> anyhow::Result<Self> {
        let value = get(name).ok_or_else(|| anyhow::anyhow!("missing required env var: {name}"))?;
        anyhow::ensure!(!value.is_empty(), "{name} must not be empty");
        anyhow::ensure!(
            value.trim() == value,
            "{name} must not have leading or trailing whitespace"
        );
        Ok(Self(secure::SecretText::from_string(value)))
    }

    pub(crate) fn optional(
        get: &impl Fn(&str) -> Option<String>,
        name: &'static str,
    ) -> anyhow::Result<Option<Self>> {
        get(name)
            .map(|value| {
                anyhow::ensure!(!value.is_empty(), "{name} must not be empty");
                anyhow::ensure!(
                    value.trim() == value,
                    "{name} must not have leading or trailing whitespace"
                );
                Ok(Self(secure::SecretText::from_string(value)))
            })
            .transpose()
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.expose()
    }

    pub(crate) fn transfer_secret_allocation(self) -> String {
        self.0.into_string()
    }
}
/// 生产系统时钟（组合根注入 `OidcProvider`）。
///
/// 组合根是 sanctioned 直读系统时钟点（`diport::Clock` rustdoc：「prod `SystemClock` 内部调 `SystemTime::now`，
/// 受 clippy `disallowed_methods` 约束、仅在 adapter / 组合根 item-level 解禁」）。
pub struct SystemClock;

impl diport::Clock for SystemClock {
    fn now(&self) -> SystemTime {
        // reason: 组合根生产时钟——唯一 sanctioned 直读系统时钟点（rust-standards「Clock 构造器位置参」的 prod 实现）。
        #[allow(clippy::disallowed_methods)]
        SystemTime::now()
    }
}

/// Fully parsed, independent DLX lifecycle dependencies that do not require external I/O.
/// Startup capability probes consume this bundle only after every credential and key boundary has
/// passed fail-fast validation.
struct DlxLifecycleBootstrapConfig {
    archiver_pg: postgres::PgConfig,
    verifier_pg: postgres::PgConfig,
    purger_pg: postgres::PgConfig,
    archive_store: s3::S3DlxArchiveStore,
    hot_vault_provider: vault::VaultKeyProvider,
    archive_vault_provider: vault::VaultKeyProvider,
    hot_key: eventexec::DlxHotKeyName,
    archive_key: eventexec::DlxArchiveKeyName,
}

async fn build_dlx_lifecycle_bootstrap_config_from(
    archiver_pg: postgres::PgConfig,
    verifier_pg: postgres::PgConfig,
    purger_pg: postgres::PgConfig,
    get: impl Fn(&str) -> Option<String>,
    clock: Arc<dyn diport::Clock>,
) -> anyhow::Result<DlxLifecycleBootstrapConfig> {
    let archive_key = event_transport::build_dlx_archive_key_name_from(&get)
        .context("build DLX archive key name")?;
    let hot_key = eventexec::DlxHotKeyName::try_new(
        get("RSS_DLX_PAYLOAD_KEY_NAME")
            .context("missing required env var: RSS_DLX_PAYLOAD_KEY_NAME")?,
    )
    .context("RSS_DLX_PAYLOAD_KEY_NAME is invalid")?;
    let (hot_vault_provider, archive_vault_provider) =
        event_transport::build_dlx_vault_key_providers_from(&get)
            .context("build independent DLX Vault key providers")?;
    let archive_store = build_s3_dlx_archive_store_from(&get, clock)
        .await
        .context("build DLX archive S3 store")?;
    Ok(DlxLifecycleBootstrapConfig {
        archiver_pg,
        verifier_pg,
        purger_pg,
        archive_store,
        hot_vault_provider,
        archive_vault_provider,
        hot_key,
        archive_key,
    })
}

async fn verify_dlx_vault_key_capability(
    provider: &vault::VaultKeyProvider,
    key: &diport::KeyName,
    coordinate: &'static str,
) -> anyhow::Result<()> {
    const CANARY_TENANT: &str = "00000000-0000-4000-8000-000000001168";
    const CANARY_PLAINTEXT: &[u8] = b"rss-dlx-vault-capability-v1";
    let tenant = vocab::TenantId::parse(CANARY_TENANT).context("parse DLX canary tenant")?;
    let aad =
        secure::ProtectionContext::authorized_maintenance(tenant, coordinate, "startup-canary", 1)
            .context("derive DLX Vault canary AAD")?
            .derive();
    let wrong_aad = secure::ProtectionContext::authorized_maintenance(
        tenant,
        coordinate,
        "startup-canary-wrong-aad",
        1,
    )
    .context("derive DLX Vault wrong-AAD canary")?
    .derive();
    let encrypted = provider
        .encrypt(
            key.clone(),
            secure::Plaintext::new(CANARY_PLAINTEXT.to_vec()),
            aad.clone(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("DLX Vault capability encrypt failed"))?;
    let ciphertext = encrypted.ciphertext().to_vec();
    let key_ref = encrypted.key().clone();
    let opened = provider
        .decrypt(RedactedBytes::new(ciphertext.clone()), key_ref.clone(), aad)
        .await
        .map_err(|_| anyhow::anyhow!("DLX Vault capability decrypt failed"))?;
    anyhow::ensure!(
        opened.expose() == CANARY_PLAINTEXT,
        "DLX Vault capability plaintext mismatch"
    );
    anyhow::ensure!(
        provider
            .decrypt(RedactedBytes::new(ciphertext), key_ref, wrong_aad)
            .await
            .is_err(),
        "DLX Vault capability accepted wrong AAD"
    );
    Ok(())
}

#[derive(Default)]
pub(crate) struct RuntimeServiceTokenReplayGuard {
    seen: Mutex<HashMap<String, SystemTime>>,
}

impl diport::ServiceTokenReplayGuard for RuntimeServiceTokenReplayGuard {
    fn check_and_record(
        &self,
        nonce: &str,
        expires_at: SystemTime,
    ) -> Result<(), diport::ServiceTokenReplayError> {
        // reason: runtime assembly owns this in-process fallback guard; production clock read is local to
        // replay-state expiry pruning and does not leak into domain logic.
        #[allow(clippy::disallowed_methods)]
        let now = SystemTime::now();
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| diport::ServiceTokenReplayError::Guard)?;
        seen.retain(|_, expires_at| *expires_at > now);
        if seen.contains_key(nonce) {
            return Err(diport::ServiceTokenReplayError::Replayed);
        }
        seen.insert(nonce.to_string(), expires_at);
        Ok(())
    }
}

/// Test/lightweight auth decision audit sink provider.
///
/// Production uses `postgres::PgAuthAuditSink` through `PgRuntimeDeps`; this provider exists for unit tests and
/// non-production assembly checks where no durable store is available.
#[derive(Clone, Default)]
pub struct TracingAuthAuditSink;

impl diport::AuditSink for TracingAuthAuditSink {
    async fn record(&self, event: diport::AuditEvent) -> Result<(), diport::AuditSinkError> {
        let outcome = match event.outcome {
            diport::AuditOutcome::Success => "success",
            diport::AuditOutcome::Failure { reason } => reason,
            _ => "unknown",
        };
        tracing::info!(
            audit.action = event.action,
            audit.outcome = outcome,
            resource.kind = event.resource_kind,
            principal.kind = ?event.principal_kind,
            "http auth audit event"
        );
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), diport::AuditSinkError> {
        Ok(())
    }
}

#[cfg(test)]
impl audit::ports::AuditListTenantAppender for TracingAuthAuditSink {
    async fn append(
        &self,
        command: audit::ports::AuditListTenantAppend,
    ) -> Result<(), diport::AuditSinkError> {
        let (scope, event, _observation) = command.into_parts();
        debug_assert_eq!(event.tenant_id, Some(scope.tenant()));
        diport::AuditSink::record(self, event).await
    }
}

/// 从 `std::env` 构造 [`event_transport::EventTransportConfig`]。
pub fn build_event_transport_config() -> anyhow::Result<event_transport::EventTransportConfig> {
    event_transport::build_event_transport_config_from(|name| std::env::var(name).ok())
}

fn topology_label(topology: bootstrap::Topology) -> &'static str {
    match topology {
        bootstrap::Topology::Demo => "demo",
        bootstrap::Topology::DurableShared => "durable-shared",
        bootstrap::Topology::DurableIsolated => "durable-isolated",
        _ => "unknown",
    }
}

fn domain_transport_config_from(
    required_domains: &[String],
    get: &impl Fn(&str) -> Option<String>,
) -> bootstrap::DomainTransportConfig {
    let mut per_domain = BTreeMap::new();
    for domain in required_domains {
        let env = domain_transport_url_env(domain);
        if let Some(url) = get(&env) {
            per_domain.insert(domain.clone(), bootstrap::DomainTransportUrl::new(url));
        }
    }
    let shared = get(DOMAIN_TRANSPORT_SHARED_URL_ENV).map(bootstrap::DomainTransportUrl::new);
    bootstrap::DomainTransportConfig::new(per_domain, shared)
}

fn outbound_mtls_policy_for_domain_from(
    domain: &str,
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<authn::OutboundMtlsPolicy> {
    let local_raw = get(DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV).ok_or_else(|| {
        anyhow::anyhow!("missing required env var: {DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV}")
    })?;
    let local = authn::SpiffeId::parse(local_raw.trim())
        .map_err(|e| anyhow::anyhow!("{DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV} invalid: {e}"))?;
    let allow_env = domain_transport_mtls_allow_set_env(domain);
    let raw_allow_set =
        get(&allow_env).ok_or_else(|| anyhow::anyhow!("missing required env var: {allow_env}"))?;
    let server_allow_set = routes::mtls_allow_set_from_csv_for_env(&raw_allow_set, &allow_env)?;
    let trust_domain_names = server_allow_set
        .iter()
        .map(|id| id.trust_domain().as_str().to_owned())
        .collect::<Vec<_>>();
    let trust_domains = authn::MtlsTrustDomainAllowSet::new(trust_domain_names)
        .map_err(|e| anyhow::anyhow!("{allow_env} trust domains invalid: {e}"))?;
    authn::OutboundMtlsPolicy::new(local, server_allow_set, trust_domains)
        .map_err(|e| anyhow::anyhow!("{allow_env} outbound mTLS policy invalid: {e}"))
}

fn build_domain_transport_targets_from(
    topology: bootstrap::Topology,
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Vec<httpd::DomainHttpTargetConfig>> {
    let required_domains = domain_transport_required_domains_from(&get)?;
    let cfg = domain_transport_config_from(&required_domains, &get);
    let required_refs = required_domains
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let resolved = bootstrap::domaintransport::resolve(topology, cfg, &required_refs)
        .context("resolve domain transport topology")?;
    let bootstrap::ResolvedDomainTransport::Remote { per_domain } = resolved else {
        return Ok(Vec::new());
    };
    let mut targets = Vec::with_capacity(per_domain.len());
    for (domain, url) in per_domain {
        let policy = outbound_mtls_policy_for_domain_from(&domain, &get)?;
        targets.push(
            httpd::DomainHttpTargetConfig::new(&domain, url.expose(), policy)
                .with_context(|| format!("build outbound domain transport target {domain}"))?,
        );
    }
    Ok(targets)
}

trait RuntimeDomainTransport:
    distributed::DomainTransport + ManagedResource + Clone + Send + Sync + 'static
{
    fn readiness(&self) -> httpd::DomainHttpReadiness;
}

impl RuntimeDomainTransport for httpd::SharedDomainHttpTransport {
    fn readiness(&self) -> httpd::DomainHttpReadiness {
        httpd::SharedDomainHttpTransport::readiness(self)
    }
}

struct DomainTransportRuntime<T> {
    transport: T,
}

impl<T> DomainTransportRuntime<T>
where
    T: RuntimeDomainTransport,
{
    fn new(transport: T) -> Self {
        Self { transport }
    }

    fn dispatch_handle(&self) -> Arc<dyn distributed::DomainTransport> {
        Arc::new(distributed::InstrumentedDomainTransport::new(
            self.transport.clone(),
            distributed::TransportMode::Remote,
            Box::new(SystemClock),
        ))
    }

    fn module_result(&self) -> anyhow::Result<DomainModuleResult> {
        let probe_name = ProbeName::parse(DOMAIN_TRANSPORT_READY_PROBE_NAME)
            .context("parse domain_transport_ready probe name")?;
        Ok(DomainModuleResult {
            probes: vec![(
                probe_name,
                Box::new(DomainTransportReadyProbe::new(self.transport.clone())),
            )],
            resources: vec![DynManagedResource::new_box(self.transport.clone())],
            workers: Vec::new(),
        })
    }
}

pub const DOMAIN_TRANSPORT_READY_PROBE_NAME: &str = "domain_transport_ready";

struct DomainTransportReadyProbe<T> {
    transport: T,
    name: ProbeName,
}

impl<T> DomainTransportReadyProbe<T>
where
    T: RuntimeDomainTransport,
{
    #[allow(clippy::expect_used)]
    fn new(transport: T) -> Self {
        let name =
            ProbeName::parse(DOMAIN_TRANSPORT_READY_PROBE_NAME).expect("valid probe name const");
        Self { transport, name }
    }
}

impl<T> bootstrap::HealthProbe for DomainTransportReadyProbe<T>
where
    T: RuntimeDomainTransport,
{
    fn check(&self) -> HealthCheck {
        let readiness = self.transport.readiness();
        let status = if readiness.is_ready() {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy
        };
        HealthCheck::new(self.name.clone(), status, readiness.detail())
    }
}

async fn wire_domain_transport_from(
    topology: bootstrap::Topology,
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<DomainTransportRuntime<httpd::SharedDomainHttpTransport>> {
    let targets = build_domain_transport_targets_from(topology, &get)?;
    anyhow::ensure!(
        !targets.is_empty(),
        "outbound domain transport must resolve remote targets"
    );
    let endpoint = get(SPIFFE_ENDPOINT_SOCKET_ENV);
    let transport = httpd::DomainHttpTransport::from_spire(targets, endpoint.as_deref())
        .await
        .with_context(|| {
            format!(
                "build outbound domain transport mTLS client ({} optional override)",
                SPIFFE_ENDPOINT_SOCKET_ENV
            )
        })?;
    Ok(DomainTransportRuntime::new(
        httpd::SharedDomainHttpTransport::new(transport),
    ))
}

// ── Session expiry sweeper helper ─────────────────────────────────────────────────────────────

const SESSION_SWEEP_INTERVAL_ENV: &str = "RSS_SESSION_SWEEP_INTERVAL_MS";
const DEFAULT_SESSION_SWEEP_INTERVAL_MS: u64 = 300_000;
const MIN_SESSION_SWEEP_INTERVAL_MS: u64 = 1_000;
const DEFAULT_SESSION_SWEEP_INTERVAL: Duration =
    Duration::from_millis(DEFAULT_SESSION_SWEEP_INTERVAL_MS);
pub const SESSION_SWEEPER_PROBE_NAME: &str = "session_sweeper";
const SESSION_SWEEPER_WORKER_NAME: &str = "session-sweeper";

/// sessions 过期清理周期（env `RSS_SESSION_SWEEP_INTERVAL_MS`）。
///
/// 未配置取默认 5 分钟；显式配置解析失败或小于 1 秒时 warn + 默认，避免误配导致热 DELETE 循环。
pub(crate) fn build_session_sweeper_interval_from(
    get: impl Fn(&str) -> Option<String>,
) -> Duration {
    match get(SESSION_SWEEP_INTERVAL_ENV) {
        None => DEFAULT_SESSION_SWEEP_INTERVAL,
        Some(raw) => match raw.trim().parse::<u64>() {
            Ok(ms) if ms >= MIN_SESSION_SWEEP_INTERVAL_MS => Duration::from_millis(ms),
            _ => {
                tracing::warn!(
                    env = SESSION_SWEEP_INTERVAL_ENV,
                    raw = %raw,
                    default_ms = DEFAULT_SESSION_SWEEP_INTERVAL_MS,
                    min_ms = MIN_SESSION_SWEEP_INTERVAL_MS,
                    "invalid session sweep interval (expected u64 ms >= 1000); using default"
                );
                DEFAULT_SESSION_SWEEP_INTERVAL
            }
        },
    }
}

fn build_session_sweeper_interval() -> Duration {
    build_session_sweeper_interval_from(|name| std::env::var(name).ok())
}

/// `rss` binary 是否请求 PostgreSQL operator namespace；具体 subcommand 由 runner 精确校验。
#[must_use]
pub fn is_postgres_command(args: &[String]) -> bool {
    matches!(args, [namespace, ..] if namespace == "postgres")
}

/// Run the release-only reader-lane migration without constructing serving pools or requiring
/// reader credentials. The postgres adapter independently verifies the exact embedded/ledger edge.
pub async fn run_postgres_reader_migration_command(
    args: &[String],
    runtime_inputs: &RuntimeInputs,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(args, [namespace, command] if namespace == "postgres" && command == "migrate-reader-lane"),
        "usage: rss postgres migrate-reader-lane"
    );
    PgRuntimeDeps::migrate_reader_lane_only(&build_pg_migrator_config(runtime_inputs.config())?)
        .await
        .context("apply exact postgres 0066 to 0067 reader-lane migration")
}

/// `rss` binary 是否请求 settings ConfigValue 维护命令。
#[must_use]
pub fn is_settings_config_value_maintenance_command(args: &[String]) -> bool {
    matches!(
        args,
        [cmd, sub, ..] if cmd == "settings-config-values" && sub == "maintenance"
    )
}

fn parse_config_value_maintenance_operation(
    raw: &str,
) -> anyhow::Result<ConfigValueMaintenanceOperation> {
    match raw {
        "backfill" => Ok(ConfigValueMaintenanceOperation::Backfill),
        "rewrap" => Ok(ConfigValueMaintenanceOperation::Rewrap),
        "both" => Ok(ConfigValueMaintenanceOperation::Both),
        other => anyhow::bail!(
            "unknown settings config value maintenance operation: {other}; expected backfill|rewrap|both"
        ),
    }
}

fn parse_positive_usize(raw: &str, flag: &str) -> anyhow::Result<usize> {
    let value = raw
        .parse::<usize>()
        .with_context(|| format!("{flag} must be a positive integer"))?;
    anyhow::ensure!(value > 0, "{flag} must be greater than zero");
    Ok(value)
}

/// `rss` binary 是否请求 projection replay / shadow-swap 控制命令。
#[must_use]
pub fn is_projection_command(args: &[String]) -> bool {
    matches!(args, [cmd, ..] if cmd == "projections")
}

const PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV: &str =
    "RSS_PROJECTION_MAINTENANCE_OPERATOR_GRANTS";
const COMMAND_IDEMPOTENCY_KEYS_ENV: &str = "RSS_COMMAND_IDEMPOTENCY_KEYS_JSON";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandAliasKeyConfig {
    id: String,
    key: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandIdempotencyKeyringConfig {
    current: CommandAliasKeyConfig,
    #[serde(default)]
    previous: Vec<CommandAliasKeyConfig>,
}

fn build_command_idempotency_keyring_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Arc<eventexec::command::CommandIdempotencyKeyring>> {
    let raw = get(COMMAND_IDEMPOTENCY_KEYS_ENV).ok_or_else(|| {
        anyhow::anyhow!("missing required env var: {COMMAND_IDEMPOTENCY_KEYS_ENV}")
    })?;
    let config: CommandIdempotencyKeyringConfig = serde_json::from_str(&raw)
        .with_context(|| format!("{COMMAND_IDEMPOTENCY_KEYS_ENV} must be valid keyring JSON"))?;
    let decode = |encoded: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .with_context(|| {
                format!("{COMMAND_IDEMPOTENCY_KEYS_ENV} keys must be base64url no-pad")
            })
    };
    let current_bytes = decode(&config.current.key)?;
    let previous_bytes = config
        .previous
        .iter()
        .map(|key| decode(&key.key))
        .collect::<anyhow::Result<Vec<_>>>()?;
    for reserved_env in [
        "RSS_TENANT_AUTHORITY_HMAC_KEY_B64URL",
        "RSS_AUDIT_CHAIN_KEY_B64URL",
    ] {
        let Some(reserved) = get(reserved_env) else {
            continue;
        };
        let Ok(reserved) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(reserved.trim())
        else {
            continue;
        };
        anyhow::ensure!(
            current_bytes != reserved && previous_bytes.iter().all(|key| key != &reserved),
            "{COMMAND_IDEMPOTENCY_KEYS_ENV} must not reuse {reserved_env} key material"
        );
    }

    let current = eventexec::command::CommandAliasKey::new(config.current.id, current_bytes)?;
    let previous = config
        .previous
        .into_iter()
        .zip(previous_bytes)
        .map(|(config, key)| eventexec::command::CommandAliasKey::new(config.id, key))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Arc::new(
        eventexec::command::CommandIdempotencyKeyring::new(current, previous)?,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectionCliArgs {
    selector: ProjectionSelector,
    command: ProjectionCliCommand,
    operator_service_token: String,
    operator_tenant: vocab::TenantId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProjectionCliCommand {
    Replay {
        batch_limit: ProjectionBatchLimit,
    },
    Status,
    Swap {
        precondition: ProjectionPointerPrecondition,
    },
}

impl ProjectionCliCommand {
    fn action(&self) -> ProjectionMaintenanceAction {
        match self {
            Self::Replay { .. } => ProjectionMaintenanceAction::Replay,
            Self::Status => ProjectionMaintenanceAction::Status,
            Self::Swap { .. } => ProjectionMaintenanceAction::Swap,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionMaintenanceAction {
    Replay,
    Status,
    Swap,
}

impl ProjectionMaintenanceAction {
    fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw {
            "replay" => Ok(Self::Replay),
            "status" => Ok(Self::Status),
            "swap" => Ok(Self::Swap),
            other => anyhow::bail!(
                "unknown projection maintenance action in {PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV}: {other}"
            ),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Replay => "replay",
            Self::Status => "status",
            Self::Swap => "swap",
        }
    }

    fn authorized_action(self) -> authn::ProjectionMaintenanceAction {
        match self {
            Self::Replay => authn::ProjectionMaintenanceAction::Replay,
            Self::Status => authn::ProjectionMaintenanceAction::Status,
            Self::Swap => authn::ProjectionMaintenanceAction::Swap,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProjectionSwapPreconditionArg {
    ExpectUnset,
    ExpectedActiveVersion(ProjectionVersion),
}

fn parse_projection_batch_limit(raw: &str) -> anyhow::Result<ProjectionBatchLimit> {
    let raw = parse_positive_usize(raw, "--batch-size")?;
    let raw = u32::try_from(raw).context("--batch-size exceeds u32")?;
    ProjectionBatchLimit::new(raw).context("--batch-size is outside projection batch bounds")
}

fn projection_cli_usage() -> &'static str {
    "usage: rss projections replay|status|swap --operator-service-token <token> --operator-tenant <uuid> --tenant <uuid> --projection <id> --version <id> [--batch-size <n>] [--expected-active-version <id>|--expect-unset]"
}

fn set_cli_arg_once<T>(slot: &mut Option<T>, flag: &str, value: T) -> anyhow::Result<()> {
    anyhow::ensure!(slot.is_none(), "{flag} must not be repeated");
    *slot = Some(value);
    Ok(())
}

fn next_cli_value<'a>(
    it: &mut std::slice::Iter<'a, String>,
    flag: &str,
) -> anyhow::Result<&'a str> {
    it.next()
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}

fn parse_projection_args(args: &[String]) -> anyhow::Result<ProjectionCliArgs> {
    anyhow::ensure!(is_projection_command(args), projection_cli_usage());
    let subcommand = args
        .get(1)
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!(projection_cli_usage()))?;
    anyhow::ensure!(
        matches!(subcommand, "replay" | "status" | "swap"),
        "unknown projection subcommand: {subcommand}; {}",
        projection_cli_usage()
    );
    let mut operator_service_token = None;
    let mut operator_tenant = None;
    let mut tenant = None;
    let mut projection = None;
    let mut version = None;
    let mut batch_limit = ProjectionBatchLimit::MAX;
    let mut batch_limit_seen = false;
    let mut precondition = None;

    let mut it = args[2..].iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--operator-service-token" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--operator-service-token requires a value"))?;
                let trimmed = raw.trim();
                anyhow::ensure!(
                    !trimmed.is_empty(),
                    "--operator-service-token must be non-empty"
                );
                set_cli_arg_once(
                    &mut operator_service_token,
                    "--operator-service-token",
                    trimmed.to_owned(),
                )?;
            }
            "--operator-tenant" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--operator-tenant requires a value"))?;
                let parsed = vocab::TenantId::parse(raw)
                    .with_context(|| format!("--operator-tenant must be a tenant UUID: {raw}"))?;
                set_cli_arg_once(&mut operator_tenant, "--operator-tenant", parsed)?;
            }
            "--tenant" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--tenant requires a value"))?;
                let parsed = vocab::TenantId::parse(raw)
                    .with_context(|| format!("--tenant must be a tenant UUID: {raw}"))?;
                set_cli_arg_once(&mut tenant, "--tenant", parsed)?;
            }
            "--projection" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--projection requires a value"))?;
                let parsed = ProjectionId::parse(raw)
                    .with_context(|| format!("--projection must be canonical: {raw}"))?;
                set_cli_arg_once(&mut projection, "--projection", parsed)?;
            }
            "--version" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--version requires a value"))?;
                let parsed = ProjectionVersion::parse(raw)
                    .with_context(|| format!("--version must be canonical: {raw}"))?;
                set_cli_arg_once(&mut version, "--version", parsed)?;
            }
            "--batch-size" => {
                anyhow::ensure!(!batch_limit_seen, "--batch-size must not be repeated");
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--batch-size requires a value"))?;
                batch_limit = parse_projection_batch_limit(raw)?;
                batch_limit_seen = true;
            }
            "--expected-active-version" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--expected-active-version requires a value"))?;
                let expected = ProjectionVersion::parse(raw).with_context(|| {
                    format!("--expected-active-version must be canonical: {raw}")
                })?;
                anyhow::ensure!(
                    precondition.is_none(),
                    "swap requires exactly one active-version precondition"
                );
                precondition = Some(ProjectionSwapPreconditionArg::ExpectedActiveVersion(
                    expected,
                ));
            }
            "--expect-unset" => {
                anyhow::ensure!(
                    precondition.is_none(),
                    "swap requires exactly one active-version precondition"
                );
                precondition = Some(ProjectionSwapPreconditionArg::ExpectUnset);
            }
            other => anyhow::bail!("unknown projection command argument: {other}"),
        }
    }

    let selector = ProjectionSelector::new(
        tenant.ok_or_else(|| anyhow::anyhow!("--tenant is required"))?,
        projection.ok_or_else(|| anyhow::anyhow!("--projection is required"))?,
        version.ok_or_else(|| anyhow::anyhow!("--version is required"))?,
    );
    let command = match subcommand {
        "replay" => {
            anyhow::ensure!(
                precondition.is_none(),
                "replay does not accept active-version preconditions"
            );
            ProjectionCliCommand::Replay { batch_limit }
        }
        "status" => {
            anyhow::ensure!(!batch_limit_seen, "status does not accept --batch-size");
            anyhow::ensure!(
                precondition.is_none(),
                "status does not accept active-version preconditions"
            );
            ProjectionCliCommand::Status
        }
        "swap" => {
            anyhow::ensure!(!batch_limit_seen, "swap does not accept --batch-size");
            let precondition = match precondition.ok_or_else(|| {
                anyhow::anyhow!("swap requires exactly one active-version precondition")
            })? {
                ProjectionSwapPreconditionArg::ExpectUnset => {
                    ProjectionPointerPrecondition::ExpectUnset
                }
                ProjectionSwapPreconditionArg::ExpectedActiveVersion(version) => {
                    ProjectionPointerPrecondition::ExpectedActiveVersion(version)
                }
            };
            ProjectionCliCommand::Swap { precondition }
        }
        _ => unreachable!("is_projection_command restricts subcommands"),
    };
    Ok(ProjectionCliArgs {
        selector,
        command,
        operator_service_token: operator_service_token
            .ok_or_else(|| anyhow::anyhow!("--operator-service-token is required"))?,
        operator_tenant: operator_tenant
            .ok_or_else(|| anyhow::anyhow!("--operator-tenant is required"))?,
    })
}

fn build_projection_target_registry() -> anyhow::Result<ProjectionTargetRegistry> {
    let mut registry =
        ProjectionTargetRegistry::from_generated(generated::event::PROJECTION_INPUTS)
            .context("build generated projection target registry")?;
    anyhow::ensure!(
        !registry.is_empty(),
        "no generated projection inputs compiled into this runtime"
    );
    registry.mark_all_generated_unsupported();
    registry
        .validate_coverage()
        .context("validate generated projection target registry coverage")?;
    Ok(registry)
}

fn projection_command_requires_registered_target(command: &ProjectionCliCommand) -> bool {
    matches!(
        command,
        ProjectionCliCommand::Replay { .. } | ProjectionCliCommand::Swap { .. }
    )
}

fn ensure_projection_command_supported_by_registry(
    registry: &ProjectionTargetRegistry,
    command: &ProjectionCliCommand,
) -> anyhow::Result<()> {
    if projection_command_requires_registered_target(command) {
        anyhow::ensure!(
            registry.has_registered_targets(),
            "no registered projection targets compiled into this runtime"
        );
    }
    Ok(())
}

fn projection_command_resource_id(parsed: &ProjectionCliArgs) -> String {
    format!(
        "operation={} tenant={} projection={} version={}",
        parsed.command.action().as_str(),
        parsed.selector.tenant(),
        parsed.selector.projection().as_str(),
        parsed.selector.version().as_str()
    )
}

async fn verified_service_maintenance_operator_subject(
    service_token: &str,
    operator_tenant: vocab::TenantId,
    pdp: &diport::DynPdp<'_>,
    maintenance_context: &str,
) -> anyhow::Result<String> {
    let (_token, principal) = authn::verify_service_token(
        service_token,
        diport::ServiceTokenTenantBinding::new(operator_tenant),
        pdp,
    )
    .await
    .with_context(|| format!("verify {maintenance_context} operator service token"))?;
    anyhow::ensure!(
        principal.kind() == vocab::PrincipalKind::Service,
        "{maintenance_context} operator must be a service principal"
    );
    Ok(principal.audit_subject().to_owned())
}

async fn verified_projection_maintenance_operator_subject(
    service_token: &str,
    operator_tenant: vocab::TenantId,
    pdp: &diport::DynPdp<'_>,
) -> anyhow::Result<authn::Principal> {
    let (_token, principal) = authn::verify_service_token(
        service_token,
        diport::ServiceTokenTenantBinding::new(operator_tenant),
        pdp,
    )
    .await
    .context("verify projection maintenance operator service token")?;
    anyhow::ensure!(
        principal.kind() == vocab::PrincipalKind::Service,
        "projection maintenance operator must be a service principal"
    );
    Ok(principal)
}

async fn record_projection_maintenance_finish_audit(
    pg: &PgMaintenanceDeps,
    operator_subject: &str,
    action: &str,
    resource_id: &str,
    outcome: MaintenanceAuditOutcome<'_>,
) -> anyhow::Result<()> {
    pg.record_projection_maintenance_audit(operator_subject, action, outcome, resource_id)
        .await
        .context("record projection maintenance finish audit")
}

const UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR: &str = "unverified-service-token";

fn parse_projection_maintenance_grants(
    raw: &str,
) -> anyhow::Result<authn::ProjectionMaintenanceGrantSet> {
    let raw = raw.trim();
    anyhow::ensure!(
        !raw.is_empty(),
        "{PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV} must not be empty"
    );
    let mut grants = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        anyhow::ensure!(
            !entry.is_empty(),
            "{PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV} must not contain empty entries"
        );
        let parts: Vec<&str> = entry.split('|').map(str::trim).collect();
        anyhow::ensure!(
            parts.len() == 4,
            "{PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV} entries must be subject|action|tenant|projection"
        );
        let [subject, action, tenant, projection] = parts.as_slice() else {
            unreachable!("len checked");
        };
        anyhow::ensure!(
            !subject.is_empty(),
            "{PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV} subject must be non-empty"
        );
        let action = ProjectionMaintenanceAction::parse(action)?.authorized_action();
        let tenant = vocab::TenantId::parse(tenant).with_context(|| {
            format!("{PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV} tenant must be a UUID: {tenant}")
        })?;
        let projection = ProjectionId::parse(projection).with_context(|| {
                format!("{PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV} projection must be canonical: {projection}")
            })?;
        grants.push(authn::ProjectionMaintenanceGrant::new(
            *subject,
            action,
            tenant,
            projection.as_str(),
        )?);
    }
    anyhow::ensure!(
        !grants.is_empty(),
        "{PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV} must contain at least one grant"
    );
    authn::ProjectionMaintenanceGrantSet::new(grants).map_err(Into::into)
}

fn load_projection_maintenance_grants() -> anyhow::Result<authn::ProjectionMaintenanceGrantSet> {
    let raw = std::env::var(PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV)
        .with_context(|| format!("{PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV} is required"))?;
    parse_projection_maintenance_grants(&raw)
}

async fn projection_maintenance_operator_receipt(
    pg: &PgMaintenanceDeps,
    parsed: &ProjectionCliArgs,
    resource_id: &str,
) -> anyhow::Result<authn::ProjectionMaintenanceReceipt> {
    let operator_provider = match build_provider_with_replay_guard(pg.service_token_replay_guard())
    {
        Ok(provider) => provider,
        Err(err) => {
            record_projection_maintenance_finish_audit(
                pg,
                UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR,
                &format!("projection.{}.finish", parsed.command.action().as_str()),
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_provider_config",
                },
            )
            .await?;
            return Err(err).context("projection maintenance operator verifier");
        }
    };
    let operator_pdp = diport::DynPdp::from_ref(&operator_provider);
    let principal = match verified_projection_maintenance_operator_subject(
        &parsed.operator_service_token,
        parsed.operator_tenant,
        operator_pdp,
    )
    .await
    {
        Ok(principal) => principal,
        Err(err) => {
            record_projection_maintenance_finish_audit(
                pg,
                UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR,
                &format!("projection.{}.finish", parsed.command.action().as_str()),
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_auth",
                },
            )
            .await?;
            return Err(err);
        }
    };
    let subject = principal.audit_subject().to_owned();
    let grants = match load_projection_maintenance_grants() {
        Ok(grants) => grants,
        Err(err) => {
            record_projection_maintenance_finish_audit(
                pg,
                &subject,
                &format!("projection.{}.finish", parsed.command.action().as_str()),
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_grants",
                },
            )
            .await?;
            return Err(err);
        }
    };
    match grants.authorize(
        &principal,
        parsed.command.action().authorized_action(),
        parsed.selector.tenant(),
        parsed.selector.projection().as_str(),
    ) {
        Ok(receipt) => Ok(receipt),
        Err(err) => {
            record_projection_maintenance_finish_audit(
                pg,
                &subject,
                &format!("projection.{}.finish", parsed.command.action().as_str()),
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_authorization",
                },
            )
            .await?;
            Err(err.into())
        }
    }
}

fn format_optional_lsn(lsn: Option<consistency::Lsn>) -> String {
    lsn.map(|value| value.get().to_string())
        .unwrap_or_else(|| "none".to_owned())
}

fn format_optional_epoch(epoch: Option<vocab::Epoch>) -> String {
    epoch
        .map(|value| value.get().to_string())
        .unwrap_or_else(|| "none".to_owned())
}

fn format_optional_engine_kind(kind: Option<&'static str>) -> &'static str {
    kind.unwrap_or("none")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProjectionStopCliFields {
    stop: &'static str,
    failed_at_lsn: Option<consistency::Lsn>,
    skipped_at_lsn: Option<consistency::Lsn>,
    kind: Option<&'static str>,
}

fn projection_engine_kind_cli(kind: EngineErrorKind) -> &'static str {
    match kind {
        EngineErrorKind::Transient => "transient",
        EngineErrorKind::Permanent => "permanent",
        EngineErrorKind::Invariant => "invariant",
        _ => "unknown",
    }
}

fn projection_stop_cli_fields(stop: &ProjectionStop) -> ProjectionStopCliFields {
    match stop {
        ProjectionStop::Completed => ProjectionStopCliFields {
            stop: "completed",
            failed_at_lsn: None,
            skipped_at_lsn: None,
            kind: None,
        },
        ProjectionStop::ApplyFailed { failed_at, kind } => ProjectionStopCliFields {
            stop: "apply_failed",
            failed_at_lsn: Some(*failed_at),
            skipped_at_lsn: None,
            kind: Some(projection_engine_kind_cli(*kind)),
        },
        ProjectionStop::OutOfOrder { failed_at } => ProjectionStopCliFields {
            stop: "out_of_order",
            failed_at_lsn: Some(*failed_at),
            skipped_at_lsn: None,
            kind: None,
        },
        ProjectionStop::Fenced => ProjectionStopCliFields {
            stop: "fenced",
            failed_at_lsn: None,
            skipped_at_lsn: None,
            kind: None,
        },
        ProjectionStop::CheckpointUnsaved => ProjectionStopCliFields {
            stop: "checkpoint_unsaved",
            failed_at_lsn: None,
            skipped_at_lsn: None,
            kind: None,
        },
        ProjectionStop::DeadLetterUnsaved { failed_at } => ProjectionStopCliFields {
            stop: "dead_letter_unsaved",
            failed_at_lsn: Some(*failed_at),
            skipped_at_lsn: None,
            kind: None,
        },
        ProjectionStop::PoisonSkipped { skipped_at, kind } => ProjectionStopCliFields {
            stop: "poison_skipped",
            failed_at_lsn: None,
            skipped_at_lsn: Some(*skipped_at),
            kind: Some(projection_engine_kind_cli(*kind)),
        },
        ProjectionStop::SourceReadFailed { kind } => ProjectionStopCliFields {
            stop: "source_read_failed",
            failed_at_lsn: None,
            skipped_at_lsn: None,
            kind: Some(projection_engine_kind_cli(*kind)),
        },
        ProjectionStop::CheckpointUnread => ProjectionStopCliFields {
            stop: "checkpoint_unread",
            failed_at_lsn: None,
            skipped_at_lsn: None,
            kind: None,
        },
        _ => ProjectionStopCliFields {
            stop: "unknown",
            failed_at_lsn: None,
            skipped_at_lsn: None,
            kind: None,
        },
    }
}

fn projection_replay_batch_is_full(scanned: usize, batch_limit: ProjectionBatchLimit) -> bool {
    scanned >= batch_limit.get() as usize
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectionReplayCliRun {
    scanned: usize,
    applied: usize,
    filtered: usize,
    skipped: usize,
    dead_lettered: usize,
    stop: ProjectionStop,
}

async fn run_projection_status(
    pg: &PgMaintenanceDeps,
    registry: &ProjectionTargetRegistry,
    selector: &ProjectionSelector,
    receipt: &authn::ProjectionMaintenanceReceipt,
) -> anyhow::Result<()> {
    registry
        .bindings_for(selector.projection())
        .context("projection is not generated for this runtime")?;
    let status = pg.projection_control(receipt).status(selector).await?;
    let active_version = status
        .pointer()
        .map(|pointer| pointer.version().as_str().to_owned())
        .unwrap_or_else(|| "none".to_owned());
    let high_water = status
        .pointer()
        .and_then(|pointer| pointer.high_water_lsn());
    println!(
        "operation=status tenant={} projection={} selector_version={} active_version={} high_water_lsn={} selected_shadow_high_water_lsn={} source_high_water_lsn={} token={}",
        selector.tenant(),
        selector.projection().as_str(),
        selector.version().as_str(),
        active_version,
        format_optional_lsn(high_water),
        format_optional_lsn(status.selected_shadow_high_water_lsn()),
        format_optional_lsn(status.source_high_water_lsn()),
        format_optional_epoch(status.token())
    );
    Ok(())
}

async fn run_projection_swap(
    pg: &PgMaintenanceDeps,
    registry: &ProjectionTargetRegistry,
    selector: &ProjectionSelector,
    precondition: ProjectionPointerPrecondition,
    receipt: &authn::ProjectionMaintenanceReceipt,
) -> anyhow::Result<()> {
    registry
        .target(selector.projection())
        .context("projection target is not swappable by this runtime")?;
    let outcome = pg
        .projection_control(receipt)
        .promote(selector, precondition)
        .await
        .context("promote projection active pointer")?;
    let previous = outcome
        .previous()
        .map(|pointer| pointer.version().as_str().to_owned())
        .unwrap_or_else(|| "none".to_owned());
    println!(
        "operation=swap tenant={} projection={} active_version={} previous_version={} high_water_lsn={} token={}",
        selector.tenant(),
        selector.projection().as_str(),
        outcome.active().version().as_str(),
        previous,
        format_optional_lsn(outcome.active().high_water_lsn()),
        outcome.token().get()
    );
    Ok(())
}

async fn run_projection_replay(
    pg: &PgMaintenanceDeps,
    registry: &ProjectionTargetRegistry,
    selector: &ProjectionSelector,
    batch_limit: ProjectionBatchLimit,
    receipt: &authn::ProjectionMaintenanceReceipt,
) -> anyhow::Result<ProjectionReplayCliRun> {
    let target = registry
        .target(selector.projection())
        .context("projection target is not replayable by this runtime")?;
    let bindings = registry
        .bindings_for(selector.projection())
        .context("projection input bindings are not generated for this runtime")?;
    let dlx_payload_protector =
        event_transport::build_dlx_payload_protector_from(&|name| std::env::var(name).ok())
            .context("build projection replay DLQ payload protector")?;
    let (source, checkpoint, dead_letter) = pg
        .projection_replay_stores(receipt, selector, dlx_payload_protector)?
        .into_parts()?;
    let witness = SerialInOrder::from_source(&source);
    let projector = ProjectionReplayProjector::new(selector.clone(), bindings, target);
    let harness = ProjectionHarness::new(
        Arc::new(projector),
        Arc::new(checkpoint),
        selector.shadow_checkpoint_owner(),
        selector.shadow_checkpoint_id(),
        Arc::new(dead_letter),
        witness,
    );
    let config = eventexec::ProjectionRunnerConfig::new(
        batch_limit,
        Duration::from_secs(1),
        eventexec::ProjectionPoisonPolicy::Isolate,
    )?;
    let mut scanned = 0usize;
    let mut applied = 0usize;
    let mut filtered = 0usize;
    let mut skipped = 0usize;
    let mut dead_lettered = 0usize;
    loop {
        let run = projection_runner_once(&source, &harness, config).await;
        scanned = scanned.saturating_add(run.scanned);
        applied = applied.saturating_add(run.applied);
        filtered = filtered.saturating_add(run.filtered);
        skipped = skipped.saturating_add(run.skipped);
        dead_lettered = dead_lettered.saturating_add(run.dead_lettered);
        let full_batch = projection_replay_batch_is_full(run.scanned, batch_limit);
        let stop = run.stop;
        if matches!(stop, ProjectionStop::Completed) && full_batch {
            continue;
        }
        return Ok(ProjectionReplayCliRun {
            scanned,
            applied,
            filtered,
            skipped,
            dead_lettered,
            stop,
        });
    }
}

async fn run_projection_command_inner(
    pg: &PgMaintenanceDeps,
    registry: &ProjectionTargetRegistry,
    parsed: &ProjectionCliArgs,
    receipt: &authn::ProjectionMaintenanceReceipt,
) -> anyhow::Result<()> {
    match &parsed.command {
        ProjectionCliCommand::Status => {
            run_projection_status(pg, registry, &parsed.selector, receipt).await
        }
        ProjectionCliCommand::Swap { precondition } => {
            run_projection_swap(
                pg,
                registry,
                &parsed.selector,
                precondition.clone(),
                receipt,
            )
            .await
        }
        ProjectionCliCommand::Replay { batch_limit } => {
            let run = run_projection_replay(pg, registry, &parsed.selector, *batch_limit, receipt)
                .await?;
            let stop = projection_stop_cli_fields(&run.stop);
            println!(
                "operation=replay tenant={} projection={} version={} scanned={} matched={} applied={} filtered={} skipped={} dlq={} stop={} failed_at_lsn={} skipped_at_lsn={} kind={}",
                parsed.selector.tenant(),
                parsed.selector.projection().as_str(),
                parsed.selector.version().as_str(),
                run.scanned,
                run.applied,
                run.applied,
                run.filtered,
                run.skipped,
                run.dead_lettered,
                stop.stop,
                format_optional_lsn(stop.failed_at_lsn),
                format_optional_lsn(stop.skipped_at_lsn),
                format_optional_engine_kind(stop.kind)
            );
            anyhow::ensure!(
                matches!(run.stop, ProjectionStop::Completed),
                "projection replay stopped before completion: stop={} failed_at_lsn={} skipped_at_lsn={} kind={}",
                stop.stop,
                format_optional_lsn(stop.failed_at_lsn),
                format_optional_lsn(stop.skipped_at_lsn),
                format_optional_engine_kind(stop.kind)
            );
            Ok(())
        }
    }
}

#[allow(async_fn_in_trait)]
trait ProjectionControlRuntime {
    type Session;

    fn build_registry(&self) -> anyhow::Result<ProjectionTargetRegistry>;

    async fn connect_maintenance(&self) -> anyhow::Result<Self::Session>;

    async fn record_projection_maintenance_audit(
        &self,
        session: &Self::Session,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> anyhow::Result<()>;

    async fn operator_receipt(
        &self,
        session: &Self::Session,
        parsed: &ProjectionCliArgs,
        resource_id: &str,
    ) -> anyhow::Result<authn::ProjectionMaintenanceReceipt>;

    async fn run_projection_command(
        &self,
        session: &Self::Session,
        registry: &ProjectionTargetRegistry,
        parsed: &ProjectionCliArgs,
        receipt: &authn::ProjectionMaintenanceReceipt,
    ) -> anyhow::Result<()>;

    async fn shutdown(&self, session: Self::Session);
}

struct ProductionProjectionControlRuntime<'a> {
    config: SnapshotConfig<'a>,
}

impl ProjectionControlRuntime for ProductionProjectionControlRuntime<'_> {
    type Session = PgMaintenanceDeps;

    fn build_registry(&self) -> anyhow::Result<ProjectionTargetRegistry> {
        build_projection_target_registry()
    }

    async fn connect_maintenance(&self) -> anyhow::Result<Self::Session> {
        PgRuntimeDeps::connect_maintenance(&build_pg_migrator_config(self.config)?)
            .await
            .context("setup postgres maintenance deps")
    }

    async fn record_projection_maintenance_audit(
        &self,
        session: &Self::Session,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> anyhow::Result<()> {
        session
            .record_projection_maintenance_audit(operator_subject, action, outcome, resource_id)
            .await
            .context("record projection maintenance audit")
    }

    async fn operator_receipt(
        &self,
        session: &Self::Session,
        parsed: &ProjectionCliArgs,
        resource_id: &str,
    ) -> anyhow::Result<authn::ProjectionMaintenanceReceipt> {
        projection_maintenance_operator_receipt(session, parsed, resource_id).await
    }

    async fn run_projection_command(
        &self,
        session: &Self::Session,
        registry: &ProjectionTargetRegistry,
        parsed: &ProjectionCliArgs,
        receipt: &authn::ProjectionMaintenanceReceipt,
    ) -> anyhow::Result<()> {
        run_projection_command_inner(session, registry, parsed, receipt).await
    }

    async fn shutdown(&self, session: Self::Session) {
        session.shutdown().await.ok();
    }
}

async fn run_projection_control_command_with_runtime<R>(
    args: &[String],
    runtime: &R,
) -> anyhow::Result<()>
where
    R: ProjectionControlRuntime,
{
    let parsed = parse_projection_args(args)?;
    let registry = runtime.build_registry()?;
    ensure_projection_command_supported_by_registry(&registry, &parsed.command)?;
    let resource_id = projection_command_resource_id(&parsed);
    let session = runtime.connect_maintenance().await?;
    let start_action = format!("projection.{}.start", parsed.command.action().as_str());
    if let Err(err) = runtime
        .record_projection_maintenance_audit(
            &session,
            UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR,
            &start_action,
            MaintenanceAuditOutcome::Success,
            &resource_id,
        )
        .await
        .context("record projection maintenance start audit")
    {
        runtime.shutdown(session).await;
        return Err(err);
    }

    let finish_action = format!("projection.{}.finish", parsed.command.action().as_str());
    let receipt = match runtime
        .operator_receipt(&session, &parsed, &resource_id)
        .await
    {
        Ok(receipt) => receipt,
        Err(err) => {
            runtime.shutdown(session).await;
            return Err(err);
        }
    };
    let operator_subject = receipt.operator_subject().to_owned();
    let command_result = runtime
        .run_projection_command(&session, &registry, &parsed, &receipt)
        .await;
    let finish_outcome = if command_result.is_ok() {
        MaintenanceAuditOutcome::Success
    } else {
        MaintenanceAuditOutcome::Failure {
            reason: "run_error",
        }
    };
    let audit_result = runtime
        .record_projection_maintenance_audit(
            &session,
            &operator_subject,
            &finish_action,
            finish_outcome,
            &resource_id,
        )
        .await
        .context("record projection maintenance finish audit");
    runtime.shutdown(session).await;
    audit_result?;
    command_result
}

/// 执行 `rss projections replay|status|swap`。
pub async fn run_projection_control_command(
    args: &[String],
    runtime_inputs: &RuntimeInputs,
) -> anyhow::Result<()> {
    let runtime = ProductionProjectionControlRuntime {
        config: runtime_inputs.config(),
    };
    run_projection_control_command_with_runtime(args, &runtime).await
}

/// `rss` binary 是否请求 per-tenant audit ledger full-chain verify。
#[must_use]
pub fn is_audit_ledger_verify_command(args: &[String]) -> bool {
    matches!(
        args,
        [cmd, sub, ..] if cmd == "audit-ledger" && sub == "verify"
    )
}

const AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV: &str = "RSS_AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS";
const UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR: &str = "unverified-service-token";

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditLedgerVerifyArgs {
    operator_service_token: String,
    operator_tenant: vocab::TenantId,
    tenant: vocab::TenantId,
    batch: vocab::Limit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditLedgerVerifyGrant {
    subject: String,
    tenant: vocab::TenantId,
}

fn audit_ledger_verify_usage() -> &'static str {
    "usage: rss audit-ledger verify --operator-service-token <token> --operator-tenant <uuid> --tenant <uuid> [--batch-size <1..500>]"
}

fn parse_audit_ledger_verify_batch(raw: &str) -> anyhow::Result<vocab::Limit> {
    let value = parse_positive_usize(raw, "--batch-size")?;
    let value = u16::try_from(value).context("--batch-size exceeds u16")?;
    vocab::Limit::new(value).context("--batch-size must be <= 500")
}

fn parse_audit_ledger_verify_args(args: &[String]) -> anyhow::Result<AuditLedgerVerifyArgs> {
    anyhow::ensure!(
        is_audit_ledger_verify_command(args),
        audit_ledger_verify_usage()
    );
    let mut operator_service_token = None;
    let mut operator_tenant = None;
    let mut tenant = None;
    let mut batch = vocab::Limit::new(500).context("default audit ledger verify batch")?;
    let mut batch_seen = false;

    let mut it = args[2..].iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--operator-service-token" => {
                let raw = next_cli_value(&mut it, "--operator-service-token")?;
                let trimmed = raw.trim();
                anyhow::ensure!(
                    !trimmed.is_empty(),
                    "--operator-service-token must be non-empty"
                );
                set_cli_arg_once(
                    &mut operator_service_token,
                    "--operator-service-token",
                    trimmed.to_owned(),
                )?;
            }
            "--operator-tenant" => {
                let raw = next_cli_value(&mut it, "--operator-tenant")?;
                let parsed = vocab::TenantId::parse(raw)
                    .with_context(|| format!("--operator-tenant must be a tenant UUID: {raw}"))?;
                set_cli_arg_once(&mut operator_tenant, "--operator-tenant", parsed)?;
            }
            "--tenant" => {
                let raw = next_cli_value(&mut it, "--tenant")?;
                let parsed = vocab::TenantId::parse(raw)
                    .with_context(|| format!("--tenant must be a tenant UUID: {raw}"))?;
                set_cli_arg_once(&mut tenant, "--tenant", parsed)?;
            }
            "--batch-size" => {
                anyhow::ensure!(!batch_seen, "--batch-size must not be repeated");
                let raw = next_cli_value(&mut it, "--batch-size")?;
                batch = parse_audit_ledger_verify_batch(raw)?;
                batch_seen = true;
            }
            "--all-tenants" => {
                anyhow::bail!("audit ledger verify does not support --all-tenants")
            }
            "--namespace" => {
                anyhow::bail!("audit ledger verify does not support --namespace")
            }
            other => anyhow::bail!("unknown audit ledger verify argument: {other}"),
        }
    }

    Ok(AuditLedgerVerifyArgs {
        operator_service_token: operator_service_token
            .ok_or_else(|| anyhow::anyhow!("--operator-service-token is required"))?,
        operator_tenant: operator_tenant
            .ok_or_else(|| anyhow::anyhow!("--operator-tenant is required"))?,
        tenant: tenant.ok_or_else(|| anyhow::anyhow!("--tenant is required"))?,
        batch,
    })
}

fn audit_ledger_verify_resource_id(parsed: &AuditLedgerVerifyArgs) -> String {
    format!("tenant={} batch_size={}", parsed.tenant, parsed.batch.get())
}

fn parse_audit_ledger_verify_grants(raw: &str) -> anyhow::Result<Vec<AuditLedgerVerifyGrant>> {
    let raw = raw.trim();
    anyhow::ensure!(
        !raw.is_empty(),
        "{AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV} must not be empty"
    );
    let mut grants = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        anyhow::ensure!(
            !entry.is_empty(),
            "{AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV} must not contain empty entries"
        );
        let parts: Vec<&str> = entry.split('|').map(str::trim).collect();
        anyhow::ensure!(
            parts.len() == 2,
            "{AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV} entries must be subject|tenant"
        );
        let [subject, tenant] = parts.as_slice() else {
            unreachable!("len checked");
        };
        anyhow::ensure!(
            !subject.is_empty(),
            "{AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV} subject must be non-empty"
        );
        grants.push(AuditLedgerVerifyGrant {
            subject: (*subject).to_owned(),
            tenant: vocab::TenantId::parse(tenant).with_context(|| {
                format!("{AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV} tenant must be a UUID: {tenant}")
            })?,
        });
    }
    anyhow::ensure!(
        !grants.is_empty(),
        "{AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV} must contain at least one grant"
    );
    Ok(grants)
}

fn load_audit_ledger_verify_grants() -> anyhow::Result<Vec<AuditLedgerVerifyGrant>> {
    let raw = std::env::var(AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV)
        .with_context(|| format!("{AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV} is required"))?;
    parse_audit_ledger_verify_grants(&raw)
}

fn authorize_audit_ledger_verify_operator(
    operator_subject: &str,
    parsed: &AuditLedgerVerifyArgs,
    grants: &[AuditLedgerVerifyGrant],
) -> anyhow::Result<()> {
    let allowed = grants
        .iter()
        .any(|grant| grant.subject == operator_subject && grant.tenant == parsed.tenant);
    anyhow::ensure!(
        allowed,
        "audit ledger verify operator is not authorized for tenant={}",
        parsed.tenant
    );
    Ok(())
}

async fn verified_audit_ledger_verify_operator_subject(
    service_token: &str,
    operator_tenant: vocab::TenantId,
    pdp: &diport::DynPdp<'_>,
) -> anyhow::Result<String> {
    verified_service_maintenance_operator_subject(
        service_token,
        operator_tenant,
        pdp,
        "audit ledger verify",
    )
    .await
}

async fn record_audit_ledger_verify_finish_audit(
    pg: &PgMaintenanceDeps,
    operator_subject: &str,
    resource_id: &str,
    outcome: MaintenanceAuditOutcome<'_>,
) -> anyhow::Result<()> {
    pg.record_audit_ledger_verify_audit(
        operator_subject,
        "audit.ledger.verify.finish",
        outcome,
        resource_id,
    )
    .await
    .context("record audit ledger verify finish audit")
}

async fn audit_ledger_verify_operator_subject(
    pg: &PgMaintenanceDeps,
    parsed: &AuditLedgerVerifyArgs,
    resource_id: &str,
) -> anyhow::Result<String> {
    let operator_provider = match build_provider_with_replay_guard(pg.service_token_replay_guard())
    {
        Ok(provider) => provider,
        Err(err) => {
            record_audit_ledger_verify_finish_audit(
                pg,
                UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR,
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_provider_config",
                },
            )
            .await?;
            return Err(err).context("audit ledger verify operator verifier");
        }
    };
    let operator_pdp = diport::DynPdp::from_ref(&operator_provider);
    let subject = match verified_audit_ledger_verify_operator_subject(
        &parsed.operator_service_token,
        parsed.operator_tenant,
        operator_pdp,
    )
    .await
    {
        Ok(subject) => subject,
        Err(err) => {
            record_audit_ledger_verify_finish_audit(
                pg,
                UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR,
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_auth",
                },
            )
            .await?;
            return Err(err);
        }
    };
    let grants = match load_audit_ledger_verify_grants() {
        Ok(grants) => grants,
        Err(err) => {
            record_audit_ledger_verify_finish_audit(
                pg,
                &subject,
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_grants",
                },
            )
            .await?;
            return Err(err);
        }
    };
    if let Err(err) = authorize_audit_ledger_verify_operator(&subject, parsed, &grants) {
        record_audit_ledger_verify_finish_audit(
            pg,
            &subject,
            resource_id,
            MaintenanceAuditOutcome::Failure {
                reason: "operator_authorization",
            },
        )
        .await?;
        return Err(err);
    }
    Ok(subject)
}

#[allow(async_fn_in_trait)]
trait AuditLedgerVerifyRuntime {
    type Session;

    async fn connect_maintenance(&self) -> anyhow::Result<Self::Session>;

    async fn record_audit_ledger_verify_audit(
        &self,
        session: &Self::Session,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> anyhow::Result<()>;

    async fn operator_subject(
        &self,
        session: &Self::Session,
        parsed: &AuditLedgerVerifyArgs,
        resource_id: &str,
    ) -> anyhow::Result<String>;

    async fn verify_tenant(
        &self,
        session: &Self::Session,
        parsed: &AuditLedgerVerifyArgs,
    ) -> anyhow::Result<AuditLedgerVerifyReport>;

    async fn shutdown(&self, session: Self::Session);
}

struct ProductionAuditLedgerVerifyRuntime<'a> {
    config: SnapshotConfig<'a>,
}

impl AuditLedgerVerifyRuntime for ProductionAuditLedgerVerifyRuntime<'_> {
    type Session = PgMaintenanceDeps;

    async fn connect_maintenance(&self) -> anyhow::Result<Self::Session> {
        let (migrator_config, audit_admin_config) = build_pg_audit_maintenance_config(self.config)
            .context("build audit maintenance postgres config")?;
        match audit_admin_config.as_ref() {
            Some(config) => {
                PgRuntimeDeps::connect_maintenance_with_audit_admin_config(&migrator_config, config)
                    .await
                    .context("setup postgres maintenance deps with audit admin")
            }
            None => PgRuntimeDeps::connect_maintenance(&migrator_config)
                .await
                .context("setup postgres maintenance deps"),
        }
    }

    async fn record_audit_ledger_verify_audit(
        &self,
        session: &Self::Session,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> anyhow::Result<()> {
        session
            .record_audit_ledger_verify_audit(operator_subject, action, outcome, resource_id)
            .await
            .context("record audit ledger verify audit")
    }

    async fn operator_subject(
        &self,
        session: &Self::Session,
        parsed: &AuditLedgerVerifyArgs,
        resource_id: &str,
    ) -> anyhow::Result<String> {
        audit_ledger_verify_operator_subject(session, parsed, resource_id).await
    }

    async fn verify_tenant(
        &self,
        session: &Self::Session,
        parsed: &AuditLedgerVerifyArgs,
    ) -> anyhow::Result<AuditLedgerVerifyReport> {
        let hasher = domains::audit::build_audit_hasher(|name| std::env::var(name).ok())
            .context("audit chain key")?;
        let repo = session.audit_admin_repo(hasher).context(
            "audit ledger verify requires RSS_PG_AUDIT_ADMIN_USERNAME/RSS_PG_AUDIT_ADMIN_PASSWORD",
        )?;
        repo.verify_tenant(parsed.tenant, parsed.batch)
            .await
            .context("verify audit ledger")
    }

    async fn shutdown(&self, session: Self::Session) {
        session.shutdown().await.ok();
    }
}

async fn run_audit_ledger_verify_command_with_runtime<R>(
    args: &[String],
    runtime: &R,
) -> anyhow::Result<()>
where
    R: AuditLedgerVerifyRuntime,
{
    let parsed = parse_audit_ledger_verify_args(args)?;
    let resource_id = audit_ledger_verify_resource_id(&parsed);
    let session = runtime.connect_maintenance().await?;
    if let Err(err) = runtime
        .record_audit_ledger_verify_audit(
            &session,
            UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR,
            "audit.ledger.verify.start",
            MaintenanceAuditOutcome::Success,
            &resource_id,
        )
        .await
        .context("record audit ledger verify start audit")
    {
        runtime.shutdown(session).await;
        return Err(err);
    }

    let operator_subject = match runtime
        .operator_subject(&session, &parsed, &resource_id)
        .await
    {
        Ok(subject) => subject,
        Err(err) => {
            runtime.shutdown(session).await;
            return Err(err);
        }
    };
    let command_result = runtime.verify_tenant(&session, &parsed).await;
    let finish_outcome = if command_result.is_ok() {
        MaintenanceAuditOutcome::Success
    } else {
        MaintenanceAuditOutcome::Failure {
            reason: "run_error",
        }
    };
    let audit_result = runtime
        .record_audit_ledger_verify_audit(
            &session,
            &operator_subject,
            "audit.ledger.verify.finish",
            finish_outcome,
            &resource_id,
        )
        .await
        .context("record audit ledger verify finish audit");
    runtime.shutdown(session).await;
    audit_result?;
    let report = command_result?;
    println!(
        "operation=verify tenant={} batch_size={} checked_entries={}",
        report.tenant,
        parsed.batch.get(),
        report.checked_entries
    );
    Ok(())
}

/// 执行 `rss audit-ledger verify`。
pub async fn run_audit_ledger_verify_command(
    args: &[String],
    runtime_inputs: &RuntimeInputs,
) -> anyhow::Result<()> {
    let runtime = ProductionAuditLedgerVerifyRuntime {
        config: runtime_inputs.config(),
    };
    run_audit_ledger_verify_command_with_runtime(args, &runtime).await
}

/// `rss` binary 是否请求 DLQ inspection / replay / redrive 控制命令。
#[must_use]
pub fn is_dlq_command(args: &[String]) -> bool {
    matches!(args, [cmd, ..] if cmd == "dlq")
}

const DLQ_OPERATOR_GRANTS_ENV: &str = "RSS_DLQ_OPERATOR_GRANTS";
const UNVERIFIED_DLQ_OPERATOR: &str = "unverified-service-token";

#[derive(Debug, Clone, PartialEq, Eq)]
struct DlqCliArgs {
    command: DlqCliCommand,
    operator_service_token: String,
    operator_tenant: vocab::TenantId,
    tenant: vocab::TenantId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DlqCliCommand {
    List {
        source: Option<diport::DeadLetterSource>,
        producer_domain: Option<String>,
        consumer_domain: Option<String>,
        contract_id: Option<String>,
        limit: u32,
        cursor: Option<DlqCursor>,
    },
    Inspect {
        target: DlqInspectTarget,
    },
    ReplayDeadLetter {
        dead_letter_id: DeadLetterId,
        replay_id: IdemKey,
    },
    RedriveOutbox {
        event_id: IdemKey,
    },
    ResolveExpiredOutbox {
        event_id: IdemKey,
        change_ticket: OutboxResolutionChangeTicket,
        resolution_kind: OutboxExpiredResolutionKind,
        evidence_event_id: Option<IdemKey>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DlqMaintenanceAction {
    List,
    Inspect,
    ReplayDeadLetter,
    RedriveOutbox,
    ResolveExpiredOutbox,
}

impl DlqMaintenanceAction {
    fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw {
            "list" => Ok(Self::List),
            "inspect" => Ok(Self::Inspect),
            "replay-dead-letter" => Ok(Self::ReplayDeadLetter),
            "redrive-outbox" => Ok(Self::RedriveOutbox),
            "resolve-expired-outbox" => Ok(Self::ResolveExpiredOutbox),
            other => anyhow::bail!(
                "unknown DLQ maintenance action in {DLQ_OPERATOR_GRANTS_ENV}: {other}"
            ),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Inspect => "inspect",
            Self::ReplayDeadLetter => "replay-dead-letter",
            Self::RedriveOutbox => "redrive-outbox",
            Self::ResolveExpiredOutbox => "resolve-expired-outbox",
        }
    }
}

impl DlqCliCommand {
    fn action(&self) -> DlqMaintenanceAction {
        match self {
            Self::List { .. } => DlqMaintenanceAction::List,
            Self::Inspect { .. } => DlqMaintenanceAction::Inspect,
            Self::ReplayDeadLetter { .. } => DlqMaintenanceAction::ReplayDeadLetter,
            Self::RedriveOutbox { .. } => DlqMaintenanceAction::RedriveOutbox,
            Self::ResolveExpiredOutbox { .. } => DlqMaintenanceAction::ResolveExpiredOutbox,
        }
    }

    fn requires_payload_protector(&self) -> bool {
        matches!(self, Self::ReplayDeadLetter { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DlqMaintenanceGrant {
    subject: String,
    action: DlqMaintenanceAction,
    tenant: vocab::TenantId,
}

fn dlq_cli_usage() -> &'static str {
    "usage: rss dlq list|inspect|replay-dead-letter|redrive-outbox|resolve-expired-outbox --operator-service-token <token> --operator-tenant <uuid> --tenant <uuid> [--producer-domain <domain>] [--consumer-domain <domain>] ..."
}

fn parse_dlq_limit(raw: &str) -> anyhow::Result<u32> {
    let value = parse_positive_usize(raw, "--limit")?;
    let value = u32::try_from(value).context("--limit exceeds u32")?;
    anyhow::ensure!(value <= 500, "--limit must be <= 500");
    Ok(value)
}

fn parse_dlq_source(raw: &str) -> anyhow::Result<diport::DeadLetterSource> {
    diport::DeadLetterSource::parse(raw)
        .ok_or_else(|| anyhow::anyhow!("--source must be consumer|outbox_relay|saga|projection"))
}

fn parse_dlq_kind_target(kind: &str, id: &str) -> anyhow::Result<DlqInspectTarget> {
    match kind {
        "dead-letter" => Ok(DlqInspectTarget::DeadLetter(
            DeadLetterId::parse(id)
                .with_context(|| format!("--id must be a dead_letter UUID: {id}"))?,
        )),
        "outbox-dlx" => Ok(DlqInspectTarget::OutboxDlx(
            IdemKey::parse(id).with_context(|| format!("--id must be an outbox event id: {id}"))?,
        )),
        other => anyhow::bail!("--kind must be dead-letter|outbox-dlx, got {other}"),
    }
}

#[derive(Debug)]
struct DlqRawArgs {
    operator_service_token: Option<String>,
    operator_tenant: Option<vocab::TenantId>,
    tenant: Option<vocab::TenantId>,
    source: Option<diport::DeadLetterSource>,
    producer_domain: Option<String>,
    consumer_domain: Option<String>,
    contract_id: Option<String>,
    limit: u32,
    limit_seen: bool,
    cursor: Option<DlqCursor>,
    kind: Option<String>,
    id: Option<String>,
    dead_letter_id: Option<DeadLetterId>,
    replay_id: Option<IdemKey>,
    event_id: Option<IdemKey>,
    change_ticket: Option<OutboxResolutionChangeTicket>,
    resolution_kind: Option<OutboxExpiredResolutionKind>,
    evidence_event_id: Option<IdemKey>,
}

impl Default for DlqRawArgs {
    fn default() -> Self {
        Self {
            operator_service_token: None,
            operator_tenant: None,
            tenant: None,
            source: None,
            producer_domain: None,
            consumer_domain: None,
            contract_id: None,
            limit: 100,
            limit_seen: false,
            cursor: None,
            kind: None,
            id: None,
            dead_letter_id: None,
            replay_id: None,
            event_id: None,
            change_ticket: None,
            resolution_kind: None,
            evidence_event_id: None,
        }
    }
}

fn parse_dlq_raw_args(args: &[String]) -> anyhow::Result<DlqRawArgs> {
    let mut parsed = DlqRawArgs::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--operator-service-token" => {
                let value = next_cli_value(&mut it, "--operator-service-token")?;
                let trimmed = value.trim();
                anyhow::ensure!(
                    !trimmed.is_empty(),
                    "--operator-service-token must be non-empty"
                );
                set_cli_arg_once(
                    &mut parsed.operator_service_token,
                    "--operator-service-token",
                    trimmed.to_owned(),
                )?;
            }
            "--operator-tenant" => {
                let value = next_cli_value(&mut it, "--operator-tenant")?;
                let tenant = vocab::TenantId::parse(value)
                    .with_context(|| format!("--operator-tenant must be a tenant UUID: {value}"))?;
                set_cli_arg_once(&mut parsed.operator_tenant, "--operator-tenant", tenant)?;
            }
            "--tenant" => {
                let value = next_cli_value(&mut it, "--tenant")?;
                let tenant = vocab::TenantId::parse(value)
                    .with_context(|| format!("--tenant must be a tenant UUID: {value}"))?;
                set_cli_arg_once(&mut parsed.tenant, "--tenant", tenant)?;
            }
            "--source" => {
                let value = next_cli_value(&mut it, "--source")?;
                set_cli_arg_once(&mut parsed.source, "--source", parse_dlq_source(value)?)?;
            }
            "--producer-domain" => {
                let value = next_cli_value(&mut it, "--producer-domain")?;
                anyhow::ensure!(
                    !value.trim().is_empty(),
                    "--producer-domain must be non-empty"
                );
                set_cli_arg_once(
                    &mut parsed.producer_domain,
                    "--producer-domain",
                    value.trim().to_owned(),
                )?;
            }
            "--consumer-domain" => {
                let value = next_cli_value(&mut it, "--consumer-domain")?;
                anyhow::ensure!(
                    !value.trim().is_empty(),
                    "--consumer-domain must be non-empty"
                );
                set_cli_arg_once(
                    &mut parsed.consumer_domain,
                    "--consumer-domain",
                    value.trim().to_owned(),
                )?;
            }
            "--contract-id" => {
                let value = next_cli_value(&mut it, "--contract-id")?;
                anyhow::ensure!(!value.trim().is_empty(), "--contract-id must be non-empty");
                set_cli_arg_once(
                    &mut parsed.contract_id,
                    "--contract-id",
                    value.trim().to_owned(),
                )?;
            }
            "--limit" => {
                anyhow::ensure!(!parsed.limit_seen, "--limit must not be repeated");
                let value = next_cli_value(&mut it, "--limit")?;
                parsed.limit = parse_dlq_limit(value)?;
                parsed.limit_seen = true;
            }
            "--cursor" => {
                let value = next_cli_value(&mut it, "--cursor")?;
                set_cli_arg_once(
                    &mut parsed.cursor,
                    "--cursor",
                    DlqCursor::parse(value).context("--cursor is invalid")?,
                )?;
            }
            "--kind" => {
                let value = next_cli_value(&mut it, "--kind")?;
                set_cli_arg_once(&mut parsed.kind, "--kind", value.to_owned())?;
            }
            "--id" => {
                let value = next_cli_value(&mut it, "--id")?;
                anyhow::ensure!(!value.trim().is_empty(), "--id must be non-empty");
                set_cli_arg_once(&mut parsed.id, "--id", value.trim().to_owned())?;
            }
            "--dead-letter-id" => {
                let value = next_cli_value(&mut it, "--dead-letter-id")?;
                set_cli_arg_once(
                    &mut parsed.dead_letter_id,
                    "--dead-letter-id",
                    DeadLetterId::parse(value)
                        .with_context(|| format!("--dead-letter-id must be a UUID: {value}"))?,
                )?;
            }
            "--replay-id" => {
                let value = next_cli_value(&mut it, "--replay-id")?;
                set_cli_arg_once(
                    &mut parsed.replay_id,
                    "--replay-id",
                    IdemKey::parse(value).with_context(|| {
                        format!("--replay-id must be an idempotency key: {value}")
                    })?,
                )?;
            }
            "--event-id" => {
                let value = next_cli_value(&mut it, "--event-id")?;
                set_cli_arg_once(
                    &mut parsed.event_id,
                    "--event-id",
                    IdemKey::parse(value).with_context(|| {
                        format!("--event-id must be an idempotency key: {value}")
                    })?,
                )?;
            }
            "--change-ticket" => {
                let value = next_cli_value(&mut it, "--change-ticket")?;
                set_cli_arg_once(
                    &mut parsed.change_ticket,
                    "--change-ticket",
                    OutboxResolutionChangeTicket::parse(value)
                        .context("--change-ticket is invalid")?,
                )?;
            }
            "--resolution-kind" => {
                let value = next_cli_value(&mut it, "--resolution-kind")?;
                set_cli_arg_once(
                    &mut parsed.resolution_kind,
                    "--resolution-kind",
                    OutboxExpiredResolutionKind::parse(value)
                        .context("--resolution-kind must be accepted_gap|compensated")?,
                )?;
            }
            "--evidence-event-id" => {
                let value = next_cli_value(&mut it, "--evidence-event-id")?;
                set_cli_arg_once(
                    &mut parsed.evidence_event_id,
                    "--evidence-event-id",
                    IdemKey::parse(value)
                        .with_context(|| format!("--evidence-event-id is invalid: {value}"))?,
                )?;
            }
            other => anyhow::bail!("unknown dlq command argument: {other}"),
        }
    }
    Ok(parsed)
}

fn parse_dlq_args(args: &[String]) -> anyhow::Result<DlqCliArgs> {
    anyhow::ensure!(is_dlq_command(args), dlq_cli_usage());
    let subcommand = args
        .get(1)
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!(dlq_cli_usage()))?;
    anyhow::ensure!(
        matches!(
            subcommand,
            "list" | "inspect" | "replay-dead-letter" | "redrive-outbox" | "resolve-expired-outbox"
        ),
        "unknown dlq subcommand: {subcommand}; {}",
        dlq_cli_usage()
    );
    let mut raw = parse_dlq_raw_args(&args[2..])?;

    let command = match subcommand {
        "list" => {
            anyhow::ensure!(
                raw.kind.is_none() && raw.id.is_none(),
                "list does not accept --kind or --id"
            );
            anyhow::ensure!(
                raw.dead_letter_id.is_none()
                    && raw.replay_id.is_none()
                    && raw.event_id.is_none()
                    && raw.change_ticket.is_none()
                    && raw.resolution_kind.is_none()
                    && raw.evidence_event_id.is_none(),
                "list does not accept mutation target flags"
            );
            DlqCliCommand::List {
                source: raw.source.take(),
                producer_domain: raw.producer_domain.take(),
                consumer_domain: raw.consumer_domain.take(),
                contract_id: raw.contract_id.take(),
                limit: raw.limit,
                cursor: raw.cursor.take(),
            }
        }
        "inspect" => {
            anyhow::ensure!(
                raw.source.is_none()
                    && raw.producer_domain.is_none()
                    && raw.consumer_domain.is_none()
                    && raw.contract_id.is_none()
                    && raw.cursor.is_none()
                    && !raw.limit_seen,
                "inspect does not accept list filters"
            );
            anyhow::ensure!(
                raw.dead_letter_id.is_none()
                    && raw.replay_id.is_none()
                    && raw.event_id.is_none()
                    && raw.change_ticket.is_none()
                    && raw.resolution_kind.is_none()
                    && raw.evidence_event_id.is_none(),
                "inspect does not accept mutation target flags"
            );
            let kind = raw
                .kind
                .take()
                .ok_or_else(|| anyhow::anyhow!("--kind is required"))?;
            let id = raw
                .id
                .take()
                .ok_or_else(|| anyhow::anyhow!("--id is required"))?;
            DlqCliCommand::Inspect {
                target: parse_dlq_kind_target(&kind, &id)?,
            }
        }
        "replay-dead-letter" => {
            anyhow::ensure!(
                raw.source.is_none()
                    && raw.producer_domain.is_none()
                    && raw.consumer_domain.is_none()
                    && raw.contract_id.is_none()
                    && raw.cursor.is_none()
                    && !raw.limit_seen
                    && raw.kind.is_none()
                    && raw.id.is_none()
                    && raw.event_id.is_none()
                    && raw.change_ticket.is_none()
                    && raw.resolution_kind.is_none()
                    && raw.evidence_event_id.is_none(),
                "replay-dead-letter only accepts --dead-letter-id and --replay-id target flags"
            );
            DlqCliCommand::ReplayDeadLetter {
                dead_letter_id: raw
                    .dead_letter_id
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("--dead-letter-id is required"))?,
                replay_id: raw
                    .replay_id
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("--replay-id is required"))?,
            }
        }
        "redrive-outbox" => {
            anyhow::ensure!(
                raw.source.is_none()
                    && raw.producer_domain.is_none()
                    && raw.consumer_domain.is_none()
                    && raw.contract_id.is_none()
                    && raw.cursor.is_none()
                    && !raw.limit_seen
                    && raw.kind.is_none()
                    && raw.id.is_none()
                    && raw.dead_letter_id.is_none()
                    && raw.replay_id.is_none()
                    && raw.change_ticket.is_none()
                    && raw.resolution_kind.is_none()
                    && raw.evidence_event_id.is_none(),
                "redrive-outbox only accepts --event-id target flag"
            );
            DlqCliCommand::RedriveOutbox {
                event_id: raw
                    .event_id
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("--event-id is required"))?,
            }
        }
        "resolve-expired-outbox" => {
            anyhow::ensure!(
                raw.source.is_none()
                    && raw.producer_domain.is_none()
                    && raw.consumer_domain.is_none()
                    && raw.contract_id.is_none()
                    && raw.cursor.is_none()
                    && !raw.limit_seen
                    && raw.kind.is_none()
                    && raw.id.is_none()
                    && raw.dead_letter_id.is_none()
                    && raw.replay_id.is_none(),
                "resolve-expired-outbox only accepts resolution target flags"
            );
            let event_id = raw
                .event_id
                .take()
                .ok_or_else(|| anyhow::anyhow!("--event-id is required"))?;
            let change_ticket = raw
                .change_ticket
                .take()
                .ok_or_else(|| anyhow::anyhow!("--change-ticket is required"))?;
            let resolution_kind = raw
                .resolution_kind
                .take()
                .ok_or_else(|| anyhow::anyhow!("--resolution-kind is required"))?;
            let evidence_event_id = raw.evidence_event_id.take();
            anyhow::ensure!(
                matches!(
                    (resolution_kind, evidence_event_id.is_some()),
                    (OutboxExpiredResolutionKind::AcceptedGap, false)
                        | (OutboxExpiredResolutionKind::Compensated, true)
                ),
                "accepted_gap forbids --evidence-event-id; compensated requires it"
            );
            DlqCliCommand::ResolveExpiredOutbox {
                event_id,
                change_ticket,
                resolution_kind,
                evidence_event_id,
            }
        }
        _ => unreachable!("subcommand checked"),
    };

    Ok(DlqCliArgs {
        command,
        operator_service_token: raw
            .operator_service_token
            .take()
            .ok_or_else(|| anyhow::anyhow!("--operator-service-token is required"))?,
        operator_tenant: raw
            .operator_tenant
            .take()
            .ok_or_else(|| anyhow::anyhow!("--operator-tenant is required"))?,
        tenant: raw
            .tenant
            .take()
            .ok_or_else(|| anyhow::anyhow!("--tenant is required"))?,
    })
}

fn parse_dlq_operator_grants(raw: &str) -> anyhow::Result<Vec<DlqMaintenanceGrant>> {
    let raw = raw.trim();
    anyhow::ensure!(
        !raw.is_empty(),
        "{DLQ_OPERATOR_GRANTS_ENV} must not be empty"
    );
    let mut grants = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        anyhow::ensure!(
            !entry.is_empty(),
            "{DLQ_OPERATOR_GRANTS_ENV} must not contain empty entries"
        );
        let parts: Vec<_> = entry.split('|').map(str::trim).collect();
        anyhow::ensure!(
            parts.len() == 3,
            "{DLQ_OPERATOR_GRANTS_ENV} entries must be subject|action|tenant"
        );
        let [subject, action, tenant] = parts.as_slice() else {
            unreachable!("len checked");
        };
        anyhow::ensure!(
            !subject.is_empty(),
            "{DLQ_OPERATOR_GRANTS_ENV} subject must be non-empty"
        );
        grants.push(DlqMaintenanceGrant {
            subject: (*subject).to_owned(),
            action: DlqMaintenanceAction::parse(action)?,
            tenant: vocab::TenantId::parse(tenant).with_context(|| {
                format!("{DLQ_OPERATOR_GRANTS_ENV} tenant must be a UUID: {tenant}")
            })?,
        });
    }
    anyhow::ensure!(
        !grants.is_empty(),
        "{DLQ_OPERATOR_GRANTS_ENV} must contain at least one grant"
    );
    Ok(grants)
}

fn load_dlq_operator_grants() -> anyhow::Result<Vec<DlqMaintenanceGrant>> {
    let raw = std::env::var(DLQ_OPERATOR_GRANTS_ENV)
        .with_context(|| format!("{DLQ_OPERATOR_GRANTS_ENV} is required"))?;
    parse_dlq_operator_grants(&raw)
}

fn authorize_dlq_operator(
    operator_subject: &str,
    parsed: &DlqCliArgs,
    grants: &[DlqMaintenanceGrant],
) -> anyhow::Result<()> {
    let action = parsed.command.action();
    let allowed = grants.iter().any(|grant| {
        grant.subject == operator_subject && grant.action == action && grant.tenant == parsed.tenant
    });
    anyhow::ensure!(
        allowed,
        "DLQ operator is not authorized for action={} tenant={}",
        action.as_str(),
        parsed.tenant
    );
    Ok(())
}

fn dlq_command_resource_id(parsed: &DlqCliArgs) -> String {
    let target = match &parsed.command {
        DlqCliCommand::List {
            source,
            producer_domain,
            consumer_domain,
            contract_id,
            ..
        } => format!(
            "source={} producer_domain={} consumer_domain={} contract_id={}",
            source.map(|source| source.as_str()).unwrap_or("all"),
            producer_domain.as_deref().unwrap_or("all"),
            consumer_domain.as_deref().unwrap_or("all"),
            contract_id.as_deref().unwrap_or("all")
        ),
        DlqCliCommand::Inspect { target } => match target {
            DlqInspectTarget::DeadLetter(dead_letter_id) => {
                format!("kind=dead_letter dead_letter_id={dead_letter_id}")
            }
            DlqInspectTarget::OutboxDlx(event_id) => {
                format!("kind=outbox_dlx event_id={}", event_id.as_str())
            }
        },
        DlqCliCommand::ReplayDeadLetter {
            dead_letter_id,
            replay_id,
        } => {
            format!(
                "dead_letter_id={dead_letter_id} replay_id={}",
                replay_id.as_str()
            )
        }
        DlqCliCommand::RedriveOutbox { event_id } => format!("event_id={}", event_id.as_str()),
        DlqCliCommand::ResolveExpiredOutbox {
            event_id,
            resolution_kind,
            ..
        } => format!(
            "event_id={} resolution_kind={}",
            event_id.as_str(),
            resolution_kind.as_label()
        ),
    };
    format!(
        "operation={} tenant={} {}",
        parsed.command.action().as_str(),
        parsed.tenant,
        target
    )
}

async fn authenticate_dlq_operator_subject(
    service_token: &str,
    operator_tenant: vocab::TenantId,
    pdp: &diport::DynPdp<'_>,
) -> anyhow::Result<String> {
    verified_service_maintenance_operator_subject(
        service_token,
        operator_tenant,
        pdp,
        "DLQ maintenance",
    )
    .await
}

async fn record_dlq_maintenance_finish_audit(
    pg: &PgMaintenanceDeps,
    operator_subject: &str,
    action: &str,
    resource_id: &str,
    outcome: MaintenanceAuditOutcome<'_>,
) -> anyhow::Result<()> {
    pg.record_dlq_maintenance_audit(operator_subject, action, outcome, resource_id)
        .await
        .context("record DLQ maintenance finish audit")
}

async fn dlq_operator_subject(
    pg: &PgMaintenanceDeps,
    parsed: &DlqCliArgs,
    resource_id: &str,
) -> anyhow::Result<String> {
    let operator_provider = match build_provider_with_replay_guard(pg.service_token_replay_guard())
    {
        Ok(provider) => provider,
        Err(err) => {
            record_dlq_maintenance_finish_audit(
                pg,
                UNVERIFIED_DLQ_OPERATOR,
                &format!("dlq.{}.finish", parsed.command.action().as_str()),
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_provider_config",
                },
            )
            .await?;
            return Err(err).context("DLQ maintenance operator verifier");
        }
    };
    let operator_pdp = diport::DynPdp::from_ref(&operator_provider);
    let subject = match authenticate_dlq_operator_subject(
        &parsed.operator_service_token,
        parsed.operator_tenant,
        operator_pdp,
    )
    .await
    {
        Ok(subject) => subject,
        Err(err) => {
            record_dlq_maintenance_finish_audit(
                pg,
                UNVERIFIED_DLQ_OPERATOR,
                &format!("dlq.{}.finish", parsed.command.action().as_str()),
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_auth",
                },
            )
            .await?;
            return Err(err);
        }
    };
    let grants = match load_dlq_operator_grants() {
        Ok(grants) => grants,
        Err(err) => {
            record_dlq_maintenance_finish_audit(
                pg,
                &subject,
                &format!("dlq.{}.finish", parsed.command.action().as_str()),
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_grants",
                },
            )
            .await?;
            return Err(err);
        }
    };
    if let Err(err) = authorize_dlq_operator(&subject, parsed, &grants) {
        record_dlq_maintenance_finish_audit(
            pg,
            &subject,
            &format!("dlq.{}.finish", parsed.command.action().as_str()),
            resource_id,
            MaintenanceAuditOutcome::Failure {
                reason: "operator_authorization",
            },
        )
        .await?;
        return Err(err);
    }
    Ok(subject)
}

/// The single bridge from an authenticated + exactly authorized DLQ principal to the typed
/// terminal-resolution witness. Callers must invoke this only after `dlq_operator_subject` has
/// completed service-token verification and the exact action/tenant grant check.
fn verified_dlq_operator_subject(
    operator_subject: &str,
) -> anyhow::Result<VerifiedOperatorSubject> {
    VerifiedOperatorSubject::from_verified(operator_subject)
        .context("verified DLQ operator subject is invalid")
}

fn dlq_summary_json_line(summary: &DlqEntrySummary) -> anyhow::Result<String> {
    let value = serde_json::json!({
        "kind": summary.kind().as_label(),
        "id": summary.id(),
        "source": summary.source().as_str(),
        "tenant": summary.tenant().to_string(),
        "messageId": summary.message_id(),
        "producerDomain": summary.producer_domain(),
        "consumerDomain": summary.consumer_domain(),
        "contractId": summary.contract_id(),
        "topic": summary.topic(),
        "consumerGroup": summary.consumer_group(),
        "payloadLen": summary.payload_len(),
        "errorSummary": summary.error_summary(),
        "numAttempts": summary.num_attempts(),
        "lastAttemptEpochSecs": summary.last_attempt_epoch_secs(),
    });
    serde_json::to_string(&value).context("render DLQ summary json")
}

fn print_dlq_summary(summary: &DlqEntrySummary) -> anyhow::Result<()> {
    println!("{}", dlq_summary_json_line(summary)?);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DlqCommandOutcome {
    Completed,
    Expired,
    Rejected(&'static str),
}

fn dlq_redrive_result_line(
    tenant: vocab::TenantId,
    event_id: &IdemKey,
    outcome: DlqRedriveOutcome,
) -> String {
    format!(
        "operation=redrive-outbox tenant={tenant} event_id={} outcome={}",
        event_id.as_str(),
        outcome.as_label()
    )
}

#[allow(clippy::too_many_arguments)]
// reason: the helper receives one closed CLI command's typed fields plus its authorized witnesses.
async fn run_expired_outbox_resolution<S: DlqStore>(
    store: &S,
    tenant: vocab::TenantId,
    event_id: &IdemKey,
    change_ticket: &OutboxResolutionChangeTicket,
    resolution_kind: OutboxExpiredResolutionKind,
    evidence_event_id: Option<&IdemKey>,
    capability: OperatorDlqCapability,
    operator_subject: &VerifiedOperatorSubject,
) -> anyhow::Result<DlqCommandOutcome> {
    let request = match resolution_kind {
        OutboxExpiredResolutionKind::AcceptedGap => OutboxExpiredResolutionRequest::accepted_gap(
            tenant,
            event_id.clone(),
            change_ticket.clone(),
            operator_subject.clone(),
            capability,
        ),
        OutboxExpiredResolutionKind::Compensated => {
            let evidence_event_id = evidence_event_id
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("compensated evidence invariant"))?;
            OutboxExpiredResolutionRequest::compensated(
                tenant,
                event_id.clone(),
                evidence_event_id,
                change_ticket.clone(),
                operator_subject.clone(),
                capability,
            )
        }
    };
    let outcome = store.resolve_expired_outbox(request).await?;
    println!(
        "operation=resolve-expired-outbox tenant={} event_id={} resolution_kind={} outcome={}",
        tenant,
        event_id.as_str(),
        resolution_kind.as_label(),
        outcome.as_label()
    );
    match outcome {
        OutboxExpiredResolutionOutcome::Resolved | OutboxExpiredResolutionOutcome::NotFound => {
            Ok(DlqCommandOutcome::Completed)
        }
        OutboxExpiredResolutionOutcome::NotExpired => {
            Ok(DlqCommandOutcome::Rejected("not_expired"))
        }
        OutboxExpiredResolutionOutcome::EvidenceRejected => {
            Ok(DlqCommandOutcome::Rejected("evidence_rejected"))
        }
    }
}

async fn run_dlq_command_inner<S: DlqStore>(
    store: &S,
    parsed: &DlqCliArgs,
    capability: OperatorDlqCapability,
    operator_subject: &VerifiedOperatorSubject,
) -> anyhow::Result<DlqCommandOutcome> {
    match &parsed.command {
        DlqCliCommand::List {
            source,
            producer_domain,
            consumer_domain,
            contract_id,
            limit,
            cursor,
        } => {
            let mut query = DlqListQuery::new(parsed.tenant).with_limit(*limit);
            if let Some(source) = source {
                query = query.with_source(*source);
            }
            if let Some(domain) = producer_domain {
                query = query.with_producer_domain(domain.clone());
            }
            if let Some(domain) = consumer_domain {
                query = query.with_consumer_domain(domain.clone());
            }
            if let Some(contract_id) = contract_id {
                query = query.with_contract_id(contract_id.clone());
            }
            if let Some(cursor) = cursor {
                query = query.with_cursor(cursor.clone());
            }
            let result = store.list_dlq(query).await?;
            for summary in result.data() {
                print_dlq_summary(summary)?;
            }
            println!(
                "operation=list tenant={} count={} has_more={} next_cursor={}",
                parsed.tenant,
                result.data().len(),
                result.has_more(),
                result.next_cursor().unwrap_or("none")
            );
            Ok(DlqCommandOutcome::Completed)
        }
        DlqCliCommand::Inspect { target } => {
            let summary = store
                .inspect_dlq(DlqInspectRequest::new(parsed.tenant, target.clone()))
                .await?;
            print_dlq_summary(&summary)?;
            match target {
                DlqInspectTarget::DeadLetter(dead_letter_id) => println!(
                    "operation=inspect tenant={} kind=dead_letter dead_letter_id={}",
                    parsed.tenant, dead_letter_id
                ),
                DlqInspectTarget::OutboxDlx(event_id) => println!(
                    "operation=inspect tenant={} kind=outbox_dlx event_id={}",
                    parsed.tenant,
                    event_id.as_str()
                ),
            }
            Ok(DlqCommandOutcome::Completed)
        }
        DlqCliCommand::ReplayDeadLetter {
            dead_letter_id,
            replay_id,
        } => {
            let outcome = store
                .replay_dead_letter(DlqReplayRequest::new(
                    parsed.tenant,
                    dead_letter_id.clone(),
                    replay_id.clone(),
                    capability,
                ))
                .await?;
            println!(
                "operation=replay-dead-letter tenant={} dead_letter_id={} replay_id={} outcome={}",
                parsed.tenant,
                dead_letter_id,
                replay_id.as_str(),
                outcome.as_label()
            );
            Ok(DlqCommandOutcome::Completed)
        }
        DlqCliCommand::RedriveOutbox { event_id } => {
            let outcome = store
                .redrive_outbox(DlqRedriveRequest::new(
                    parsed.tenant,
                    event_id.clone(),
                    capability,
                ))
                .await?;
            println!(
                "{}",
                dlq_redrive_result_line(parsed.tenant, event_id, outcome)
            );
            match outcome {
                DlqRedriveOutcome::Expired => Ok(DlqCommandOutcome::Expired),
                DlqRedriveOutcome::Redriven | DlqRedriveOutcome::NotFound => {
                    Ok(DlqCommandOutcome::Completed)
                }
            }
        }
        DlqCliCommand::ResolveExpiredOutbox {
            event_id,
            change_ticket,
            resolution_kind,
            evidence_event_id,
        } => {
            run_expired_outbox_resolution(
                store,
                parsed.tenant,
                event_id,
                change_ticket,
                *resolution_kind,
                evidence_event_id.as_ref(),
                capability,
                operator_subject,
            )
            .await
        }
    }
}

#[allow(async_fn_in_trait)]
trait DlqControlRuntime {
    type Session;
    type Store: DlqStore;

    async fn connect_maintenance(&self) -> anyhow::Result<Self::Session>;

    async fn record_dlq_maintenance_audit(
        &self,
        session: &Self::Session,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> anyhow::Result<()>;

    async fn operator_subject(
        &self,
        session: &Self::Session,
        parsed: &DlqCliArgs,
        resource_id: &str,
    ) -> anyhow::Result<String>;

    fn dlq_store(
        &self,
        session: &Self::Session,
        command: &DlqCliCommand,
    ) -> anyhow::Result<Self::Store>;

    async fn shutdown(&self, session: Self::Session);
}

struct ProductionDlqControlRuntime<'a> {
    config: SnapshotConfig<'a>,
}

impl DlqControlRuntime for ProductionDlqControlRuntime<'_> {
    type Session = PgMaintenanceDeps;
    type Store = PgDlqStore;

    async fn connect_maintenance(&self) -> anyhow::Result<Self::Session> {
        PgRuntimeDeps::connect_maintenance(&build_pg_migrator_config(self.config)?)
            .await
            .context("setup postgres maintenance deps")
    }

    async fn record_dlq_maintenance_audit(
        &self,
        session: &Self::Session,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> anyhow::Result<()> {
        session
            .record_dlq_maintenance_audit(operator_subject, action, outcome, resource_id)
            .await
            .context("record DLQ maintenance audit")
    }

    async fn operator_subject(
        &self,
        session: &Self::Session,
        parsed: &DlqCliArgs,
        resource_id: &str,
    ) -> anyhow::Result<String> {
        dlq_operator_subject(session, parsed, resource_id).await
    }

    fn dlq_store(
        &self,
        session: &Self::Session,
        command: &DlqCliCommand,
    ) -> anyhow::Result<Self::Store> {
        if command.requires_payload_protector() {
            let dlx_payload_protector =
                event_transport::build_dlx_payload_protector_from(&|name| std::env::var(name).ok())
                    .context("build DLQ payload protector")?;
            Ok(session.dlq_store(dlx_payload_protector, generated::event::PROJECTION_INPUTS))
        } else {
            Ok(session.dlq_store_without_payload_replay())
        }
    }

    async fn shutdown(&self, session: Self::Session) {
        session.shutdown().await.ok();
    }
}

async fn run_dlq_control_command_with_runtime<R>(args: &[String], runtime: &R) -> anyhow::Result<()>
where
    R: DlqControlRuntime,
{
    let parsed = parse_dlq_args(args)?;
    let resource_id = dlq_command_resource_id(&parsed);
    let session = runtime.connect_maintenance().await?;
    let start_action = format!("dlq.{}.start", parsed.command.action().as_str());
    if let Err(err) = runtime
        .record_dlq_maintenance_audit(
            &session,
            UNVERIFIED_DLQ_OPERATOR,
            &start_action,
            MaintenanceAuditOutcome::Success,
            &resource_id,
        )
        .await
        .context("record DLQ maintenance start audit")
    {
        runtime.shutdown(session).await;
        return Err(err);
    }

    let finish_action = format!("dlq.{}.finish", parsed.command.action().as_str());
    let operator_subject = match runtime
        .operator_subject(&session, &parsed, &resource_id)
        .await
    {
        Ok(subject) => subject,
        Err(err) => {
            runtime.shutdown(session).await;
            return Err(err);
        }
    };
    let capability = issue_authorized_dlq_capability();
    // This wrapper is deliberately created only after service-token verification and exact
    // action/tenant grant authorization have both succeeded in `operator_subject`.
    let verified_operator_subject = verified_dlq_operator_subject(&operator_subject);
    let command_result = match (
        verified_operator_subject,
        runtime.dlq_store(&session, &parsed.command),
    ) {
        (Ok(operator_subject), Ok(store)) => {
            run_dlq_command_inner(&store, &parsed, capability, &operator_subject).await
        }
        (Err(err), _) | (_, Err(err)) => Err(err),
    };
    let finish_outcome = match &command_result {
        Ok(DlqCommandOutcome::Completed) => MaintenanceAuditOutcome::Success,
        Ok(DlqCommandOutcome::Expired) => MaintenanceAuditOutcome::Failure { reason: "expired" },
        Ok(DlqCommandOutcome::Rejected(reason)) => MaintenanceAuditOutcome::Failure { reason },
        Err(_) => MaintenanceAuditOutcome::Failure {
            reason: "run_error",
        },
    };
    let audit_result = runtime
        .record_dlq_maintenance_audit(
            &session,
            &operator_subject,
            &finish_action,
            finish_outcome,
            &resource_id,
        )
        .await
        .context("record DLQ maintenance finish audit");
    runtime.shutdown(session).await;
    audit_result?;
    match command_result.with_context(|| format!("DLQ command failed: {resource_id}"))? {
        DlqCommandOutcome::Completed => Ok(()),
        DlqCommandOutcome::Expired => {
            anyhow::bail!("DLQ command failed: {resource_id}: redrive horizon expired")
        }
        DlqCommandOutcome::Rejected(reason) => {
            anyhow::bail!("DLQ command failed: {resource_id}: {reason}")
        }
    }
}

fn issue_authorized_dlq_capability() -> OperatorDlqCapability {
    OperatorDlqCapability::issue_for_authorized_operator()
}

/// 执行 `rss dlq ...`。
pub async fn run_dlq_control_command(
    args: &[String],
    runtime_inputs: &RuntimeInputs,
) -> anyhow::Result<()> {
    let runtime = ProductionDlqControlRuntime {
        config: runtime_inputs.config(),
    };
    run_dlq_control_command_with_runtime(args, &runtime).await
}

/// Whether the rss binary was invoked for reconcile target inspection or recovery.
#[must_use]
pub fn is_reconcile_target_command(args: &[String]) -> bool {
    matches!(args, [cmd, ..] if cmd == "reconcile-target")
}

const RECONCILE_OPERATOR_GRANTS_ENV: &str = "RSS_RECONCILE_OPERATOR_GRANTS";
const UNVERIFIED_RECONCILE_OPERATOR: &str = "unverified-service-token";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileMaintenanceAction {
    Inspect,
    Resume,
}

impl ReconcileMaintenanceAction {
    fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw {
            "inspect" => Ok(Self::Inspect),
            "resume" => Ok(Self::Resume),
            other => anyhow::bail!(
                "unknown reconcile target action in {RECONCILE_OPERATOR_GRANTS_ENV}: {other}"
            ),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Resume => "resume",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReconcileTargetCliArgs {
    action: ReconcileMaintenanceAction,
    operator_service_token: String,
    operator_tenant: vocab::TenantId,
    tenant: vocab::TenantId,
    target_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReconcileMaintenanceGrant {
    subject: String,
    action: ReconcileMaintenanceAction,
    tenant: vocab::TenantId,
}

fn reconcile_target_usage() -> &'static str {
    "usage: rss reconcile-target inspect|resume --operator-service-token <token> --operator-tenant <uuid> --tenant <uuid> --target-id <uuid>"
}

fn parse_reconcile_target_args(args: &[String]) -> anyhow::Result<ReconcileTargetCliArgs> {
    anyhow::ensure!(is_reconcile_target_command(args), reconcile_target_usage());
    let action = args
        .get(1)
        .ok_or_else(|| anyhow::anyhow!(reconcile_target_usage()))
        .and_then(|raw| ReconcileMaintenanceAction::parse(raw))?;
    let mut operator_service_token = None;
    let mut operator_tenant = None;
    let mut tenant = None;
    let mut target_id = None;
    let mut it = args[2..].iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--operator-service-token" => {
                let value = next_cli_value(&mut it, "--operator-service-token")?;
                let value = value.trim();
                anyhow::ensure!(
                    !value.is_empty(),
                    "--operator-service-token must be non-empty"
                );
                set_cli_arg_once(
                    &mut operator_service_token,
                    "--operator-service-token",
                    value.to_owned(),
                )?;
            }
            "--operator-tenant" => {
                let value = next_cli_value(&mut it, "--operator-tenant")?;
                set_cli_arg_once(
                    &mut operator_tenant,
                    "--operator-tenant",
                    vocab::TenantId::parse(value).with_context(|| {
                        format!("--operator-tenant must be a tenant UUID: {value}")
                    })?,
                )?;
            }
            "--tenant" => {
                let value = next_cli_value(&mut it, "--tenant")?;
                set_cli_arg_once(
                    &mut tenant,
                    "--tenant",
                    vocab::TenantId::parse(value)
                        .with_context(|| format!("--tenant must be a tenant UUID: {value}"))?,
                )?;
            }
            "--target-id" => {
                let value = next_cli_value(&mut it, "--target-id")?;
                let parsed = uuid::Uuid::parse_str(value)
                    .with_context(|| format!("--target-id must be a UUID: {value}"))?;
                set_cli_arg_once(&mut target_id, "--target-id", parsed.to_string())?;
            }
            other => anyhow::bail!("unknown reconcile target argument: {other}"),
        }
    }
    Ok(ReconcileTargetCliArgs {
        action,
        operator_service_token: operator_service_token
            .ok_or_else(|| anyhow::anyhow!("--operator-service-token is required"))?,
        operator_tenant: operator_tenant
            .ok_or_else(|| anyhow::anyhow!("--operator-tenant is required"))?,
        tenant: tenant.ok_or_else(|| anyhow::anyhow!("--tenant is required"))?,
        target_id: target_id.ok_or_else(|| anyhow::anyhow!("--target-id is required"))?,
    })
}

fn parse_reconcile_operator_grants(raw: &str) -> anyhow::Result<Vec<ReconcileMaintenanceGrant>> {
    let raw = raw.trim();
    anyhow::ensure!(
        !raw.is_empty(),
        "{RECONCILE_OPERATOR_GRANTS_ENV} must not be empty"
    );
    let mut grants = Vec::new();
    for entry in raw.split(',') {
        let parts: Vec<_> = entry.split('|').map(str::trim).collect();
        anyhow::ensure!(
            parts.len() == 3,
            "{RECONCILE_OPERATOR_GRANTS_ENV} entries must be subject|action|tenant"
        );
        let [subject, action, tenant] = parts.as_slice() else {
            unreachable!("length checked");
        };
        anyhow::ensure!(
            !subject.is_empty(),
            "{RECONCILE_OPERATOR_GRANTS_ENV} subject must be non-empty"
        );
        grants.push(ReconcileMaintenanceGrant {
            subject: (*subject).to_owned(),
            action: ReconcileMaintenanceAction::parse(action)?,
            tenant: vocab::TenantId::parse(tenant).with_context(|| {
                format!("{RECONCILE_OPERATOR_GRANTS_ENV} tenant must be a UUID: {tenant}")
            })?,
        });
    }
    Ok(grants)
}

fn authorize_reconcile_operator(
    subject: &str,
    parsed: &ReconcileTargetCliArgs,
    grants: &[ReconcileMaintenanceGrant],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        grants.iter().any(|grant| {
            grant.subject == subject
                && grant.action == parsed.action
                && grant.tenant == parsed.tenant
        }),
        "reconcile target operator is not authorized for action={} tenant={}",
        parsed.action.as_str(),
        parsed.tenant
    );
    Ok(())
}

async fn record_reconcile_audit(
    pg: &PgMaintenanceDeps,
    subject: &str,
    action: &str,
    outcome: MaintenanceAuditOutcome<'_>,
    resource_id: &str,
) -> anyhow::Result<()> {
    pg.record_reconcile_maintenance_audit(subject, action, outcome, resource_id)
        .await
        .context("record reconcile target maintenance audit")
}

fn reconcile_summary_json(summary: &ReconcileTargetSummary) -> anyhow::Result<String> {
    serde_json::to_string(&serde_json::json!({
        "tenant": summary.tenant().to_string(),
        "targetId": summary.target_id(),
        "reconcilerId": summary.reconciler_id(),
        "resourceKind": summary.resource_kind(),
        "status": summary.status().as_label(),
        "disabledReason": summary.disabled_reason().map(|reason| reason.as_label()),
    }))
    .context("render reconcile target summary")
}

async fn execute_reconcile_target_command(
    store: &PgReconcileStore,
    parsed: &ReconcileTargetCliArgs,
    capability: OperatorReconcileCapability,
) -> anyhow::Result<ReconcileTargetSummary> {
    match parsed.action {
        ReconcileMaintenanceAction::Inspect => ReconcileOperatorStore::inspect_target(
            store,
            parsed.tenant,
            &parsed.target_id,
            capability,
        )
        .await
        .map_err(anyhow::Error::new),
        ReconcileMaintenanceAction::Resume => ReconcileOperatorStore::resume_target(
            store,
            parsed.tenant,
            &parsed.target_id,
            capability,
        )
        .await
        .map_err(anyhow::Error::new),
    }
}

fn issue_authorized_reconcile_capability() -> OperatorReconcileCapability {
    OperatorReconcileCapability::issue_for_authorized_operator()
}

/// Execute an authenticated, audited tenant-scoped reconcile target operator command.
pub async fn run_reconcile_target_command(
    args: &[String],
    runtime_inputs: &RuntimeInputs,
) -> anyhow::Result<()> {
    let parsed = parse_reconcile_target_args(args)?;
    let resource_id = format!("tenant={} target_id={}", parsed.tenant, parsed.target_id);
    let start_action = format!("reconcile.target.{}.start", parsed.action.as_str());
    let finish_action = format!("reconcile.target.{}.finish", parsed.action.as_str());
    let pg =
        PgRuntimeDeps::connect_maintenance(&build_pg_migrator_config(runtime_inputs.config())?)
            .await
            .context("setup postgres maintenance deps")?;
    if let Err(error) = record_reconcile_audit(
        &pg,
        UNVERIFIED_RECONCILE_OPERATOR,
        &start_action,
        MaintenanceAuditOutcome::Success,
        &resource_id,
    )
    .await
    {
        pg.shutdown().await.ok();
        return Err(error);
    }
    let provider = match build_provider_with_replay_guard(pg.service_token_replay_guard()) {
        Ok(provider) => provider,
        Err(error) => {
            record_reconcile_audit(
                &pg,
                UNVERIFIED_RECONCILE_OPERATOR,
                &finish_action,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_provider_config",
                },
                &resource_id,
            )
            .await?;
            pg.shutdown().await.ok();
            return Err(error).context("reconcile target operator verifier");
        }
    };
    let subject = match verified_service_maintenance_operator_subject(
        &parsed.operator_service_token,
        parsed.operator_tenant,
        diport::DynPdp::from_ref(&provider),
        "reconcile target maintenance",
    )
    .await
    {
        Ok(subject) => subject,
        Err(error) => {
            record_reconcile_audit(
                &pg,
                UNVERIFIED_RECONCILE_OPERATOR,
                &finish_action,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_auth",
                },
                &resource_id,
            )
            .await?;
            pg.shutdown().await.ok();
            return Err(error);
        }
    };
    let authorization = std::env::var(RECONCILE_OPERATOR_GRANTS_ENV)
        .with_context(|| format!("{RECONCILE_OPERATOR_GRANTS_ENV} is required"))
        .and_then(|raw| parse_reconcile_operator_grants(&raw))
        .and_then(|grants| authorize_reconcile_operator(&subject, &parsed, &grants));
    if let Err(error) = authorization {
        record_reconcile_audit(
            &pg,
            &subject,
            &finish_action,
            MaintenanceAuditOutcome::Failure {
                reason: "operator_authorization",
            },
            &resource_id,
        )
        .await?;
        pg.shutdown().await.ok();
        return Err(error);
    }
    let command_result = execute_reconcile_target_command(
        &pg.reconcile_store(),
        &parsed,
        issue_authorized_reconcile_capability(),
    )
    .await;
    let outcome = if command_result.is_ok() {
        MaintenanceAuditOutcome::Success
    } else {
        MaintenanceAuditOutcome::Failure {
            reason: "run_error",
        }
    };
    let audit_result =
        record_reconcile_audit(&pg, &subject, &finish_action, outcome, &resource_id).await;
    pg.shutdown().await.ok();
    audit_result?;
    let summary = command_result?;
    println!("{}", reconcile_summary_json(&summary)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct SettingsConfigValueMaintenanceArgs {
    options: ConfigValueMaintenanceOptions,
    operator_service_token: String,
    operator_tenant: vocab::TenantId,
}

fn parse_settings_config_value_maintenance_args(
    args: &[String],
) -> anyhow::Result<SettingsConfigValueMaintenanceArgs> {
    anyhow::ensure!(
        is_settings_config_value_maintenance_command(args),
        "usage: rss settings-config-values maintenance --operator-service-token <token> --operator-tenant <uuid> [--operation backfill|rewrap|both] [--tenant <uuid>] [--batch-size <n>] [--max-rows <n>] [--dry-run]"
    );
    let mut options = ConfigValueMaintenanceOptions::default();
    let mut operator_service_token = None;
    let mut operator_tenant = None;
    let mut it = args[2..].iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--operator-service-token" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--operator-service-token requires a value"))?;
                let trimmed = raw.trim();
                anyhow::ensure!(
                    !trimmed.is_empty(),
                    "--operator-service-token must be non-empty"
                );
                operator_service_token = Some(trimmed.to_owned());
            }
            "--operator-tenant" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--operator-tenant requires a value"))?;
                let tenant = vocab::TenantId::parse(raw)
                    .with_context(|| format!("--operator-tenant must be a tenant UUID: {raw}"))?;
                operator_tenant = Some(tenant);
            }
            "--operation" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--operation requires a value"))?;
                options = ConfigValueMaintenanceOptions::new(
                    parse_config_value_maintenance_operation(raw)?,
                )
                .with_tenant_opt(options.tenant_opt())
                .with_batch_size(options.batch_size())
                .with_max_rows(options.max_rows())
                .with_dry_run(options.dry_run());
            }
            "--tenant" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--tenant requires a value"))?;
                let tenant = vocab::TenantId::parse(raw)
                    .with_context(|| format!("--tenant must be a tenant UUID: {raw}"))?;
                options = options.with_tenant(tenant);
            }
            "--batch-size" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--batch-size requires a value"))?;
                options = options.with_batch_size(parse_positive_usize(raw, "--batch-size")?);
            }
            "--max-rows" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--max-rows requires a value"))?;
                options = options.with_max_rows(Some(parse_positive_usize(raw, "--max-rows")?));
            }
            "--dry-run" => {
                options = options.with_dry_run(true);
            }
            other => {
                anyhow::bail!("unknown settings config value maintenance argument: {other}");
            }
        }
    }
    let operator_service_token = operator_service_token
        .ok_or_else(|| anyhow::anyhow!("--operator-service-token is required"))?;
    let operator_tenant =
        operator_tenant.ok_or_else(|| anyhow::anyhow!("--operator-tenant is required"))?;
    Ok(SettingsConfigValueMaintenanceArgs {
        options,
        operator_service_token,
        operator_tenant,
    })
}

fn settings_config_value_maintenance_resource_id(
    options: &ConfigValueMaintenanceOptions,
) -> String {
    let scope = options
        .tenant_opt()
        .map(|tenant| format!("tenant:{tenant}"))
        .unwrap_or_else(|| "all".to_owned());
    let max_rows = options
        .max_rows()
        .map(|max_rows| max_rows.to_string())
        .unwrap_or_else(|| "none".to_owned());
    format!(
        "operation={} scope={} dry_run={} batch_size={} max_rows={}",
        options.operation().as_str(),
        scope,
        options.dry_run(),
        options.batch_size(),
        max_rows
    )
}

const UNVERIFIED_CONFIG_MAINTENANCE_OPERATOR: &str = "unverified-service-token";

async fn verified_config_value_maintenance_operator_subject(
    service_token: &str,
    operator_tenant: vocab::TenantId,
    pdp: &diport::DynPdp<'_>,
) -> anyhow::Result<String> {
    verified_service_maintenance_operator_subject(
        service_token,
        operator_tenant,
        pdp,
        "settings config value maintenance",
    )
    .await
}

async fn record_config_value_maintenance_finish_audit(
    pg: &PgMaintenanceDeps,
    operator_subject: &str,
    resource_id: &str,
    outcome: MaintenanceAuditOutcome<'_>,
) -> anyhow::Result<()> {
    pg.record_config_value_maintenance_audit(
        operator_subject,
        "settings.config-values.maintenance.finish",
        outcome,
        resource_id,
    )
    .await
    .context("record settings config value maintenance finish audit")
}

async fn settings_config_value_maintenance_operator_subject(
    pg: &PgMaintenanceDeps,
    parsed: &SettingsConfigValueMaintenanceArgs,
    resource_id: &str,
) -> anyhow::Result<String> {
    let operator_provider = match build_provider() {
        Ok(provider) => provider,
        Err(err) => {
            record_config_value_maintenance_finish_audit(
                pg,
                UNVERIFIED_CONFIG_MAINTENANCE_OPERATOR,
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_provider_config",
                },
            )
            .await?;
            return Err(err).context("settings config value maintenance operator verifier");
        }
    };
    let operator_pdp = diport::DynPdp::from_ref(&operator_provider);
    match verified_config_value_maintenance_operator_subject(
        &parsed.operator_service_token,
        parsed.operator_tenant,
        operator_pdp,
    )
    .await
    {
        Ok(subject) => Ok(subject),
        Err(err) => {
            record_config_value_maintenance_finish_audit(
                pg,
                UNVERIFIED_CONFIG_MAINTENANCE_OPERATOR,
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_auth",
                },
            )
            .await?;
            Err(err)
        }
    }
}

async fn settings_config_value_maintenance_protection(
    pg: &PgMaintenanceDeps,
    operator_subject: &str,
    resource_id: &str,
) -> anyhow::Result<ConfigValueProtection> {
    let key_provider = match build_vault_key_provider_from(|name| std::env::var(name).ok()) {
        Ok(provider) => provider,
        Err(err) => {
            record_config_value_maintenance_finish_audit(
                pg,
                operator_subject,
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "key_provider_config",
                },
            )
            .await?;
            return Err(err).context("settings config value maintenance key provider");
        }
    };
    let key_name = match build_settings_config_value_key_name_from(|name| std::env::var(name).ok())
    {
        Ok(key_name) => key_name,
        Err(err) => {
            record_config_value_maintenance_finish_audit(
                pg,
                operator_subject,
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "key_name_config",
                },
            )
            .await?;
            return Err(err).context("settings config value key name");
        }
    };
    Ok(ConfigValueProtection::new(
        DynKeyProvider::new_box(key_provider),
        key_name,
    ))
}

/// 执行 `rss settings-config-values maintenance`。
pub async fn run_settings_config_value_maintenance(
    args: &[String],
    runtime_inputs: &RuntimeInputs,
) -> anyhow::Result<()> {
    let parsed = parse_settings_config_value_maintenance_args(args)?;
    let options = parsed.options.clone();
    let resource_id = settings_config_value_maintenance_resource_id(&options);
    let pg =
        PgRuntimeDeps::connect_maintenance(&build_pg_migrator_config(runtime_inputs.config())?)
            .await
            .context("setup postgres maintenance deps")?;
    pg.record_config_value_maintenance_audit(
        UNVERIFIED_CONFIG_MAINTENANCE_OPERATOR,
        "settings.config-values.maintenance.start",
        MaintenanceAuditOutcome::Success,
        &resource_id,
    )
    .await
    .context("record settings config value maintenance start audit")?;
    let operator_subject = match settings_config_value_maintenance_operator_subject(
        &pg,
        &parsed,
        &resource_id,
    )
    .await
    {
        Ok(subject) => subject,
        Err(err) => {
            pg.shutdown().await.ok();
            return Err(err);
        }
    };
    let capability =
        ConfigValueMaintenanceCapability::from_verified_service_subject(operator_subject.clone())
            .context("settings config value maintenance operator subject")?;
    let protection =
        match settings_config_value_maintenance_protection(&pg, &operator_subject, &resource_id)
            .await
        {
            Ok(protection) => protection,
            Err(err) => {
                pg.shutdown().await.ok();
                return Err(err);
            }
        };
    let maintenance = pg.config_value_maintenance(protection, capability);
    let report = match maintenance.run(&options).await {
        Ok(report) => report,
        Err(err) => {
            record_config_value_maintenance_finish_audit(
                &pg,
                &operator_subject,
                &resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "run_error",
                },
            )
            .await
            .context("record settings config value maintenance failure audit")?;
            pg.shutdown().await.ok();
            return Err(err).context("settings config value maintenance");
        }
    };
    let audit_outcome = if report.failed == 0 {
        MaintenanceAuditOutcome::Success
    } else {
        MaintenanceAuditOutcome::Failure {
            reason: "failed_rows",
        }
    };
    record_config_value_maintenance_finish_audit(
        &pg,
        &operator_subject,
        &resource_id,
        audit_outcome,
    )
    .await?;
    let scope = options
        .tenant_opt()
        .map(|tenant| format!("tenant:{tenant}"))
        .unwrap_or_else(|| "all".to_owned());
    let max_rows = options
        .max_rows()
        .map(|max_rows| max_rows.to_string())
        .unwrap_or_else(|| "none".to_owned());
    println!(
        "operation={} dry_run={} scope={} batch_size={} max_rows={} selected={} backfilled={} rewrapped={} unchanged={} failed={} remaining_plaintext={}",
        options.operation().as_str(),
        options.dry_run(),
        scope,
        options.batch_size(),
        max_rows,
        report.selected,
        report.backfilled,
        report.rewrapped,
        report.unchanged,
        report.failed,
        report.remaining_plaintext
    );
    pg.shutdown().await.ok();
    anyhow::ensure!(
        report.failed == 0,
        "settings config value maintenance completed with failed rows"
    );
    Ok(())
}

// ── RlsReadyProbe ──────────────────────────────────────────────────────────────────────────────

/// RLS 能力门 readyz 兜底探针稳定名（underscore_case，与 prometheus 约定一致）。
pub const RLS_READY_PROBE_NAME: &str = "rls_ready";

/// RLS 能力门 readyz 兜底探针——读 [`PgRuntimeHandle::rls_ready_handle`] 的启动核验镜像（非 pool）。
///
/// 启动期 `verify_rls_capability` 失败时 `setup` 直接 fail-fast（进程不进入服务态），故进程在跑 ⇒ 此探针
/// 恒 `Healthy`；其价值是把「durable RLS 能力已就绪」这一不变式**显式暴露**到 readyz（运维可见），并为
/// 后续周期性再核验留接线点（届时改为写采样状态即可，探针形态不变）。
///
/// `check`（sync，non-blocking）：读 `AtomicBool`（Acquire），`true → Healthy("ready")` /
/// `false → Unhealthy("not-enforced")`（fail-closed）。`detail` 固定 `&'static str` const（禁夹带 PII）。
pub struct RlsReadyProbe {
    ready: Arc<std::sync::atomic::AtomicBool>,
    name: ProbeName,
}

impl RlsReadyProbe {
    /// 构造 `RlsReadyProbe`（读 RLS 能力门镜像）。`name` 应使用 [`RLS_READY_PROBE_NAME`] 常量。
    #[allow(clippy::expect_used)]
    pub fn new(ready: Arc<std::sync::atomic::AtomicBool>) -> Self {
        // reason: RLS_READY_PROBE_NAME 是 underscore_case const literal，ProbeName::parse 仅失败于非法
        // 字符；const 已手工验证，expect 是构造期 programmer error（不可恢复，同 ConfigsReadyProbe）。
        let name = ProbeName::parse(RLS_READY_PROBE_NAME).expect("valid probe name const");
        Self { ready, name }
    }
}

impl bootstrap::HealthProbe for RlsReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = if self.ready.load(std::sync::atomic::Ordering::Acquire) {
            (HealthStatus::Healthy, "ready")
        } else {
            (HealthStatus::Unhealthy, "not-enforced")
        };
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

// ── SessionSweeperProbe / worker ──────────────────────────────────────────────────────────────

const SESSION_SWEEPER_HEALTHY: u8 = 0;
const SESSION_SWEEPER_DEGRADED: u8 = 1;
const SESSION_SWEEPER_STOPPED: u8 = 2;

struct SessionSweeperHealth(std::sync::atomic::AtomicU8);

impl SessionSweeperHealth {
    fn healthy() -> Self {
        Self(std::sync::atomic::AtomicU8::new(SESSION_SWEEPER_HEALTHY))
    }

    fn mark_healthy(&self) {
        self.0.store(
            SESSION_SWEEPER_HEALTHY,
            std::sync::atomic::Ordering::Release,
        );
    }

    fn mark_degraded(&self) {
        self.0.store(
            SESSION_SWEEPER_DEGRADED,
            std::sync::atomic::Ordering::Release,
        );
    }

    fn mark_stopped(&self) {
        self.0.store(
            SESSION_SWEEPER_STOPPED,
            std::sync::atomic::Ordering::Release,
        );
    }

    fn status_detail(&self) -> (HealthStatus, &'static str) {
        match self.0.load(std::sync::atomic::Ordering::Acquire) {
            SESSION_SWEEPER_HEALTHY => (HealthStatus::Healthy, "worker"),
            SESSION_SWEEPER_DEGRADED => (HealthStatus::Degraded, "degraded"),
            _ => (HealthStatus::Unhealthy, "stopped"),
        }
    }
}

struct SessionSweeperStoppedGuard(Arc<SessionSweeperHealth>);

impl Drop for SessionSweeperStoppedGuard {
    fn drop(&mut self) {
        self.0.mark_stopped();
    }
}

struct SessionSweeperProbe {
    name: ProbeName,
    health: Arc<SessionSweeperHealth>,
}

impl bootstrap::HealthProbe for SessionSweeperProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = self.health.status_detail();
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

struct SessionSweeperWorker {
    handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    token: CancellationToken,
}

impl ManagedResource for SessionSweeperWorker {
    fn name(&self) -> &str {
        SESSION_SWEEPER_WORKER_NAME
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        let mut handle = self.handle.lock().await;
        if let Some(handle) = handle.take()
            && let Err(err) = handle.await
        {
            tracing::warn!(error = %err, "session sweeper worker join failed");
        }
        Ok(())
    }
}

fn spawn_session_sweeper(
    sweeper: postgres::PgSessionSweeper,
    period: Duration,
    token: CancellationToken,
    health: Arc<SessionSweeperHealth>,
) -> SessionSweeperWorker {
    let child = token.child_token();
    let worker_token = child.clone();
    let handle = tokio::spawn(async move {
        let _stopped = SessionSweeperStoppedGuard(Arc::clone(&health));
        let mut ticker = tokio::time::interval(period);
        loop {
            tokio::select! {
                biased;
                () = worker_token.cancelled() => break,
                _ = ticker.tick() => {
                    tokio::select! {
                        biased;
                        () = worker_token.cancelled() => break,
                        deleted = sweeper.sweep_expired() => {
                            match deleted {
                                Ok(deleted) => {
                                    tracing::debug!(target_table = "sessions", deleted, "session sweeper: tick completed");
                                    health.mark_healthy();
                                }
                                Err(err) => {
                                    tracing::warn!(
                                        target_table = "sessions",
                                        error = %err,
                                        "session sweeper: sweep failed, marking worker degraded; backing off to next tick"
                                    );
                                    health.mark_degraded();
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    SessionSweeperWorker {
        handle: tokio::sync::Mutex::new(Some(handle)),
        token: child,
    }
}

fn session_sweeper_module_result(
    worker: bootstrap::WorkerSpec,
    health: Arc<SessionSweeperHealth>,
) -> anyhow::Result<DomainModuleResult> {
    let probe_name = ProbeName::parse(SESSION_SWEEPER_PROBE_NAME)
        .context("session_sweeper probe name is invalid")?;
    Ok(DomainModuleResult {
        probes: vec![(
            probe_name.clone(),
            Box::new(SessionSweeperProbe {
                name: probe_name,
                health,
            }),
        )],
        workers: vec![worker],
        ..Default::default()
    })
}

fn wire_session_sweeper(pg: &PgRuntimeHandle) -> anyhow::Result<DomainModuleResult> {
    let period = build_session_sweeper_interval();
    let sweeper = pg.infra().session_sweeper();
    let health = Arc::new(SessionSweeperHealth::healthy());
    let worker_health = Arc::clone(&health);
    let worker: bootstrap::WorkerSpec = Box::new(move |token| {
        DynManagedResource::new_box(spawn_session_sweeper(sweeper, period, token, worker_health))
    });
    tracing::info!(
        interval_ms = period.as_millis(),
        "session sweeper interval configured"
    );
    session_sweeper_module_result(worker, health)
}

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
/// 不静默退回 fmt（值非法 ≠ 未配）。返回的 exporter 由 [`run`] 接管生命周期（注册进 `ShutdownStack` 关停时 flush）。
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

/// 在入口捕获唯一一代生产配置，并装配 tracing subscriber（fmt + `RUST_LOG`
/// filter + 可选 otel OTLP/gRPC 桥接 Layer，默认 `info`）。
///
/// 组合根 binary 入口在 [`run`] **之前**调用——否则运行时入口的全部结构化日志
/// （bind / serve / shutdown / fail-fast）皆为 no-op。`RUST_LOG`、[`OTEL_ENDPOINT_ENV`] 与后续
/// serving consumer 全部来自这个 snapshot，不再读取 ambient environment。
///
/// 返回必填 [`RuntimeInputs`]；只有该输入可进入 [`run`] 或 [`shutdown_runtime`]。
pub fn prepare_runtime() -> anyhow::Result<RuntimeInputs> {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    use tracing_subscriber::{EnvFilter, fmt};

    let runtime_config = RuntimeConfigSnapshot::capture(EnvConfigSource)
        .context("capture process runtime configuration")?;
    let config = runtime_config.view();
    let filter = config
        .value("RUST_LOG")
        .and_then(|raw| EnvFilter::try_new(raw).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));
    let trace_export = build_trace_export(config)?;
    // Option<Layer> 即 no-op layer（None → 不导出 trace）：覆盖「配 / 未配 endpoint」两态，subscriber 形态恒定。
    let otel_layer = trace_export.as_ref().map(|e| e.layer());
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(otel_layer)
        .init();
    Ok(RuntimeInputs::new(runtime_config, trace_export))
}

/// Flush the trace exporter when a prepared runtime exits before serving launch.
pub async fn shutdown_runtime(mut runtime_inputs: RuntimeInputs) -> anyhow::Result<()> {
    shutdown_pending_trace_export(&mut runtime_inputs).await
}

async fn shutdown_pending_trace_export(runtime_inputs: &mut RuntimeInputs) -> anyhow::Result<()> {
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
    inputs: RuntimeInputs,
}

impl RuntimeLifecycleOwner {
    fn new(inputs: RuntimeInputs) -> Self {
        Self { inputs }
    }

    async fn run(mut self) -> anyhow::Result<()> {
        let startup_result = run_startup(&mut self.inputs).await;
        self.finish(startup_result).await
    }

    async fn finish(mut self, startup_result: anyhow::Result<()>) -> anyhow::Result<()> {
        let cleanup_result = shutdown_pending_trace_export(&mut self.inputs).await;
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

struct RuntimeModuleAssemblyInputs {
    domains_module: DomainModuleResult,
    session_sweeper_module: DomainModuleResult,
    s3_canary_module: DomainModuleResult,
    provider_module: DomainModuleResult,
    oidc_resource: Box<DynManagedResource<'static>>,
    domain_transport_module: DomainModuleResult,
    event_module: DomainModuleResult,
    dlx_lifecycle_module: DomainModuleResult,
    redis_readiness_worker: bootstrap::WorkerSpec,
}

fn assemble_runtime_module_outputs(inputs: RuntimeModuleAssemblyInputs) -> DomainModuleResult {
    let mut module = DomainModuleResult::default();
    module.merge(inputs.domains_module);
    module.merge(inputs.session_sweeper_module);
    module.merge(inputs.s3_canary_module);
    module.merge(inputs.provider_module);
    module.resources.push(inputs.oidc_resource);
    module.merge(inputs.domain_transport_module);
    module.merge(inputs.event_module);
    module.merge(inputs.dlx_lifecycle_module);
    module.workers.push(inputs.redis_readiness_worker);
    module
}

fn validate_domain_listener_evidence(
    actual: &[bootstrap::DomainListenerBinding],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        actual == modules_gen::DOMAIN_LISTENER_BINDINGS,
        "runtime domain-listener evidence drift: expected {}, observed {}",
        modules_gen::DOMAIN_LISTENER_BINDINGS.len(),
        actual.len()
    );
    Ok(())
}

fn validate_provider_output_evidence() -> anyhow::Result<()> {
    let mut actual = provider_output::provider_output_bindings();
    actual.extend_from_slice(event_transport::PROVIDER_OUTPUT_BINDINGS);
    validate_provider_output_bindings(&actual)
}

fn validate_provider_output_bindings(
    actual: &[bootstrap::ProviderOutputBinding],
) -> anyhow::Result<()> {
    let mut actual = actual.to_vec();
    actual.sort_by_key(|binding| (binding.port, binding.provider, binding.consumer));
    let mut expected: Vec<_> = modules_gen::PROVIDER_OUTPUT_BINDINGS
        .iter()
        .copied()
        .filter(|binding| !binding.channels.is_empty())
        .collect();
    expected.sort_by_key(|binding| (binding.port, binding.provider, binding.consumer));
    anyhow::ensure!(
        actual == expected,
        "runtime provider-output evidence drift: expected {}, observed {}",
        expected.len(),
        actual.len()
    );
    Ok(())
}

async fn after_required_preflight<Capability, Output, Preflight, Migrate>(
    preflight: Preflight,
    migrate: impl FnOnce(Capability) -> Migrate,
) -> anyhow::Result<Output>
where
    Preflight: std::future::Future<Output = anyhow::Result<Capability>>,
    Migrate: std::future::Future<Output = anyhow::Result<Output>>,
{
    let capability = preflight.await?;
    migrate(capability).await
}

/// 生产组合根入口：构造共享基础设施 → generated domains → `compose_bindings`
/// → 聚合 readiness/lifecycle outputs → 装配认证接线 → 挂 Health listener
/// → bind + serve + 信号优雅关停。
///
/// 缺配 / 连不上 / migration 失败均 **fail-fast**（不静默 ready）。各域业务 handler ↔ service 接线
/// 由 manifest-derived domain list 驱动，禁止回退为手写 per-domain wiring。
/// tracing subscriber 与配置 snapshot 由 [`prepare_runtime`] 在 `main` 中先于本 fn 装配。
// reason: 组合根入口顺序编排（provider setup → generated domains → compose → finalize → serve）
// 多条 tracing 宏展开在 cognitive_complexity 计数贡献额外节点——item-level carve-out（error-handling.md §Carve-out）。
#[allow(clippy::cognitive_complexity)]
pub async fn run(runtime_inputs: RuntimeInputs) -> anyhow::Result<()> {
    RuntimeLifecycleOwner::new(runtime_inputs).run().await
}

#[allow(clippy::cognitive_complexity)]
async fn run_startup(runtime_inputs: &mut RuntimeInputs) -> anyhow::Result<()> {
    let runtime_plan = plan::RuntimePlan::bundled().context("build runtime assembly plan")?;
    let runtime_plan_summary = runtime_plan.summary();
    let provider_counts = runtime_plan_summary.provider_counts();
    tracing::info!(
        assembly.name = runtime_plan_summary.name(),
        assembly.profile = runtime_plan_summary.profile(),
        assembly.declared_topology = runtime_plan_summary.topology(),
        assembly.domains = ?runtime_plan_summary.domains(),
        assembly.listeners = ?runtime_plan_summary.listeners(),
        assembly.providers.total = provider_counts.total,
        assembly.providers.active = provider_counts.active,
        assembly.providers.draft = provider_counts.draft,
        assembly.providers.deprecated = provider_counts.deprecated,
        assembly.providers.persistent = provider_counts.persistent,
        assembly.providers.ephemeral_memory = provider_counts.ephemeral_memory,
        "runtime assembly plan loaded"
    );
    drop(runtime_plan);

    // BuildProvider phase: production credential verifier provider.
    let runtime_oidc = phase_result(
        RuntimePhase::BuildProvider,
        build_runtime_oidc_provider(runtime_inputs.config()).context("build runtime OIDC provider"),
    )?;
    let provider = runtime_oidc.provider();

    // BuildInfra phase: provider bundles, topology config, shared deps, and metrics exporter.
    let (
        pg_owner,
        deps,
        s3_canary_config,
        event_cfg,
        dlx_lifecycle,
        domain_transport,
        metrics_exporter,
        pg_readiness_period,
        redis_readiness_period,
        _command_idempotency_keyring,
    ) = phase_result(
        RuntimePhase::BuildInfra,
        async {
            let config = runtime_inputs.config();
            let pg_config = PgRuntimeConfig::from_snapshot(config)
                .context("build snapshot-backed postgres config")?;
            let redis_config = RedisRuntimeConfig::from_snapshot(config)
                .context("build snapshot-backed redis config")?;
            let PgRuntimeConfigParts {
                serving: app_pg_config,
                tenant_read: tenant_read_pg_config,
                migrator: migrator_config,
                audit_admin: audit_admin_config,
                dlx_archiver: dlx_archiver_pg_config,
                dlx_verifier: dlx_verifier_pg_config,
                dlx_purger: dlx_purger_pg_config,
                legacy_policy: plaintext_policy,
                readiness_period: pg_readiness_period,
            } = pg_config.into_parts();
            let config_value = |name: &str| config.value(name).map(str::to_owned);
            // Phase A parses every configuration and proves all external DLX capabilities before
            // the forward-only 0062 migration can commit. A bad credential or WORM/key capability
            // therefore cannot strand the deployment between incompatible schema generations.
            let vault = build_vault_runtime_deps(config_value).context("setup vault deps")?;
            let settings_config_value_key_name =
                build_settings_config_value_key_name_from(config_value)
                    .context("settings config value key name")?;
            let (redis, redis_readiness_period) = build_redis_runtime_deps(redis_config)
                .await
                .context("setup redis deps")?;
            let s3 = build_s3_runtime_deps_from(config_value).context("setup s3 deps")?;
            let s3_canary_config =
                build_s3_canary_config_from(config_value).context("s3 canary config")?;
            let event_cfg = build_event_transport_config().context("event transport config")?;
            tracing::info!(
                runtime.event_topology = topology_label(event_cfg.topology),
                relay.lease_ttl_ms = event_cfg.relay_budget.lease_ttl_millis(),
                relay.publish_timeout_ms = event_cfg.relay_budget.publish_timeout_millis(),
                relay.settle_timeout_ms = event_cfg.relay_budget.settle_timeout_millis(),
                relay.safety_margin_ms = event_cfg.relay_budget.safety_margin_millis(),
                relay.required_budget_ms = event_cfg.relay_budget.required_budget_millis(),
                "runtime event transport budget loaded"
            );
            if event_cfg.topology == bootstrap::Topology::Demo {
                anyhow::bail!(
                    "RSS_TOPOLOGY=demo is not supported in the production runtime; \
                     use durable-shared or durable-isolated"
                );
            }
            let dlx_bootstrap = build_dlx_lifecycle_bootstrap_config_from(
                dlx_archiver_pg_config,
                dlx_verifier_pg_config,
                dlx_purger_pg_config,
                config_value,
                Arc::new(SystemClock),
            )
            .await?;
            let DlxLifecycleBootstrapConfig {
                archiver_pg: dlx_archiver_pg_config,
                verifier_pg: dlx_verifier_pg_config,
                purger_pg: dlx_purger_pg_config,
                archive_store,
                hot_vault_provider,
                archive_vault_provider,
                hot_key,
                archive_key,
            } = dlx_bootstrap;
            let hot_payload_protector = event_cfg
                .dlx_payload_protector
                .clone()
                .context("durable DLX hot payload protector missing")?;
            let archive_key_for_preflight = archive_key.clone();

            let (pg_owner, dlx_pg_owner, archive_store, archive_vault_provider) =
                after_required_preflight(
                    async move {
                        PgDlxLifecycleRuntime::preflight_identities(
                            &dlx_archiver_pg_config,
                            &dlx_verifier_pg_config,
                            &dlx_purger_pg_config,
                        )
                        .await
                        .context("preflight independent DLX postgres identities")?;
                        let archive_store = archive_store
                            .verify()
                            .await
                            .context("verify DLX archive S3 WORM capability")?;
                        verify_dlx_vault_key_capability(
                            &hot_vault_provider,
                            hot_key.as_key_name(),
                            "dlx-hot-startup",
                        )
                        .await
                        .context("verify DLX hot Vault capability")?;
                        verify_dlx_vault_key_capability(
                            &archive_vault_provider,
                            archive_key_for_preflight.as_key_name(),
                            "dlx-archive-startup",
                        )
                        .await
                        .context("verify DLX archive Vault capability")?;
                        Ok((
                            dlx_archiver_pg_config,
                            dlx_verifier_pg_config,
                            dlx_purger_pg_config,
                            archive_store,
                            archive_vault_provider,
                        ))
                    },
                    |(
                        dlx_archiver_pg_config,
                        dlx_verifier_pg_config,
                        dlx_purger_pg_config,
                        archive_store,
                        archive_vault_provider,
                    )| async move {
                        // Phase B is the only destructive step. Exact function/table ACL checks run
                        // through `setup` only after the migration has installed the closed surface.
                        let pg_owner = PgRuntimeDeps::setup_with_audit_admin_config(
                            &migrator_config,
                            &app_pg_config,
                            &tenant_read_pg_config,
                            audit_admin_config.as_ref(),
                            plaintext_policy,
                            generated::event::PROJECTION_INPUT_GENERATION,
                            generated::event::PROJECTION_INPUTS,
                        )
                        .await
                        .context("setup postgres deps after DLX capability preflight")?;
                        let dlx_pg_owner = PgDlxLifecycleRuntime::setup(
                            &dlx_archiver_pg_config,
                            &dlx_verifier_pg_config,
                            &dlx_purger_pg_config,
                            hot_payload_protector,
                        )
                        .await
                        .context("verify exact DLX lifecycle postgres ACLs")?;
                        Ok((
                            pg_owner,
                            dlx_pg_owner,
                            archive_store,
                            archive_vault_provider,
                        ))
                    },
                )
                .await?;
            let pg = pg_owner.handle();
            let dlx_lifecycle = event_transport::DlxLifecycleRuntimeDeps::new(
                dlx_pg_owner,
                archive_store,
                archive_vault_provider,
                archive_key,
            );
            let domain_transport = wire_domain_transport_from(event_cfg.topology, config_value)
                .await
                .context("wire outbound domain transport")?;
            let command_idempotency_keyring = build_command_idempotency_keyring_from(config_value)
                .context("build command idempotency keyring")?;

            // 共享基础设施依赖（infra 流入各域 wire_X；「字段仅 infra」是约定，机器门见 #1448）。
            let deps = SharedRuntimeDeps {
                pg,
                redis,
                s3,
                vault,
                settings_config_value_key_name,
                domain_transport: domain_transport.dispatch_handle(),
            };

            // Prometheus 指标导出（#1253）：装进程级 `metrics` global recorder（counter!/gauge! 发射点经此写入）+ 持 render 句柄。
            // **fail-fast**：global recorder 已装（重复 install）即 Err——误配在接线期暴露，不静默 noop。Arc<dyn> 共享给 /metrics handler。
            // PromExporter 的 ManagedResource::shutdown 是文档化 no-op（pull exporter 无后台任务/连接），故不进 ShutdownStack。
            //
            // assembly.toml 治理豁免（与 oidc/vault/postgres 等 adapter 同——均在组合根注入、不在 `[[diportProviders]]` 声明）：
            // `cargo xtask assembly validate` 的 `DiportPort` 仅 gate `diport::RevocationStore` 的「production 必须 durability=persistent」。
            // `MetricsExporter` 是无状态 pull port，无 ephemeral/persistent 之分、无 dev/demo vs prod provider 选择，治理无可校验项 ⇒ 不入 enum。
            let metrics_exporter: Arc<dyn diport::MetricsExporter> = Arc::new(
                prometheus::PromExporter::install().context("install prometheus recorder")?,
            );

            Ok::<_, anyhow::Error>((
                pg_owner,
                deps,
                s3_canary_config,
                event_cfg,
                dlx_lifecycle,
                domain_transport,
                metrics_exporter,
                pg_readiness_period,
                redis_readiness_period,
                command_idempotency_keyring,
            ))
        }
        .await,
    )?;

    // WireDomains phase: domain roots, registry/module outputs, probes, workers, and event transport.
    let (mut registry, pg_readiness_period, domain_module) = phase_result(
        RuntimePhase::WireDomains,
        async {
            // assembly.toml 的 domain 顺序经 committed generated glue 成为 live 单源；typed route/subscriber
            // handles 已由各 Domain::init 捕获进 Registry，不经 SharedRuntimeDeps/DomainModuleResult service bag。
            // bootstrap 启动 tail-verify（跨租户全量巡检）defer 到 Part B；本接线仍只收窄 request/subscriber capability。
            let mut domain_bindings = modules_gen::wire_domains(&deps)
                .await
                .context("wire generated domains")?;
            let (mut registry, domains_module) = bootstrap::compose_bindings(&mut domain_bindings)
                .context("compose generated domains")?;
            validate_domain_listener_evidence(&registry.domain_listener_bindings())
                .context("validate runtime domain-listener evidence")?;

            let session_sweeper_module =
                wire_session_sweeper(&deps.pg).context("wire session sweeper")?;
            let s3_canary_module =
                wire_s3_canary(&deps, s3_canary_config).context("wire s3 canary")?;
            // provider capability bundle 单源装配：adapter 保持 diport-only 原语，runtime 本地适配为唯一
            // DomainModuleResult，并按 Redis → S3 → Vault 固定顺序进入统一 merge 路径。
            let provider_module = crate::provider_output::build_provider_module(&deps);
            validate_provider_output_evidence()
                .context("validate runtime provider-output evidence")?;
            let oidc_resource = runtime_oidc.managed_resource();
            // 框架归属 RLS 能力门 readyz 兜底探针（须先于 take_health_reporter）：把启动期 verify_rls_capability
            // 的结果显式暴露到 readyz（启动已 fail-fast，故进程在跑时恒 ready；运维可见 + 周期再核验接线点）。
            let rls_probe_name =
                ProbeName::parse(RLS_READY_PROBE_NAME).context("parse rls_ready probe name")?;
            registry
                .probe(
                    rls_probe_name,
                    Box::new(RlsReadyProbe::new(deps.pg.rls_ready_handle())),
                )
                .context("register rls_ready probe")?;
            let redis_ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let redis_probe_name =
                ProbeName::parse(REDIS_READY_PROBE_NAME).context("parse redis_ready probe name")?;
            registry
                .probe(
                    redis_probe_name,
                    Box::new(RedisReadyProbe::new(Arc::clone(&redis_ready))),
                )
                .context("register redis_ready probe")?;
            let oidc_jwks_probe_name = ProbeName::parse(OIDC_JWKS_READY_PROBE_NAME)
                .context("parse oidc_jwks_ready probe name")?;
            registry
                .probe(
                    oidc_jwks_probe_name,
                    Box::new(OidcJwksReadyProbe::new(runtime_oidc.jwks_readiness())),
                )
                .context("register oidc_jwks_ready probe")?;

            // 事件传输接线（#1251）：topology-gated durable AMQP/Redis + outbox relay + consumer workers。
            // Demo 拓扑已在构造 SharedRuntimeDeps 前 fail-fast；production runtime 不走 in-memory path。
            let domain_transport_module = domain_transport
                .module_result()
                .context("wire outbound domain transport module")?;
            let distributed = wire_distributed(&deps).context("wire distributed")?;
            let event_subscribers =
                event_transport::bridge_generated_subscriptions(registry.drain_subscribers())
                    .context("bridge generated event subscriptions")?;
            let event_module = event_transport::wire_event_transport(
                &deps.pg,
                distributed,
                event_subscribers,
                event_cfg,
            )
            .await
            .context("wire event transport")?;
            let dlx_lifecycle_module =
                event_transport::wire_dlx_lifecycle(dlx_lifecycle).context("wire DLX lifecycle")?;
            // 聚合各域 module result / provider capability guards / event transport outputs。
            let redis_for_sampler = deps.redis.clone();
            let redis_readiness_worker: bootstrap::WorkerSpec = Box::new(move |token| {
                DynManagedResource::new_box(spawn_redis_readiness_sampler(
                    redis_for_sampler.clone(),
                    redis_readiness_period,
                    token,
                    Arc::clone(&redis_ready),
                ))
            });
            let mut module = crate::assemble_runtime_module_outputs(RuntimeModuleAssemblyInputs {
                domains_module,
                session_sweeper_module,
                s3_canary_module,
                provider_module,
                oidc_resource,
                domain_transport_module,
                event_module,
                dlx_lifecycle_module,
                redis_readiness_worker,
            });

            // 排空 module 探针进 registry（须先于 take_health_reporter，readyz 才聚合域 + event worker probes）。
            for (name, probe) in std::mem::take(&mut module.probes) {
                let probe_label = name.as_str().to_owned();
                registry
                    .probe(name, probe)
                    .with_context(|| format!("register module probe '{probe_label}'"))?;
            }

            tracing::info!(
                sample_interval_secs = pg_readiness_period.as_secs(),
                "pg readiness sampler interval configured"
            );
            tracing::info!(
                sample_interval_secs = redis_readiness_period.as_secs(),
                "redis readiness sampler interval configured"
            );

            Ok::<_, anyhow::Error>((registry, pg_readiness_period, module))
        }
        .await,
    )?;

    // Finalize phase: authenticated routers and the dedicated health listener.
    let listeners = phase_result(
        RuntimePhase::Finalize,
        (|| {
            use crate::listeners::health_listener;
            use crate::routes::{AssembledListener, assemble_authed_routers};

            // 装配域路由认证接线（drain registry 路由组，借 &mut——probe 留存供下方 readyz）。
            // Auth decision audit is a flat durable sink, not the audit ledger hash-chain actor model.
            let auth_audit_sink = httpserve::AuditSinkHandle::new(
                deps.pg.for_domain::<caps::Audit>().auth_audit_sink(),
            );
            let auth_audit_clock: Arc<dyn diport::Clock> = Arc::new(SystemClock);
            let mut listeners = assemble_authed_routers(
                runtime_inputs.config(),
                &mut registry,
                provider,
                auth_audit_sink,
                auth_audit_clock,
            )
            .context("assemble authed routers")?;

            // Health listener（框架归属）：readyz 经 Arc<HealthReporter>（Send+Sync）每请求聚合探针。registry 路由组
            // 已 drain，探针经 take_health_reporter 移出（整体非 Sync 的 Registry 无法进 axum handler 闭包）。
            let reporter = Arc::new(registry.take_health_reporter());
            let (listener, routes) =
                health_listener(reporter, metrics_exporter).context("build health listener")?;
            listeners.push(AssembledListener::plain(listener, routes));

            Ok::<_, anyhow::Error>(listeners)
        })(),
    )?;

    let trace_export = runtime_inputs.take_trace_export();
    // Launch phase: listener serving plus LIFO shutdown resource registration.
    let trace_exporter = trace_export.map(DynManagedResource::new_box);
    let pg_runtime_module =
        crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period);
    let launch_plan = launch::LaunchPlan::new(launch::LaunchPlanParts {
        listeners,
        trace_exporter,
        pg_runtime_module,
        domain_module,
    });
    phase_result(
        RuntimePhase::Launch,
        launch::launch(runtime_inputs.config(), launch_plan)
            .await
            .map(|()| RuntimeOutputs::completed()),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::{AssembledListener, assemble_authed_routers};

    use audit::ports::TenantRepoScope as AuditTenantRepoScope;
    use axum::http::Method;
    use diport::ServiceTokenReplayGuard;
    use eventexec::{
        DlqError, EVENT_CONSUMER_PROBE, OUTBOX_RELAY_PROBE, OUTBOX_SAMPLER_PROBE,
        OUTBOX_SWEEPER_PROBE, SWEEPER_WORKER_NAME,
    };
    use identity::ports::TenantRepoScope as IdentityTenantRepoScope;
    use oidc::OidcProvider;
    use primitives::ListenerKind;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    struct FixedDlxBootstrapClock;

    impl diport::Clock for FixedDlxBootstrapClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000)
        }
    }

    #[test]
    fn env_secret_is_redacted_borrow_compared_and_owned_by_the_shared_funnel() {
        let first = EnvSecret::required(
            &|name| (name == "SECRET").then(|| "secret-value".to_owned()),
            "SECRET",
        )
        .unwrap_or_else(|_| unreachable!());
        let second = EnvSecret::required(
            &|name| (name == "SECRET").then(|| "secret-value".to_owned()),
            "SECRET",
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(first.expose(), second.expose());
        assert_eq!(format!("{first:?}"), "EnvSecret(<redacted>)");
        assert_eq!(second.expose(), "secret-value");
    }

    fn full_dlx_bootstrap_env(name: &str) -> Option<String> {
        match name {
            "RSS_S3_ENDPOINT_URL" => Some("https://s3.example.test".to_owned()),
            "RSS_DLX_ARCHIVE_S3_BUCKET" => Some("rss-dlx-archive".to_owned()),
            "RSS_VAULT_ADDR" => Some("https://vault.example.test".to_owned()),
            "RSS_VAULT_TOKEN" => Some("vault-token".to_owned()),
            "RSS_DLX_HOT_VAULT_TOKEN" => Some("dlx-hot-vault-token".to_owned()),
            "RSS_DLX_ARCHIVE_VAULT_TOKEN" => Some("dlx-archive-vault-token".to_owned()),
            "RSS_VAULT_TRANSIT_MOUNT" => Some("transit".to_owned()),
            "RSS_DLX_PAYLOAD_KEY_NAME" => Some("dlx-hot".to_owned()),
            "RSS_DLX_ARCHIVE_KEY_NAME" => Some("dlx-archive".to_owned()),
            _ => None,
        }
    }

    fn test_dlx_pg_config(username: &str) -> postgres::PgConfig {
        postgres::PgConfig::new(
            "postgres.internal",
            5432,
            "rss",
            username,
            postgres::PgPassword::new("test-only-password"),
        )
        .with_ssl_mode(postgres::PgSslMode::Disable)
    }

    #[tokio::test]
    async fn dlx_bootstrap_config_requires_independent_key_domains() {
        let reused_key = build_dlx_lifecycle_bootstrap_config_from(
            test_dlx_pg_config("rss_dlx_archiver"),
            test_dlx_pg_config("rss_dlx_verifier"),
            test_dlx_pg_config("rss_dlx_purger"),
            |name| match name {
                "RSS_DLX_ARCHIVE_KEY_NAME" => Some("dlx-hot".to_owned()),
                _ => full_dlx_bootstrap_env(name),
            },
            Arc::new(FixedDlxBootstrapClock),
        )
        .await;
        assert!(
            reused_key
                .err()
                .is_some_and(|error| format!("{error:#}").contains("must differ"))
        );
    }

    #[tokio::test]
    async fn failed_dlx_preflight_never_enters_destructive_migration_phase() {
        let migration_calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&migration_calls);
        let result = after_required_preflight(
            async { anyhow::bail!("preflight failed") },
            move |(): ()| async move {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;

        assert!(result.is_err());
        assert_eq!(migration_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn generated_graph_evidence_matches_live_runtime_carriers() {
        assert!(validate_provider_output_evidence().is_ok());

        let missing_provider = provider_output::provider_output_bindings();
        assert!(validate_provider_output_bindings(&missing_provider).is_err());
        assert!(validate_domain_listener_evidence(&[]).is_err());
    }

    #[test]
    fn runtime_module_output_harness_captures_merge_and_probe_drain_order() {
        assert_eq!(
            runtime_module_harness_transcript(),
            [
                "phase-order: build_provider -> build_infra -> wire_domains -> finalize -> launch",
                "module-probes: configs_ready, keyprovider_ready, session_sweeper, s3_object_store_ready, domain_transport_ready, outbox_relay_identity, outbox_relay_settings, outbox_sampler, outbox_sweeper, event_consumer:settings_config-version-changed__settings__settings_config-version-changed, event_consumer:identity_session-created__audit__audit_session-created, event_consumer:identity_role-assigned__audit__audit_role-assigned, event_consumer:identity_role-revoked__audit__audit_role-revoked, event_consumer:identity_policy-updated__audit__audit_policy-updated, inbox_sweeper, dlx_lifecycle, dlx_archive_ready",
                "module-resources: redis, s3, vault-secret-resolver, vault-key-provider, oidc-jwks, domain-http-transport, identity-pub, identity-sub, settings-pub, settings-sub, postgres-dlx-lifecycle",
                "module-workers: keyprovider-readiness-sampler, session-sweeper, s3-canary-sampler, outbox-relay-identity, outbox-relay-settings, outbox-sampler, outbox-sweeper, event-consumer:settings:settings.config-version-changed, event-consumer:audit:identity.session-created, event-consumer:audit:identity.role-assigned, event-consumer:audit:identity.role-revoked, event-consumer:audit:identity.policy-updated, inbox-sweeper, dlx-lifecycle, dlx-archive-readiness, redis-readiness-sampler",
                "readyz-probes-before-reporter: rls_ready, redis_ready, oidc_jwks_ready, configs_ready, keyprovider_ready, session_sweeper, s3_object_store_ready, domain_transport_ready, outbox_relay_identity, outbox_relay_settings, outbox_sampler, outbox_sweeper, event_consumer:settings_config-version-changed__settings__settings_config-version-changed, event_consumer:identity_session-created__audit__audit_session-created, event_consumer:identity_role-assigned__audit__audit_role-assigned, event_consumer:identity_role-revoked__audit__audit_role-revoked, event_consumer:identity_policy-updated__audit__audit_policy-updated, inbox_sweeper, dlx_lifecycle, dlx_archive_ready",
                "reporter-probe-count: 20",
                "registry-probe-count-after-take: 0",
            ]
            .join("\n")
        );
    }

    fn runtime_module_harness_transcript() -> String {
        let mut module = runtime_module_output_harness();
        let module_probes = probe_names(&module.probes);
        let module_resources = resource_names(&module.resources);
        let module_workers = worker_names(module.workers);

        let mut registry = bootstrap::Registry::new();
        for name in [
            RLS_READY_PROBE_NAME,
            REDIS_READY_PROBE_NAME,
            OIDC_JWKS_READY_PROBE_NAME,
        ] {
            register_probe(&mut registry, name);
        }
        for (name, probe) in module.probes.drain(..) {
            let result = registry.probe(name, probe);
            assert!(result.is_ok(), "module probe drains");
        }
        let readyz_probe_names = registry
            .readyz_report()
            .checks()
            .iter()
            .map(|check| check.name().as_str().to_owned())
            .collect::<Vec<_>>();
        let reporter = registry.take_health_reporter();

        [
            format!("phase-order: {}", phase_order_transcript_for_harness()),
            format!("module-probes: {}", module_probes.join(", ")),
            format!("module-resources: {}", module_resources.join(", ")),
            format!("module-workers: {}", module_workers.join(", ")),
            format!(
                "readyz-probes-before-reporter: {}",
                readyz_probe_names.join(", ")
            ),
            format!("reporter-probe-count: {}", reporter.probe_count()),
            format!(
                "registry-probe-count-after-take: {}",
                registry.probe_count()
            ),
        ]
        .join("\n")
    }

    fn runtime_module_output_harness() -> DomainModuleResult {
        assemble_runtime_module_outputs(RuntimeModuleAssemblyInputs {
            domains_module: harness_module(
                &[CONFIGS_READY_PROBE_NAME, KEYPROVIDER_READY_PROBE_NAME],
                &[],
                &["keyprovider-readiness-sampler"],
            ),
            session_sweeper_module: harness_module(
                &[SESSION_SWEEPER_PROBE_NAME],
                &[],
                &["session-sweeper"],
            ),
            s3_canary_module: harness_module(
                &[crate::infra::s3::S3_READY_PROBE_NAME],
                &[],
                &["s3-canary-sampler"],
            ),
            provider_module: harness_module(
                &[],
                &["redis", "s3", "vault-secret-resolver", "vault-key-provider"],
                &[],
            ),
            oidc_resource: harness_resource("oidc-jwks"),
            domain_transport_module: harness_module(
                &[DOMAIN_TRANSPORT_READY_PROBE_NAME],
                &["domain-http-transport"],
                &[],
            ),
            event_module: event_transport_harness_module(),
            dlx_lifecycle_module: harness_module(
                &[
                    event_transport::DLX_LIFECYCLE_PROBE,
                    event_transport::DLX_ARCHIVE_READINESS_PROBE,
                ],
                &["postgres-dlx-lifecycle"],
                &[
                    event_transport::DLX_LIFECYCLE_WORKER_NAME,
                    event_transport::DLX_ARCHIVE_READINESS_WORKER_NAME,
                ],
            ),
            redis_readiness_worker: harness_worker("redis-readiness-sampler"),
        })
    }

    fn event_transport_harness_module() -> DomainModuleResult {
        let mut module = DomainModuleResult::default();
        for domain in ["identity", "settings"] {
            module
                .resources
                .push(harness_resource_owned(format!("{domain}-pub")));
            module
                .resources
                .push(harness_resource_owned(format!("{domain}-sub")));
        }
        for domain in ["identity", "settings"] {
            module.probes.push(harness_probe_owned(format!(
                "{OUTBOX_RELAY_PROBE}_{domain}"
            )));
            module
                .workers
                .push(harness_worker_owned(format!("outbox-relay-{domain}")));
        }
        module.probes.push(harness_probe(OUTBOX_SAMPLER_PROBE));
        module.workers.push(harness_worker("outbox-sampler"));
        module.probes.push(harness_probe(OUTBOX_SWEEPER_PROBE));
        module.workers.push(harness_worker(SWEEPER_WORKER_NAME));
        for (topic, consumer, group) in [
            (
                "settings.config-version-changed",
                "settings",
                "settings.config-version-changed",
            ),
            ("identity.session-created", "audit", "audit.session-created"),
            ("identity.role-assigned", "audit", "audit.role-assigned"),
            ("identity.role-revoked", "audit", "audit.role-revoked"),
            ("identity.policy-updated", "audit", "audit.policy-updated"),
        ] {
            module.probes.push(harness_probe_owned(format!(
                "{EVENT_CONSUMER_PROBE}:{}__{}__{}",
                topic.replace('.', "_"),
                consumer.replace('.', "_"),
                group.replace('.', "_")
            )));
            module.workers.push(harness_worker_owned(format!(
                "event-consumer:{consumer}:{topic}"
            )));
        }
        module
            .probes
            .push(harness_probe(crate::event_transport::INBOX_SWEEPER_PROBE));
        module.workers.push(harness_worker(
            crate::event_transport::INBOX_SWEEPER_WORKER_NAME,
        ));
        module
    }

    fn harness_module(
        probes: &[&'static str],
        resources: &[&'static str],
        workers: &[&'static str],
    ) -> DomainModuleResult {
        DomainModuleResult {
            probes: probes.iter().copied().map(harness_probe).collect(),
            resources: resources.iter().copied().map(harness_resource).collect(),
            workers: workers.iter().copied().map(harness_worker).collect(),
        }
    }

    #[allow(clippy::expect_used)]
    fn harness_probe(name: &'static str) -> (ProbeName, Box<dyn bootstrap::HealthProbe>) {
        harness_probe_owned(name.to_owned())
    }

    #[allow(clippy::expect_used)]
    fn harness_probe_owned(name: String) -> (ProbeName, Box<dyn bootstrap::HealthProbe>) {
        let name = ProbeName::parse(&name).expect("harness probe names are valid");
        (
            name.clone(),
            Box::new(HarnessProbe {
                name,
                status: HealthStatus::Healthy,
            }),
        )
    }

    #[allow(clippy::expect_used)]
    fn register_probe(registry: &mut bootstrap::Registry, name: &'static str) {
        let (name, probe) = harness_probe(name);
        registry.probe(name, probe).expect("direct probe registers");
    }

    fn probe_names(probes: &[(ProbeName, Box<dyn bootstrap::HealthProbe>)]) -> Vec<String> {
        probes
            .iter()
            .map(|(name, _)| name.as_str().to_owned())
            .collect()
    }

    fn resource_names(resources: &[Box<DynManagedResource<'static>>]) -> Vec<String> {
        resources
            .iter()
            .map(|resource| resource.name().to_owned())
            .collect()
    }

    fn worker_names(workers: Vec<bootstrap::WorkerSpec>) -> Vec<String> {
        let token = CancellationToken::new();
        workers
            .into_iter()
            .map(|worker| worker(token.clone()).name().to_owned())
            .collect()
    }

    fn harness_resource(name: &'static str) -> Box<DynManagedResource<'static>> {
        harness_resource_owned(name.to_owned())
    }

    fn harness_resource_owned(name: String) -> Box<DynManagedResource<'static>> {
        DynManagedResource::new_box(HarnessResource { name })
    }

    fn harness_worker(name: &'static str) -> bootstrap::WorkerSpec {
        harness_worker_owned(name.to_owned())
    }

    fn harness_worker_owned(name: String) -> bootstrap::WorkerSpec {
        Box::new(move |_token| harness_resource_owned(name.clone()))
    }

    fn phase_order_transcript_for_harness() -> String {
        RuntimePhase::ALL
            .iter()
            .copied()
            .map(RuntimePhase::as_str)
            .collect::<Vec<_>>()
            .join(" -> ")
    }

    struct HarnessProbe {
        name: ProbeName,
        status: HealthStatus,
    }

    impl bootstrap::HealthProbe for HarnessProbe {
        fn check(&self) -> HealthCheck {
            HealthCheck::new(self.name.clone(), self.status, "ready")
        }
    }

    struct HarnessResource {
        name: String,
    }

    impl diport::ManagedResource for HarnessResource {
        fn name(&self) -> &str {
            &self.name
        }

        async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
            Ok(())
        }
    }

    fn identity_storage_error(message: &'static str) -> identity::ports::IdentityError {
        identity::ports::IdentityError::Storage(Box::new(std::io::Error::other(message)))
    }

    #[derive(Clone)]
    struct StaticRoleRepo {
        roles: Arc<std::collections::BTreeMap<String, identity::ports::Role>>,
    }

    impl StaticRoleRepo {
        fn new(roles: Vec<identity::ports::Role>) -> Self {
            Self {
                roles: Arc::new(
                    roles
                        .into_iter()
                        .map(|role| (role.id().as_str().to_string(), role))
                        .collect(),
                ),
            }
        }
    }

    impl identity::ports::RoleReadRepo for StaticRoleRepo {
        async fn find(
            &self,
            _scope: IdentityTenantRepoScope,
            id: identity::ports::RoleId,
        ) -> Result<Option<identity::ports::Role>, identity::ports::IdentityError> {
            Ok(self.roles.get(id.as_str()).cloned())
        }

        async fn list(
            &self,
            _scope: IdentityTenantRepoScope,
            _page: identity::ports::RolePage,
        ) -> Result<identity::ports::RoleListResult, identity::ports::IdentityError> {
            Ok(identity::ports::RoleListResult {
                roles: self.roles.values().cloned().collect(),
                has_more: false,
            })
        }
    }

    #[derive(Clone)]
    struct StaticRoleBindings {
        bindings: Arc<Vec<(vocab::TenantId, String, String)>>,
    }

    impl StaticRoleBindings {
        fn new(bindings: Vec<(vocab::TenantId, String, String)>) -> Self {
            Self {
                bindings: Arc::new(bindings),
            }
        }
    }

    impl identity::ports::RoleBindingLifecycle for StaticRoleBindings {
        async fn assign_and_emit(
            &self,
            _scope: IdentityTenantRepoScope,
            _binding: identity::ports::RoleBinding,
            _entry: consistency::EventEntry,
            _envelope: diport::OutboxEnvelopeParts,
        ) -> Result<(), diport::OutboxEmitError> {
            Err(diport::OutboxEmitError::new(std::io::Error::other(
                "runtime test binding lifecycle is read-only",
            )))
        }

        async fn revoke_and_emit(
            &self,
            _scope: IdentityTenantRepoScope,
            _role_id: identity::ports::RoleId,
            _subject: String,
            _entry: consistency::EventEntry,
            _envelope: diport::OutboxEnvelopeParts,
        ) -> Result<bool, diport::OutboxEmitError> {
            Err(diport::OutboxEmitError::new(std::io::Error::other(
                "runtime test binding lifecycle is read-only",
            )))
        }
    }

    impl identity::ports::RoleBindingReadRepo for StaticRoleBindings {
        async fn list_for_subject(
            &self,
            scope: IdentityTenantRepoScope,
            subject: String,
        ) -> Result<Vec<identity::ports::RoleBinding>, identity::ports::IdentityError> {
            let tenant = scope.tenant();
            self.bindings
                .iter()
                .filter(|(binding_tenant, binding_subject, _)| {
                    *binding_tenant == tenant && *binding_subject == subject
                })
                .map(|(_, binding_subject, role_id)| {
                    identity::ports::RoleBinding::hydrate(binding_subject.clone(), role_id, tenant)
                })
                .collect()
        }
    }

    struct EmptyPolicyRepo;

    impl identity::ports::PolicyRepo for EmptyPolicyRepo {
        async fn find(
            &self,
            _scope: IdentityTenantRepoScope,
            _id: identity::ports::PolicyId,
        ) -> Result<Option<identity::ports::Policy>, identity::ports::IdentityError> {
            Ok(None)
        }

        async fn list_active(
            &self,
            _scope: IdentityTenantRepoScope,
            _page: identity::ports::PolicyPage,
        ) -> Result<identity::ports::PolicyListResult, identity::ports::IdentityError> {
            Ok(identity::ports::PolicyListResult {
                policies: Vec::new(),
                has_more: false,
            })
        }

        async fn list_effective(
            &self,
            _tenant_scope: IdentityTenantRepoScope,
            _scope: identity::ports::PolicyRouteScope,
            _at: SystemTime,
        ) -> Result<Vec<identity::ports::Policy>, identity::ports::IdentityError> {
            Ok(Vec::new())
        }
    }

    struct EmptyResourceAttributeRepo;

    impl identity::ports::ResourceAttributeReadRepo for EmptyResourceAttributeRepo {
        async fn resolve_effective(
            &self,
            _tenant_scope: IdentityTenantRepoScope,
            _scope: identity::ports::PolicyRouteScope,
            _resource_id: identity::ports::ResourceAttributeResourceId,
            _required_keys: Vec<identity::ports::ResourceAttributeKey>,
            _at: SystemTime,
        ) -> Result<identity::ports::ResourceAttributeResolution, identity::ports::IdentityError>
        {
            Ok(identity::ports::ResourceAttributeResolution::Known(
                Vec::new(),
            ))
        }
    }

    struct EmptyPolicyLifecycle;

    impl identity::ports::PolicyLifecycle for EmptyPolicyLifecycle {
        async fn create_and_emit(
            &self,
            _scope: IdentityTenantRepoScope,
            _policy: identity::ports::Policy,
            _entry: consistency::EventEntry,
            _envelope: diport::OutboxEnvelopeParts,
        ) -> Result<identity::ports::Policy, identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test policy lifecycle must not be called",
            ))
        }

        async fn update_and_emit(
            &self,
            _scope: IdentityTenantRepoScope,
            _policy: identity::ports::Policy,
            _expected: identity::ports::PolicyVersion,
            _entry: consistency::EventEntry,
            _envelope: diport::OutboxEnvelopeParts,
        ) -> Result<identity::ports::Policy, identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test policy lifecycle must not be called",
            ))
        }

        async fn deactivate_and_emit(
            &self,
            _scope: IdentityTenantRepoScope,
            _id: identity::ports::PolicyId,
            _expected: identity::ports::PolicyVersion,
            _entry: consistency::EventEntry,
            _envelope: diport::OutboxEnvelopeParts,
        ) -> Result<bool, identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test policy lifecycle must not be called",
            ))
        }
    }

    struct UnusedCredentialRepo;

    impl identity::ports::CredentialRepo for UnusedCredentialRepo {
        async fn find_by_user_id(
            &self,
            _scope: IdentityTenantRepoScope,
            _user_id: ids::UserId,
        ) -> Result<Option<identity::ports::Credential>, identity::ports::IdentityError> {
            Ok(None)
        }

        async fn authenticate(
            &self,
            _scope: IdentityTenantRepoScope,
            _login: identity::ports::LoginIdentifier,
            _candidate: String,
            _now: SystemTime,
        ) -> Result<identity::ports::AuthOutcome, identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test credential repo must not be called",
            ))
        }

        async fn save(
            &self,
            _scope: IdentityTenantRepoScope,
            _credential: identity::ports::Credential,
        ) -> Result<(), identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test credential repo is read-only",
            ))
        }

        async fn apply_password_change(
            &self,
            _scope: IdentityTenantRepoScope,
            _mutation: identity::ports::PasswordChangeMutation,
        ) -> Result<(), identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test credential repo is read-only",
            ))
        }

        async fn lockout_status(
            &self,
            _scope: IdentityTenantRepoScope,
            _login: identity::ports::LoginIdentifier,
            _now: SystemTime,
        ) -> Result<bool, identity::ports::IdentityError> {
            Ok(false)
        }
    }

    struct UnusedSessionLifecycle;

    impl identity::ports::SessionLifecycle for UnusedSessionLifecycle {
        async fn persist_session_and_emit(
            &self,
            _scope: IdentityTenantRepoScope,
            _session: identity::ports::Session,
            _entry: consistency::EventEntry,
            _envelope: diport::OutboxEnvelopeParts,
        ) -> Result<(), diport::OutboxEmitError> {
            Err(diport::OutboxEmitError::new(std::io::Error::other(
                "runtime test session lifecycle must not be called",
            )))
        }

        async fn find(
            &self,
            _scope: IdentityTenantRepoScope,
            _session_id: identity::ports::SessionId,
        ) -> Result<Option<identity::ports::Session>, identity::ports::IdentityError> {
            Ok(None)
        }

        async fn logout(
            &self,
            _scope: IdentityTenantRepoScope,
            _mutation: identity::ports::SessionLogoutMutation,
        ) -> Result<(), identity::ports::IdentityError> {
            Ok(())
        }
    }

    struct UnusedRefreshStore;

    impl identity::ports::RefreshTokenStore for UnusedRefreshStore {
        async fn insert(
            &self,
            _scope: IdentityTenantRepoScope,
            _record: identity::ports::RefreshTokenRecord,
        ) -> Result<(), identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test refresh store must not be called",
            ))
        }

        async fn find_by_hash(
            &self,
            _scope: IdentityTenantRepoScope,
            _hash: identity::ports::RefreshTokenHash,
        ) -> Result<Option<identity::ports::RefreshTokenRecord>, identity::ports::IdentityError>
        {
            Ok(None)
        }

        async fn rotate(
            &self,
            _scope: IdentityTenantRepoScope,
            _mutation: identity::ports::RefreshRotationMutation,
        ) -> Result<bool, identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test refresh store must not be called",
            ))
        }

        async fn revoke_lineage(
            &self,
            _scope: IdentityTenantRepoScope,
            _lineage_id: identity::ports::RefreshTokenId,
        ) -> Result<(), identity::ports::IdentityError> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestSigner;

    impl diport::Signer for TestSigner {
        async fn sign(
            &self,
            _req: diport::SignRequest,
        ) -> Result<diport::Signature, diport::SignerError> {
            Ok(diport::Signature::new(vec![0x5a; 64]))
        }

        async fn shutdown(&self) -> Result<(), diport::SignerError> {
            Ok(())
        }
    }

    struct DelegatingAuditAdminRepo {
        repo: Arc<audit::ports::DynAuditReadRepo<'static>>,
    }

    impl audit::ports::AuditAdminRepo for DelegatingAuditAdminRepo {
        async fn list_tenant(
            &self,
            scope: audit::ports::CrossTenantReadScope,
            page: audit::ports::AuditPage,
        ) -> Result<audit::ports::AuditListResult, audit::ports::AuditError> {
            use audit::ports::AuditReadRepo as _;

            let tenant = scope.target();

            self.repo
                .list(AuditTenantRepoScope::for_test(tenant), page)
                .await
        }

        async fn verify_tenant(
            &self,
            tenant: vocab::TenantId,
            batch: vocab::Limit,
        ) -> Result<audit::ports::AuditLedgerVerifyReport, audit::ports::AuditError> {
            use audit::ports::AuditReadRepo as _;

            let mut cursor = None;
            let mut checked_entries = 0u64;
            loop {
                let result = self
                    .repo
                    .list(
                        AuditTenantRepoScope::for_test(tenant),
                        audit::ports::AuditPage {
                            limit: batch,
                            cursor,
                        },
                    )
                    .await?;
                checked_entries = checked_entries
                    .checked_add(
                        u64::try_from(result.entries.len())
                            .map_err(audit::ports::AuditError::storage)?,
                    )
                    .ok_or(audit::ports::AuditError::SequenceGap)?;
                if !result.has_more {
                    break;
                }
                cursor = result.next_cursor;
                if cursor.is_none() {
                    return Err(audit::ports::AuditError::SequenceGap);
                }
            }
            Ok(audit::ports::AuditLedgerVerifyReport {
                tenant,
                checked_entries,
            })
        }
    }

    #[allow(clippy::expect_used)]
    fn test_identity_domain_with_audit_role(
        tenant: vocab::TenantId,
    ) -> identity::IdentityDomain<TestSigner> {
        let audit_role = identity::ports::Role::hydrate(
            "audit-reader",
            "Audit reader",
            &[vocab::AUDIT_READ_PERMISSION.to_string()],
        )
        .expect("audit role");
        let roles = Arc::from(identity::ports::DynRoleReadRepo::new_box(
            StaticRoleRepo::new(vec![audit_role]),
        ));
        let binding_provider = StaticRoleBindings::new(vec![(
            tenant,
            "11111111-2222-4333-8444-555555555555".to_string(),
            "audit-reader".to_string(),
        )]);
        let binding_lifecycle = Arc::from(identity::ports::DynRoleBindingLifecycle::new_box(
            binding_provider.clone(),
        ));
        let binding_reads = Arc::from(identity::ports::DynRoleBindingReadRepo::new_box(
            binding_provider,
        ));
        let issuer = Arc::new(
            authn::JwtIssuer::new(
                Arc::new(TestSigner),
                Box::new(SystemClock),
                authn::JwtIssuerConfig {
                    key: diport::KeyId::new("runtime-test-key"),
                    alg: authn::JwtAlg::Es256,
                    purpose: diport::SigningPurpose::new("runtime-test"),
                    issuer: "https://issuer.test".to_string(),
                    audience: "rss-test".to_string(),
                    ttl: Duration::from_secs(900),
                },
            )
            .expect("jwt issuer"),
        );
        let refresh = Arc::new(identity::RefreshService::new(
            identity::ports::DynRefreshTokenStore::new_box(UnusedRefreshStore),
            issuer,
            Box::new(SystemClock),
            Duration::from_secs(900),
        ));
        let login = Arc::new(identity::LoginService::new(
            Arc::from(identity::ports::DynCredentialRepo::new_box(
                UnusedCredentialRepo,
            )),
            Arc::from(identity::ports::DynSessionLifecycle::new_box(
                UnusedSessionLifecycle,
            )),
            Arc::clone(&refresh),
            Box::new(SystemClock),
            Duration::from_secs(900),
        ));
        let rbac_admin = Arc::new(identity::RbacAdminService::new(
            Arc::clone(&roles),
            binding_lifecycle,
            Box::new(SystemClock),
        ));
        let policies = Arc::from(identity::ports::DynPolicyRepo::new_box(EmptyPolicyRepo));
        let resource_attribute_reads = Arc::from(
            identity::ports::DynResourceAttributeReadRepo::new_box(EmptyResourceAttributeRepo),
        );
        let policy_lifecycle = Arc::from(identity::ports::DynPolicyLifecycle::new_box(
            EmptyPolicyLifecycle,
        ));
        let policy_manage = Arc::new(identity::PolicyManageService::new(
            Arc::clone(&policies),
            policy_lifecycle,
            Box::new(SystemClock),
        ));
        identity::IdentityDomain::new(identity::IdentityDomainDeps {
            login,
            refresh,
            rbac_admin,
            policy_manage,
            roles,
            binding_reads,
            policies,
            resource_attribute_reads,
            clock: Arc::new(SystemClock),
        })
    }

    struct TestAuditRepos {
        read: Arc<audit::ports::DynAuditReadRepo<'static>>,
        write: Arc<audit::ports::DynAuditWriteRepo<'static>>,
    }

    #[allow(clippy::expect_used)]
    fn test_audit_repo() -> TestAuditRepos {
        let hasher = audit::ports::AuditChainHasher::new(
            RustCryptoMacVerifier,
            MacKey::from_bytes(vec![0x5a; 32]),
        )
        .expect("audit chain hasher");
        let provider = Arc::new(audit::InMemAuditRepo::new(hasher));
        TestAuditRepos {
            read: Arc::from(audit::ports::DynAuditReadRepo::new_box(Arc::clone(
                &provider,
            ))),
            write: Arc::from(audit::ports::DynAuditWriteRepo::new_box(provider)),
        }
    }

    fn test_audit_admin_repo(
        repo: Arc<audit::ports::DynAuditReadRepo<'static>>,
    ) -> Arc<audit::ports::DynAuditAdminRepo<'static>> {
        Arc::from(audit::ports::DynAuditAdminRepo::new_box(
            DelegatingAuditAdminRepo { repo },
        ))
    }

    #[allow(clippy::expect_used)]
    async fn append_sensitive_audit_record(
        repo: &Arc<audit::ports::DynAuditWriteRepo<'static>>,
        tenant: vocab::TenantId,
    ) {
        use audit::ports::AuditWriteRepo as _;

        repo.append(
            AuditTenantRepoScope::for_test(tenant),
            audit::ports::AuditRecord {
                tenant,
                actor: ids::UserId::parse("11111111-2222-4333-8444-555555555555").expect("actor"),
                actor_kind: vocab::PrincipalKind::Admin,
                action: vocab::Action::parse("audit:read").expect("action"),
                resource: audit::ports::ResourceRef::new(
                    "session",
                    "99999999-8888-4777-8666-555555555555",
                ),
                outcome: audit::ports::AuditOutcome::Success,
                recorded_at: SystemTime::UNIX_EPOCH,
            },
        )
        .await
        .expect("append audit record");
    }

    #[allow(clippy::expect_used)]
    fn runtime_test_provider() -> Arc<OidcProvider> {
        use p256::ecdsa::SigningKey;

        let key = SigningKey::from_slice(&[7u8; 32]).expect("signing key");
        Arc::new(
            provider_from_b64(
                "https://issuer.test",
                "rss-test",
                "admin,superAdmin",
                Some(&B64.encode(key.verifying_key().to_encoded_point(false).as_bytes())),
                Some(&B64.encode([9u8; 32])),
                Some("cell-a.svc-a"),
                Box::new(SystemClock),
            )
            .expect("provider"),
        )
    }

    #[allow(clippy::expect_used)]
    fn runtime_test_jwt(kind: &str, tenant: Option<vocab::TenantId>) -> String {
        use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

        let key = SigningKey::from_slice(&[7u8; 32]).expect("signing key");
        let header = B64.encode(br#"{"alg":"ES256"}"#);
        let tenant_claim = tenant
            .map(|tenant| format!(r#","tenant_id":"{tenant}""#))
            .unwrap_or_default();
        let payload = format!(
            r#"{{"sub":"11111111-2222-4333-8444-555555555555","exp":4102444800,"iss":"https://issuer.test","aud":"rss-test","kind":"{kind}"{tenant_claim}}}"#
        );
        let body = B64.encode(payload.as_bytes());
        let signing_input = format!("{header}.{body}");
        let sig: Signature = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", B64.encode(sig.to_bytes()))
    }

    fn extract_admin_router(assembled: Vec<AssembledListener>) -> anyhow::Result<axum::Router> {
        assembled
            .into_iter()
            .find_map(|assembled| {
                let (listener, routes) = assembled.into_parts();
                (listener == ListenerKind::Admin).then(|| routes.into_router_for_test())
            })
            .context("admin router")
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn assembled_admin_audit_read_uses_identity_authorizer_and_masks_sensitive_fields()
    -> anyhow::Result<()> {
        use tower::ServiceExt as _;

        let tenant =
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
        let audit_repo = test_audit_repo();
        append_sensitive_audit_record(&audit_repo.write, tenant).await;
        let identity_domain = test_identity_domain_with_audit_role(tenant);
        let audit_domain = audit::AuditDomain::new(
            Arc::clone(&audit_repo.read),
            Some(test_audit_admin_repo(Arc::clone(&audit_repo.read))),
            TracingAuthAuditSink,
            Arc::new(SystemClock),
        );
        let domains: [&dyn bootstrap::Domain; 2] = [&identity_domain, &audit_domain];
        let mut registry = bootstrap::compose(&domains)?;
        let runtime_config = crate::config::test_snapshot(&[])?;
        let app = extract_admin_router(assemble_authed_routers(
            runtime_config.view(),
            &mut registry,
            runtime_test_provider(),
            httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
            Arc::new(SystemClock),
        )?)?;

        let scoped_response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri(generated::http::audit_v1::list_entries::SPEC.route.path())
                    .header(
                        axum::http::header::AUTHORIZATION,
                        format!("Bearer {}", runtime_test_jwt("admin", Some(tenant))),
                    )
                    .body(axum::body::Body::empty())?,
            )
            .await?;
        assert_eq!(scoped_response.status(), axum::http::StatusCode::OK);
        let scoped_body = axum::body::to_bytes(scoped_response.into_body(), usize::MAX).await?;
        let scoped_json: serde_json::Value = serde_json::from_slice(&scoped_body)?;
        assert_eq!(scoped_json["data"][0]["actor"], "<redacted>");
        assert_eq!(scoped_json["data"][0]["resourceId"], "<redacted>");

        let target_response = app
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri(
                        generated::http::audit_v1::list_tenant_entries::SPEC
                            .route
                            .path()
                            .replace("{tenantId}", &tenant.to_string()),
                    )
                    .header(
                        axum::http::header::AUTHORIZATION,
                        format!("Bearer {}", runtime_test_jwt("superAdmin", None)),
                    )
                    .body(axum::body::Body::empty())?,
            )
            .await?;
        assert_eq!(target_response.status(), axum::http::StatusCode::OK);
        let target_body = axum::body::to_bytes(target_response.into_body(), usize::MAX).await?;
        let target_json: serde_json::Value = serde_json::from_slice(&target_body)?;
        assert_eq!(target_json["data"][0]["actor"], "<redacted>");
        assert_eq!(target_json["data"][0]["resourceId"], "<redacted>");
        Ok(())
    }

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    #[test]
    fn postgres_reader_migration_command_is_exact_and_has_no_legacy_shape() {
        assert!(is_postgres_command(&args(&[
            "postgres",
            "migrate-reader-lane"
        ])));
        for dispatched_but_rejected_by_runner in [
            args(&["postgres"]),
            args(&["postgres", "migrate"]),
            args(&["postgres", "migrate-reader-lane", "--all"]),
        ] {
            assert!(is_postgres_command(&dispatched_but_rejected_by_runner));
        }
        assert!(!is_postgres_command(&args(&["migrate-reader-lane"])));
    }

    static PROJECTION_REGISTRY_FIXTURE_INPUTS: &[vocab::ProjectionInputBinding] =
        &[vocab::ProjectionInputBinding::from_static(
            "audit.session-projection",
            "identity",
            "identity.session-created",
            "v1",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "identity.session.created",
        )];

    const PROJECTION_FIXTURE_OPERATOR_TENANT: &str = "00000000-0000-4000-8000-000000000001";
    const PROJECTION_FIXTURE_TENANT: &str = "00000000-0000-4000-8000-000000000002";
    const PROJECTION_FIXTURE_ID: &str = "audit.session-projection";
    const PROJECTION_FIXTURE_VERSION: &str = "v2";
    const PROJECTION_FIXTURE_OPERATOR: &str = "verified-projection-operator";

    struct NoopProjectionReplayTarget;

    impl eventexec::ProjectionReplayTarget for NoopProjectionReplayTarget {
        fn apply<'a>(
            &'a self,
            _selector: &'a ProjectionSelector,
            _event: consistency::ProjectionEventRecord,
        ) -> futures::future::BoxFuture<'a, Result<(), consistency::EngineError>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FakeProjectionAuditOutcome {
        Success,
        Failure { reason: String },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeProjectionAuditRecord {
        subject: String,
        action: String,
        outcome: FakeProjectionAuditOutcome,
        resource_id: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeProjectionCommandRecord {
        action: ProjectionMaintenanceAction,
        operator_subject: String,
        registry_has_targets: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FakeProjectionOperator {
        Verified(&'static str),
        AuthFailure,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FakeProjectionCommandResult {
        Success,
        Failure(&'static str),
    }

    struct FakeProjectionControlRuntime {
        target_registered: bool,
        operator: FakeProjectionOperator,
        command_result: FakeProjectionCommandResult,
        audits: Mutex<Vec<FakeProjectionAuditRecord>>,
        commands: Mutex<Vec<FakeProjectionCommandRecord>>,
        setup_count: AtomicUsize,
        shutdown_count: AtomicUsize,
    }

    impl FakeProjectionControlRuntime {
        fn registered(command_result: FakeProjectionCommandResult) -> Self {
            Self::new(
                true,
                FakeProjectionOperator::Verified(PROJECTION_FIXTURE_OPERATOR),
                command_result,
            )
        }

        fn unsupported(command_result: FakeProjectionCommandResult) -> Self {
            Self::new(
                false,
                FakeProjectionOperator::Verified(PROJECTION_FIXTURE_OPERATOR),
                command_result,
            )
        }

        fn auth_failure() -> Self {
            Self::new(
                true,
                FakeProjectionOperator::AuthFailure,
                FakeProjectionCommandResult::Success,
            )
        }

        fn new(
            target_registered: bool,
            operator: FakeProjectionOperator,
            command_result: FakeProjectionCommandResult,
        ) -> Self {
            Self {
                target_registered,
                operator,
                command_result,
                audits: Mutex::new(Vec::new()),
                commands: Mutex::new(Vec::new()),
                setup_count: AtomicUsize::new(0),
                shutdown_count: AtomicUsize::new(0),
            }
        }

        fn audit_records(&self) -> Vec<FakeProjectionAuditRecord> {
            match self.audits.lock() {
                Ok(records) => records.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }

        fn command_records(&self) -> Vec<FakeProjectionCommandRecord> {
            match self.commands.lock() {
                Ok(records) => records.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }

        fn setup_count(&self) -> usize {
            self.setup_count.load(Ordering::Relaxed)
        }

        fn shutdown_count(&self) -> usize {
            self.shutdown_count.load(Ordering::Relaxed)
        }
    }

    fn fake_projection_receipt(
        subject: &str,
        parsed: &ProjectionCliArgs,
    ) -> anyhow::Result<authn::ProjectionMaintenanceReceipt> {
        let principal =
            authn::test_support::principal(vocab::PrincipalKind::Service, subject, None);
        let grants = authn::ProjectionMaintenanceGrantSet::new(vec![
            authn::ProjectionMaintenanceGrant::new(
                subject,
                parsed.command.action().authorized_action(),
                parsed.selector.tenant(),
                parsed.selector.projection().as_str(),
            )?,
        ])?;
        grants
            .authorize(
                &principal,
                parsed.command.action().authorized_action(),
                parsed.selector.tenant(),
                parsed.selector.projection().as_str(),
            )
            .map_err(Into::into)
    }

    impl ProjectionControlRuntime for FakeProjectionControlRuntime {
        type Session = ();

        fn build_registry(&self) -> anyhow::Result<ProjectionTargetRegistry> {
            let mut registry =
                ProjectionTargetRegistry::from_generated(PROJECTION_REGISTRY_FIXTURE_INPUTS)?;
            if self.target_registered {
                registry.register_target(
                    ProjectionId::parse(PROJECTION_FIXTURE_ID)?,
                    Arc::new(NoopProjectionReplayTarget),
                )?;
            } else {
                registry.mark_all_generated_unsupported();
            }
            registry.validate_coverage()?;
            Ok(registry)
        }

        async fn connect_maintenance(&self) -> anyhow::Result<Self::Session> {
            self.setup_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn record_projection_maintenance_audit(
            &self,
            _session: &Self::Session,
            operator_subject: &str,
            action: &str,
            outcome: MaintenanceAuditOutcome<'_>,
            resource_id: &str,
        ) -> anyhow::Result<()> {
            let outcome = match outcome {
                MaintenanceAuditOutcome::Success => FakeProjectionAuditOutcome::Success,
                MaintenanceAuditOutcome::Failure { reason } => {
                    FakeProjectionAuditOutcome::Failure {
                        reason: reason.to_owned(),
                    }
                }
            };
            let record = FakeProjectionAuditRecord {
                subject: operator_subject.to_owned(),
                action: action.to_owned(),
                outcome,
                resource_id: resource_id.to_owned(),
            };
            match self.audits.lock() {
                Ok(mut records) => records.push(record),
                Err(poisoned) => poisoned.into_inner().push(record),
            }
            Ok(())
        }

        async fn operator_receipt(
            &self,
            session: &Self::Session,
            parsed: &ProjectionCliArgs,
            resource_id: &str,
        ) -> anyhow::Result<authn::ProjectionMaintenanceReceipt> {
            match self.operator {
                FakeProjectionOperator::Verified(subject) => {
                    fake_projection_receipt(subject, parsed)
                }
                FakeProjectionOperator::AuthFailure => {
                    let finish_action =
                        format!("projection.{}.finish", parsed.command.action().as_str());
                    self.record_projection_maintenance_audit(
                        session,
                        UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR,
                        &finish_action,
                        MaintenanceAuditOutcome::Failure {
                            reason: "operator_auth",
                        },
                        resource_id,
                    )
                    .await?;
                    anyhow::bail!("projection maintenance operator auth failed");
                }
            }
        }

        async fn run_projection_command(
            &self,
            _session: &Self::Session,
            registry: &ProjectionTargetRegistry,
            parsed: &ProjectionCliArgs,
            receipt: &authn::ProjectionMaintenanceReceipt,
        ) -> anyhow::Result<()> {
            let record = FakeProjectionCommandRecord {
                action: parsed.command.action(),
                operator_subject: receipt.operator_subject().to_owned(),
                registry_has_targets: registry.has_registered_targets(),
            };
            match self.commands.lock() {
                Ok(mut records) => records.push(record),
                Err(poisoned) => poisoned.into_inner().push(record),
            }
            match self.command_result {
                FakeProjectionCommandResult::Success => Ok(()),
                FakeProjectionCommandResult::Failure(reason) => anyhow::bail!(reason),
            }
        }

        async fn shutdown(&self, _session: Self::Session) {
            self.shutdown_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn projection_control_args(subcommand: &str, extra: &[&str]) -> Vec<String> {
        let mut parts = vec![
            "projections",
            subcommand,
            "--operator-service-token",
            "opaque-token",
            "--operator-tenant",
            PROJECTION_FIXTURE_OPERATOR_TENANT,
            "--tenant",
            PROJECTION_FIXTURE_TENANT,
            "--projection",
            PROJECTION_FIXTURE_ID,
            "--version",
            PROJECTION_FIXTURE_VERSION,
        ];
        parts.extend_from_slice(extra);
        args(&parts)
    }

    fn projection_fixture_resource_id(action: ProjectionMaintenanceAction) -> String {
        format!(
            "operation={} tenant={} projection={} version={}",
            action.as_str(),
            PROJECTION_FIXTURE_TENANT,
            PROJECTION_FIXTURE_ID,
            PROJECTION_FIXTURE_VERSION
        )
    }

    fn assert_projection_lifecycle_audit(
        runtime: &FakeProjectionControlRuntime,
        action: ProjectionMaintenanceAction,
        expected_finish: FakeProjectionAuditOutcome,
    ) {
        let audits = runtime.audit_records();
        assert_eq!(audits.len(), 2);
        let resource_id = projection_fixture_resource_id(action);
        assert_eq!(
            audits[0],
            FakeProjectionAuditRecord {
                subject: UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR.to_owned(),
                action: format!("projection.{}.start", action.as_str()),
                outcome: FakeProjectionAuditOutcome::Success,
                resource_id: resource_id.clone(),
            }
        );
        assert_eq!(
            audits[1],
            FakeProjectionAuditRecord {
                subject: PROJECTION_FIXTURE_OPERATOR.to_owned(),
                action: format!("projection.{}.finish", action.as_str()),
                outcome: expected_finish,
                resource_id,
            }
        );
    }

    #[test]
    fn projection_args_parse_replay_with_typed_selector() -> anyhow::Result<()> {
        let parsed = parse_projection_args(&args(&[
            "projections",
            "replay",
            "--operator-service-token",
            "opaque-token",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
            "--tenant",
            "00000000-0000-4000-8000-000000000002",
            "--projection",
            "audit.session-projection",
            "--version",
            "v2",
            "--batch-size",
            "7",
        ]))?;

        assert_eq!(parsed.operator_service_token, "opaque-token");
        assert_eq!(
            parsed.operator_tenant,
            vocab::TenantId::parse("00000000-0000-4000-8000-000000000001")?
        );
        assert_eq!(
            parsed.selector.tenant(),
            vocab::TenantId::parse("00000000-0000-4000-8000-000000000002")?
        );
        assert_eq!(
            parsed.selector.projection().as_str(),
            "audit.session-projection"
        );
        assert_eq!(parsed.selector.version().as_str(), "v2");
        assert!(matches!(
            parsed.command,
            ProjectionCliCommand::Replay { batch_limit }
                if batch_limit.get() == 7
        ));
        Ok(())
    }

    #[test]
    fn projection_args_parse_swap_requires_exact_precondition() -> anyhow::Result<()> {
        let parsed = parse_projection_args(&args(&[
            "projections",
            "swap",
            "--operator-service-token",
            "opaque-token",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
            "--tenant",
            "00000000-0000-4000-8000-000000000002",
            "--projection",
            "audit.session-projection",
            "--version",
            "v2",
            "--expected-active-version",
            "v1",
        ]))?;
        assert!(matches!(
            parsed.command,
            ProjectionCliCommand::Swap {
                precondition: ProjectionPointerPrecondition::ExpectedActiveVersion(ref version),
            } if version.as_str() == "v1"
        ));

        let parsed = parse_projection_args(&args(&[
            "projections",
            "swap",
            "--operator-service-token",
            "opaque-token",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
            "--tenant",
            "00000000-0000-4000-8000-000000000002",
            "--projection",
            "audit.session-projection",
            "--version",
            "v2",
            "--expect-unset",
        ]))?;
        assert!(matches!(
            parsed.command,
            ProjectionCliCommand::Swap {
                precondition: ProjectionPointerPrecondition::ExpectUnset,
            }
        ));

        assert!(
            parse_projection_args(&args(&[
                "projections",
                "swap",
                "--operator-service-token",
                "opaque-token",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
                "--version",
                "v2",
            ]))
            .is_err()
        );
        assert!(
            parse_projection_args(&args(&[
                "projections",
                "swap",
                "--operator-service-token",
                "opaque-token",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
                "--version",
                "v2",
                "--expected-active-version",
                "v1",
                "--expect-unset",
            ]))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn projection_args_fail_closed_on_missing_invalid_or_unknown_flags() {
        let valid_status = [
            "projections",
            "status",
            "--operator-service-token",
            "opaque-token",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
            "--tenant",
            "00000000-0000-4000-8000-000000000002",
            "--projection",
            "audit.session-projection",
            "--version",
            "v2",
        ];
        assert!(parse_projection_args(&args(&valid_status)).is_ok());
        assert!(is_projection_command(&args(&["projections"])));
        assert!(is_projection_command(&args(&["projections", "bogus"])));

        let cases = vec![
            ("missing namespace", args(&[])),
            ("missing subcommand", args(&["projections"])),
            ("unknown subcommand", args(&["projections", "bogus"])),
            (
                "missing operator token",
                args(&[
                    "projections",
                    "status",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--projection",
                    "audit.session-projection",
                    "--version",
                    "v2",
                ]),
            ),
            (
                "empty operator token",
                args(&[
                    "projections",
                    "status",
                    "--operator-service-token",
                    " ",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--projection",
                    "audit.session-projection",
                    "--version",
                    "v2",
                ]),
            ),
            (
                "missing operator tenant",
                args(&[
                    "projections",
                    "status",
                    "--operator-service-token",
                    "opaque-token",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--projection",
                    "audit.session-projection",
                    "--version",
                    "v2",
                ]),
            ),
            (
                "missing tenant",
                args(&[
                    "projections",
                    "status",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--projection",
                    "audit.session-projection",
                    "--version",
                    "v2",
                ]),
            ),
            (
                "missing projection",
                args(&[
                    "projections",
                    "status",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--version",
                    "v2",
                ]),
            ),
            (
                "missing version",
                args(&[
                    "projections",
                    "status",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--projection",
                    "audit.session-projection",
                ]),
            ),
            (
                "invalid operator tenant",
                args(&[
                    "projections",
                    "status",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    "not-a-tenant",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--projection",
                    "audit.session-projection",
                    "--version",
                    "v2",
                ]),
            ),
            (
                "invalid projection",
                args(&[
                    "projections",
                    "status",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--projection",
                    "Audit.SessionProjection",
                    "--version",
                    "v2",
                ]),
            ),
            (
                "invalid version",
                args(&[
                    "projections",
                    "replay",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--projection",
                    "audit.session-projection",
                    "--version",
                    "v 2",
                ]),
            ),
            (
                "unknown flag",
                args(&[
                    "projections",
                    "status",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--projection",
                    "audit.session-projection",
                    "--version",
                    "v2",
                    "--bogus",
                ]),
            ),
            (
                "status rejects precondition",
                args(&[
                    "projections",
                    "status",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--projection",
                    "audit.session-projection",
                    "--version",
                    "v2",
                    "--expected-active-version",
                    "v1",
                ]),
            ),
            (
                "status rejects batch",
                args(&[
                    "projections",
                    "status",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--projection",
                    "audit.session-projection",
                    "--version",
                    "v2",
                    "--batch-size",
                    "7",
                ]),
            ),
            (
                "swap rejects batch",
                args(&[
                    "projections",
                    "swap",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--projection",
                    "audit.session-projection",
                    "--version",
                    "v2",
                    "--expect-unset",
                    "--batch-size",
                    "7",
                ]),
            ),
            (
                "replay rejects precondition",
                args(&[
                    "projections",
                    "replay",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--projection",
                    "audit.session-projection",
                    "--version",
                    "v2",
                    "--expected-active-version",
                    "v1",
                ]),
            ),
            (
                "invalid batch zero",
                args(&[
                    "projections",
                    "replay",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--projection",
                    "audit.session-projection",
                    "--version",
                    "v2",
                    "--batch-size",
                    "0",
                ]),
            ),
            (
                "invalid batch string",
                args(&[
                    "projections",
                    "replay",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--projection",
                    "audit.session-projection",
                    "--version",
                    "v2",
                    "--batch-size",
                    "not-a-number",
                ]),
            ),
            (
                "missing flag value",
                args(&[
                    "projections",
                    "status",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--tenant",
                ]),
            ),
            (
                "duplicate singleton flag",
                args(&[
                    "projections",
                    "status",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-service-token",
                    "other-token",
                    "--operator-tenant",
                    "00000000-0000-4000-8000-000000000001",
                    "--tenant",
                    "00000000-0000-4000-8000-000000000002",
                    "--projection",
                    "audit.session-projection",
                    "--version",
                    "v2",
                ]),
            ),
        ];

        for (name, candidate) in cases {
            assert!(
                parse_projection_args(&candidate).is_err(),
                "case must fail: {name}"
            );
        }
    }

    #[test]
    fn projection_registry_covers_generated_inputs_and_fixture_is_not_vacuous() -> anyhow::Result<()>
    {
        if generated::event::PROJECTION_INPUTS.is_empty() {
            let err = match build_projection_target_registry() {
                Ok(_) => anyhow::bail!("empty generated projection registry must fail fast"),
                Err(err) => err,
            };
            assert!(
                err.to_string()
                    .contains("no generated projection inputs compiled into this runtime"),
                "unexpected error: {err:#}"
            );
        } else {
            build_projection_target_registry()?.validate_coverage()?;
        }

        let mut fixture =
            ProjectionTargetRegistry::from_generated(PROJECTION_REGISTRY_FIXTURE_INPUTS)?;
        assert!(fixture.validate_coverage().is_err());
        fixture.mark_unsupported(ProjectionId::parse("audit.session-projection")?)?;
        fixture.validate_coverage()?;
        assert!(
            fixture
                .target(&ProjectionId::parse("audit.session-projection")?)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn command_idempotency_keyring_config_is_required_rotatable_and_independently_keyed()
    -> anyhow::Result<()> {
        let encode =
            |byte: u8| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![byte; 32]);
        let raw = serde_json::json!({
            "current": {"id": "k2", "key": encode(0x42)},
            "previous": [{"id": "k1", "key": encode(0x24)}]
        })
        .to_string();
        let keyring = build_command_idempotency_keyring_from(|name| {
            (name == COMMAND_IDEMPOTENCY_KEYS_ENV).then(|| raw.clone())
        })?;
        assert_eq!(
            format!("{keyring:?}"),
            "CommandIdempotencyKeyring(<redacted>)"
        );

        assert!(build_command_idempotency_keyring_from(|_| None).is_err());
        let short = serde_json::json!({
            "current": {"id": "k2", "key": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 16])}
        })
        .to_string();
        assert!(
            build_command_idempotency_keyring_from(|name| {
                (name == COMMAND_IDEMPOTENCY_KEYS_ENV).then(|| short.clone())
            })
            .is_err()
        );

        let reused = encode(0x42);
        assert!(
            build_command_idempotency_keyring_from(|name| match name {
                COMMAND_IDEMPOTENCY_KEYS_ENV => Some(raw.clone()),
                "RSS_AUDIT_CHAIN_KEY_B64URL" => Some(reused.clone()),
                _ => None,
            })
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn projection_maintenance_grants_authorize_exact_action_tenant_and_projection()
    -> anyhow::Result<()> {
        let parsed = parse_projection_args(&args(&[
            "projections",
            "status",
            "--operator-service-token",
            "opaque-token",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
            "--tenant",
            "00000000-0000-4000-8000-000000000002",
            "--projection",
            "audit.session-projection",
            "--version",
            "v2",
        ]))?;
        let grants = parse_projection_maintenance_grants(
            "verified-operator|status|00000000-0000-4000-8000-000000000002|audit.session-projection",
        )?;
        let principal = authn::test_support::principal(
            vocab::PrincipalKind::Service,
            "verified-operator",
            None,
        );
        grants.authorize(
            &principal,
            parsed.command.action().authorized_action(),
            parsed.selector.tenant(),
            parsed.selector.projection().as_str(),
        )?;

        let replay_grants = parse_projection_maintenance_grants(
            "verified-operator|replay|00000000-0000-4000-8000-000000000002|audit.session-projection",
        )?;
        assert!(
            replay_grants
                .authorize(
                    &principal,
                    parsed.command.action().authorized_action(),
                    parsed.selector.tenant(),
                    parsed.selector.projection().as_str(),
                )
                .is_err()
        );
        let wrong_tenant_grants = parse_projection_maintenance_grants(
            "verified-operator|status|00000000-0000-4000-8000-000000000003|audit.session-projection",
        )?;
        assert!(
            wrong_tenant_grants
                .authorize(
                    &principal,
                    parsed.command.action().authorized_action(),
                    parsed.selector.tenant(),
                    parsed.selector.projection().as_str(),
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn projection_replay_cli_fields_are_stable_and_loop_continues_only_on_full_completed_batch()
    -> anyhow::Result<()> {
        let fields = projection_stop_cli_fields(&ProjectionStop::ApplyFailed {
            failed_at: consistency::Lsn::new(42),
            kind: EngineErrorKind::Transient,
        });
        assert_eq!(fields.stop, "apply_failed");
        assert_eq!(fields.failed_at_lsn, Some(consistency::Lsn::new(42)));
        assert_eq!(fields.kind, Some("transient"));

        let batch_limit = ProjectionBatchLimit::new(10)?;
        assert!(projection_replay_batch_is_full(10, batch_limit));
        assert!(!projection_replay_batch_is_full(9, batch_limit));
        Ok(())
    }

    #[test]
    fn projection_replay_and_swap_require_registered_runtime_target() -> anyhow::Result<()> {
        let mut fixture =
            ProjectionTargetRegistry::from_generated(PROJECTION_REGISTRY_FIXTURE_INPUTS)?;
        fixture.mark_all_generated_unsupported();
        ensure_projection_command_supported_by_registry(&fixture, &ProjectionCliCommand::Status)?;
        let replay = ensure_projection_command_supported_by_registry(
            &fixture,
            &ProjectionCliCommand::Replay {
                batch_limit: ProjectionBatchLimit::MAX,
            },
        );
        let Err(replay_err) = replay else {
            anyhow::bail!("replay without registered targets must fail");
        };
        assert!(
            replay_err
                .to_string()
                .contains("no registered projection targets compiled into this runtime")
        );
        let swap = ensure_projection_command_supported_by_registry(
            &fixture,
            &ProjectionCliCommand::Swap {
                precondition: ProjectionPointerPrecondition::ExpectUnset,
            },
        );
        let Err(swap_err) = swap else {
            anyhow::bail!("swap without registered targets must fail");
        };
        assert!(
            swap_err
                .to_string()
                .contains("no registered projection targets compiled into this runtime")
        );
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn projection_control_entrypoint_rejects_bad_args_before_runtime_setup() {
        let snapshot = crate::config::test_snapshot(&[]).expect("capture operator config");
        let runtime_inputs = RuntimeInputs::new(snapshot, None);
        let result = run_projection_control_command(&args(&["projections"]), &runtime_inputs).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn projection_control_lifecycle_dispatches_status_replay_and_swap_with_audit()
    -> anyhow::Result<()> {
        let cases = [
            (
                ProjectionMaintenanceAction::Status,
                projection_control_args("status", &[]),
            ),
            (
                ProjectionMaintenanceAction::Replay,
                projection_control_args("replay", &["--batch-size", "7"]),
            ),
            (
                ProjectionMaintenanceAction::Swap,
                projection_control_args("swap", &["--expected-active-version", "v1"]),
            ),
        ];

        for (action, command_args) in cases {
            let runtime =
                FakeProjectionControlRuntime::registered(FakeProjectionCommandResult::Success);
            run_projection_control_command_with_runtime(&command_args, &runtime).await?;

            assert_eq!(runtime.setup_count(), 1);
            assert_eq!(runtime.shutdown_count(), 1);
            assert_projection_lifecycle_audit(
                &runtime,
                action,
                FakeProjectionAuditOutcome::Success,
            );
            assert_eq!(
                runtime.command_records(),
                vec![FakeProjectionCommandRecord {
                    action,
                    operator_subject: PROJECTION_FIXTURE_OPERATOR.to_owned(),
                    registry_has_targets: true,
                }]
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn projection_control_lifecycle_records_replay_dlx_failure_audit() -> anyhow::Result<()> {
        let runtime = FakeProjectionControlRuntime::registered(
            FakeProjectionCommandResult::Failure(
                "projection replay stopped before completion: stop=dead_letter_unsaved failed_at_lsn=42",
            ),
        );
        let result = run_projection_control_command_with_runtime(
            &projection_control_args("replay", &["--batch-size", "1"]),
            &runtime,
        )
        .await;
        let Err(err) = result else {
            anyhow::bail!("replay DLQ failure must fail the control command");
        };
        assert!(
            format!("{err:#}").contains("dead_letter_unsaved"),
            "unexpected error: {err:#}"
        );

        assert_eq!(runtime.setup_count(), 1);
        assert_eq!(runtime.shutdown_count(), 1);
        assert_projection_lifecycle_audit(
            &runtime,
            ProjectionMaintenanceAction::Replay,
            FakeProjectionAuditOutcome::Failure {
                reason: "run_error".to_owned(),
            },
        );
        assert_eq!(
            runtime.command_records(),
            vec![FakeProjectionCommandRecord {
                action: ProjectionMaintenanceAction::Replay,
                operator_subject: PROJECTION_FIXTURE_OPERATOR.to_owned(),
                registry_has_targets: true,
            }]
        );
        Ok(())
    }

    #[tokio::test]
    async fn projection_control_lifecycle_records_stale_swap_refusal_audit() -> anyhow::Result<()> {
        let runtime =
            FakeProjectionControlRuntime::registered(FakeProjectionCommandResult::Failure(
                "projection shadow checkpoint is behind source high-water",
            ));
        let result = run_projection_control_command_with_runtime(
            &projection_control_args("swap", &["--expected-active-version", "v1"]),
            &runtime,
        )
        .await;
        let Err(err) = result else {
            anyhow::bail!("stale swap must fail the control command");
        };
        assert!(
            format!("{err:#}").contains("source high-water"),
            "unexpected error: {err:#}"
        );

        assert_eq!(runtime.setup_count(), 1);
        assert_eq!(runtime.shutdown_count(), 1);
        assert_projection_lifecycle_audit(
            &runtime,
            ProjectionMaintenanceAction::Swap,
            FakeProjectionAuditOutcome::Failure {
                reason: "run_error".to_owned(),
            },
        );
        assert_eq!(
            runtime.command_records(),
            vec![FakeProjectionCommandRecord {
                action: ProjectionMaintenanceAction::Swap,
                operator_subject: PROJECTION_FIXTURE_OPERATOR.to_owned(),
                registry_has_targets: true,
            }]
        );
        Ok(())
    }

    #[tokio::test]
    async fn projection_control_lifecycle_preserves_operator_auth_failure_audit()
    -> anyhow::Result<()> {
        let runtime = FakeProjectionControlRuntime::auth_failure();
        let result = run_projection_control_command_with_runtime(
            &projection_control_args("status", &[]),
            &runtime,
        )
        .await;
        let Err(err) = result else {
            anyhow::bail!("operator auth failure must fail the control command");
        };
        assert!(
            format!("{err:#}").contains("operator auth"),
            "unexpected error: {err:#}"
        );

        assert_eq!(runtime.setup_count(), 1);
        assert_eq!(runtime.shutdown_count(), 1);
        assert!(runtime.command_records().is_empty());
        assert_eq!(
            runtime.audit_records(),
            vec![
                FakeProjectionAuditRecord {
                    subject: UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR.to_owned(),
                    action: "projection.status.start".to_owned(),
                    outcome: FakeProjectionAuditOutcome::Success,
                    resource_id: projection_fixture_resource_id(
                        ProjectionMaintenanceAction::Status
                    ),
                },
                FakeProjectionAuditRecord {
                    subject: UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR.to_owned(),
                    action: "projection.status.finish".to_owned(),
                    outcome: FakeProjectionAuditOutcome::Failure {
                        reason: "operator_auth".to_owned(),
                    },
                    resource_id: projection_fixture_resource_id(
                        ProjectionMaintenanceAction::Status
                    ),
                },
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn projection_control_lifecycle_registry_gate_runs_before_runtime_setup()
    -> anyhow::Result<()> {
        let runtime =
            FakeProjectionControlRuntime::unsupported(FakeProjectionCommandResult::Success);
        let result = run_projection_control_command_with_runtime(
            &projection_control_args("replay", &[]),
            &runtime,
        )
        .await;
        let Err(err) = result else {
            anyhow::bail!("replay without registered targets must fail");
        };
        assert!(
            format!("{err:#}")
                .contains("no registered projection targets compiled into this runtime"),
            "unexpected error: {err:#}"
        );

        assert_eq!(runtime.setup_count(), 0);
        assert_eq!(runtime.shutdown_count(), 0);
        assert!(runtime.audit_records().is_empty());
        assert!(runtime.command_records().is_empty());
        Ok(())
    }

    const AUDIT_LEDGER_FIXTURE_OPERATOR_TENANT: &str = "00000000-0000-4000-8000-000000000001";
    const AUDIT_LEDGER_FIXTURE_TENANT: &str = "00000000-0000-4000-8000-000000000002";
    const AUDIT_LEDGER_FIXTURE_OTHER_TENANT: &str = "00000000-0000-4000-8000-000000000003";
    const AUDIT_LEDGER_FIXTURE_OPERATOR: &str = "verified-audit-ledger-operator";

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FakeAuditLedgerVerifyAuditOutcome {
        Success,
        Failure { reason: String },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeAuditLedgerVerifyAuditRecord {
        subject: String,
        action: String,
        outcome: FakeAuditLedgerVerifyAuditOutcome,
        resource_id: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeAuditLedgerVerifyCommandRecord {
        tenant: vocab::TenantId,
        batch: u16,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FakeAuditLedgerVerifyOperator {
        Verified(&'static str),
        AuthFailure,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FakeAuditLedgerVerifyResult {
        Success { checked_entries: u64 },
        Failure(&'static str),
    }

    struct FakeAuditLedgerVerifyRuntime {
        operator: FakeAuditLedgerVerifyOperator,
        verify_result: FakeAuditLedgerVerifyResult,
        audits: Mutex<Vec<FakeAuditLedgerVerifyAuditRecord>>,
        commands: Mutex<Vec<FakeAuditLedgerVerifyCommandRecord>>,
        setup_count: AtomicUsize,
        shutdown_count: AtomicUsize,
    }

    impl FakeAuditLedgerVerifyRuntime {
        fn success(checked_entries: u64) -> Self {
            Self::new(
                FakeAuditLedgerVerifyOperator::Verified(AUDIT_LEDGER_FIXTURE_OPERATOR),
                FakeAuditLedgerVerifyResult::Success { checked_entries },
            )
        }

        fn failure(reason: &'static str) -> Self {
            Self::new(
                FakeAuditLedgerVerifyOperator::Verified(AUDIT_LEDGER_FIXTURE_OPERATOR),
                FakeAuditLedgerVerifyResult::Failure(reason),
            )
        }

        fn auth_failure() -> Self {
            Self::new(
                FakeAuditLedgerVerifyOperator::AuthFailure,
                FakeAuditLedgerVerifyResult::Success { checked_entries: 0 },
            )
        }

        fn new(
            operator: FakeAuditLedgerVerifyOperator,
            verify_result: FakeAuditLedgerVerifyResult,
        ) -> Self {
            Self {
                operator,
                verify_result,
                audits: Mutex::new(Vec::new()),
                commands: Mutex::new(Vec::new()),
                setup_count: AtomicUsize::new(0),
                shutdown_count: AtomicUsize::new(0),
            }
        }

        fn audit_records(&self) -> Vec<FakeAuditLedgerVerifyAuditRecord> {
            match self.audits.lock() {
                Ok(records) => records.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }

        fn command_records(&self) -> Vec<FakeAuditLedgerVerifyCommandRecord> {
            match self.commands.lock() {
                Ok(records) => records.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }

        fn setup_count(&self) -> usize {
            self.setup_count.load(Ordering::Relaxed)
        }

        fn shutdown_count(&self) -> usize {
            self.shutdown_count.load(Ordering::Relaxed)
        }
    }

    impl AuditLedgerVerifyRuntime for FakeAuditLedgerVerifyRuntime {
        type Session = ();

        async fn connect_maintenance(&self) -> anyhow::Result<Self::Session> {
            self.setup_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn record_audit_ledger_verify_audit(
            &self,
            _session: &Self::Session,
            operator_subject: &str,
            action: &str,
            outcome: MaintenanceAuditOutcome<'_>,
            resource_id: &str,
        ) -> anyhow::Result<()> {
            let outcome = match outcome {
                MaintenanceAuditOutcome::Success => FakeAuditLedgerVerifyAuditOutcome::Success,
                MaintenanceAuditOutcome::Failure { reason } => {
                    FakeAuditLedgerVerifyAuditOutcome::Failure {
                        reason: reason.to_owned(),
                    }
                }
            };
            let record = FakeAuditLedgerVerifyAuditRecord {
                subject: operator_subject.to_owned(),
                action: action.to_owned(),
                outcome,
                resource_id: resource_id.to_owned(),
            };
            match self.audits.lock() {
                Ok(mut records) => records.push(record),
                Err(poisoned) => poisoned.into_inner().push(record),
            }
            Ok(())
        }

        async fn operator_subject(
            &self,
            session: &Self::Session,
            _parsed: &AuditLedgerVerifyArgs,
            resource_id: &str,
        ) -> anyhow::Result<String> {
            match self.operator {
                FakeAuditLedgerVerifyOperator::Verified(subject) => Ok(subject.to_owned()),
                FakeAuditLedgerVerifyOperator::AuthFailure => {
                    self.record_audit_ledger_verify_audit(
                        session,
                        UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR,
                        "audit.ledger.verify.finish",
                        MaintenanceAuditOutcome::Failure {
                            reason: "operator_auth",
                        },
                        resource_id,
                    )
                    .await?;
                    anyhow::bail!("audit ledger verify operator auth failed");
                }
            }
        }

        async fn verify_tenant(
            &self,
            _session: &Self::Session,
            parsed: &AuditLedgerVerifyArgs,
        ) -> anyhow::Result<AuditLedgerVerifyReport> {
            let record = FakeAuditLedgerVerifyCommandRecord {
                tenant: parsed.tenant,
                batch: parsed.batch.get(),
            };
            match self.commands.lock() {
                Ok(mut records) => records.push(record),
                Err(poisoned) => poisoned.into_inner().push(record),
            }
            match self.verify_result {
                FakeAuditLedgerVerifyResult::Success { checked_entries } => {
                    Ok(AuditLedgerVerifyReport {
                        tenant: parsed.tenant,
                        checked_entries,
                    })
                }
                FakeAuditLedgerVerifyResult::Failure(reason) => anyhow::bail!(reason),
            }
        }

        async fn shutdown(&self, _session: Self::Session) {
            self.shutdown_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn audit_ledger_verify_args(extra: &[&str]) -> Vec<String> {
        let mut parts = vec![
            "audit-ledger",
            "verify",
            "--operator-service-token",
            "opaque-token",
            "--operator-tenant",
            AUDIT_LEDGER_FIXTURE_OPERATOR_TENANT,
            "--tenant",
            AUDIT_LEDGER_FIXTURE_TENANT,
        ];
        parts.extend_from_slice(extra);
        args(&parts)
    }

    fn audit_ledger_fixture_resource_id(batch: u16) -> String {
        format!(
            "tenant={} batch_size={}",
            AUDIT_LEDGER_FIXTURE_TENANT, batch
        )
    }

    fn assert_audit_ledger_verify_lifecycle_audit(
        runtime: &FakeAuditLedgerVerifyRuntime,
        batch: u16,
        expected_finish: FakeAuditLedgerVerifyAuditOutcome,
    ) {
        let audits = runtime.audit_records();
        assert_eq!(audits.len(), 2);
        let resource_id = audit_ledger_fixture_resource_id(batch);
        assert_eq!(
            audits[0],
            FakeAuditLedgerVerifyAuditRecord {
                subject: UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR.to_owned(),
                action: "audit.ledger.verify.start".to_owned(),
                outcome: FakeAuditLedgerVerifyAuditOutcome::Success,
                resource_id: resource_id.clone(),
            }
        );
        assert_eq!(
            audits[1],
            FakeAuditLedgerVerifyAuditRecord {
                subject: AUDIT_LEDGER_FIXTURE_OPERATOR.to_owned(),
                action: "audit.ledger.verify.finish".to_owned(),
                outcome: expected_finish,
                resource_id,
            }
        );
    }

    #[test]
    fn audit_ledger_verify_args_parse_typed_and_fail_closed() -> anyhow::Result<()> {
        let parsed =
            parse_audit_ledger_verify_args(&audit_ledger_verify_args(&["--batch-size", "7"]))?;
        assert_eq!(parsed.operator_service_token, "opaque-token");
        assert_eq!(
            parsed.operator_tenant,
            vocab::TenantId::parse(AUDIT_LEDGER_FIXTURE_OPERATOR_TENANT)?
        );
        assert_eq!(
            parsed.tenant,
            vocab::TenantId::parse(AUDIT_LEDGER_FIXTURE_TENANT)?
        );
        assert_eq!(parsed.batch.get(), 7);
        assert!(is_audit_ledger_verify_command(&args(&[
            "audit-ledger",
            "verify"
        ])));

        let cases = vec![
            ("missing namespace", args(&[])),
            ("missing subcommand", args(&["audit-ledger"])),
            ("unknown subcommand", args(&["audit-ledger", "tail"])),
            (
                "missing operator token",
                args(&[
                    "audit-ledger",
                    "verify",
                    "--operator-tenant",
                    AUDIT_LEDGER_FIXTURE_OPERATOR_TENANT,
                    "--tenant",
                    AUDIT_LEDGER_FIXTURE_TENANT,
                ]),
            ),
            (
                "empty operator token",
                args(&[
                    "audit-ledger",
                    "verify",
                    "--operator-service-token",
                    " ",
                    "--operator-tenant",
                    AUDIT_LEDGER_FIXTURE_OPERATOR_TENANT,
                    "--tenant",
                    AUDIT_LEDGER_FIXTURE_TENANT,
                ]),
            ),
            (
                "missing tenant",
                args(&[
                    "audit-ledger",
                    "verify",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    AUDIT_LEDGER_FIXTURE_OPERATOR_TENANT,
                ]),
            ),
            (
                "missing flag value",
                args(&[
                    "audit-ledger",
                    "verify",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                ]),
            ),
            (
                "duplicate singleton flag",
                args(&[
                    "audit-ledger",
                    "verify",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-service-token",
                    "other-token",
                    "--operator-tenant",
                    AUDIT_LEDGER_FIXTURE_OPERATOR_TENANT,
                    "--tenant",
                    AUDIT_LEDGER_FIXTURE_TENANT,
                ]),
            ),
            (
                "invalid batch zero",
                audit_ledger_verify_args(&["--batch-size", "0"]),
            ),
            (
                "invalid batch over max",
                audit_ledger_verify_args(&["--batch-size", "501"]),
            ),
            (
                "unsupported all tenants",
                audit_ledger_verify_args(&["--all-tenants"]),
            ),
            (
                "unsupported namespace",
                audit_ledger_verify_args(&["--namespace", "prod"]),
            ),
            ("unknown flag", audit_ledger_verify_args(&["--bogus"])),
        ];

        for (name, candidate) in cases {
            assert!(
                parse_audit_ledger_verify_args(&candidate).is_err(),
                "case must fail: {name}"
            );
        }
        Ok(())
    }

    #[test]
    fn audit_ledger_verify_grants_authorize_exact_subject_and_tenant() -> anyhow::Result<()> {
        let parsed = parse_audit_ledger_verify_args(&audit_ledger_verify_args(&[]))?;
        let grants = parse_audit_ledger_verify_grants(&format!(
            "{}|{}",
            AUDIT_LEDGER_FIXTURE_OPERATOR, AUDIT_LEDGER_FIXTURE_TENANT
        ))?;
        authorize_audit_ledger_verify_operator(AUDIT_LEDGER_FIXTURE_OPERATOR, &parsed, &grants)?;

        let wrong_subject = parse_audit_ledger_verify_grants(&format!(
            "other-operator|{}",
            AUDIT_LEDGER_FIXTURE_TENANT
        ))?;
        assert!(
            authorize_audit_ledger_verify_operator(
                AUDIT_LEDGER_FIXTURE_OPERATOR,
                &parsed,
                &wrong_subject
            )
            .is_err()
        );
        let wrong_tenant = parse_audit_ledger_verify_grants(&format!(
            "{}|{}",
            AUDIT_LEDGER_FIXTURE_OPERATOR, AUDIT_LEDGER_FIXTURE_OTHER_TENANT
        ))?;
        assert!(
            authorize_audit_ledger_verify_operator(
                AUDIT_LEDGER_FIXTURE_OPERATOR,
                &parsed,
                &wrong_tenant
            )
            .is_err()
        );
        assert!(parse_audit_ledger_verify_grants("").is_err());
        assert!(parse_audit_ledger_verify_grants("operator-only").is_err());
        assert!(parse_audit_ledger_verify_grants("operator|not-a-tenant").is_err());
        Ok(())
    }

    #[tokio::test]
    async fn audit_ledger_verify_lifecycle_records_success_audit() -> anyhow::Result<()> {
        let runtime = FakeAuditLedgerVerifyRuntime::success(3);
        run_audit_ledger_verify_command_with_runtime(
            &audit_ledger_verify_args(&["--batch-size", "7"]),
            &runtime,
        )
        .await?;

        assert_eq!(runtime.setup_count(), 1);
        assert_eq!(runtime.shutdown_count(), 1);
        assert_audit_ledger_verify_lifecycle_audit(
            &runtime,
            7,
            FakeAuditLedgerVerifyAuditOutcome::Success,
        );
        assert_eq!(
            runtime.command_records(),
            vec![FakeAuditLedgerVerifyCommandRecord {
                tenant: vocab::TenantId::parse(AUDIT_LEDGER_FIXTURE_TENANT)?,
                batch: 7,
            }]
        );
        Ok(())
    }

    #[tokio::test]
    async fn audit_ledger_verify_lifecycle_records_run_error_audit() -> anyhow::Result<()> {
        let runtime =
            FakeAuditLedgerVerifyRuntime::failure("audit ledger verify requires audit admin pool");
        let result =
            run_audit_ledger_verify_command_with_runtime(&audit_ledger_verify_args(&[]), &runtime)
                .await;
        let Err(err) = result else {
            anyhow::bail!("verify failure must fail the command");
        };
        assert!(
            format!("{err:#}").contains("audit admin pool"),
            "unexpected error: {err:#}"
        );

        assert_eq!(runtime.setup_count(), 1);
        assert_eq!(runtime.shutdown_count(), 1);
        assert_audit_ledger_verify_lifecycle_audit(
            &runtime,
            500,
            FakeAuditLedgerVerifyAuditOutcome::Failure {
                reason: "run_error".to_owned(),
            },
        );
        assert_eq!(runtime.command_records().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn audit_ledger_verify_lifecycle_preserves_operator_auth_failure_audit()
    -> anyhow::Result<()> {
        let runtime = FakeAuditLedgerVerifyRuntime::auth_failure();
        let result =
            run_audit_ledger_verify_command_with_runtime(&audit_ledger_verify_args(&[]), &runtime)
                .await;
        let Err(err) = result else {
            anyhow::bail!("operator auth failure must fail the command");
        };
        assert!(
            format!("{err:#}").contains("operator auth"),
            "unexpected error: {err:#}"
        );

        assert_eq!(runtime.setup_count(), 1);
        assert_eq!(runtime.shutdown_count(), 1);
        assert!(runtime.command_records().is_empty());
        assert_eq!(
            runtime.audit_records(),
            vec![
                FakeAuditLedgerVerifyAuditRecord {
                    subject: UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR.to_owned(),
                    action: "audit.ledger.verify.start".to_owned(),
                    outcome: FakeAuditLedgerVerifyAuditOutcome::Success,
                    resource_id: audit_ledger_fixture_resource_id(500),
                },
                FakeAuditLedgerVerifyAuditRecord {
                    subject: UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR.to_owned(),
                    action: "audit.ledger.verify.finish".to_owned(),
                    outcome: FakeAuditLedgerVerifyAuditOutcome::Failure {
                        reason: "operator_auth".to_owned(),
                    },
                    resource_id: audit_ledger_fixture_resource_id(500),
                },
            ]
        );
        Ok(())
    }

    const DLQ_FIXTURE_OPERATOR_TENANT: &str = "00000000-0000-4000-8000-000000000001";
    const DLQ_FIXTURE_TENANT: &str = "00000000-0000-4000-8000-000000000002";
    const DLQ_FIXTURE_OTHER_TENANT: &str = "00000000-0000-4000-8000-000000000003";
    const DLQ_FIXTURE_OPERATOR: &str = "verified-dlq-operator";
    const DLQ_FIXTURE_DEAD_LETTER_ID: &str = "11111111-1111-4111-8111-111111111111";
    const DLQ_FIXTURE_REPLAY_ID: &str = "evt-dlq-replay";
    const DLQ_FIXTURE_EVENT_ID: &str = "evt-outbox-dlx";
    const DLQ_FIXTURE_EVIDENCE_EVENT_ID: &str = "evt-outbox-compensation";
    const DLQ_FIXTURE_CHANGE_TICKET: &str = "CHG-1742";

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FakeDlqAuditOutcome {
        Success,
        Failure { reason: String },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeDlqAuditRecord {
        subject: String,
        action: String,
        outcome: FakeDlqAuditOutcome,
        resource_id: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FakeDlqCommandRecord {
        List {
            tenant: vocab::TenantId,
            source: Option<diport::DeadLetterSource>,
            producer_domain: Option<String>,
            consumer_domain: Option<String>,
            contract_id: Option<String>,
            limit: u32,
            cursor: Option<String>,
        },
        Inspect {
            tenant: vocab::TenantId,
            target: DlqInspectTarget,
        },
        ReplayDeadLetter {
            tenant: vocab::TenantId,
            dead_letter_id: String,
            replay_id: String,
        },
        RedriveOutbox {
            tenant: vocab::TenantId,
            event_id: String,
        },
        ResolveExpiredOutbox {
            tenant: vocab::TenantId,
            event_id: String,
            resolution_kind: OutboxExpiredResolutionKind,
            evidence_event_id: Option<String>,
            operator_subject: String,
        },
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FakeDlqOperator {
        Verified(&'static str),
        AuthFailure,
        GrantFailure,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FakeDlqStoreMode {
        Success,
        NotFound,
        Expired,
        EvidenceRejected,
        StoreFailure,
    }

    #[derive(Clone)]
    struct FakeDlqStore {
        mode: FakeDlqStoreMode,
        commands: Arc<Mutex<Vec<FakeDlqCommandRecord>>>,
    }

    impl FakeDlqStore {
        fn new(mode: FakeDlqStoreMode, commands: Arc<Mutex<Vec<FakeDlqCommandRecord>>>) -> Self {
            Self { mode, commands }
        }

        fn push(&self, record: FakeDlqCommandRecord) {
            match self.commands.lock() {
                Ok(mut records) => records.push(record),
                Err(poisoned) => poisoned.into_inner().push(record),
            }
        }

        fn maybe_fail(&self) -> Result<(), DlqError> {
            match self.mode {
                FakeDlqStoreMode::Success
                | FakeDlqStoreMode::NotFound
                | FakeDlqStoreMode::Expired
                | FakeDlqStoreMode::EvidenceRejected => Ok(()),
                FakeDlqStoreMode::StoreFailure => Err(DlqError::Store),
            }
        }
    }

    impl DlqStore for FakeDlqStore {
        async fn list_dlq(
            &self,
            query: DlqListQuery,
        ) -> Result<eventexec::DlqListResult, DlqError> {
            self.push(FakeDlqCommandRecord::List {
                tenant: query.tenant(),
                source: query.source(),
                producer_domain: query.producer_domain().map(ToOwned::to_owned),
                consumer_domain: query.consumer_domain().map(ToOwned::to_owned),
                contract_id: query.contract_id().map(ToOwned::to_owned),
                limit: query.limit(),
                cursor: query.cursor().map(DlqCursor::encode),
            });
            self.maybe_fail()?;
            let rows = vec![dlq_summary(
                query.tenant(),
                eventexec::DlqEntryKind::DeadLetter,
            )];
            Ok(eventexec::DlqListResult::from_sorted_rows(&query, rows))
        }

        async fn inspect_dlq(
            &self,
            request: DlqInspectRequest,
        ) -> Result<DlqEntrySummary, DlqError> {
            self.push(FakeDlqCommandRecord::Inspect {
                tenant: request.tenant(),
                target: request.target().clone(),
            });
            self.maybe_fail()?;
            Ok(dlq_summary(request.tenant(), request.target().kind()))
        }

        async fn replay_dead_letter(
            &self,
            request: DlqReplayRequest,
        ) -> Result<eventexec::DlqReplayOutcome, DlqError> {
            self.push(FakeDlqCommandRecord::ReplayDeadLetter {
                tenant: request.tenant(),
                dead_letter_id: request.dead_letter_id().as_str().to_owned(),
                replay_id: request.replay_id().as_str().to_owned(),
            });
            self.maybe_fail()?;
            Ok(eventexec::DlqReplayOutcome::Inserted)
        }

        async fn redrive_outbox(
            &self,
            request: DlqRedriveRequest,
        ) -> Result<eventexec::DlqRedriveOutcome, DlqError> {
            self.push(FakeDlqCommandRecord::RedriveOutbox {
                tenant: request.tenant(),
                event_id: request.event_id().as_str().to_owned(),
            });
            match self.mode {
                FakeDlqStoreMode::Success => Ok(eventexec::DlqRedriveOutcome::Redriven),
                FakeDlqStoreMode::NotFound => Ok(eventexec::DlqRedriveOutcome::NotFound),
                FakeDlqStoreMode::Expired => Ok(eventexec::DlqRedriveOutcome::Expired),
                FakeDlqStoreMode::EvidenceRejected | FakeDlqStoreMode::StoreFailure => {
                    Err(DlqError::Store)
                }
            }
        }

        async fn resolve_expired_outbox(
            &self,
            request: OutboxExpiredResolutionRequest,
        ) -> Result<OutboxExpiredResolutionOutcome, DlqError> {
            self.push(FakeDlqCommandRecord::ResolveExpiredOutbox {
                tenant: request.tenant(),
                event_id: request.event_id().as_str().to_owned(),
                resolution_kind: request.kind(),
                evidence_event_id: request
                    .evidence_event_id()
                    .map(|event_id| event_id.as_str().to_owned()),
                operator_subject: request.operator_subject().as_str().to_owned(),
            });
            match self.mode {
                FakeDlqStoreMode::Success => Ok(OutboxExpiredResolutionOutcome::Resolved),
                FakeDlqStoreMode::NotFound => Ok(OutboxExpiredResolutionOutcome::NotFound),
                FakeDlqStoreMode::Expired => Ok(OutboxExpiredResolutionOutcome::NotExpired),
                FakeDlqStoreMode::EvidenceRejected => {
                    Ok(OutboxExpiredResolutionOutcome::EvidenceRejected)
                }
                FakeDlqStoreMode::StoreFailure => Err(DlqError::Store),
            }
        }
    }

    struct FakeDlqControlRuntime {
        operator: FakeDlqOperator,
        store_mode: FakeDlqStoreMode,
        audits: Mutex<Vec<FakeDlqAuditRecord>>,
        commands: Arc<Mutex<Vec<FakeDlqCommandRecord>>>,
        setup_count: AtomicUsize,
        shutdown_count: AtomicUsize,
    }

    impl FakeDlqControlRuntime {
        fn verified(store_mode: FakeDlqStoreMode) -> Self {
            Self::new(FakeDlqOperator::Verified(DLQ_FIXTURE_OPERATOR), store_mode)
        }

        fn auth_failure() -> Self {
            Self::new(FakeDlqOperator::AuthFailure, FakeDlqStoreMode::Success)
        }

        fn grant_failure() -> Self {
            Self::new(FakeDlqOperator::GrantFailure, FakeDlqStoreMode::Success)
        }

        fn new(operator: FakeDlqOperator, store_mode: FakeDlqStoreMode) -> Self {
            Self {
                operator,
                store_mode,
                audits: Mutex::new(Vec::new()),
                commands: Arc::new(Mutex::new(Vec::new())),
                setup_count: AtomicUsize::new(0),
                shutdown_count: AtomicUsize::new(0),
            }
        }

        fn audit_records(&self) -> Vec<FakeDlqAuditRecord> {
            match self.audits.lock() {
                Ok(records) => records.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }

        fn command_records(&self) -> Vec<FakeDlqCommandRecord> {
            match self.commands.lock() {
                Ok(records) => records.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }

        fn setup_count(&self) -> usize {
            self.setup_count.load(Ordering::Relaxed)
        }

        fn shutdown_count(&self) -> usize {
            self.shutdown_count.load(Ordering::Relaxed)
        }
    }

    impl DlqControlRuntime for FakeDlqControlRuntime {
        type Session = ();
        type Store = FakeDlqStore;

        async fn connect_maintenance(&self) -> anyhow::Result<Self::Session> {
            self.setup_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn record_dlq_maintenance_audit(
            &self,
            _session: &Self::Session,
            operator_subject: &str,
            action: &str,
            outcome: MaintenanceAuditOutcome<'_>,
            resource_id: &str,
        ) -> anyhow::Result<()> {
            let outcome = match outcome {
                MaintenanceAuditOutcome::Success => FakeDlqAuditOutcome::Success,
                MaintenanceAuditOutcome::Failure { reason } => FakeDlqAuditOutcome::Failure {
                    reason: reason.to_owned(),
                },
            };
            let record = FakeDlqAuditRecord {
                subject: operator_subject.to_owned(),
                action: action.to_owned(),
                outcome,
                resource_id: resource_id.to_owned(),
            };
            match self.audits.lock() {
                Ok(mut records) => records.push(record),
                Err(poisoned) => poisoned.into_inner().push(record),
            }
            Ok(())
        }

        async fn operator_subject(
            &self,
            session: &Self::Session,
            parsed: &DlqCliArgs,
            resource_id: &str,
        ) -> anyhow::Result<String> {
            match self.operator {
                FakeDlqOperator::Verified(subject) => Ok(subject.to_owned()),
                FakeDlqOperator::AuthFailure => {
                    self.record_dlq_maintenance_audit(
                        session,
                        UNVERIFIED_DLQ_OPERATOR,
                        &format!("dlq.{}.finish", parsed.command.action().as_str()),
                        MaintenanceAuditOutcome::Failure {
                            reason: "operator_auth",
                        },
                        resource_id,
                    )
                    .await?;
                    anyhow::bail!("DLQ operator auth failed");
                }
                FakeDlqOperator::GrantFailure => {
                    self.record_dlq_maintenance_audit(
                        session,
                        DLQ_FIXTURE_OPERATOR,
                        &format!("dlq.{}.finish", parsed.command.action().as_str()),
                        MaintenanceAuditOutcome::Failure {
                            reason: "operator_authorization",
                        },
                        resource_id,
                    )
                    .await?;
                    anyhow::bail!("DLQ operator grant failed");
                }
            }
        }

        fn dlq_store(
            &self,
            _session: &Self::Session,
            _command: &DlqCliCommand,
        ) -> anyhow::Result<Self::Store> {
            Ok(FakeDlqStore::new(
                self.store_mode,
                Arc::clone(&self.commands),
            ))
        }

        async fn shutdown(&self, _session: Self::Session) {
            self.shutdown_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn dlq_summary(tenant: vocab::TenantId, kind: eventexec::DlqEntryKind) -> DlqEntrySummary {
        DlqEntrySummary::new(
            kind,
            "dlq-row-1",
            diport::DeadLetterSource::Consumer,
            tenant,
            "msg-1",
            "identity",
            Some("audit".to_owned()),
            "identity.session-created",
            "identity.session.created",
            Some("identity.session.consumer".to_owned()),
            12,
            "max retries exhausted",
            3,
            1_700_000_000,
        )
    }

    fn dlq_control_args(subcommand: &str, extra: &[&str]) -> Vec<String> {
        let mut parts = vec![
            "dlq",
            subcommand,
            "--operator-service-token",
            "opaque-token",
            "--operator-tenant",
            DLQ_FIXTURE_OPERATOR_TENANT,
            "--tenant",
            DLQ_FIXTURE_TENANT,
        ];
        parts.extend_from_slice(extra);
        args(&parts)
    }

    fn dlq_fixture_resource_id(action: DlqMaintenanceAction, target: &str) -> String {
        format!(
            "operation={} tenant={} {}",
            action.as_str(),
            DLQ_FIXTURE_TENANT,
            target
        )
    }

    fn assert_dlq_lifecycle_audit(
        runtime: &FakeDlqControlRuntime,
        action: DlqMaintenanceAction,
        target: &str,
        expected_finish: FakeDlqAuditOutcome,
    ) {
        let audits = runtime.audit_records();
        assert_eq!(audits.len(), 2);
        let resource_id = dlq_fixture_resource_id(action, target);
        assert_eq!(
            audits[0],
            FakeDlqAuditRecord {
                subject: UNVERIFIED_DLQ_OPERATOR.to_owned(),
                action: format!("dlq.{}.start", action.as_str()),
                outcome: FakeDlqAuditOutcome::Success,
                resource_id: resource_id.clone(),
            }
        );
        assert_eq!(
            audits[1],
            FakeDlqAuditRecord {
                subject: DLQ_FIXTURE_OPERATOR.to_owned(),
                action: format!("dlq.{}.finish", action.as_str()),
                outcome: expected_finish,
                resource_id,
            }
        );
    }

    #[test]
    fn dlq_args_parse_list_and_inspect() -> anyhow::Result<()> {
        let list = parse_dlq_args(&dlq_control_args(
            "list",
            &[
                "--source",
                "consumer",
                "--producer-domain",
                "identity",
                "--consumer-domain",
                "audit",
                "--contract-id",
                "identity.session-created",
                "--limit",
                "7",
                "--cursor",
                "1700000000:dead_letter:row-1",
            ],
        ))?;
        assert_eq!(list.operator_service_token, "opaque-token");
        assert_eq!(
            list.operator_tenant,
            vocab::TenantId::parse(DLQ_FIXTURE_OPERATOR_TENANT)?
        );
        assert_eq!(list.tenant, vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?);
        assert!(matches!(
            list.command,
            DlqCliCommand::List {
                source: Some(diport::DeadLetterSource::Consumer),
                ref producer_domain,
                ref consumer_domain,
                ref contract_id,
                limit: 7,
                ref cursor,
            } if producer_domain.as_deref() == Some("identity")
                && consumer_domain.as_deref() == Some("audit")
                && contract_id.as_deref() == Some("identity.session-created")
                && cursor.as_ref().map(DlqCursor::encode).as_deref()
                    == Some("1700000000:dead_letter:row-1")
        ));

        let inspect = parse_dlq_args(&dlq_control_args(
            "inspect",
            &["--kind", "outbox-dlx", "--id", DLQ_FIXTURE_EVENT_ID],
        ))?;
        assert!(matches!(
            inspect.command,
            DlqCliCommand::Inspect {
                target: DlqInspectTarget::OutboxDlx(ref event_id),
            } if event_id.as_str() == DLQ_FIXTURE_EVENT_ID
        ));
        Ok(())
    }

    #[test]
    fn dlq_args_parse_replay_redrive_and_expired_resolution() -> anyhow::Result<()> {
        let replay = parse_dlq_args(&dlq_control_args(
            "replay-dead-letter",
            &[
                "--dead-letter-id",
                DLQ_FIXTURE_DEAD_LETTER_ID,
                "--replay-id",
                DLQ_FIXTURE_REPLAY_ID,
            ],
        ))?;
        assert!(matches!(
            replay.command,
            DlqCliCommand::ReplayDeadLetter {
                ref dead_letter_id,
                ref replay_id,
            } if dead_letter_id.as_str() == DLQ_FIXTURE_DEAD_LETTER_ID
                && replay_id.as_str() == DLQ_FIXTURE_REPLAY_ID
        ));

        let redrive = parse_dlq_args(&dlq_control_args(
            "redrive-outbox",
            &["--event-id", DLQ_FIXTURE_EVENT_ID],
        ))?;
        assert!(matches!(
            redrive.command,
            DlqCliCommand::RedriveOutbox { ref event_id }
                if event_id.as_str() == DLQ_FIXTURE_EVENT_ID
        ));

        let accepted_gap = parse_dlq_args(&dlq_control_args(
            "resolve-expired-outbox",
            &[
                "--event-id",
                DLQ_FIXTURE_EVENT_ID,
                "--change-ticket",
                DLQ_FIXTURE_CHANGE_TICKET,
                "--resolution-kind",
                "accepted_gap",
            ],
        ))?;
        assert!(matches!(
            accepted_gap.command,
            DlqCliCommand::ResolveExpiredOutbox {
                ref event_id,
                ref change_ticket,
                resolution_kind: OutboxExpiredResolutionKind::AcceptedGap,
                evidence_event_id: None,
            } if event_id.as_str() == DLQ_FIXTURE_EVENT_ID
                && change_ticket.as_str() == DLQ_FIXTURE_CHANGE_TICKET
        ));

        let compensated = parse_dlq_args(&dlq_control_args(
            "resolve-expired-outbox",
            &[
                "--event-id",
                DLQ_FIXTURE_EVENT_ID,
                "--change-ticket",
                DLQ_FIXTURE_CHANGE_TICKET,
                "--resolution-kind",
                "compensated",
                "--evidence-event-id",
                DLQ_FIXTURE_EVIDENCE_EVENT_ID,
            ],
        ))?;
        assert!(matches!(
            compensated.command,
            DlqCliCommand::ResolveExpiredOutbox {
                resolution_kind: OutboxExpiredResolutionKind::Compensated,
                evidence_event_id: Some(ref evidence_event_id),
                ..
            } if evidence_event_id.as_str() == DLQ_FIXTURE_EVIDENCE_EVENT_ID
        ));
        Ok(())
    }

    #[test]
    fn dlq_args_fail_closed_on_missing_invalid_duplicate_or_unknown_flags() {
        let cases = [
            ("missing namespace", args(&[])),
            ("missing subcommand", args(&["dlq"])),
            ("unknown subcommand", args(&["dlq", "skip"])),
            (
                "missing operator token",
                args(&[
                    "dlq",
                    "list",
                    "--operator-tenant",
                    DLQ_FIXTURE_OPERATOR_TENANT,
                    "--tenant",
                    DLQ_FIXTURE_TENANT,
                ]),
            ),
            (
                "invalid tenant",
                args(&[
                    "dlq",
                    "list",
                    "--operator-service-token",
                    "opaque-token",
                    "--operator-tenant",
                    DLQ_FIXTURE_OPERATOR_TENANT,
                    "--tenant",
                    "not-a-uuid",
                ]),
            ),
            (
                "invalid inspect id",
                dlq_control_args("inspect", &["--kind", "dead-letter", "--id", "not-a-uuid"]),
            ),
            (
                "invalid cursor",
                dlq_control_args("list", &["--cursor", "not-a-cursor"]),
            ),
            (
                "duplicate tenant",
                dlq_control_args("list", &["--tenant", DLQ_FIXTURE_TENANT]),
            ),
            (
                "unknown flag",
                dlq_control_args(
                    "redrive-outbox",
                    &["--event-id", DLQ_FIXTURE_EVENT_ID, "--bogus"],
                ),
            ),
            (
                "wrong flag for subcommand",
                dlq_control_args(
                    "redrive-outbox",
                    &["--event-id", DLQ_FIXTURE_EVENT_ID, "--limit", "1"],
                ),
            ),
            (
                "accepted gap rejects evidence",
                dlq_control_args(
                    "resolve-expired-outbox",
                    &[
                        "--event-id",
                        DLQ_FIXTURE_EVENT_ID,
                        "--change-ticket",
                        DLQ_FIXTURE_CHANGE_TICKET,
                        "--resolution-kind",
                        "accepted_gap",
                        "--evidence-event-id",
                        DLQ_FIXTURE_EVIDENCE_EVENT_ID,
                    ],
                ),
            ),
            (
                "compensated requires evidence",
                dlq_control_args(
                    "resolve-expired-outbox",
                    &[
                        "--event-id",
                        DLQ_FIXTURE_EVENT_ID,
                        "--change-ticket",
                        DLQ_FIXTURE_CHANGE_TICKET,
                        "--resolution-kind",
                        "compensated",
                    ],
                ),
            ),
            (
                "dirty change ticket is rejected",
                dlq_control_args(
                    "resolve-expired-outbox",
                    &[
                        "--event-id",
                        DLQ_FIXTURE_EVENT_ID,
                        "--change-ticket",
                        " CHG-1742",
                        "--resolution-kind",
                        "accepted_gap",
                    ],
                ),
            ),
        ];

        for (name, candidate) in cases {
            assert!(
                parse_dlq_args(&candidate).is_err(),
                "case must fail closed: {name}"
            );
        }
    }

    #[test]
    fn dlq_operator_grants_authorize_exact_subject_action_and_tenant() -> anyhow::Result<()> {
        let parsed = parse_dlq_args(&dlq_control_args(
            "redrive-outbox",
            &["--event-id", DLQ_FIXTURE_EVENT_ID],
        ))?;
        let grants = parse_dlq_operator_grants(&format!(
            "{DLQ_FIXTURE_OPERATOR}|redrive-outbox|{DLQ_FIXTURE_TENANT}"
        ))?;
        authorize_dlq_operator(DLQ_FIXTURE_OPERATOR, &parsed, &grants)?;

        let wrong_action = parse_dlq_operator_grants(&format!(
            "{DLQ_FIXTURE_OPERATOR}|list|{DLQ_FIXTURE_TENANT}"
        ))?;
        assert!(authorize_dlq_operator(DLQ_FIXTURE_OPERATOR, &parsed, &wrong_action).is_err());

        let wrong_tenant = parse_dlq_operator_grants(&format!(
            "{DLQ_FIXTURE_OPERATOR}|redrive-outbox|{DLQ_FIXTURE_OTHER_TENANT}"
        ))?;
        assert!(authorize_dlq_operator(DLQ_FIXTURE_OPERATOR, &parsed, &wrong_tenant).is_err());

        let resolution = parse_dlq_args(&dlq_control_args(
            "resolve-expired-outbox",
            &[
                "--event-id",
                DLQ_FIXTURE_EVENT_ID,
                "--change-ticket",
                DLQ_FIXTURE_CHANGE_TICKET,
                "--resolution-kind",
                "accepted_gap",
            ],
        ))?;
        let resolution_grant = parse_dlq_operator_grants(&format!(
            "{DLQ_FIXTURE_OPERATOR}|resolve-expired-outbox|{DLQ_FIXTURE_TENANT}"
        ))?;
        authorize_dlq_operator(DLQ_FIXTURE_OPERATOR, &resolution, &resolution_grant)?;
        assert!(authorize_dlq_operator(DLQ_FIXTURE_OPERATOR, &resolution, &grants).is_err());

        assert!(parse_dlq_operator_grants("").is_err());
        assert!(parse_dlq_operator_grants("subject|skip|tenant").is_err());
        Ok(())
    }

    #[test]
    fn reconcile_operator_args_and_grants_are_exactly_tenant_scoped() -> anyhow::Result<()> {
        let tenant = "018f5d8a-7b6c-7d2e-8a1b-1234567890ab";
        let target = "018f5d8a-7b6c-7d2e-8a1b-1234567890ac";
        let parsed = parse_reconcile_target_args(&args(&[
            "reconcile-target",
            "resume",
            "--operator-service-token",
            "opaque-token",
            "--operator-tenant",
            tenant,
            "--tenant",
            tenant,
            "--target-id",
            target,
        ]))?;
        let grants = parse_reconcile_operator_grants(&format!("operator|resume|{tenant}"))?;
        authorize_reconcile_operator("operator", &parsed, &grants)?;
        assert!(
            authorize_reconcile_operator(
                "other",
                &parsed,
                &parse_reconcile_operator_grants(&format!("other|inspect|{tenant}"))?,
            )
            .is_err()
        );
        assert!(parse_reconcile_operator_grants("operator|resume|not-a-uuid").is_err());
        Ok(())
    }

    #[test]
    fn reconcile_operator_args_fail_closed() {
        let tenant = "018f5d8a-7b6c-7d2e-8a1b-1234567890ab";
        let target = "018f5d8a-7b6c-7d2e-8a1b-1234567890ac";
        for candidate in [
            args(&["reconcile-target"]),
            args(&[
                "reconcile-target",
                "resume",
                "--operator-service-token",
                "token",
                "--operator-tenant",
                tenant,
                "--tenant",
                tenant,
            ]),
            args(&[
                "reconcile-target",
                "unknown",
                "--operator-service-token",
                "token",
                "--operator-tenant",
                tenant,
                "--tenant",
                tenant,
                "--target-id",
                target,
            ]),
        ] {
            assert!(parse_reconcile_target_args(&candidate).is_err());
        }
    }

    #[test]
    fn reconcile_operator_summary_is_payload_free() -> anyhow::Result<()> {
        let tenant = vocab::TenantId::parse("018f5d8a-7b6c-7d2e-8a1b-1234567890ab")?;
        let summary = eventexec::ReconcileTargetSummary::new(
            tenant,
            "018f5d8a-7b6c-7d2e-8a1b-1234567890ac".to_owned(),
            "device".to_owned(),
            "device".to_owned(),
            eventexec::ReconcileTargetStatus::Disabled,
            Some(eventexec::ReconcileQuarantineReason::FactConflict),
        )?;
        let rendered = reconcile_summary_json(&summary)?;
        assert!(rendered.contains("\"disabledReason\":\"fact_conflict\""));
        for forbidden in ["payload", "metadata", "fingerprint", "resourceId"] {
            assert!(!rendered.contains(forbidden), "must not expose {forbidden}");
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn dlq_operator_provider_uses_durable_replay_guard() {
        let source = include_str!("lib.rs");
        let function = source
            .split("async fn dlq_operator_subject(")
            .nth(1)
            .and_then(|rest| rest.split("fn dlq_summary_json_line(").next())
            .expect("dlq_operator_subject source slice");

        assert!(
            function.contains("build_provider_with_replay_guard")
                && function.contains("pg.service_token_replay_guard()"),
            "DLQ operator verifier must inject the durable PG service-token replay guard"
        );
        assert!(
            !function.contains("build_provider()"),
            "DLQ operator verifier must not fall back to the in-process replay guard"
        );
    }

    #[tokio::test]
    async fn dlq_control_lifecycle_dispatches_commands_with_audit() -> anyhow::Result<()> {
        let cases = [
            (
                DlqMaintenanceAction::List,
                dlq_control_args(
                    "list",
                    &[
                        "--source",
                        "consumer",
                        "--producer-domain",
                        "identity",
                        "--consumer-domain",
                        "audit",
                        "--contract-id",
                        "identity.session-created",
                        "--limit",
                        "7",
                        "--cursor",
                        "1700000000:dead_letter:row-1",
                    ],
                ),
                "source=consumer producer_domain=identity consumer_domain=audit contract_id=identity.session-created",
                FakeDlqCommandRecord::List {
                    tenant: vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?,
                    source: Some(diport::DeadLetterSource::Consumer),
                    producer_domain: Some("identity".to_owned()),
                    consumer_domain: Some("audit".to_owned()),
                    contract_id: Some("identity.session-created".to_owned()),
                    limit: 7,
                    cursor: Some("1700000000:dead_letter:row-1".to_owned()),
                },
            ),
            (
                DlqMaintenanceAction::Inspect,
                dlq_control_args(
                    "inspect",
                    &["--kind", "dead-letter", "--id", DLQ_FIXTURE_DEAD_LETTER_ID],
                ),
                "kind=dead_letter dead_letter_id=11111111-1111-4111-8111-111111111111",
                FakeDlqCommandRecord::Inspect {
                    tenant: vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?,
                    target: DlqInspectTarget::DeadLetter(DeadLetterId::parse(
                        DLQ_FIXTURE_DEAD_LETTER_ID,
                    )?),
                },
            ),
            (
                DlqMaintenanceAction::ReplayDeadLetter,
                dlq_control_args(
                    "replay-dead-letter",
                    &[
                        "--dead-letter-id",
                        DLQ_FIXTURE_DEAD_LETTER_ID,
                        "--replay-id",
                        DLQ_FIXTURE_REPLAY_ID,
                    ],
                ),
                "dead_letter_id=11111111-1111-4111-8111-111111111111 replay_id=evt-dlq-replay",
                FakeDlqCommandRecord::ReplayDeadLetter {
                    tenant: vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?,
                    dead_letter_id: DLQ_FIXTURE_DEAD_LETTER_ID.to_owned(),
                    replay_id: DLQ_FIXTURE_REPLAY_ID.to_owned(),
                },
            ),
            (
                DlqMaintenanceAction::RedriveOutbox,
                dlq_control_args("redrive-outbox", &["--event-id", DLQ_FIXTURE_EVENT_ID]),
                "event_id=evt-outbox-dlx",
                FakeDlqCommandRecord::RedriveOutbox {
                    tenant: vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?,
                    event_id: DLQ_FIXTURE_EVENT_ID.to_owned(),
                },
            ),
            (
                DlqMaintenanceAction::ResolveExpiredOutbox,
                dlq_control_args(
                    "resolve-expired-outbox",
                    &[
                        "--event-id",
                        DLQ_FIXTURE_EVENT_ID,
                        "--change-ticket",
                        DLQ_FIXTURE_CHANGE_TICKET,
                        "--resolution-kind",
                        "accepted_gap",
                    ],
                ),
                "event_id=evt-outbox-dlx resolution_kind=accepted_gap",
                FakeDlqCommandRecord::ResolveExpiredOutbox {
                    tenant: vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?,
                    event_id: DLQ_FIXTURE_EVENT_ID.to_owned(),
                    resolution_kind: OutboxExpiredResolutionKind::AcceptedGap,
                    evidence_event_id: None,
                    operator_subject: DLQ_FIXTURE_OPERATOR.to_owned(),
                },
            ),
        ];

        for (action, command_args, target, expected_command) in cases {
            let runtime = FakeDlqControlRuntime::verified(FakeDlqStoreMode::Success);
            run_dlq_control_command_with_runtime(&command_args, &runtime).await?;

            assert_eq!(runtime.setup_count(), 1);
            assert_eq!(runtime.shutdown_count(), 1);
            assert_dlq_lifecycle_audit(&runtime, action, target, FakeDlqAuditOutcome::Success);
            assert_eq!(runtime.command_records(), vec![expected_command]);
        }

        Ok(())
    }

    #[tokio::test]
    async fn dlq_control_lifecycle_audits_command_failure() -> anyhow::Result<()> {
        let runtime = FakeDlqControlRuntime::verified(FakeDlqStoreMode::StoreFailure);
        let result = run_dlq_control_command_with_runtime(
            &dlq_control_args("redrive-outbox", &["--event-id", DLQ_FIXTURE_EVENT_ID]),
            &runtime,
        )
        .await;
        let Err(err) = result else {
            anyhow::bail!("store failure must fail");
        };
        assert!(
            format!("{err:#}").contains("operation=redrive-outbox tenant="),
            "DLQ command failure must include operation and tenant context: {err:#}"
        );
        assert_eq!(runtime.setup_count(), 1);
        assert_eq!(runtime.shutdown_count(), 1);
        assert_dlq_lifecycle_audit(
            &runtime,
            DlqMaintenanceAction::RedriveOutbox,
            "event_id=evt-outbox-dlx",
            FakeDlqAuditOutcome::Failure {
                reason: "run_error".to_owned(),
            },
        );
        assert!(matches!(
            runtime.command_records().as_slice(),
            [FakeDlqCommandRecord::RedriveOutbox { .. }]
        ));
        Ok(())
    }

    #[tokio::test]
    async fn dlq_control_lifecycle_audits_expired_redrive_and_returns_error() -> anyhow::Result<()>
    {
        let tenant = vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?;
        let event_id = IdemKey::parse(DLQ_FIXTURE_EVENT_ID)?;
        let output = dlq_redrive_result_line(tenant, &event_id, DlqRedriveOutcome::Expired);
        assert_eq!(
            output,
            format!(
                "operation=redrive-outbox tenant={DLQ_FIXTURE_TENANT} \
                 event_id={DLQ_FIXTURE_EVENT_ID} outcome=expired"
            )
        );

        let runtime = FakeDlqControlRuntime::verified(FakeDlqStoreMode::Expired);
        let result = run_dlq_control_command_with_runtime(
            &dlq_control_args("redrive-outbox", &["--event-id", DLQ_FIXTURE_EVENT_ID]),
            &runtime,
        )
        .await;
        let Err(err) = result else {
            anyhow::bail!("expired same-ID redrive must fail");
        };
        let error_text = format!("{err:#}");
        assert!(
            error_text.contains("expired"),
            "expired redrive must remain distinguishable from a store failure: {error_text}"
        );
        assert!(
            !error_text.to_ascii_lowercase().contains("store"),
            "expired redrive must not be disguised as a store error: {error_text}"
        );
        assert_eq!(runtime.setup_count(), 1);
        assert_eq!(runtime.shutdown_count(), 1);
        assert_dlq_lifecycle_audit(
            &runtime,
            DlqMaintenanceAction::RedriveOutbox,
            "event_id=evt-outbox-dlx",
            FakeDlqAuditOutcome::Failure {
                reason: "expired".to_owned(),
            },
        );
        for audit in runtime.audit_records() {
            for forbidden in ["payload", "metadata", "partition", "error"] {
                assert!(
                    !audit.resource_id.contains(forbidden),
                    "audit resource must exclude {forbidden}: {}",
                    audit.resource_id
                );
            }
        }
        assert!(matches!(
            runtime.command_records().as_slice(),
            [FakeDlqCommandRecord::RedriveOutbox { .. }]
        ));
        Ok(())
    }

    #[tokio::test]
    async fn dlq_verified_subject_is_injected_and_resolution_rejections_are_safely_audited()
    -> anyhow::Result<()> {
        let command = dlq_control_args(
            "resolve-expired-outbox",
            &[
                "--event-id",
                DLQ_FIXTURE_EVENT_ID,
                "--change-ticket",
                DLQ_FIXTURE_CHANGE_TICKET,
                "--resolution-kind",
                "accepted_gap",
            ],
        );
        for (mode, reason) in [
            (FakeDlqStoreMode::Expired, "not_expired"),
            (FakeDlqStoreMode::EvidenceRejected, "evidence_rejected"),
        ] {
            let runtime = FakeDlqControlRuntime::verified(mode);
            let result = run_dlq_control_command_with_runtime(&command, &runtime).await;
            let Err(error) = result else {
                anyhow::bail!("terminal resolution rejection must return a non-zero outcome");
            };
            assert!(format!("{error:#}").contains(reason));
            assert_eq!(
                runtime.command_records(),
                vec![FakeDlqCommandRecord::ResolveExpiredOutbox {
                    tenant: vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?,
                    event_id: DLQ_FIXTURE_EVENT_ID.to_owned(),
                    resolution_kind: OutboxExpiredResolutionKind::AcceptedGap,
                    evidence_event_id: None,
                    operator_subject: DLQ_FIXTURE_OPERATOR.to_owned(),
                }],
                "the typed request subject must come from the verified runtime principal"
            );
            assert_dlq_lifecycle_audit(
                &runtime,
                DlqMaintenanceAction::ResolveExpiredOutbox,
                "event_id=evt-outbox-dlx resolution_kind=accepted_gap",
                FakeDlqAuditOutcome::Failure {
                    reason: reason.to_owned(),
                },
            );
            for audit in runtime.audit_records() {
                assert!(!audit.resource_id.contains(DLQ_FIXTURE_CHANGE_TICKET));
                for forbidden in ["payload", "metadata", "partition", "error"] {
                    assert!(!audit.resource_id.contains(forbidden));
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn dlq_control_lifecycle_keeps_not_found_redrive_successful() -> anyhow::Result<()> {
        let runtime = FakeDlqControlRuntime::verified(FakeDlqStoreMode::NotFound);
        run_dlq_control_command_with_runtime(
            &dlq_control_args("redrive-outbox", &["--event-id", DLQ_FIXTURE_EVENT_ID]),
            &runtime,
        )
        .await?;

        assert_eq!(runtime.setup_count(), 1);
        assert_eq!(runtime.shutdown_count(), 1);
        assert_dlq_lifecycle_audit(
            &runtime,
            DlqMaintenanceAction::RedriveOutbox,
            "event_id=evt-outbox-dlx",
            FakeDlqAuditOutcome::Success,
        );
        assert!(matches!(
            runtime.command_records().as_slice(),
            [FakeDlqCommandRecord::RedriveOutbox { .. }]
        ));
        Ok(())
    }

    #[tokio::test]
    async fn dlq_control_lifecycle_does_not_call_store_before_auth_or_grant_success()
    -> anyhow::Result<()> {
        for runtime in [
            FakeDlqControlRuntime::auth_failure(),
            FakeDlqControlRuntime::grant_failure(),
        ] {
            let result = run_dlq_control_command_with_runtime(
                &dlq_control_args("redrive-outbox", &["--event-id", DLQ_FIXTURE_EVENT_ID]),
                &runtime,
            )
            .await;
            assert!(result.is_err());
            assert_eq!(runtime.setup_count(), 1);
            assert_eq!(runtime.shutdown_count(), 1);
            assert!(runtime.command_records().is_empty());
        }
        Ok(())
    }

    #[test]
    fn dlq_summary_renders_json_line_without_space_delimited_free_text() -> anyhow::Result<()> {
        let tenant = vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?;
        let summary = DlqEntrySummary::new(
            eventexec::DlqEntryKind::DeadLetter,
            "dlq-row-1",
            diport::DeadLetterSource::Consumer,
            tenant,
            "msg-1",
            "identity",
            Some("audit".to_owned()),
            "identity.session-created",
            "identity.session.created",
            Some("identity.session.consumer".to_owned()),
            12,
            "max retries exhausted with spaces",
            3,
            1_700_000_000,
        );

        let rendered = dlq_summary_json_line(&summary)?;
        let parsed: serde_json::Value = serde_json::from_str(&rendered)?;
        assert_eq!(parsed["errorSummary"], "max retries exhausted with spaces");
        assert_eq!(parsed["contractId"], "identity.session-created");
        assert!(
            !rendered.contains("error_summary=max retries exhausted"),
            "free text must not be emitted in space-delimited key=value form: {rendered}"
        );
        Ok(())
    }

    #[test]
    fn settings_config_value_maintenance_args_default_to_both() -> anyhow::Result<()> {
        let parsed = parse_settings_config_value_maintenance_args(&args(&[
            "settings-config-values",
            "maintenance",
            "--operator-service-token",
            "opaque-token",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
        ]))?;
        assert_eq!(parsed.operator_service_token, "opaque-token");
        assert_eq!(
            parsed.operator_tenant,
            vocab::TenantId::parse("00000000-0000-4000-8000-000000000001")?
        );
        assert_eq!(parsed.options.batch_size(), 500);
        assert_eq!(parsed.options.max_rows(), None);
        assert!(!parsed.options.dry_run());
        Ok(())
    }

    #[test]
    fn settings_config_value_maintenance_args_parse_flags() -> anyhow::Result<()> {
        let parsed = parse_settings_config_value_maintenance_args(&args(&[
            "settings-config-values",
            "maintenance",
            "--operator-service-token",
            "opaque-token",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
            "--operation",
            "backfill",
            "--tenant",
            "00000000-0000-4000-8000-000000000001",
            "--batch-size",
            "7",
            "--max-rows",
            "9",
            "--dry-run",
        ]))?;
        assert_eq!(parsed.operator_service_token, "opaque-token");
        assert_eq!(parsed.options.batch_size(), 7);
        assert_eq!(parsed.options.max_rows(), Some(9));
        assert!(parsed.options.tenant_opt().is_some());
        assert!(parsed.options.dry_run());
        Ok(())
    }

    #[test]
    fn settings_config_value_maintenance_args_fail_closed() {
        assert!(
            parse_settings_config_value_maintenance_args(&args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token",
                "opaque-token",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--bogus",
            ]))
            .is_err()
        );
        assert!(
            parse_settings_config_value_maintenance_args(&args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token",
                "opaque-token",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--operation",
                "decrypt",
            ]))
            .is_err()
        );
        assert!(
            parse_settings_config_value_maintenance_args(&args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token",
                "opaque-token",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--batch-size",
                "0",
            ]))
            .is_err()
        );
        assert!(
            parse_settings_config_value_maintenance_args(&args(&[
                "settings-config-values",
                "maintenance",
            ]))
            .is_err()
        );
        assert!(
            parse_settings_config_value_maintenance_args(&args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token",
                "",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
            ]))
            .is_err()
        );
        assert!(
            parse_settings_config_value_maintenance_args(&args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token",
                "opaque-token",
            ]))
            .is_err()
        );
        assert!(
            parse_settings_config_value_maintenance_args(&args(&[
                "settings-config-values",
                "maintenance",
                "--operator-subject",
                "ops@example.com",
            ]))
            .is_err()
        );
    }

    struct StubPdp {
        result: Result<diport::VerifiedClaims, diport::PdpError>,
    }

    impl diport::Pdp for StubPdp {
        async fn verify(
            &self,
            _raw: &diport::RawCredential,
        ) -> Result<diport::VerifiedClaims, diport::PdpError> {
            self.result.clone()
        }
    }

    fn stub_pdp(
        result: Result<diport::VerifiedClaims, diport::PdpError>,
    ) -> Box<diport::DynPdp<'static>> {
        diport::DynPdp::new_box(StubPdp { result })
    }

    #[tokio::test]
    async fn settings_config_value_maintenance_operator_subject_comes_from_verified_service_token()
    -> anyhow::Result<()> {
        let pdp = stub_pdp(Ok(diport::VerifiedClaims::new(
            "verified-operator",
            None,
            Some("ignored".to_owned()),
        )));
        let subject = verified_config_value_maintenance_operator_subject(
            "opaque-token",
            vocab::TenantId::parse("00000000-0000-4000-8000-000000000001")?,
            &pdp,
        )
        .await?;

        assert_eq!(subject, "verified-operator");
        Ok(())
    }

    #[tokio::test]
    async fn settings_config_value_maintenance_operator_token_failure_is_fail_closed()
    -> anyhow::Result<()> {
        let pdp = stub_pdp(Err(diport::PdpError::InvalidSignature));
        let result = verified_config_value_maintenance_operator_subject(
            "opaque-token",
            vocab::TenantId::parse("00000000-0000-4000-8000-000000000001")?,
            &pdp,
        )
        .await;

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn session_sweeper_interval_defaults_and_parses_env() {
        let default = build_session_sweeper_interval_from(|_| None);
        assert_eq!(default, DEFAULT_SESSION_SWEEP_INTERVAL);

        let parsed = build_session_sweeper_interval_from(|name| {
            (name == SESSION_SWEEP_INTERVAL_ENV).then(|| "120000".to_string())
        });
        assert_eq!(parsed, Duration::from_millis(120_000));

        let invalid = build_session_sweeper_interval_from(|name| {
            (name == SESSION_SWEEP_INTERVAL_ENV).then(|| "not-a-number".to_string())
        });
        assert_eq!(invalid, DEFAULT_SESSION_SWEEP_INTERVAL);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_maintenance_module_emits_session_sweeper_probe_and_worker() {
        struct NoopResource;
        impl diport::ManagedResource for NoopResource {
            fn name(&self) -> &str {
                "noop-session-sweeper"
            }

            async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
                Ok(())
            }
        }

        let health = Arc::new(SessionSweeperHealth::healthy());
        let worker: bootstrap::WorkerSpec =
            Box::new(|_| diport::DynManagedResource::new_box(NoopResource));
        let result =
            session_sweeper_module_result(worker, health).expect("session sweeper module result");
        assert_eq!(result.probes.len(), 1);
        assert_eq!(result.probes[0].0.as_str(), SESSION_SWEEPER_PROBE_NAME);
        assert!(result.resources.is_empty());
        assert_eq!(
            result.workers.len(),
            1,
            "session sweeper must be registered as a managed worker"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: 静态回归守卫切分当前源码；缺目标函数时测试应硬失败。
    fn session_sweeper_worker_cancellation_races_inflight_sweep() {
        let source = include_str!("lib.rs");
        let function = source
            .split("fn spawn_session_sweeper(")
            .nth(1)
            .and_then(|rest| rest.split("fn session_sweeper_module_result(").next())
            .expect("spawn_session_sweeper source slice");
        assert!(
            function.contains("deleted = sweeper.sweep_expired()")
                && function.contains("() = worker_token.cancelled() => break"),
            "session sweeper worker must race cancellation against an in-flight sweep"
        );
    }

    /// RlsReadyProbe：`true → Healthy("ready")` / `false → Unhealthy("not-enforced")`（fail-closed）。
    #[test]
    fn rls_ready_probe_maps_flag_to_health() {
        use bootstrap::HealthProbe;
        use std::sync::atomic::{AtomicBool, Ordering};

        let flag = Arc::new(AtomicBool::new(true));
        let probe = RlsReadyProbe::new(Arc::clone(&flag));
        let ready = probe.check();
        assert_eq!(ready.status(), HealthStatus::Healthy);
        assert_eq!(ready.detail(), "ready");
        assert_eq!(ready.name().as_str(), RLS_READY_PROBE_NAME);

        flag.store(false, Ordering::Release);
        let down = probe.check();
        assert_eq!(down.status(), HealthStatus::Unhealthy);
        assert_eq!(down.detail(), "not-enforced");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn runtime_replay_guard_expires_seen_nonce() {
        let guard = RuntimeServiceTokenReplayGuard::default();
        let expired = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        let future = SystemTime::UNIX_EPOCH + Duration::from_secs(4_102_444_800);
        guard
            .check_and_record("nonce-a", expired)
            .expect("first record");
        guard
            .check_and_record("nonce-a", future)
            .expect("expired nonce pruned before second record");
        assert!(matches!(
            guard.check_and_record("nonce-a", future),
            Err(diport::ServiceTokenReplayError::Replayed)
        ));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_required_domains_must_be_non_empty() {
        let err = build_domain_transport_targets_from(bootstrap::Topology::DurableShared, |_| None)
            .expect_err("missing required domains must fail");
        assert!(
            err.to_string()
                .contains(DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV),
            "error should name env var: {err}"
        );

        let err = build_domain_transport_targets_from(bootstrap::Topology::DurableShared, |name| {
            (name == DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV).then(String::new)
        })
        .expect_err("empty required domain entry must fail");
        assert!(
            err.to_string()
                .contains(DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV),
            "error should name env var: {err}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_per_domain_allow_set_is_required() {
        let err = build_domain_transport_targets_from(bootstrap::Topology::DurableShared, |name| {
            match name {
                DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV => Some("identity".to_string()),
                "RSS_IDENTITY_DOMAIN_TRANSPORT_URL" => {
                    Some("https://identity.internal/rpc".to_string())
                }
                DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV => {
                    Some("spiffe://example.org/ns/rss/sa/runtime".to_string())
                }
                _ => None,
            }
        })
        .expect_err("remote target requires exact server SPIFFE allow-set");
        assert!(
            err.to_string()
                .contains("RSS_IDENTITY_DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET"),
            "error should name per-domain allow-set env: {err}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_isolated_topology_forbids_shared_fallback() {
        let err =
            build_domain_transport_targets_from(bootstrap::Topology::DurableIsolated, |name| {
                match name {
                    DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV => Some("identity".to_string()),
                    DOMAIN_TRANSPORT_SHARED_URL_ENV => {
                        Some("https://gateway.internal/rpc".to_string())
                    }
                    _ => None,
                }
            })
            .expect_err("isolated topology must not use shared domain transport fallback");
        assert!(
            format!("{err:#}").contains(DOMAIN_TRANSPORT_SHARED_URL_ENV),
            "error should name shared fallback env: {err}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_targets_build_typed_outbound_mtls_policy() {
        let targets =
            build_domain_transport_targets_from(bootstrap::Topology::DurableShared, |name| {
                match name {
                    DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV => Some("identity".to_string()),
                    DOMAIN_TRANSPORT_SHARED_URL_ENV => {
                        Some("https://gateway.internal/rpc".to_string())
                    }
                    DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV => {
                        Some("spiffe://example.org/ns/rss/sa/runtime".to_string())
                    }
                    "RSS_IDENTITY_DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET" => {
                        Some("spiffe://example.org/ns/rss/sa/identity".to_string())
                    }
                    _ => None,
                }
            })
            .expect("valid domain transport target config");
        assert_eq!(targets.len(), 1);
    }

    #[derive(Clone)]
    struct NoopRuntimeDomainTransport {
        ready: Arc<std::sync::atomic::AtomicBool>,
    }

    impl distributed::DomainTransport for NoopRuntimeDomainTransport {
        fn dispatch(
            &self,
            _request: distributed::DomainRequest,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Result<
                            distributed::DomainResponse,
                            distributed::DomainTransportError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                Ok(distributed::DomainResponse::new(
                    204,
                    Vec::new(),
                    Vec::new(),
                ))
            })
        }
    }

    impl ManagedResource for NoopRuntimeDomainTransport {
        fn name(&self) -> &str {
            "domain-http-transport"
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            Ok(())
        }
    }

    impl RuntimeDomainTransport for NoopRuntimeDomainTransport {
        fn readiness(&self) -> httpd::DomainHttpReadiness {
            if self.ready.load(std::sync::atomic::Ordering::Acquire) {
                httpd::DomainHttpReadiness::Ready
            } else {
                httpd::DomainHttpReadiness::MtlsSourceUnavailable
            }
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_runtime_exports_dispatch_resource_and_readyz() {
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let runtime = DomainTransportRuntime::new(NoopRuntimeDomainTransport {
            ready: Arc::clone(&ready),
        });
        let _dispatch = runtime.dispatch_handle();
        let module = runtime
            .module_result()
            .expect("domain transport module result");

        assert_eq!(module.resources.len(), 1);
        assert_eq!(module.resources[0].name(), "domain-http-transport");
        assert_eq!(module.probes.len(), 1);
        let healthy = module.probes[0].1.check();
        assert_eq!(healthy.name().as_str(), DOMAIN_TRANSPORT_READY_PROBE_NAME);
        assert_eq!(healthy.status(), HealthStatus::Healthy);
        assert_eq!(healthy.detail(), "ready");

        ready.store(false, std::sync::atomic::Ordering::Release);
        let unhealthy = module.probes[0].1.check();
        assert_eq!(unhealthy.status(), HealthStatus::Unhealthy);
        assert_eq!(unhealthy.detail(), "mtls-source-unavailable");
    }

    #[test]
    fn system_clock_now_is_after_epoch() {
        use diport::Clock as _;
        // 覆盖组合根生产时钟读点（disallowed_methods item-level 解禁线）。
        assert!(SystemClock.now() > SystemTime::UNIX_EPOCH);
    }

    /// `RLS_READY_PROBE_NAME` 是合法 `ProbeName`；真实 `RlsReadyProbe` 可注册 + 重名拒绝（与 configs_ready 对称）。
    #[test]
    #[allow(clippy::expect_used)]
    fn rls_ready_registers_and_is_unique() {
        use std::sync::atomic::AtomicBool;
        // reason: RLS_READY_PROBE_NAME 是 const literal，parse 只可能在字符非法时失败。
        let name_a =
            primitives::ProbeName::parse(RLS_READY_PROBE_NAME).expect("valid probe name const");
        let name_b =
            primitives::ProbeName::parse(RLS_READY_PROBE_NAME).expect("valid probe name const");
        let mut registry = bootstrap::compose(&[]).expect("empty compose");
        let flag = Arc::new(AtomicBool::new(true));

        registry
            .probe(name_a, Box::new(RlsReadyProbe::new(Arc::clone(&flag))))
            .expect("first register ok");
        let result = registry.probe(name_b, Box::new(RlsReadyProbe::new(flag)));
        assert!(
            result.is_err(),
            "duplicate rls_ready probe name should be rejected"
        );
    }

    // ── build_trace_export_from_value：endpoint typed 安全边界（fail-fast）─────────────
    // 显式 raw value（不读真实 env）覆盖 None / TLS / loopback-http / 非 loopback 明文 / 非法 scheme 五态。

    #[test]
    #[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
    fn build_trace_export_unset_endpoint_is_none() {
        // 未配 RSS_OTEL_ENDPOINT → 仅 fmt 日志、不导出 trace（按需开启），且非 Err。
        let out = build_trace_export_from_value(None).expect("unset endpoint is Ok(None)");
        assert!(out.is_none(), "unset endpoint must yield None");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn build_trace_export_uses_the_captured_endpoint_mapping() {
        let snapshot =
            crate::config::test_snapshot(&[(OTEL_ENDPOINT_ENV, "http://localhost:4317")])
                .expect("capture trace endpoint");

        let out = build_trace_export(snapshot.view())
            .expect("snapshot-backed loopback endpoint builds exporter");
        assert!(out.is_some(), "captured endpoint must enable exporting");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn run_pre_handoff_failure_explicitly_shuts_down_trace_exporter() {
        let snapshot = crate::config::test_snapshot(&[]).expect("capture empty runtime config");
        let endpoint = otel::OtelEndpoint::insecure_localhost("http://localhost:4317")
            .expect("hermetic loopback endpoint");
        let provider = otel::build_otlp_provider(endpoint).expect("build lazy hermetic provider");
        let shutdown_witness = provider.clone();
        let inputs = RuntimeInputs::new(snapshot, Some(otel::OtelExporter::new(provider)));

        let err = run(inputs)
            .await
            .expect_err("missing OIDC config must fail before launch handoff");
        assert!(format!("{err:#}").contains("build runtime OIDC provider"));
        assert!(
            shutdown_witness.shutdown().is_err(),
            "pre-handoff failure must explicitly shut down the shared provider"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn runtime_lifecycle_owner_does_not_shutdown_exporter_after_handoff() {
        let snapshot = crate::config::test_snapshot(&[]).expect("capture empty runtime config");
        let endpoint = otel::OtelEndpoint::insecure_localhost("http://localhost:4317")
            .expect("hermetic loopback endpoint");
        let provider = otel::build_otlp_provider(endpoint).expect("build lazy hermetic provider");
        let handoff_witness = provider.clone();
        let inputs = RuntimeInputs::new(snapshot, Some(otel::OtelExporter::new(provider)));
        let mut owner = RuntimeLifecycleOwner::new(inputs);
        let handed_off = owner
            .inputs
            .take_trace_export()
            .expect("exporter must move into launch ownership");

        owner
            .finish(Ok(()))
            .await
            .expect("empty outer owner must finish without a second shutdown");
        assert!(
            handoff_witness.force_flush().is_ok(),
            "provider must remain live after exporter handoff"
        );
        diport::ManagedResource::shutdown(&handed_off)
            .await
            .expect("launch owner shuts exporter down");
        assert!(
            handoff_witness.shutdown().is_err(),
            "launch shutdown must be visible through the shared provider"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
    async fn build_trace_export_loopback_http_builds_exporter() {
        // 明文 http 指向 loopback → 显式 opt-in，构建出 exporter（connect_lazy，不连真实 collector）。
        let out = build_trace_export_from_value(Some("http://localhost:4317"))
            .expect("loopback http endpoint builds exporter");
        assert!(out.is_some(), "loopback http must build Some(exporter)");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
    async fn build_trace_export_tls_https_builds_exporter() {
        let out = build_trace_export_from_value(Some("https://collector.internal:4317"))
            .expect("https TLS endpoint builds exporter");
        assert!(out.is_some(), "https endpoint must build Some(exporter)");
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
    fn build_trace_export_nonloopback_http_is_err() {
        // 明文 http 指向非 loopback host → fail-closed Err（不静默放行明文导出到远端）。
        let err = build_trace_export_from_value(Some("http://collector.internal:4317"))
            .map(|_| ()) // OtelExporter 非 Debug，expect_err 前把 Ok 臂折叠成 ()
            .expect_err("non-loopback plaintext must fail-fast");
        assert!(
            format!("{err:#}").contains("loopback"),
            "err 应提示 loopback 约束: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
    fn build_trace_export_bad_scheme_is_err() {
        // 非 http(s) scheme → fail-fast（误配在接线期暴露，不静默退回 fmt）。
        const SECRET_FRAGMENT: &str = "collector-token";
        let err = build_trace_export_from_value(Some(
            "grpc://user:collector-token@collector.internal:4317",
        ))
        .map(|_| ()) // OtelExporter 非 Debug，expect_err 前把 Ok 臂折叠成 ()
        .expect_err("non http(s) scheme must fail-fast");
        let error = format!("{err:#}");
        assert!(
            error.contains(OTEL_ENDPOINT_ENV),
            "err 应含 env 变量名: {err}"
        );
        assert!(
            !error.contains(SECRET_FRAGMENT),
            "trace endpoint errors must not expose configured credentials"
        );
    }
}
