//! event_transport — topology-gated 事件传输组合根接线（issue #1251）。
//!
//! [`wire_event_transport`] 是 `run()` 事件传输单入口：根据 [`EventTransportConfig`] 中的拓扑决策
//! 连接 AMQP（per-domain），spawn relay worker + PG inbox consumer workers，并直接返回
//! [`bootstrap::DomainModuleResult`] 交给 `run()` 的统一 merge/drain 路径。
//!
//! LIFO 顺序由通用 module funnel 保证：AMQP guards 进入 `resources`，relay / consumer /
//! sampler / sweeper 进入 `workers`；launch 先注册 resources 再注册 workers，故关停时
//! workers 先 drain，AMQP 连接后断开。
//!
//! Demo 拓扑：`wire_event_transport` 返回空 [`bootstrap::DomainModuleResult`]；生产 Demo
//! 时组合根 `run()` 在此前已 `anyhow::bail!`（TOPO-INMEM-SEAL-01 组合根层保证）。
//!
//! INVARIANT: EVENT-TRANSPORT-OUTPUT-TYPE-01 { level = "Hard", exec = "native-compile", source = "code", native = "crate-private wire_event_transport returns one owned DomainModuleResult directly; legacy field projection is not representable" }
//!
//! ## relay_loop 专用 OS 线程
//!
//! `PgOutbox` 持 `Box<DynPublisher<'static>>`，dynosaur 生成的 `DynPublisher` 是 `Send+!Sync`，
//! 导致 `Arc<PgOutbox>: !Send`，无法 `tokio::spawn(relay_loop(Arc<PgOutbox>, ...))`。
//! 解法：由 `eventexec::ManagedBlockingWorker` 把 `PgOutbox`（`Send`）移入
//! 专用 OS 线程，线程内建 current-thread tokio runtime + `block_on(relay_loop(Arc::new(outbox), ...))`；
//! `Arc<PgOutbox>`（`!Send`）始终在单一线程内构建与持有，不跨线程，无需 `Send`。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use base64::Engine as _;
use bootstrap::{DomainModuleResult, SubscriberBinding, WorkerSpec};
#[cfg(test)]
use bootstrap::{ReconcileSubscriberOwner, SubscriberCapability};
use consistency::RetentionSweeper;
use crypto::RustCryptoMacVerifier;
#[cfg(test)]
use diport::ManagedResource as _;
use diport::{
    AckableSubscriber as _, Clock, DlxArchiveBacklog, DlxLifecycleError, DlxLifecycleRepository,
    DynDeadLetterStore, DynKeyProvider, DynManagedResource, KeyProvider as _, RedactedBytes, Topic,
};
#[cfg(test)]
use eventexec::ManagedBlockingWorker;
use eventexec::{
    ConsumerMeta, DlxArchiveKeyName, DlxHotKeyName, DlxLifecycle, DlxLifecycleHealth,
    DlxLifecycleTickReport, EVENT_CONSUMER_PROBE, INBOX_SAMPLER_PROBE, InboxBacklogSelection,
    InboxSamplerConfig, LeaseConfig, MetricsInboxMetrics, MetricsOutboxMetrics,
    MetricsRetentionMetrics, OUTBOX_RELAY_PROBE, OUTBOX_SAMPLER_PROBE, OUTBOX_SWEEPER_PROBE,
    RelayConfig, RetentionMetrics, RetentionOutcome, RetentionTarget, SWEEPER_WORKER_NAME,
    SamplerConfig, SweeperConfig, SweeperWorker, TenantAuthority, WorkerHealth,
    apply_dlx_lifecycle_health, spawn_on_dedicated_runtime, spawn_relay, sweeper_loop,
};
use eventing::delivery::DeliveryBudget;
#[cfg(test)]
use generated::event::{EventSpec, SubscriptionSpec};
use generated::event::{SubscriberReadiness, SubscriptionDispatchKey};
use postgres::{
    DlxPayloadProtector, PgDlxLifecycleRepository, PgDlxLifecycleRuntime, PgRuntimeHandle, caps,
};
use primitives::{HealthCheck, MacKey, ProbeName};
use vault::VaultKeyProvider;

use crate::EnvSecret;
use crate::config::{ServingConfigMapper, SnapshotConfig};
use crate::distributed_runtime::{
    CoordinatedRetentionSweeper, DistributedRuntimeDeps, InboxBacklogMaintenance,
    MaintenanceCoordinator, OutboxBacklogMaintenance,
};
use crate::infra::vault::{DEFAULT_VAULT_TIMEOUT, build_vault_tls_client_from};
use crate::support::SystemClock;
use eventing_composition::{
    AuditConsumerFactory, SettingsConsumerFactory, WorkerInputs,
    coordinated_inbox_backlog_sampler_loop, coordinated_outbox_backlog_sampler_loop,
};
pub use eventing_composition::{BridgedSubscription, BridgedSubscriptions};

// ── 对外类型 ──────────────────────────────────────────────────────────────────

pub struct EventTransportConfig {
    topology: bootstrap::Topology,
    decision: EventDecision,
    tenant_authority: Option<Arc<TenantAuthority>>,
    dlx_payload_protector: Option<DlxPayloadProtector>,
    /// Required for durable topologies; absent for Demo.
    amqp_ca: Option<amqp::AmqpPrivateCa>,
    local_producers: Vec<generated::event::ProducerDomain>,
}

impl EventTransportConfig {
    pub(crate) fn from_execution(
        mapper: &ServingConfigMapper<'_>,
        execution: &crate::plan::LocalEventExecutionPlan,
    ) -> anyhow::Result<Self> {
        map_event_transport_from_snapshot(
            mapper.config(),
            execution.required_amqp_domains(),
            execution.local_producers(),
            execution.is_active(),
        )
    }

    #[cfg(test)]
    pub(crate) fn from_mapper(mapper: &ServingConfigMapper<'_>) -> anyhow::Result<Self> {
        let required = generated_required_domains();
        map_event_transport_from_snapshot(
            mapper.config(),
            &required,
            generated::event::PRODUCER_DOMAINS,
            true,
        )
    }

    pub(crate) const fn topology(&self) -> bootstrap::Topology {
        self.topology
    }

    pub(crate) fn dlx_payload_protector(&self) -> Option<DlxPayloadProtector> {
        self.dlx_payload_protector.clone()
    }

    #[cfg(feature = "integration")]
    pub fn tenant_authority_for_test(&self) -> Option<Arc<TenantAuthority>> {
        self.tenant_authority.clone()
    }
}

pub struct EventWorkerConfig {
    relay: RelayTiming,
}

impl EventWorkerConfig {
    pub(crate) fn from_mapper(mapper: &ServingConfigMapper<'_>) -> anyhow::Result<Self> {
        Ok(Self {
            relay: RelayTiming::from_snapshot(mapper.config())?,
        })
    }

    #[cfg(test)]
    pub(crate) fn relay_poll_interval(&self) -> Duration {
        self.relay.relay.poll_interval()
    }

    #[cfg(test)]
    pub(crate) fn relay_max_in_flight(&self) -> usize {
        self.relay.relay.max_in_flight()
    }

    pub(crate) const fn relay_budget(&self) -> DeliveryBudget {
        self.relay.budget
    }

    #[cfg(test)]
    pub(crate) fn relay_sample_interval(&self) -> Duration {
        self.relay.sampler.sample_interval()
    }

    #[cfg(test)]
    pub(crate) fn inbox_sample_interval(&self) -> Duration {
        self.relay.inbox_sample_interval
    }

    #[cfg(test)]
    pub(crate) fn outbox_sweep_interval(&self) -> Duration {
        self.relay.outbox_sweeper.sweep_interval()
    }

    #[cfg(test)]
    pub(crate) fn outbox_retain_seconds(&self) -> u64 {
        self.relay.outbox_sweeper.retain_seconds()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DlxWorkerConfig {
    lifecycle_interval: Duration,
    lifecycle_tick_timeout: Duration,
    archive_readiness_interval: Duration,
    archive_readiness_timeout: Duration,
}

impl DlxWorkerConfig {
    pub(crate) const fn canonical() -> Self {
        Self {
            lifecycle_interval: DLX_LIFECYCLE_INTERVAL,
            lifecycle_tick_timeout: DLX_LIFECYCLE_TICK_TIMEOUT,
            archive_readiness_interval: DLX_ARCHIVE_READINESS_INTERVAL,
            archive_readiness_timeout: DLX_ARCHIVE_READINESS_TIMEOUT,
        }
    }
}

#[cfg(any(test, feature = "integration"))]
pub struct EventTransportTestValues {
    topology: bootstrap::Topology,
    per_domain: BTreeMap<String, String>,
    shared: Option<String>,
    amqp_ca_pem: Option<Vec<u8>>,
    tenant_key_b64url: Option<String>,
    tenant_ttl_secs: u64,
    tenant_clock_skew_secs: u64,
    dlx_payload_key_name: Option<String>,
    vault_addr: String,
    vault_general_token: Option<String>,
    dlx_hot_token: String,
    dlx_archive_token: String,
    vault_transit_mount: String,
}

#[cfg(any(test, feature = "integration"))]
impl EventTransportTestValues {
    pub fn demo() -> Self {
        Self {
            topology: bootstrap::Topology::Demo,
            per_domain: BTreeMap::new(),
            shared: None,
            amqp_ca_pem: None,
            tenant_key_b64url: None,
            tenant_ttl_secs: DEFAULT_TENANT_AUTHORITY_TTL_SECS,
            tenant_clock_skew_secs: DEFAULT_TENANT_AUTHORITY_CLOCK_SKEW_SECS,
            dlx_payload_key_name: None,
            vault_addr: "https://vault.example:8200".to_owned(),
            vault_general_token: None,
            dlx_hot_token: "s.dlx-hot-testtoken".to_owned(),
            dlx_archive_token: "s.dlx-archive-testtoken".to_owned(),
            vault_transit_mount: "transit".to_owned(),
        }
    }

    pub fn durable_shared(shared: impl Into<String>) -> Self {
        let mut values = Self::demo();
        values.topology = bootstrap::Topology::DurableShared;
        values.shared = Some(shared.into());
        // Unit/e2e callers may override with a fixture-matching CA via `with_amqp_ca_pem`.
        values.amqp_ca_pem = Some(TEST_AMQP_CA_PEM.as_bytes().to_vec());
        values.tenant_key_b64url =
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42_u8; 32]));
        values.dlx_payload_key_name = Some("dlx-payload".to_owned());
        values
    }

    pub fn durable_isolated_with_shared(shared: impl Into<String>) -> Self {
        let mut values = Self::durable_shared(shared);
        values.topology = bootstrap::Topology::DurableIsolated;
        values
    }

    pub fn with_amqp_ca_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.amqp_ca_pem = Some(pem.into());
        self
    }

    pub fn without_shared_url(mut self) -> Self {
        self.shared = None;
        self
    }

    pub fn with_domain_url(mut self, domain: impl Into<String>, url: impl Into<String>) -> Self {
        self.per_domain.insert(domain.into(), url.into());
        self
    }

    pub fn without_tenant_authority_key(mut self) -> Self {
        self.tenant_key_b64url = None;
        self
    }

    pub fn with_tenant_authority_key_b64url(mut self, key: impl Into<String>) -> Self {
        self.tenant_key_b64url = Some(key.into());
        self
    }

    pub fn with_tenant_clock_skew_secs(mut self, seconds: u64) -> Self {
        self.tenant_clock_skew_secs = seconds;
        self
    }

    pub fn without_dlx_payload_key(mut self) -> Self {
        self.dlx_payload_key_name = None;
        self
    }

    pub fn build(self) -> anyhow::Result<EventTransportConfig> {
        // Production egress: plaintext AMQP opt-in is banned (#1710); always Deny.
        let policy = secure::PlaintextEndpointPolicy::Deny;
        let per_domain = self
            .per_domain
            .into_iter()
            .map(|(domain, url)| {
                bootstrap::AmqpUrl::parse(url, policy)
                    .map(|url| (domain, url))
                    .context("test per-domain AMQP URL is invalid")
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        let shared = self
            .shared
            .map(|url| {
                bootstrap::AmqpUrl::parse(url, policy).context("test shared AMQP URL is invalid")
            })
            .transpose()?;
        let transport = bootstrap::eventtransport::TransportConfig::new(per_domain, shared);
        let decision =
            resolve_event_decision(self.topology, transport, &generated_required_domains())?;
        if self.topology == bootstrap::Topology::Demo {
            return Ok(EventTransportConfig {
                topology: self.topology,
                decision,
                tenant_authority: None,
                dlx_payload_protector: None,
                amqp_ca: None,
                local_producers: generated::event::PRODUCER_DOMAINS.to_vec(),
            });
        }

        let amqp_ca = amqp::AmqpPrivateCa::from_pem(self.amqp_ca_pem.clone().ok_or_else(|| {
            anyhow::anyhow!("missing required AMQP private CA PEM for durable topology")
        })?)
        .context("parse durable AMQP private CA PEM")?;

        let get = |name: &str| match name {
            TENANT_AUTHORITY_HMAC_KEY_ENV => self.tenant_key_b64url.clone(),
            TENANT_AUTHORITY_TTL_ENV => Some(self.tenant_ttl_secs.to_string()),
            TENANT_AUTHORITY_CLOCK_SKEW_ENV => Some(self.tenant_clock_skew_secs.to_string()),
            DLX_PAYLOAD_KEY_NAME_ENV => self.dlx_payload_key_name.clone(),
            VAULT_ADDR_ENV => Some(self.vault_addr.clone()),
            "RSS_VAULT_TOKEN" => self.vault_general_token.clone(),
            DLX_HOT_VAULT_TOKEN_ENV => Some(self.dlx_hot_token.clone()),
            DLX_ARCHIVE_VAULT_TOKEN_ENV => Some(self.dlx_archive_token.clone()),
            VAULT_TRANSIT_MOUNT_ENV => Some(self.vault_transit_mount.clone()),
            _ => None,
        };
        Ok(EventTransportConfig {
            topology: self.topology,
            decision,
            tenant_authority: Some(build_tenant_authority_from(&get)?),
            dlx_payload_protector: Some(build_dlx_payload_protector_from(&get)?),
            amqp_ca: Some(amqp_ca),
            local_producers: generated::event::PRODUCER_DOMAINS.to_vec(),
        })
    }
}

#[cfg(any(test, feature = "integration"))]
pub struct EventWorkerTestValues {
    poll: Duration,
    max_in_flight: usize,
    budget: DeliveryBudget,
    sample: Duration,
    inbox_sample: Duration,
    sweep: Duration,
    retain_seconds: u64,
}

#[cfg(any(test, feature = "integration"))]
impl EventWorkerTestValues {
    pub fn canonical() -> anyhow::Result<Self> {
        Ok(Self {
            poll: Duration::from_millis(200),
            max_in_flight: 16,
            budget: DeliveryBudget::new(
                Duration::from_millis(DEFAULT_RELAY_LEASE_TTL_MS),
                Duration::from_millis(DEFAULT_RELAY_PUBLISH_TIMEOUT_MS),
                Duration::from_millis(DEFAULT_RELAY_SETTLE_TIMEOUT_MS),
                Duration::from_millis(DEFAULT_RELAY_SAFETY_MARGIN_MS),
            )?,
            sample: Duration::from_millis(30_000),
            inbox_sample: Duration::from_millis(30_000),
            sweep: Duration::from_millis(300_000),
            retain_seconds: 604_800,
        })
    }

    pub fn with_relay_poll_interval(mut self, value: Duration) -> Self {
        self.poll = value;
        self
    }

    pub fn with_relay_sample_interval(mut self, value: Duration) -> Self {
        self.sample = value;
        self
    }

    pub fn with_inbox_sample_interval(mut self, value: Duration) -> Self {
        self.inbox_sample = value;
        self
    }

    pub fn with_outbox_sweep_interval(mut self, value: Duration) -> Self {
        self.sweep = value;
        self
    }

    pub fn build(self) -> anyhow::Result<EventWorkerConfig> {
        Ok(EventWorkerConfig {
            relay: RelayTiming::new(
                self.poll,
                self.max_in_flight,
                self.budget,
                self.sample,
                self.inbox_sample,
                self.sweep,
                self.retain_seconds,
            )?,
        })
    }
}

// ── 内部类型 ──────────────────────────────────────────────────────────────────

pub(crate) const INBOX_SWEEPER_WORKER_NAME: &str = "inbox-sweeper";
pub(crate) const INBOX_SWEEPER_PROBE: &str = "inbox_sweeper";
pub(crate) const DLX_LIFECYCLE_WORKER_NAME: &str = "dlx-lifecycle";
pub(crate) const DLX_LIFECYCLE_PROBE: &str = "dlx_lifecycle";
pub(crate) const DLX_ARCHIVE_READINESS_WORKER_NAME: &str = "dlx-archive-readiness";
pub(crate) const DLX_ARCHIVE_READINESS_PROBE: &str = "dlx_archive_ready";
pub(crate) const DLX_ARCHIVE_KEY_READINESS_WORKER_NAME: &str = "dlx-archive-key-readiness";
pub(crate) const DLX_ARCHIVE_KEY_READINESS_PROBE: &str = "dlx_archive_key_ready";
const DLX_LIFECYCLE_INTERVAL: Duration = Duration::from_secs(30);
const DLX_LIFECYCLE_TICK_TIMEOUT: Duration = Duration::from_secs(25);
const DLX_ARCHIVE_READINESS_INTERVAL: Duration = Duration::from_secs(60);
const DLX_ARCHIVE_READINESS_TIMEOUT: Duration = Duration::from_secs(5);
const EVENT_WORKER_SHUTDOWN_BUDGET: eventing::lifecycle::ShutdownBudget =
    eventing::lifecycle::ShutdownBudget::STANDARD;
pub(crate) const RUNTIME_INSTANCE_ID_ENV: &str = "RSS_RUNTIME_INSTANCE_ID";
pub(crate) const REQUIRED_ADMISSION_EPOCH_ENV: &str = "RSS_DR_REQUIRED_ADMISSION_EPOCH_ID";

pub(crate) fn production_dr_admission_identity(
    config: crate::config::SnapshotConfig<'_>,
    runtime_plan_fingerprint: &str,
) -> anyhow::Result<eventexec::DrAdmissionProcessIdentity> {
    let instance_raw = config
        .value(RUNTIME_INSTANCE_ID_ENV)
        .with_context(|| format!("{RUNTIME_INSTANCE_ID_ENV} is required"))?;
    let instance_id =
        uuid::Uuid::parse_str(instance_raw).context("RSS_RUNTIME_INSTANCE_ID must be a UUID")?;
    let required = config
        .value(REQUIRED_ADMISSION_EPOCH_ENV)
        .map(primitives::AdmissionEpochId::parse)
        .transpose()
        .context("RSS_DR_REQUIRED_ADMISSION_EPOCH_ID must be a canonical UUID")?;
    let identity = eventexec::DrAdmissionProcessIdentity::new(
        "runtime",
        runtime_plan_fingerprint,
        instance_id,
        uuid::Uuid::new_v4(),
        required,
    )
    .context("build runtime DR admission process identity")?;
    Ok(identity)
}
const AMQP_CA_CERT_PEM_PATH_ENV: &str = "RSS_AMQP_CA_CERT_PEM_PATH";
#[cfg(any(test, feature = "integration"))]
use crate::infra::TEST_PRIVATE_CA_PEM as TEST_AMQP_CA_PEM;
const TENANT_AUTHORITY_HMAC_KEY_ENV: &str = "RSS_TENANT_AUTHORITY_HMAC_KEY_B64URL";
const TENANT_AUTHORITY_TTL_ENV: &str = "RSS_TENANT_AUTHORITY_TTL_SECS";
const DEFAULT_TENANT_AUTHORITY_TTL_SECS: u64 = 3600;
const TENANT_AUTHORITY_CLOCK_SKEW_ENV: &str = "RSS_TENANT_AUTHORITY_CLOCK_SKEW_SECS";
const DEFAULT_TENANT_AUTHORITY_CLOCK_SKEW_SECS: u64 = 60;
const DLX_PAYLOAD_KEY_NAME_ENV: &str = "RSS_DLX_PAYLOAD_KEY_NAME";
const DLX_ARCHIVE_KEY_NAME_ENV: &str = "RSS_DLX_ARCHIVE_KEY_NAME";
const VAULT_ADDR_ENV: &str = "RSS_VAULT_ADDR";
const VAULT_TRANSIT_MOUNT_ENV: &str = "RSS_VAULT_TRANSIT_MOUNT";
const RELAY_LEASE_TTL_ENV: &str = "RSS_RELAY_LEASE_TTL_MS";
const RELAY_PUBLISH_TIMEOUT_ENV: &str = "RSS_RELAY_PUBLISH_TIMEOUT_MS";
const RELAY_SETTLE_TIMEOUT_ENV: &str = "RSS_RELAY_SETTLE_TIMEOUT_MS";
const RELAY_SAFETY_MARGIN_ENV: &str = "RSS_RELAY_SAFETY_MARGIN_MS";
const DEFAULT_RELAY_LEASE_TTL_MS: u64 = 60_000;
const DEFAULT_RELAY_PUBLISH_TIMEOUT_MS: u64 = 40_000;
const DEFAULT_RELAY_SETTLE_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_RELAY_SAFETY_MARGIN_MS: u64 = 5_000;
pub(crate) const DLX_HOT_VAULT_TOKEN_ENV: &str = "RSS_DLX_HOT_VAULT_TOKEN";
pub(crate) const DLX_ARCHIVE_VAULT_TOKEN_ENV: &str = "RSS_DLX_ARCHIVE_VAULT_TOKEN";

/// worker 健康 → readyz `HealthCheck` 适配探针。
pub(crate) struct WorkerHealthProbe {
    name: ProbeName,
    health: Arc<WorkerHealth>,
}

impl WorkerHealthProbe {
    pub(crate) fn new(name: ProbeName, health: Arc<WorkerHealth>) -> Self {
        Self { name, health }
    }
}

impl bootstrap::HealthProbe for WorkerHealthProbe {
    fn check(&self) -> HealthCheck {
        HealthCheck::new(
            self.name.clone(),
            self.health.status(),
            self.health.detail(),
        )
    }
}

/// Relay 时序参数聚合（减少 [`wire_durable`] 参数列表长度）。
struct RelayTiming {
    relay: RelayConfig,
    budget: DeliveryBudget,
    sampler: SamplerConfig,
    inbox_sample_interval: Duration,
    outbox_sweeper: SweeperConfig,
}

impl RelayTiming {
    fn from_snapshot(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        let budget = DeliveryBudget::new(
            parse_strict_duration_ms_env(
                config.value(RELAY_LEASE_TTL_ENV).map(str::to_owned),
                RELAY_LEASE_TTL_ENV,
                DEFAULT_RELAY_LEASE_TTL_MS,
            )?,
            parse_strict_duration_ms_env(
                config.value(RELAY_PUBLISH_TIMEOUT_ENV).map(str::to_owned),
                RELAY_PUBLISH_TIMEOUT_ENV,
                DEFAULT_RELAY_PUBLISH_TIMEOUT_MS,
            )?,
            parse_strict_duration_ms_env(
                config.value(RELAY_SETTLE_TIMEOUT_ENV).map(str::to_owned),
                RELAY_SETTLE_TIMEOUT_ENV,
                DEFAULT_RELAY_SETTLE_TIMEOUT_MS,
            )?,
            parse_strict_duration_ms_env(
                config.value(RELAY_SAFETY_MARGIN_ENV).map(str::to_owned),
                RELAY_SAFETY_MARGIN_ENV,
                DEFAULT_RELAY_SAFETY_MARGIN_MS,
            )?,
        )
        .context("invalid outbox relay budget")?;
        Self::new(
            parse_duration_ms_env(
                config
                    .value("RSS_RELAY_POLL_INTERVAL_MS")
                    .map(str::to_owned),
                "RSS_RELAY_POLL_INTERVAL_MS",
                200,
            ),
            parse_usize_env(
                config.value("RSS_RELAY_MAX_IN_FLIGHT").map(str::to_owned),
                "RSS_RELAY_MAX_IN_FLIGHT",
                16,
            ),
            budget,
            parse_duration_ms_env(
                config
                    .value("RSS_RELAY_SAMPLE_INTERVAL_MS")
                    .map(str::to_owned),
                "RSS_RELAY_SAMPLE_INTERVAL_MS",
                30_000,
            ),
            parse_duration_ms_env(
                config
                    .value("RSS_INBOX_SAMPLE_INTERVAL_MS")
                    .map(str::to_owned),
                "RSS_INBOX_SAMPLE_INTERVAL_MS",
                30_000,
            ),
            parse_duration_ms_env(
                config
                    .value("RSS_OUTBOX_SWEEP_INTERVAL_MS")
                    .map(str::to_owned),
                "RSS_OUTBOX_SWEEP_INTERVAL_MS",
                300_000,
            ),
            parse_u64_env(
                config.value("RSS_OUTBOX_RETAIN_SECONDS").map(str::to_owned),
                "RSS_OUTBOX_RETAIN_SECONDS",
                604_800,
            ),
        )
    }

    fn new(
        poll: Duration,
        max_in_flight: usize,
        budget: DeliveryBudget,
        sample: Duration,
        inbox_sample_interval: Duration,
        sweep: Duration,
        retain_seconds: u64,
    ) -> anyhow::Result<Self> {
        let relay = RelayConfig::new(poll, max_in_flight).context("build relay config")?;
        let sampler = SamplerConfig::new(
            generated::event::PRODUCER_DOMAINS
                .iter()
                .map(|domain| domain.as_str().to_owned())
                .collect(),
            sample,
        )
        .context("build outbox sampler config")?;
        let outbox_sweeper =
            SweeperConfig::new(retain_seconds, sweep).context("build outbox sweeper config")?;
        Ok(Self {
            relay,
            budget,
            sampler,
            inbox_sample_interval,
            outbox_sweeper,
        })
    }
}

/// Production-only verified dependencies for the DLX lifecycle worker. Construction requires the
/// independent PostgreSQL role, a startup-verified WORM store, and a typed archive key.
pub(crate) struct DlxLifecycleRuntimeDeps {
    pg_owner: PgDlxLifecycleRuntime,
    backlog_repository: PgDlxLifecycleRepository,
    archive_store_readiness: s3::VerifiedS3DlxArchiveStore,
    archive_key_provider: Arc<VaultKeyProvider>,
    archive_key: DlxArchiveKeyName,
    lifecycle: DlxLifecycle<
        PgDlxLifecycleRepository,
        s3::VerifiedS3DlxArchiveStore,
        SharedVaultKeyProvider,
    >,
}

impl DlxLifecycleRuntimeDeps {
    pub(crate) fn new(
        pg_owner: PgDlxLifecycleRuntime,
        archive_store: s3::VerifiedS3DlxArchiveStore,
        archive_key_provider: VaultKeyProvider,
        archive_key: DlxArchiveKeyName,
    ) -> Self {
        let repository = pg_owner.repository();
        let archive_key_provider = Arc::new(archive_key_provider);
        Self {
            pg_owner,
            backlog_repository: repository.clone(),
            archive_store_readiness: archive_store.clone(),
            archive_key_provider: Arc::clone(&archive_key_provider),
            archive_key: archive_key.clone(),
            lifecycle: DlxLifecycle::new(
                repository,
                archive_store,
                SharedVaultKeyProvider(archive_key_provider),
                archive_key,
            ),
        }
    }

    fn into_rollback_module(self) -> DomainModuleResult {
        let mut output = DomainModuleResult::default();
        output.push_resource(DynManagedResource::new_box(self.pg_owner));
        output
    }
}

#[derive(Clone)]
struct SharedVaultKeyProvider(Arc<VaultKeyProvider>);

impl diport::KeyProvider for SharedVaultKeyProvider {
    async fn encrypt(
        &self,
        key: diport::KeyName,
        plaintext: secure::Plaintext,
        aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        self.0.encrypt(key, plaintext, aad).await
    }

    async fn decrypt(
        &self,
        ciphertext: RedactedBytes,
        key: diport::KeyRef,
        aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, diport::KeyProviderError> {
        self.0.decrypt(ciphertext, key, aad).await
    }

    async fn rewrap(
        &self,
        ciphertext: RedactedBytes,
        key: diport::KeyRef,
        aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        self.0.rewrap(ciphertext, key, aad).await
    }

    async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
        diport::KeyProvider::shutdown(self.0.as_ref()).await
    }
}

impl diport::ManagedResource for SharedVaultKeyProvider {
    fn name(&self) -> &str {
        "vault-dlx-archive-key-provider"
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        diport::ManagedResource::shutdown(self.0.as_ref()).await
    }
}

pub(crate) struct DlxRoleOutputs {
    pub(crate) lifecycle_repository: DomainModuleResult,
    pub(crate) archive_store: DomainModuleResult,
    pub(crate) archive_key_provider: DomainModuleResult,
}

#[derive(Clone)]
struct EventSecurity {
    tenant_authority: Arc<TenantAuthority>,
    dlx_payload_protector: DlxPayloadProtector,
    amqp_ca: amqp::AmqpPrivateCa,
}

struct DurableEventExecution {
    per_domain: BTreeMap<String, bootstrap::AmqpUrl>,
    local_producers: Vec<generated::event::ProducerDomain>,
}

// ── 公开函数 ──────────────────────────────────────────────────────────────────

/// 需要 per-domain AMQP vhost 连接的域集 = **generated producer domain ∪ consumer 订阅 topic owner**
/// （topic 首 '.' 前的前缀段）。两类都要 vhost：relay 往发布域 vhost 发布 outbox，consumer 从订阅 topic owner
/// vhost 拉取。转小写、去重、排序。
#[cfg(test)]
pub(crate) fn required_domains(subscribers: &[BridgedSubscription]) -> Vec<String> {
    let mut domains: Vec<String> = generated::event::PRODUCER_DOMAINS
        .iter()
        .map(|domain| domain.as_str().to_string())
        .collect();
    domains.extend(subscribers.iter().map(BridgedSubscription::topic_owner));
    domains.sort_unstable();
    domains.dedup();
    domains
}

#[cfg(any(test, feature = "integration"))]
fn generated_required_domains() -> Vec<String> {
    let mut domains: Vec<String> = generated::event::PRODUCER_DOMAINS
        .iter()
        .map(|domain| domain.as_str().to_owned())
        .collect();
    domains.extend(
        generated::event::EVENTS
            .iter()
            .filter(|event| !event.subscriptions().is_empty())
            .map(|event| topic_owner(event.topic())),
    );
    domains.sort_unstable();
    domains.dedup();
    domains
}

#[cfg(any(test, feature = "integration"))]
fn topic_owner(topic: &str) -> String {
    topic
        .split('.')
        .next()
        .unwrap_or(topic)
        .to_ascii_lowercase()
}

#[cfg(test)]
fn consumer_meta_parts_for_subscription(
    subscription: &BridgedSubscription,
) -> (&'static str, &'static str, &'static str) {
    (
        subscription.consumer(),
        subscription.contract_id(),
        subscription.topic(),
    )
}

fn consumer_meta_for_subscription(
    subscription: &BridgedSubscription,
    tenant_authority: Arc<TenantAuthority>,
) -> ConsumerMeta {
    subscription.consumer_meta(tenant_authority)
}

pub(crate) fn bridge_generated_subscriptions_for_execution(
    bindings: Vec<SubscriberBinding>,
    execution: &crate::plan::LocalEventExecutionPlan,
) -> anyhow::Result<BridgedSubscriptions> {
    eventing_composition::bridge_generated_subscriptions_selected(
        bindings,
        execution.local_subscriptions(),
    )
}

#[cfg(any(test, feature = "integration"))]
pub fn bridge_generated_subscriptions(
    bindings: Vec<SubscriberBinding>,
) -> anyhow::Result<BridgedSubscriptions> {
    eventing_composition::bridge_generated_subscriptions(bindings)
}

#[cfg(test)]
fn bridge_subscriptions_with_events(
    bindings: Vec<SubscriberBinding>,
    events: &[EventSpec],
) -> anyhow::Result<BridgedSubscriptions> {
    eventing_composition::bridge_subscriptions_with_events_for_test(bindings, events)
}

/// topology 接线决策（纯函数，不依赖 PG/infra；可脱离容器单测）。
///
/// 从 transport config resolve：
/// - Demo → [`EventDecision::Demo`]
/// - Durable → [`EventDecision::Durable`]
#[derive(Debug)]
enum EventDecision {
    Inactive,
    Demo,
    Durable {
        per_domain: BTreeMap<String, bootstrap::AmqpUrl>,
    },
}

/// resolve transport 接线决策（从 [`wire_event_transport`] 抽出，便于单测）。
fn resolve_event_decision<T: AsRef<str>>(
    topology: bootstrap::Topology,
    transport: bootstrap::eventtransport::TransportConfig,
    required: &[T],
) -> anyhow::Result<EventDecision> {
    let required_refs = required.iter().map(AsRef::as_ref).collect::<Vec<_>>();
    let transport = bootstrap::eventtransport::resolve(topology, transport, &required_refs)
        .context("resolve event transport")?;
    match transport {
        bootstrap::ResolvedTransport::Demo => Ok(EventDecision::Demo),
        bootstrap::ResolvedTransport::Durable { per_domain } => {
            Ok(EventDecision::Durable { per_domain })
        }
        _ => anyhow::bail!("unknown event transport resolution"),
    }
}

/// topology-gated 事件传输接线单入口（`run()` 调用点）。
///
/// - Demo 拓扑：返回空 [`DomainModuleResult`]（不建连接/不 spawn；生产 Demo fail-fast 由 `run()` 保证）。
/// - Durable 拓扑（Shared / Isolated）：连接 per-domain AMQP → spawn relay + PG inbox consumer workers。
///
/// `cfg` 按值消费（`TransportConfig` 不 impl Clone）。
pub(crate) struct EventAdmissions {
    relay: primitives::RelayAdmission,
    consumer: primitives::ConsumerAdmission,
    write: primitives::WriteAdmission,
}

impl EventAdmissions {
    pub(crate) fn new(
        relay: primitives::RelayAdmission,
        consumer: primitives::ConsumerAdmission,
        write: primitives::WriteAdmission,
    ) -> Self {
        Self {
            relay,
            consumer,
            write,
        }
    }
}

pub(crate) struct EventTransportWiring<'a> {
    pg: &'a PgRuntimeHandle,
    distributed: DistributedRuntimeDeps,
    subscribers: BridgedSubscriptions,
    cfg: EventTransportConfig,
    worker: EventWorkerConfig,
    audit_key: Option<MacKey>,
    admissions: EventAdmissions,
}

impl<'a> EventTransportWiring<'a> {
    pub(crate) fn new(
        pg: &'a PgRuntimeHandle,
        distributed: DistributedRuntimeDeps,
        subscribers: BridgedSubscriptions,
        cfg: EventTransportConfig,
        worker: EventWorkerConfig,
        audit_key: Option<MacKey>,
        admissions: EventAdmissions,
    ) -> Self {
        Self {
            pg,
            distributed,
            subscribers,
            cfg,
            worker,
            audit_key,
            admissions,
        }
    }
}

pub(crate) async fn wire_event_transport(
    wiring: EventTransportWiring<'_>,
) -> anyhow::Result<DomainModuleResult> {
    let EventTransportWiring {
        pg,
        distributed,
        subscribers,
        cfg,
        worker,
        audit_key,
        admissions,
    } = wiring;
    let local_producers = cfg.local_producers.clone();
    let timing = worker.relay;
    let security = match &cfg.decision {
        EventDecision::Durable { .. } => event_security_for_topology(cfg.topology, &cfg)?,
        EventDecision::Inactive | EventDecision::Demo => None,
    };
    match cfg.decision {
        EventDecision::Inactive => Ok(DomainModuleResult::default()),
        EventDecision::Demo => {
            // reason: Demo 拓扑返回空产物——函数可在无 env/容器下单测；生产走 Demo 时
            // 组合根 `run()` 在此函数调用前已 fail-fast（TOPO-INMEM-SEAL-01）。
            tracing::warn!(
                stage = "event-transport",
                "Demo 拓扑：事件传输不接线（组合根 fail-fast 保证生产路径不进此臂）"
            );
            Ok(DomainModuleResult::default())
        }
        EventDecision::Durable { per_domain } => {
            let security = security.context("durable event security config missing")?;
            pg.validate_relay_budget(timing.budget)
                .context("runtime relay budget does not match governed database policy")?;
            wire_durable(
                pg,
                DurableWiring {
                    distributed,
                    subscribers,
                    execution: DurableEventExecution {
                        per_domain,
                        local_producers,
                    },
                    timing,
                    security,
                    audit_key,
                    admissions,
                },
            )
            .await
        }
    }
}

/// Wires the single production DLX lifecycle worker. The owner is consumed here so the dedicated
/// PostgreSQL pool and worker are registered through the same lifecycle funnel.
pub(crate) fn wire_dlx_lifecycle(
    deps: DlxLifecycleRuntimeDeps,
    worker: DlxWorkerConfig,
    write_admission: primitives::WriteAdmission,
) -> Result<DlxRoleOutputs, DlxLifecycleWireFailure> {
    let probe_name =
        match ProbeName::parse(DLX_LIFECYCLE_PROBE).context("parse DLX lifecycle probe name") {
            Ok(name) => name,
            Err(error) => {
                return Err(DlxLifecycleWireFailure {
                    deps: Box::new(deps),
                    error,
                });
            }
        };
    let archive_probe_name = match ProbeName::parse(DLX_ARCHIVE_READINESS_PROBE)
        .context("parse DLX archive readiness probe name")
    {
        Ok(name) => name,
        Err(error) => {
            return Err(DlxLifecycleWireFailure {
                deps: Box::new(deps),
                error,
            });
        }
    };
    let archive_key_probe_name = match ProbeName::parse(DLX_ARCHIVE_KEY_READINESS_PROBE)
        .context("parse DLX archive key readiness probe name")
    {
        Ok(name) => name,
        Err(error) => {
            return Err(DlxLifecycleWireFailure {
                deps: Box::new(deps),
                error,
            });
        }
    };
    let DlxLifecycleRuntimeDeps {
        pg_owner,
        backlog_repository,
        archive_store_readiness,
        archive_key_provider,
        archive_key,
        lifecycle,
    } = deps;
    let health = Arc::new(WorkerHealth::starting());
    let lifecycle_worker = build_dlx_lifecycle_worker(
        lifecycle,
        backlog_repository,
        Arc::clone(&health),
        worker,
        write_admission,
    );
    let probe = build_dlx_lifecycle_probe(probe_name.clone(), health);
    let archive_health = Arc::new(WorkerHealth::starting());
    let archive_worker = build_dlx_archive_readiness_worker(
        archive_store_readiness,
        Arc::clone(&archive_health),
        worker,
    );
    let archive_probe = Box::new(WorkerHealthProbe::new(
        archive_probe_name.clone(),
        archive_health,
    ));
    let archive_key_health = Arc::new(WorkerHealth::starting());
    let archive_key_resource =
        DynManagedResource::new_box(SharedVaultKeyProvider(Arc::clone(&archive_key_provider)));
    let archive_key_worker = build_dlx_archive_key_readiness_worker(
        archive_key_provider,
        archive_key,
        Arc::clone(&archive_key_health),
        worker,
    );
    let archive_key_probe = Box::new(WorkerHealthProbe::new(
        archive_key_probe_name.clone(),
        archive_key_health,
    ));
    let mut lifecycle_repository = DomainModuleResult::default();
    lifecycle_repository.push_probe((probe_name, probe));
    lifecycle_repository.push_resource(DynManagedResource::new_box(pg_owner));
    lifecycle_repository.push_worker(lifecycle_worker);
    let mut archive_store = DomainModuleResult::default();
    archive_store.push_probe((archive_probe_name, archive_probe));
    archive_store.push_worker(archive_worker);
    let mut archive_key_provider_output = DomainModuleResult::default();
    archive_key_provider_output.push_probe((archive_key_probe_name, archive_key_probe));
    archive_key_provider_output.push_resource(archive_key_resource);
    archive_key_provider_output.push_worker(archive_key_worker);
    Ok(DlxRoleOutputs {
        lifecycle_repository,
        archive_store,
        archive_key_provider: archive_key_provider_output,
    })
}

pub(crate) struct DlxLifecycleWireFailure {
    deps: Box<DlxLifecycleRuntimeDeps>,
    error: anyhow::Error,
}

impl DlxLifecycleWireFailure {
    pub(crate) fn into_rollback(self) -> (DomainModuleResult, anyhow::Error) {
        ((*self.deps).into_rollback_module(), self.error)
    }
}

trait DlxArchiveReadiness {
    async fn probe_archive_readiness(&self) -> Result<(), s3::S3DlxArchiveCapabilityError>;
}

impl DlxArchiveReadiness for s3::VerifiedS3DlxArchiveStore {
    async fn probe_archive_readiness(&self) -> Result<(), s3::S3DlxArchiveCapabilityError> {
        self.probe_readiness().await
    }
}

fn dlx_archive_probe_health(
    result: Result<(), s3::S3DlxArchiveCapabilityError>,
) -> DlxLifecycleHealth {
    match result {
        Ok(()) => DlxLifecycleHealth::Healthy,
        Err(s3::S3DlxArchiveCapabilityError::Provider) => DlxLifecycleHealth::Degraded,
        Err(
            s3::S3DlxArchiveCapabilityError::VersioningRequired
            | s3::S3DlxArchiveCapabilityError::ObjectLockRequired
            | s3::S3DlxArchiveCapabilityError::ComplianceRequired
            | s3::S3DlxArchiveCapabilityError::RetentionTooShort
            | s3::S3DlxArchiveCapabilityError::LifecycleRequired
            | s3::S3DlxArchiveCapabilityError::CanaryInvariant,
        ) => DlxLifecycleHealth::Unhealthy,
    }
}

fn apply_dlx_archive_probe_result(
    health: &WorkerHealth,
    result: Result<(), s3::S3DlxArchiveCapabilityError>,
) {
    let probe_health = dlx_archive_probe_health(result);
    apply_dlx_lifecycle_health(health, probe_health);
    if probe_health != DlxLifecycleHealth::Healthy {
        tracing::warn!(
            invariant = probe_health == DlxLifecycleHealth::Unhealthy,
            "DLX archive periodic readiness probe failed"
        );
    }
}

fn build_dlx_archive_readiness_worker<S>(
    store: S,
    health: Arc<WorkerHealth>,
    config: DlxWorkerConfig,
) -> WorkerSpec
where
    S: DlxArchiveReadiness + Send + 'static,
{
    WorkerSpec::observational_phase_one("assemblies.runtime.src.event_transport.01", move |token| {
        DynManagedResource::new_box(spawn_on_dedicated_runtime(
            DLX_ARCHIVE_READINESS_WORKER_NAME,
            token,
            Arc::clone(&health),
            EVENT_WORKER_SHUTDOWN_BUDGET,
            move |thread_token| async move {
                dlx_archive_readiness_loop(store, thread_token, Arc::clone(&health), config).await;
                Ok(())
            },
        ))
    })
}

async fn dlx_archive_readiness_loop<S>(
    store: S,
    token: tokio_util::sync::CancellationToken,
    health: Arc<WorkerHealth>,
    config: DlxWorkerConfig,
) where
    S: DlxArchiveReadiness,
{
    let mut ticker = tokio::time::interval(config.archive_readiness_interval);
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                if run_bounded_dlx_archive_readiness_probe(&store, &token, &health, config).await
                    == DlxLoopStep::Cancelled
                {
                    break;
                }
            }
        }
    }
}

fn build_dlx_archive_key_readiness_worker(
    provider: Arc<VaultKeyProvider>,
    key: DlxArchiveKeyName,
    health: Arc<WorkerHealth>,
    config: DlxWorkerConfig,
) -> WorkerSpec {
    WorkerSpec::observational_phase_one("assemblies.runtime.src.event_transport.02", move |token| {
        DynManagedResource::new_box(spawn_on_dedicated_runtime(
            DLX_ARCHIVE_KEY_READINESS_WORKER_NAME,
            token,
            Arc::clone(&health),
            EVENT_WORKER_SHUTDOWN_BUDGET,
            move |thread_token| async move {
                dlx_archive_key_readiness_loop(
                    VaultArchiveKeyReadiness { provider, key },
                    thread_token,
                    Arc::clone(&health),
                    config,
                )
                .await;
                Ok(())
            },
        ))
    })
}

trait DlxArchiveKeyReadiness {
    async fn probe_archive_key_readiness(&self) -> anyhow::Result<()>;
}

struct VaultArchiveKeyReadiness {
    provider: Arc<VaultKeyProvider>,
    key: DlxArchiveKeyName,
}

impl DlxArchiveKeyReadiness for VaultArchiveKeyReadiness {
    async fn probe_archive_key_readiness(&self) -> anyhow::Result<()> {
        verify_dlx_vault_key_capability(
            self.provider.as_ref(),
            self.key.as_key_name(),
            "dlx-archive-readiness",
        )
        .await
    }
}

async fn dlx_archive_key_readiness_loop<R>(
    readiness: R,
    token: tokio_util::sync::CancellationToken,
    health: Arc<WorkerHealth>,
    config: DlxWorkerConfig,
) where
    R: DlxArchiveKeyReadiness,
{
    let mut ticker = tokio::time::interval(config.archive_readiness_interval);
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                let sample = tokio::time::timeout(
                    config.archive_readiness_timeout,
                    readiness.probe_archive_key_readiness(),
                ).await;
                apply_dlx_archive_key_readiness_sample(&health, sample);
            }
        }
    }
}

#[allow(
    clippy::cognitive_complexity,
    reason = "exhaustive readiness result mapping keeps health and diagnostics in one boundary"
)]
fn apply_dlx_archive_key_readiness_sample(
    health: &WorkerHealth,
    sample: Result<anyhow::Result<()>, tokio::time::error::Elapsed>,
) {
    match sample {
        Ok(Ok(())) => apply_dlx_lifecycle_health(health, DlxLifecycleHealth::Healthy),
        Ok(Err(error)) => {
            apply_dlx_lifecycle_health(health, DlxLifecycleHealth::Degraded);
            tracing::warn!(error = %error, "DLX archive key readiness failed");
        }
        Err(_) => {
            apply_dlx_lifecycle_health(health, DlxLifecycleHealth::Degraded);
            tracing::warn!("DLX archive key readiness timed out");
        }
    }
}

pub(crate) async fn verify_dlx_vault_key_capability(
    provider: &VaultKeyProvider,
    key: &diport::KeyName,
    coordinate: &'static str,
) -> anyhow::Result<()> {
    const CANARY_TENANT: &str = "00000000-0000-4000-8000-000000001168";
    const CANARY_PLAINTEXT: &[u8] = b"rss-dlx-vault-capability-v1";
    let tenant =
        rss_request_context::TenantId::parse(CANARY_TENANT).context("parse DLX canary tenant")?;
    let aad = secure::ProtectionContext::authorized_maintenance(
        tenant,
        coordinate,
        "readiness-canary",
        1,
    )
    .context("derive DLX Vault canary AAD")?
    .derive();
    let wrong_aad = secure::ProtectionContext::authorized_maintenance(
        tenant,
        coordinate,
        "readiness-canary-wrong-aad",
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

async fn run_bounded_dlx_archive_readiness_probe<S>(
    store: &S,
    token: &tokio_util::sync::CancellationToken,
    health: &WorkerHealth,
    config: DlxWorkerConfig,
) -> DlxLoopStep
where
    S: DlxArchiveReadiness,
{
    tokio::select! {
        biased;
        () = token.cancelled() => DlxLoopStep::Cancelled,
        probe = tokio::time::timeout(
            config.archive_readiness_timeout,
            store.probe_archive_readiness(),
        ) => {
            match probe {
                Ok(result) => apply_dlx_archive_probe_result(health, result),
                Err(_) => {
                    apply_dlx_lifecycle_health(health, DlxLifecycleHealth::Degraded);
                    tracing::warn!("DLX archive periodic readiness probe timed out");
                }
            }
            DlxLoopStep::Continue
        }
    }
}

fn build_dlx_lifecycle_worker<L, B>(
    lifecycle: L,
    backlog_repository: B,
    health: Arc<WorkerHealth>,
    config: DlxWorkerConfig,
    write_admission: primitives::WriteAdmission,
) -> WorkerSpec
where
    L: DlxTickRunner + Send + 'static,
    B: DlxBacklogReader + Send + 'static,
{
    WorkerSpec::writes_phase_one(
        "assemblies.runtime.src.event_transport.03",
        &write_admission,
        move |token, worker_admission| {
            DynManagedResource::new_box(spawn_on_dedicated_runtime(
                DLX_LIFECYCLE_WORKER_NAME,
                token,
                Arc::clone(&health),
                EVENT_WORKER_SHUTDOWN_BUDGET,
                move |thread_token| async move {
                    dlx_lifecycle_loop(
                        lifecycle,
                        backlog_repository,
                        DlxLoopContext {
                            token: thread_token,
                            health: Arc::clone(&health),
                            metrics: Arc::new(MetricsRetentionMetrics),
                            clock: Arc::new(SystemClock),
                            config,
                            write_admission: worker_admission,
                        },
                    )
                    .await;
                    Ok(())
                },
            ))
        },
    )
}

fn build_dlx_lifecycle_probe(
    probe_name: ProbeName,
    health: Arc<WorkerHealth>,
) -> Box<dyn bootstrap::HealthProbe> {
    Box::new(WorkerHealthProbe::new(probe_name, health))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DlxTickObservation {
    health: DlxLifecycleHealth,
    archived: u64,
    purged: u64,
    receipts_reconciled: u64,
    primary_failure: Option<DlxLifecycleError>,
}

impl DlxTickObservation {
    const fn outcome(self) -> RetentionOutcome {
        match self.health {
            DlxLifecycleHealth::Healthy => RetentionOutcome::Success,
            DlxLifecycleHealth::Degraded => RetentionOutcome::Transient,
            DlxLifecycleHealth::Unhealthy => RetentionOutcome::Invariant,
        }
    }
}

impl From<DlxLifecycleTickReport> for DlxTickObservation {
    fn from(report: DlxLifecycleTickReport) -> Self {
        Self {
            health: report.health(),
            archived: report.archived(),
            purged: report.purged(),
            receipts_reconciled: report.receipts_reconciled(),
            primary_failure: report.primary_failure(),
        }
    }
}

trait DlxTickRunner {
    async fn tick_observation(&self, now_epoch_secs: i64) -> DlxTickObservation;
}

impl DlxTickRunner
    for DlxLifecycle<
        PgDlxLifecycleRepository,
        s3::VerifiedS3DlxArchiveStore,
        SharedVaultKeyProvider,
    >
{
    async fn tick_observation(&self, now_epoch_secs: i64) -> DlxTickObservation {
        self.tick(now_epoch_secs).await.into()
    }
}

trait DlxBacklogReader {
    async fn read_archive_backlog(&self) -> Result<DlxArchiveBacklog, DlxLifecycleError>;
}

impl DlxBacklogReader for PgDlxLifecycleRepository {
    async fn read_archive_backlog(&self) -> Result<DlxArchiveBacklog, DlxLifecycleError> {
        self.archive_backlog().await
    }
}

struct DlxLoopContext {
    token: tokio_util::sync::CancellationToken,
    health: Arc<WorkerHealth>,
    metrics: Arc<dyn RetentionMetrics>,
    clock: Arc<dyn Clock>,
    config: DlxWorkerConfig,
    write_admission: primitives::WriteAdmission,
}

async fn dlx_lifecycle_loop<L, B>(lifecycle: L, backlog_repository: B, context: DlxLoopContext)
where
    L: DlxTickRunner,
    B: DlxBacklogReader,
{
    let DlxLoopContext {
        token,
        health,
        metrics,
        clock,
        config,
        write_admission,
    } = context;
    let mut ticker = tokio::time::interval(config.lifecycle_interval);
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                let Ok(_permit) = write_admission.try_enter() else {
                    continue;
                };
                if run_bounded_dlx_lifecycle_tick(
                    &lifecycle,
                    &backlog_repository,
                    &token,
                    &health,
                    metrics.as_ref(),
                    clock.as_ref(),
                    config,
                ).await == DlxLoopStep::Cancelled {
                    break;
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DlxLoopStep {
    Continue,
    Cancelled,
}

async fn run_bounded_dlx_lifecycle_tick<L, B>(
    lifecycle: &L,
    backlog_repository: &B,
    token: &tokio_util::sync::CancellationToken,
    health: &WorkerHealth,
    metrics: &dyn RetentionMetrics,
    clock: &dyn Clock,
    config: DlxWorkerConfig,
) -> DlxLoopStep
where
    L: DlxTickRunner,
    B: DlxBacklogReader,
{
    tokio::select! {
        biased;
        () = token.cancelled() => DlxLoopStep::Cancelled,
        result = tokio::time::timeout(
            config.lifecycle_tick_timeout,
            run_dlx_lifecycle_tick(lifecycle, backlog_repository, health, metrics, clock),
        ) => {
            if result.is_err() {
                apply_dlx_lifecycle_health(health, DlxLifecycleHealth::Degraded);
                metrics.record_sweep(
                    RetentionTarget::DeadLetter,
                    RetentionOutcome::Transient,
                    0,
                    config.lifecycle_tick_timeout.as_secs_f64(),
                );
                tracing::warn!("DLX lifecycle tick exceeded total I/O budget");
            }
            DlxLoopStep::Continue
        }
    }
}

async fn run_dlx_lifecycle_tick<L, B>(
    lifecycle: &L,
    backlog_repository: &B,
    health: &WorkerHealth,
    metrics: &dyn RetentionMetrics,
    clock: &dyn Clock,
) where
    L: DlxTickRunner,
    B: DlxBacklogReader,
{
    let started = clock.now();
    let report = lifecycle
        .tick_observation(
            rss_contract::Timepoint::saturating_from_system_time(started).unix_seconds(),
        )
        .await;
    let lifecycle_health = match backlog_repository.read_archive_backlog().await {
        Ok(backlog) => {
            metrics.record_archive_backlog(backlog);
            report.health
        }
        Err(_) => {
            mark_dlx_backlog_unavailable();
            if report.health == DlxLifecycleHealth::Healthy {
                DlxLifecycleHealth::Degraded
            } else {
                report.health
            }
        }
    };
    let final_outcome = DlxTickObservation {
        health: lifecycle_health,
        ..report
    }
    .outcome();
    let duration = elapsed_seconds(started, clock.now());
    if let Some(failure) = report.primary_failure {
        record_dlx_primary_failure(failure);
    }
    // `tick_observation` aggregates candidate/archive/receipt/purge/reconcile. Emitting a single
    // phase-labelled archive metric would invent granularity, so the aggregate uses the typed
    // dead-letter retention target only, after backlog sampling has finalized the outcome.
    metrics.record_sweep(
        RetentionTarget::DeadLetter,
        final_outcome,
        report.purged,
        duration,
    );
    apply_dlx_lifecycle_health(health, lifecycle_health);
    tracing::debug!(
        archived = report.archived,
        purged = report.purged,
        receipts_reconciled = report.receipts_reconciled,
        outcome = final_outcome.as_label(),
        "DLX lifecycle tick completed"
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DlxFailureLabels {
    operation: &'static str,
    reason: &'static str,
}

impl From<DlxLifecycleError> for DlxFailureLabels {
    fn from(error: DlxLifecycleError) -> Self {
        Self {
            operation: error.operation().as_label(),
            reason: error.reason().as_label(),
        }
    }
}

fn record_dlx_primary_failure(error: DlxLifecycleError) {
    let labels = DlxFailureLabels::from(error);
    metrics::counter!(
        "dead_letter_lifecycle_failures_total",
        "operation" => labels.operation,
        "reason" => labels.reason,
    )
    .increment(1);
    tracing::warn!(
        dlx.operation = labels.operation,
        dlx.reason = labels.reason,
        "DLX lifecycle tick failed"
    );
}

fn mark_dlx_backlog_unavailable() {
    metrics::gauge!("dead_letter_archive_pending_depth").set(f64::NAN);
    metrics::gauge!("dead_letter_archive_oldest_pending_age_seconds").set(f64::NAN);
}

fn elapsed_seconds(started: SystemTime, finished: SystemTime) -> f64 {
    finished
        .duration_since(started)
        .map(|value| value.as_secs_f64())
        .unwrap_or(0.0)
}

/// Map one immutable serving snapshot into exact topology/security configuration.
fn map_event_transport_from_snapshot(
    config: SnapshotConfig<'_>,
    required_domains: &[String],
    local_producers: &[generated::event::ProducerDomain],
    active: bool,
) -> anyhow::Result<EventTransportConfig> {
    let get = |name: &str| config.value(name).map(str::to_owned);
    let topo_raw = get("RSS_TOPOLOGY")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_TOPOLOGY"))?;
    let topology = parse_topology(topo_raw.trim())?;

    let transport = if topology == bootstrap::Topology::Demo {
        bootstrap::eventtransport::TransportConfig::default()
    } else {
        // env 只把 AMQP 配置完整映射成 typed config——per-domain（`RSS_<DOMAIN>_AMQP_URL`，优先）+ 共享回退
        // （`RSS_AMQP_URL`）；per-domain/shared 完备性与隔离由 `eventtransport::resolve` 单源 fail-closed 强制，
        // env builder 不提前收窄语义（review #342 F1：durable-shared 仅配 RSS_AMQP_URL 也应可启动）。
        // Production egress: plaintext AMQP opt-in is banned (#1710); always Deny.
        let policy = secure::PlaintextEndpointPolicy::Deny;
        let mut per_domain = BTreeMap::new();
        for domain in required_domains {
            let domain = domain.as_str();
            let env = format!("RSS_{}_AMQP_URL", domain.to_ascii_uppercase());
            if let Some(url) = get(&env) {
                let parsed = bootstrap::AmqpUrl::parse(url, policy).with_context(|| {
                    format!("{env} must be amqps:// (plaintext amqp:// is banned in production)")
                })?;
                per_domain.insert(domain.to_string(), parsed);
            }
        }
        let shared = get("RSS_AMQP_URL")
            .map(|url| {
                bootstrap::AmqpUrl::parse(url, policy).context(
                    "RSS_AMQP_URL must be amqps:// (plaintext amqp:// is banned in production)",
                )
            })
            .transpose()?;
        bootstrap::eventtransport::TransportConfig::new(per_domain, shared)
    };
    let decision = if active {
        resolve_event_decision(topology, transport, required_domains)?
    } else {
        EventDecision::Inactive
    };
    let (tenant_authority, dlx_payload_protector, amqp_ca) =
        if topology == bootstrap::Topology::Demo {
            (None, None, None)
        } else {
            let amqp_ca = active
                .then(|| {
                    let pem = crate::infra::read_required_ca_pem(
                        config.value(AMQP_CA_CERT_PEM_PATH_ENV),
                        AMQP_CA_CERT_PEM_PATH_ENV,
                    )?;
                    amqp::AmqpPrivateCa::from_pem(pem).with_context(|| {
                        format!("parse AMQP private CA PEM from {AMQP_CA_CERT_PEM_PATH_ENV}")
                    })
                })
                .transpose()?;
            (
                active
                    .then(|| build_tenant_authority_from(&get))
                    .transpose()?,
                Some(build_dlx_payload_protector(config)?),
                amqp_ca,
            )
        };

    Ok(EventTransportConfig {
        topology,
        decision,
        tenant_authority,
        dlx_payload_protector,
        amqp_ca,
        local_producers: local_producers.to_vec(),
    })
}

fn event_security_for_topology(
    topology: bootstrap::Topology,
    cfg: &EventTransportConfig,
) -> anyhow::Result<Option<EventSecurity>> {
    if topology == bootstrap::Topology::Demo {
        return Ok(None);
    }
    Ok(Some(EventSecurity {
        tenant_authority: cfg
            .tenant_authority
            .clone()
            .ok_or_else(|| anyhow::anyhow!("missing durable tenant authority config"))?,
        dlx_payload_protector: cfg
            .dlx_payload_protector
            .clone()
            .ok_or_else(|| anyhow::anyhow!("missing durable dlx payload protector config"))?,
        amqp_ca: cfg
            .amqp_ca
            .clone()
            .ok_or_else(|| anyhow::anyhow!("missing durable AMQP private CA config"))?,
    }))
}

// ── 内部函数 ──────────────────────────────────────────────────────────────────

/// durable 拓扑接线内核（Shared / Isolated）：建立 AMQP，spawn relay + PG inbox consumer workers。
// reason: wire_durable 是顺序聚合函数，步骤严格有序（AMQP resources → relay → consumers）；
// 拆分会把 module channel 填充顺序散布到多处，隐藏通用 resources → workers 注册约束。
struct DurableWiring {
    distributed: DistributedRuntimeDeps,
    subscribers: BridgedSubscriptions,
    execution: DurableEventExecution,
    timing: RelayTiming,
    security: EventSecurity,
    audit_key: Option<MacKey>,
    admissions: EventAdmissions,
}

#[allow(clippy::cognitive_complexity)]
async fn wire_durable(
    pg: &PgRuntimeHandle,
    wiring: DurableWiring,
) -> anyhow::Result<DomainModuleResult> {
    let DurableWiring {
        distributed,
        subscribers,
        execution,
        timing,
        security,
        audit_key,
        admissions,
    } = wiring;
    let EventAdmissions {
        relay: relay_admission,
        consumer: consumer_admission,
        write: write_admission,
    } = admissions;
    let (subscribers, inbox_backlog_selection) = subscribers.into_runtime_parts();
    let DurableEventExecution {
        per_domain,
        local_producers,
    } = execution;
    let mut module = DomainModuleResult::default();
    // projection replay / shadow-swap 由 `rss projections` 离线控制面处理；本函数只装配在线传输 worker。
    // 每个 required 域（generated producer domain ∪ subscriber 订阅 topic owner）由 resolver 保证有已校验
    // AMQP URL → 下方 amqp_map 逐域连接；任一步失败都先异步关闭 module 已拥有的连接。
    let mut amqp_map: BTreeMap<String, amqp::AmqpRuntimeDeps> = BTreeMap::new();
    for (domain_upper, url) in &per_domain {
        let domain = domain_upper.to_ascii_lowercase();
        let endpoint = url.as_ref().clone();
        let publisher = amqp::AmqpPublisherEndpoint::new(endpoint.clone());
        let subscriber = amqp::AmqpSubscriberEndpoint::new(endpoint);
        let amqp_deps = match amqp::AmqpRuntimeDeps::connect_with_private_ca(
            &publisher,
            &subscriber,
            security.amqp_ca.clone(),
            &domain,
            timing.budget.publish_timeout(),
        )
        .await
        .with_context(|| format!("connect amqp for domain '{domain}'"))
        {
            Ok(deps) => deps,
            Err(primary) => {
                return Err(crate::provider_output::abort_uncommitted(module, primary).await);
            }
        };
        module.extend_resources(amqp_deps.runtime_resources());
        tracing::info!(domain, "durable event transport: amqp connected");
        amqp_map.insert(domain, amqp_deps);
    }

    // Relay workers：generated producer registry 是迭代单源；闭枚举 match 把每个 producer 映射到
    // postgres sealed capability。新增 producer 变体若未接 PG capability 会在此编译失败。
    for producer in generated::event::PRODUCER_DOMAINS
        .iter()
        .copied()
        .filter(|producer| local_producers.contains(producer))
    {
        let domain = producer.as_str();
        let publisher = match relay_publisher(&amqp_map, domain) {
            Ok(publisher) => publisher,
            Err(primary) => {
                return Err(crate::provider_output::abort_uncommitted(module, primary).await);
            }
        };
        let outbox = match producer {
            generated::event::ProducerDomain::Identity => pg.for_domain::<caps::Identity>().outbox(
                publisher,
                timing.budget,
                Arc::clone(&security.tenant_authority),
                security.dlx_payload_protector.clone(),
            ),
            generated::event::ProducerDomain::Settings => pg.for_domain::<caps::Settings>().outbox(
                publisher,
                timing.budget,
                Arc::clone(&security.tenant_authority),
                security.dlx_payload_protector.clone(),
            ),
        };
        if let Err(primary) = wire_domain_relay(
            domain,
            outbox,
            &timing,
            relay_admission.clone(),
            &mut module,
        ) {
            return Err(crate::provider_output::abort_uncommitted(module, primary).await);
        }
    }
    if let Err(primary) = wire_outbox_maintenance(
        pg,
        &distributed,
        &timing,
        write_admission.clone(),
        &mut module,
    ) {
        return Err(crate::provider_output::abort_uncommitted(module, primary).await);
    }

    let inbox_sampler_config =
        match inbox_sampler_registration(inbox_backlog_selection, timing.inbox_sample_interval) {
            Ok(config) => config,
            Err(primary) => {
                return Err(crate::provider_output::abort_uncommitted(module, primary).await);
            }
        };
    if let Some(config) = inbox_sampler_config
        && let Err(primary) = wire_inbox_backlog_sampler(
            pg.infra().inbox_backlog_source(),
            distributed.inbox_backlog_maintenance_coordinator(config.selection().groups())?,
            config,
            &mut module,
        )
    {
        return Err(crate::provider_output::abort_uncommitted(module, primary).await);
    }

    // Consumer resource bundle（per binding PG inbox + DLX + subscriber + worker + probe + inbox sweeper）。
    if let Err(primary) = wire_consumer_resource_bundle(
        subscribers,
        ConsumerWiring {
            pg,
            amqp_map: &amqp_map,
            security: &security,
            timing: &timing,
            audit_key: audit_key.as_ref(),
            admission: consumer_admission,
            write_admission,
        },
        &mut module,
    )
    .await
    {
        return Err(crate::provider_output::abort_uncommitted(module, primary).await);
    }

    Ok(module)
}

/// 取某发布域的 AMQP publisher 句柄（relay 用）；该域无连接即 fail-closed。
fn relay_publisher(
    amqp_map: &BTreeMap<String, amqp::AmqpRuntimeDeps>,
    domain: &str,
) -> anyhow::Result<Box<diport::DynPublisher<'static>>> {
    Ok(amqp_map
        .get(domain)
        .with_context(|| format!("no amqp connection for relay domain '{domain}'"))?
        .infra()
        .publisher())
}

pub(crate) fn retain_admission_authority(
    pg: PgRuntimeHandle,
    control: primitives::ProcessAdmissionControl,
    identity: eventexec::DrAdmissionProcessIdentity,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let health = Arc::new(WorkerHealth::starting());
    let probe_name = ProbeName::parse("dr_admission").context("parse DR admission probe name")?;
    module.push_probe((
        probe_name.clone(),
        Box::new(WorkerHealthProbe::new(probe_name, Arc::clone(&health))),
    ));
    module.push_worker(WorkerSpec::observational_phase_one(
        "assemblies.runtime.src.event_transport.04",
        move |token| {
            DynManagedResource::new_box(spawn_on_dedicated_runtime(
                "runtime-dr-admission-owner",
                token,
                Arc::clone(&health),
                EVENT_WORKER_SHUTDOWN_BUDGET,
                move |thread_token| async move {
                    eventexec::run_dr_admission_controller(
                        pg,
                        control,
                        identity,
                        thread_token,
                        health,
                    )
                    .await;
                    Ok(())
                },
            ))
        },
    ));
    Ok(())
}

/// 为单个 L2 发布域声明一个 outbox relay worker（`eventexec::spawn_relay`：专用 OS 线程 + `WorkerStoppedGuard`
/// panic-safety 守卫，与 ConsumerWorker 对称）+ 一个 per-domain readyz 探针，收进 module。
///
/// `outbox` 已绑该域 vhost publisher（调用方按 `caps::*` marker 构造，编译期防跨域错插）；`PgOutbox: Send+!Sync`
/// → `spawn_relay` 接 `store: A`（`A: Send`），在专用线程内 `Arc::new(store)`；provider-bound
/// `PgOutbox` 是 relay domain 的单一输入。
fn wire_domain_relay(
    domain: &str,
    outbox: postgres::PgOutbox,
    timing: &RelayTiming,
    admission: primitives::RelayAdmission,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let relay_cfg = timing.relay.clone();
    let health = Arc::new(WorkerHealth::healthy());
    let worker_name = format!("outbox-relay-{domain}");
    let worker_identity = format!("outbox-relay:{domain}");
    let worker_health = Arc::clone(&health);
    let worker = WorkerSpec::relay_deferred(
        worker_identity,
        &admission,
        move |token, relay_admission| {
            DynManagedResource::new_box(spawn_relay(
                worker_name,
                outbox,
                relay_cfg,
                Arc::new(SystemClock),
                token,
                worker_health,
                Arc::new(MetricsOutboxMetrics),
                relay_admission,
                EVENT_WORKER_SHUTDOWN_BUDGET,
            ))
        },
    );
    module.push_worker(worker);
    // per-domain 探针名（多 relay 各自唯一）：`{OUTBOX_RELAY_PROBE}_{domain}`。
    let probe_name = ProbeName::parse(&format!("{OUTBOX_RELAY_PROBE}_{domain}"))
        .context("parse relay probe name")?;
    module.push_probe((
        probe_name.clone(),
        Box::new(WorkerHealthProbe {
            name: probe_name,
            health,
        }),
    ));
    tracing::info!(
        domain,
        "durable event transport: outbox relay worker spawned"
    );
    Ok(())
}

/// outbox maintenance workers：backlog sampler + published-row sweeper。
fn wire_outbox_maintenance(
    pg: &PgRuntimeHandle,
    distributed: &DistributedRuntimeDeps,
    timing: &RelayTiming,
    admission: primitives::WriteAdmission,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let sampler_cfg = timing.sampler.clone();
    let sweeper_cfg = timing.outbox_sweeper.clone();

    let maintenance = pg.infra().outbox_maintenance();
    let coordinator = distributed.outbox_maintenance_coordinator(sampler_cfg.domains())?;
    wire_sampler_worker(maintenance.clone(), coordinator, sampler_cfg, module)?;
    wire_sweeper_worker(
        CoordinatedRetentionSweeper::new(maintenance, distributed.outbox_retention_coordinator()),
        sweeper_cfg,
        SWEEPER_WORKER_NAME,
        OUTBOX_SWEEPER_PROBE,
        RetentionTarget::OutboxPublished,
        admission,
        module,
    )?;

    Ok(())
}

fn wire_inbox_backlog_sampler(
    source: postgres::PgInboxBacklogSource,
    coordinator: MaintenanceCoordinator<InboxBacklogMaintenance>,
    config: InboxSamplerConfig,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let health = Arc::new(WorkerHealth::starting());
    let worker_health = Arc::clone(&health);
    let worker = WorkerSpec::observational_phase_one(
        "assemblies.runtime.src.event_transport.06-inbox",
        move |token| {
            DynManagedResource::new_box(spawn_on_dedicated_runtime(
                "inbox-backlog-sampler",
                token,
                Arc::clone(&worker_health),
                EVENT_WORKER_SHUTDOWN_BUDGET,
                move |thread_token| async move {
                    coordinated_inbox_backlog_sampler_loop(
                        Arc::new(source),
                        coordinator,
                        config,
                        thread_token,
                        Arc::clone(&worker_health),
                        Arc::new(MetricsInboxMetrics),
                    )
                    .await;
                    Ok(())
                },
            ))
        },
    );
    module.push_worker(worker);

    let probe_name =
        ProbeName::parse(INBOX_SAMPLER_PROBE).context("parse inbox sampler probe name")?;
    module.push_probe((
        probe_name.clone(),
        Box::new(WorkerHealthProbe {
            name: probe_name,
            health,
        }),
    ));
    Ok(())
}

fn inbox_sampler_registration(
    selection: InboxBacklogSelection,
    interval: Duration,
) -> anyhow::Result<Option<InboxSamplerConfig>> {
    if selection.is_empty() {
        return Ok(None);
    }
    InboxSamplerConfig::new(selection, interval)
        .map(Some)
        .context("build inbox backlog sampler config")
}

fn wire_sampler_worker(
    maintenance: postgres::PgOutboxMaintenance,
    coordinator: MaintenanceCoordinator<OutboxBacklogMaintenance>,
    config: SamplerConfig,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let health = Arc::new(WorkerHealth::healthy());
    let worker_health = Arc::clone(&health);
    let worker = WorkerSpec::observational_phase_one(
        "assemblies.runtime.src.event_transport.06",
        move |token| {
            DynManagedResource::new_box(spawn_on_dedicated_runtime(
                "outbox-sampler",
                token,
                Arc::clone(&worker_health),
                EVENT_WORKER_SHUTDOWN_BUDGET,
                move |thread_token| async move {
                    coordinated_outbox_backlog_sampler_loop(
                        Arc::new(maintenance),
                        coordinator,
                        config,
                        thread_token,
                        Arc::clone(&worker_health),
                        Arc::new(MetricsOutboxMetrics),
                    )
                    .await;
                    Ok(())
                },
            ))
        },
    );
    module.push_worker(worker);

    let probe_name =
        ProbeName::parse(OUTBOX_SAMPLER_PROBE).context("parse outbox sampler probe name")?;
    module.push_probe((
        probe_name.clone(),
        Box::new(WorkerHealthProbe {
            name: probe_name,
            health,
        }),
    ));
    Ok(())
}

fn wire_sweeper_worker<S>(
    maintenance: CoordinatedRetentionSweeper<S>,
    config: SweeperConfig,
    worker_name: &'static str,
    probe_name: &'static str,
    target: RetentionTarget,
    admission: primitives::WriteAdmission,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()>
where
    S: RetentionSweeper + Send + Sync + 'static,
{
    let health = Arc::new(WorkerHealth::healthy());
    let worker_health = Arc::clone(&health);
    let worker = WorkerSpec::writes_phase_one(
        "assemblies.runtime.src.event_transport.07",
        &admission,
        move |token, worker_admission| {
            DynManagedResource::new_box(spawn_on_dedicated_runtime(
                worker_name,
                token,
                Arc::clone(&worker_health),
                EVENT_WORKER_SHUTDOWN_BUDGET,
                move |thread_token| async move {
                    sweeper_loop(
                        Arc::new(maintenance),
                        config,
                        Arc::new(SystemClock),
                        thread_token,
                        Arc::clone(&worker_health),
                        target,
                        worker_admission,
                    )
                    .await;
                    Ok(())
                },
            ))
        },
    );
    module.push_worker(worker);

    let probe_name = ProbeName::parse(probe_name).context("parse sweeper probe name")?;
    module.push_probe((
        probe_name.clone(),
        Box::new(WorkerHealthProbe {
            name: probe_name,
            health,
        }),
    ));
    Ok(())
}

/// Consumer resource bundle 接线（PG inbox + DLX + subscriber + worker + probe + inbox sweeper）。
struct ConsumerWiring<'a> {
    pg: &'a PgRuntimeHandle,
    amqp_map: &'a BTreeMap<String, amqp::AmqpRuntimeDeps>,
    security: &'a EventSecurity,
    timing: &'a RelayTiming,
    audit_key: Option<&'a MacKey>,
    admission: primitives::ConsumerAdmission,
    write_admission: primitives::WriteAdmission,
}

async fn wire_consumer_resource_bundle(
    subscribers: Vec<BridgedSubscription>,
    wiring: ConsumerWiring<'_>,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let ConsumerWiring {
        pg,
        amqp_map,
        security,
        timing,
        audit_key,
        admission,
        write_admission,
    } = wiring;
    let binding_count = subscribers.len();
    for subscription in subscribers {
        let owner = subscription.topic_owner();
        let amqp_conn = amqp_map
            .get(&owner)
            .with_context(|| format!("no amqp connection for topic owner '{owner}'"))?;
        let subscriber = amqp_conn.infra().subscriber();
        let consumer = subscription.consumer();
        let contract_id = subscription.contract_id();
        let topic_name = subscription.topic();
        let topic = Topic::new(topic_name);
        amqp_conn
            .infra()
            .subscriber()
            .prepare_ackable(topic.clone())
            .await
            .with_context(|| format!("prepare durable consumer topology for '{topic_name}'"))?;
        let meta =
            consumer_meta_for_subscription(&subscription, Arc::clone(&security.tenant_authority));
        let inbox = pg.infra().inbox();
        let lease_cfg = LeaseConfig::from_ttl(inbox.lease_ttl());
        let idempotency = Arc::new(inbox);
        let consumer_health = Arc::new(WorkerHealth::starting());
        let consumer_probe =
            make_consumer_probe(binding_count, &subscription, Arc::clone(&consumer_health))?;
        let dlx = DynDeadLetterStore::new_box(
            pg.infra()
                .dead_letter(security.dlx_payload_protector.clone()),
        );
        let worker_name = format!("event-consumer:{consumer}:{topic_name}");
        let worker = consumer_tx_worker_for_subscription(
            pg,
            &subscription,
            audit_key,
            WorkerInputs::new(
                worker_name,
                subscriber,
                topic,
                idempotency,
                dlx,
                meta,
                lease_cfg,
                Arc::clone(&consumer_health),
                admission.clone(),
            ),
        )?;
        tracing::info!(
            consumer,
            contract_id,
            topic = topic_name,
            external_effect_policy = ?subscription.dispatch_token().policy(),
            "durable event transport: pg consumer-tx worker registered"
        );
        match subscription.readiness() {
            SubscriberReadiness::Required => {
                // Required 是 generated topology 的强制服务语义：worker 与 readyz probe 必须成对注册。
                // 穷尽 match 让未来新增 readiness variant 在组合根编译失败，而不是静默降级。
                module.push_worker(worker);
                module.push_probe(consumer_probe);
            }
        }
    }
    wire_inbox_sweeper(pg, timing, write_admission, module)?;
    Ok(())
}

#[cfg(test)]
fn test_capability_for_spec(spec: SubscriptionSpec) -> anyhow::Result<SubscriberCapability> {
    let capability = match spec.dispatch() {
        SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit
        | SubscriptionDispatchKey::IdentityRoleAssignedV1Audit
        | SubscriptionDispatchKey::IdentityRoleRevokedV1Audit
        | SubscriptionDispatchKey::IdentitySecurityEventV1Audit
        | SubscriptionDispatchKey::IdentitySessionCreatedV1Audit => {
            SubscriberCapability::AdapterNativeTransactional
        }
        SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings => {
            SubscriberCapability::DomainReconcile(ReconcileSubscriberOwner::from_owner(
                settings::ConfigVersionReconciler::test_ack(),
            ))
        }
    };
    Ok(capability)
}

#[cfg(test)]
fn consumer_tx_plan_for_spec(
    spec: SubscriptionSpec,
) -> anyhow::Result<eventing_composition::GeneratedDispatchToken> {
    let capability = test_capability_for_spec(spec)?;
    eventing_composition::GeneratedDispatchToken::resolve(spec, capability)
}

fn consumer_tx_worker_for_subscription(
    pg: &PgRuntimeHandle,
    subscription: &BridgedSubscription,
    audit_key: Option<&MacKey>,
    inputs: WorkerInputs,
) -> anyhow::Result<WorkerSpec> {
    let token = subscription.dispatch_token().clone();
    match token.dispatch() {
        SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit
        | SubscriptionDispatchKey::IdentityRoleAssignedV1Audit
        | SubscriptionDispatchKey::IdentityRoleRevokedV1Audit
        | SubscriptionDispatchKey::IdentitySecurityEventV1Audit
        | SubscriptionDispatchKey::IdentitySessionCreatedV1Audit => AuditConsumerFactory::new(
            pg,
            audit_key.context("local audit subscription requires audit consumer key")?,
        )
        .worker(token, inputs),
        SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings => {
            SettingsConsumerFactory::new(pg).worker(token, inputs)
        }
    }
}

fn wire_inbox_sweeper(
    pg: &PgRuntimeHandle,
    timing: &RelayTiming,
    admission: primitives::WriteAdmission,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let sweeper = pg.infra().inbox_sweeper();
    let config = SweeperConfig::new(
        sweeper.retention_seconds(),
        timing.outbox_sweeper.sweep_interval(),
    )
    .context("build inbox sweeper config")?;
    let health = Arc::new(WorkerHealth::healthy());
    let worker_health = Arc::clone(&health);
    let worker = WorkerSpec::writes_phase_one(
        "assemblies.runtime.src.event_transport.08",
        &admission,
        move |token, worker_admission| {
            let loop_health = Arc::clone(&worker_health);
            let make = move |loop_token| async move {
                let _stopped = loop_health.stopped_on_exit();
                sweeper_loop(
                    Arc::new(sweeper),
                    config,
                    Arc::new(SystemClock),
                    loop_token,
                    Arc::clone(&loop_health),
                    RetentionTarget::InboxReceipts,
                    worker_admission,
                )
                .await;
            };
            DynManagedResource::new_box(SweeperWorker::spawn(
                INBOX_SWEEPER_WORKER_NAME,
                make,
                worker_health,
                token,
                EVENT_WORKER_SHUTDOWN_BUDGET,
            ))
        },
    );
    module.push_worker(worker);

    let probe_name =
        ProbeName::parse(INBOX_SWEEPER_PROBE).context("parse inbox sweeper probe name")?;
    module.push_probe((
        probe_name.clone(),
        Box::new(WorkerHealthProbe {
            name: probe_name,
            health,
        }),
    ));
    Ok(())
}

/// consumer readyz 探针：单 binding 用 `EVENT_CONSUMER_PROBE`，多 binding 用完整 subscription identity 区分。
fn make_consumer_probe(
    binding_count: usize,
    subscription: &BridgedSubscription,
    health: Arc<WorkerHealth>,
) -> anyhow::Result<(ProbeName, Box<dyn bootstrap::HealthProbe>)> {
    let probe_name_str = if binding_count == 1 {
        EVENT_CONSUMER_PROBE.to_string()
    } else {
        format!("{}:{}", EVENT_CONSUMER_PROBE, subscription.identity_slug())
    };
    let probe_name = ProbeName::parse(&probe_name_str).context("parse consumer probe name")?;
    let probe: Box<dyn bootstrap::HealthProbe> = Box::new(WorkerHealthProbe {
        name: probe_name.clone(),
        health,
    });
    Ok((probe_name, probe))
}

// ── parse helpers ─────────────────────────────────────────────────────────────

/// `RSS_TOPOLOGY` 字符串（已 trim）→ [`bootstrap::Topology`]。
pub(crate) fn parse_topology(s: &str) -> anyhow::Result<bootstrap::Topology> {
    match s.to_ascii_lowercase().as_str() {
        "demo" => Ok(bootstrap::Topology::Demo),
        "durable-shared" => Ok(bootstrap::Topology::DurableShared),
        "durable-isolated" => Ok(bootstrap::Topology::DurableIsolated),
        other => anyhow::bail!(
            "unknown RSS_TOPOLOGY '{other}'; expected demo | durable-shared | durable-isolated"
        ),
    }
}

/// 可选 `u64` 毫秒 env var → [`Duration`]（解析失败或缺失时 warn + 回退 default）。
fn parse_duration_ms_env(raw: Option<String>, env_name: &'static str, default_ms: u64) -> Duration {
    let Some(s) = raw else {
        return Duration::from_millis(default_ms);
    };
    match s.trim().parse::<u64>() {
        Ok(ms) => Duration::from_millis(ms),
        Err(_) => {
            // reason: relay 时序参数是调优配置而非正确性依赖——解析失败 warn+默认值比 fail-fast 更易运维；
            // 日志仅携带 env_name 不携带原始凭据路径（无 PII 风险：毫秒数值非机密）。
            tracing::warn!(
                env = env_name,
                raw = %s,
                default_ms,
                "invalid duration (expected u64 ms); falling back to default"
            );
            Duration::from_millis(default_ms)
        }
    }
}

/// 正确性预算 env：缺失使用 canonical 默认；一旦存在，任何解析/范围/关系错误均由 builder fail-fast。
fn parse_strict_duration_ms_env(
    raw: Option<String>,
    env_name: &'static str,
    default_ms: u64,
) -> anyhow::Result<Duration> {
    let Some(raw) = raw else {
        return Ok(Duration::from_millis(default_ms));
    };
    let millis = raw
        .trim()
        .parse::<u64>()
        .with_context(|| format!("{env_name} must be an unsigned integer millisecond value"))?;
    Ok(Duration::from_millis(millis))
}

/// 可选 `usize` env var → `usize`（解析失败或缺失时 warn + 回退 default）。
fn parse_usize_env(raw: Option<String>, env_name: &'static str, default: usize) -> usize {
    let Some(s) = raw else {
        return default;
    };
    match s.trim().parse::<usize>() {
        Ok(v) => v,
        Err(_) => {
            // reason: relay 批量参数是调优配置——解析失败 warn+默认值比 fail-fast 更易运维；
            // 日志仅携带 env_name 不携带值（批量大小非机密，但统一不记 raw 保持 PII-safe 习惯）。
            tracing::warn!(
                env = env_name,
                raw = %s,
                default,
                "invalid usize; falling back to default"
            );
            default
        }
    }
}

/// 可选 `u64` env var → `u64`（解析失败或缺失时 warn + 回退 default）。
fn parse_u64_env(raw: Option<String>, env_name: &'static str, default: u64) -> u64 {
    let Some(s) = raw else {
        return default;
    };
    match s.trim().parse::<u64>() {
        Ok(v) => v,
        Err(_) => {
            tracing::warn!(
                env = env_name,
                raw = %s,
                default,
                "invalid u64; falling back to default"
            );
            default
        }
    }
}

fn parse_required_u64_env(
    raw: Option<String>,
    env_name: &'static str,
    default: u64,
) -> anyhow::Result<u64> {
    let Some(s) = raw else {
        return Ok(default);
    };
    s.trim()
        .parse::<u64>()
        .with_context(|| format!("{env_name} must be an integer seconds value"))
}

fn system_epoch_secs() -> i64 {
    rss_contract::Timepoint::saturating_from_system_time(SystemClock.now()).unix_seconds()
}

fn build_tenant_authority_from(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Arc<TenantAuthority>> {
    let key_raw = get(TENANT_AUTHORITY_HMAC_KEY_ENV).ok_or_else(|| {
        anyhow::anyhow!("missing required env var: {TENANT_AUTHORITY_HMAC_KEY_ENV}")
    })?;
    let key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key_raw.trim())
        .with_context(|| format!("{TENANT_AUTHORITY_HMAC_KEY_ENV} must be base64url no-pad"))?;
    let ttl_secs = parse_required_u64_env(
        get(TENANT_AUTHORITY_TTL_ENV),
        TENANT_AUTHORITY_TTL_ENV,
        DEFAULT_TENANT_AUTHORITY_TTL_SECS,
    )?;
    let clock_skew_secs = parse_required_u64_env(
        get(TENANT_AUTHORITY_CLOCK_SKEW_ENV),
        TENANT_AUTHORITY_CLOCK_SKEW_ENV,
        DEFAULT_TENANT_AUTHORITY_CLOCK_SKEW_SECS,
    )?;
    Ok(Arc::new(
        TenantAuthority::new(
            Arc::new(RustCryptoMacVerifier),
            MacKey::from_bytes(key_bytes),
            ttl_secs,
            clock_skew_secs,
            Arc::new(system_epoch_secs),
        )
        .map_err(|e| anyhow::anyhow!("tenant authority config error: {e}"))?,
    ))
}

pub(crate) fn build_dlx_payload_protector(
    config: SnapshotConfig<'_>,
) -> anyhow::Result<DlxPayloadProtector> {
    build_dlx_payload_protector_from(&|name| config.value(name).map(str::to_owned))
}

/// Build the Projection replay capsule protector without acquiring the unrelated archive lane.
pub(crate) fn build_projection_replay_dlx_payload_protector(
    config: SnapshotConfig<'_>,
) -> anyhow::Result<DlxPayloadProtector> {
    build_projection_replay_dlx_payload_protector_from(&|name| {
        config.value(name).map(str::to_owned)
    })
}

fn build_dlx_payload_protector_from(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<DlxPayloadProtector> {
    let key_name = get(DLX_PAYLOAD_KEY_NAME_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {DLX_PAYLOAD_KEY_NAME_ENV}"))?;
    let key_name = DlxHotKeyName::try_new(key_name.trim().to_string())
        .map_err(|e| anyhow::anyhow!("{DLX_PAYLOAD_KEY_NAME_ENV} is invalid: {e}"))?;
    let provider = build_dlx_vault_key_providers_from(get)?.0;
    Ok(DlxPayloadProtector::new(
        DynKeyProvider::new_box(provider),
        key_name,
    ))
}

fn build_projection_replay_dlx_payload_protector_from(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<DlxPayloadProtector> {
    let key_name = get(DLX_PAYLOAD_KEY_NAME_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {DLX_PAYLOAD_KEY_NAME_ENV}"))?;
    let key_name = DlxHotKeyName::try_new(key_name.trim().to_string())
        .map_err(|e| anyhow::anyhow!("{DLX_PAYLOAD_KEY_NAME_ENV} is invalid: {e}"))?;
    let provider = build_projection_replay_vault_key_provider_from(get)?;
    Ok(DlxPayloadProtector::new(
        DynKeyProvider::new_box(provider),
        key_name,
    ))
}

fn build_projection_replay_vault_key_provider_from(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<VaultKeyProvider> {
    let addr = get(VAULT_ADDR_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_ADDR_ENV}"))?;
    let hot_token = EnvSecret::required(get, DLX_HOT_VAULT_TOKEN_ENV)?;
    let mount = get(VAULT_TRANSIT_MOUNT_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_TRANSIT_MOUNT_ENV}"))?;
    VaultKeyProvider::new(
        build_vault_tls_client_from(get)?,
        addr,
        hot_token.transfer_secret_allocation(),
        mount,
        DEFAULT_VAULT_TIMEOUT,
    )
    .map_err(|e| anyhow::anyhow!("DLX hot Vault key provider config error: {e}"))
}

#[cfg(test)]
pub(crate) fn build_dlx_archive_vault_key_provider_from(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<VaultKeyProvider> {
    build_dlx_vault_key_providers_from(get).map(|(_hot, archive)| archive)
}

pub(crate) fn build_dlx_vault_key_providers_from(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<(VaultKeyProvider, VaultKeyProvider)> {
    let addr = get(VAULT_ADDR_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_ADDR_ENV}"))?;
    let hot_token = EnvSecret::required(get, DLX_HOT_VAULT_TOKEN_ENV)?;
    let archive_token = EnvSecret::required(get, DLX_ARCHIVE_VAULT_TOKEN_ENV)?;
    anyhow::ensure!(
        hot_token.differs_from(&archive_token),
        "{DLX_HOT_VAULT_TOKEN_ENV} must differ from {DLX_ARCHIVE_VAULT_TOKEN_ENV}"
    );
    if let Some(general_token) = EnvSecret::optional(get, "RSS_VAULT_TOKEN")? {
        anyhow::ensure!(
            hot_token.differs_from(&general_token),
            "{DLX_HOT_VAULT_TOKEN_ENV} must differ from RSS_VAULT_TOKEN"
        );
        anyhow::ensure!(
            archive_token.differs_from(&general_token),
            "{DLX_ARCHIVE_VAULT_TOKEN_ENV} must differ from RSS_VAULT_TOKEN"
        );
    }
    let mount = get(VAULT_TRANSIT_MOUNT_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_TRANSIT_MOUNT_ENV}"))?;
    let hot = VaultKeyProvider::new(
        build_vault_tls_client_from(get)?,
        addr.clone(),
        hot_token.transfer_secret_allocation(),
        mount.clone(),
        DEFAULT_VAULT_TIMEOUT,
    )
    .map_err(|e| anyhow::anyhow!("DLX hot Vault key provider config error: {e}"))?;
    let archive = VaultKeyProvider::new(
        build_vault_tls_client_from(get)?,
        addr,
        archive_token.transfer_secret_allocation(),
        mount,
        DEFAULT_VAULT_TIMEOUT,
    )
    .map_err(|e| anyhow::anyhow!("DLX archive Vault key provider config error: {e}"))?;
    Ok((hot, archive))
}

/// Parses the independent cold-archive key and rejects reuse of the hot replay-capsule key.
pub(crate) fn build_dlx_archive_key_name_from(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<DlxArchiveKeyName> {
    let archive = get(DLX_ARCHIVE_KEY_NAME_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {DLX_ARCHIVE_KEY_NAME_ENV}"))?;
    let hot = get(DLX_PAYLOAD_KEY_NAME_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {DLX_PAYLOAD_KEY_NAME_ENV}"))?;
    anyhow::ensure!(
        archive.trim() != hot.trim(),
        "{DLX_ARCHIVE_KEY_NAME_ENV} must differ from {DLX_PAYLOAD_KEY_NAME_ENV}"
    );
    DlxArchiveKeyName::try_new(archive.trim().to_owned())
        .map_err(|error| anyhow::anyhow!("{DLX_ARCHIVE_KEY_NAME_ENV} is invalid: {error}"))
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bootstrap::SubscriberBinding;
    use diport::{DlxLifecycleOperation, DlxLifecycleReason};

    fn open_write_admission() -> primitives::WriteAdmission {
        let (control, _, _, writes) = primitives::prepare_dr_admission_controls().into_parts();
        control
            .start_running()
            .unwrap_or_else(|_| unreachable!("fresh test admission must start"));
        writes
    }

    struct WideSettingsWrapper {
        _service: Option<Arc<settings::SettingsService>>,
    }

    fn reconcile_capability() -> SubscriberCapability {
        SubscriberCapability::DomainReconcile(ReconcileSubscriberOwner::from_owner(
            settings::ConfigVersionReconciler::test_ack(),
        ))
    }

    #[test]
    fn settings_plan_rejects_wide_owner_wrapper() -> anyhow::Result<()> {
        let spec = generated::event::EVENTS
            .iter()
            .flat_map(|event| event.subscriptions())
            .find(|spec| {
                spec.dispatch() == SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings
            })
            .copied()
            .context("settings config-version subscription must exist")?;
        let capability = SubscriberCapability::DomainReconcile(
            ReconcileSubscriberOwner::from_owner(WideSettingsWrapper { _service: None }),
        );

        let Err(error) = eventing_composition::GeneratedDispatchToken::resolve(spec, capability)
        else {
            anyhow::bail!("wide settings wrapper must fail exact owner activation");
        };

        assert!(
            error.to_string().contains("owner capability mismatch"),
            "{error:#}"
        );
        Ok(())
    }

    #[allow(clippy::unwrap_used)]
    // reason: 测试构造合法 consumer group；parse 失败即测试写错。
    fn test_binding(
        contract_id: &'static str,
        topic: &'static str,
        consumer: &'static str,
        group: &'static str,
    ) -> SubscriberBinding {
        let spec = generated::event::EVENTS
            .iter()
            .find(|event| event.contract_id() == contract_id && event.topic() == topic)
            .and_then(|event| {
                event
                    .subscriptions()
                    .iter()
                    .find(|spec| spec.consumer() == consumer)
            })
            .copied()
            .unwrap();
        let capability = test_capability_for_spec(spec).unwrap();
        test_binding_with_capability(contract_id, topic, consumer, group, capability)
    }

    #[allow(clippy::unwrap_used)]
    fn test_binding_with_capability(
        contract_id: &'static str,
        topic: &'static str,
        consumer: &'static str,
        group: &'static str,
        capability: SubscriberCapability,
    ) -> SubscriberBinding {
        SubscriberBinding::from_test_parts(
            contract_id,
            topic,
            consumer,
            consistency::ConsumerGroup::parse(group).unwrap(),
            capability,
        )
    }

    #[test]
    fn placement_selected_live_bridge_closes_all_remote_subsets() -> anyhow::Result<()> {
        use assembly_schema::AssemblyDomain;
        use std::collections::BTreeMap;

        let domains = crate::modules_gen::ASSEMBLY_DOMAINS;
        for remote_mask in 0_u8..(1_u8 << domains.len()) {
            let mut values = BTreeMap::from([
                ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
                ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
                ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
                ("RSS_TOPOLOGY", "durable-shared"),
                ("RSS_DOMAIN_TRANSPORT_URL", "https://gateway.internal/rpc"),
            ]);
            for (index, domain) in domains.iter().enumerate() {
                if remote_mask & (1 << index) == 0 {
                    continue;
                }
                let key = match domain {
                    AssemblyDomain::Settings => "RSS_SETTINGS_DOMAIN_PLACEMENT_WORKLOAD",
                    AssemblyDomain::Identity => "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD",
                    AssemblyDomain::Audit => "RSS_AUDIT_DOMAIN_PLACEMENT_WORKLOAD",
                    other => anyhow::bail!("unexpected bundled domain {other:?}"),
                };
                values.insert(key, "peer-cell");
            }
            let values = values.into_iter().collect::<Vec<_>>();
            let snapshot = crate::config::test_snapshot(&values)?;
            let execution = crate::plan::RuntimePlan::bundled(snapshot.view())?
                .place(bootstrap::Topology::DurableShared, snapshot.view())?
                .into_parts()
                .events;
            let bindings = execution
                .local_subscriptions()
                .iter()
                .map(|dispatch| {
                    let (event, spec) = generated::event::EVENTS
                        .iter()
                        .find_map(|event| {
                            event
                                .subscriptions()
                                .iter()
                                .find(|spec| spec.dispatch() == *dispatch)
                                .map(|spec| (*event, *spec))
                        })
                        .context("selected dispatch must have one generated subscription")?;
                    Ok(test_binding_with_capability(
                        event.contract_id(),
                        event.topic(),
                        spec.consumer(),
                        spec.group(),
                        test_capability_for_spec(spec)?,
                    ))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let selected = execution.local_subscriptions().len();
            let bridged = bridge_generated_subscriptions_for_execution(bindings, &execution)?;
            anyhow::ensure!(
                bridged.subscriptions().len() == selected,
                "mask={remote_mask} live bridge count drift"
            );
        }
        Ok(())
    }

    #[allow(clippy::unwrap_used)]
    // reason: generated registry 与 binding 精确匹配；失败即测试写错。
    fn test_subscription(
        contract_id: &'static str,
        topic: &'static str,
        consumer: &'static str,
        group: &'static str,
    ) -> BridgedSubscription {
        let event = generated::event::EVENTS
            .iter()
            .copied()
            .find(|event| event.contract_id() == contract_id && event.topic() == topic)
            .unwrap();
        let (mut subscriptions, _selection) = bridge_subscriptions_with_events(
            vec![test_binding(contract_id, topic, consumer, group)],
            &[event],
        )
        .unwrap()
        .into_runtime_parts();
        subscriptions.pop().unwrap()
    }

    #[test]
    fn event_worker_config_reads_one_snapshot_generation() {
        let snapshot = crate::config::test_snapshot(&[
            ("RSS_RELAY_POLL_INTERVAL_MS", "201"),
            ("RSS_RELAY_MAX_IN_FLIGHT", "17"),
            ("RSS_RELAY_SAMPLE_INTERVAL_MS", "30001"),
            ("RSS_INBOX_SAMPLE_INTERVAL_MS", "30002"),
            ("RSS_OUTBOX_SWEEP_INTERVAL_MS", "300001"),
            ("RSS_OUTBOX_RETAIN_SECONDS", "604801"),
        ])
        .unwrap_or_else(|_| unreachable!());

        let mapper = crate::config::ServingConfigMapper::for_test(snapshot.view());
        let worker = EventWorkerConfig::from_mapper(&mapper).unwrap_or_else(|_| unreachable!());

        assert_eq!(worker.relay_poll_interval(), Duration::from_millis(201));
        assert_eq!(worker.relay_max_in_flight(), 17);
        assert_eq!(
            worker.relay_sample_interval(),
            Duration::from_millis(30_001)
        );
        assert_eq!(
            worker.inbox_sample_interval(),
            Duration::from_millis(30_002)
        );
        assert_eq!(
            worker.outbox_sweep_interval(),
            Duration::from_millis(300_001)
        );
        assert_eq!(worker.outbox_retain_seconds(), 604_801);
    }

    #[test]
    fn event_transport_config_is_minted_from_snapshot_capability() {
        let ca_path = {
            let path = std::env::temp_dir().join(format!(
                "rss-event-transport-test-ca-{}.pem",
                std::process::id()
            ));
            std::fs::write(&path, TEST_AMQP_CA_PEM).unwrap_or_else(|_| unreachable!());
            path
        };
        let ca_path = ca_path.to_str().unwrap_or_else(|| unreachable!());
        let snapshot = crate::config::test_snapshot(&[
            ("RSS_TOPOLOGY", "durable-shared"),
            ("RSS_AMQP_URL", "amqps://su:sp@host/shared"),
            (AMQP_CA_CERT_PEM_PATH_ENV, ca_path),
            (
                TENANT_AUTHORITY_HMAC_KEY_ENV,
                "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI",
            ),
            (DLX_PAYLOAD_KEY_NAME_ENV, "dlx-payload"),
            (VAULT_ADDR_ENV, "https://vault.example:8200"),
            (DLX_HOT_VAULT_TOKEN_ENV, "s.dlx-hot-testtoken"),
            (DLX_ARCHIVE_VAULT_TOKEN_ENV, "s.dlx-archive-testtoken"),
            (VAULT_TRANSIT_MOUNT_ENV, "transit"),
        ])
        .unwrap_or_else(|_| unreachable!());

        let mapper = crate::config::ServingConfigMapper::for_test(snapshot.view());
        let config = EventTransportConfig::from_mapper(&mapper).unwrap_or_else(|_| unreachable!());

        assert!(matches!(config.decision, EventDecision::Durable { .. }));
    }

    #[test]
    fn event_transport_typed_topology_rejects_missing_and_blank_snapshot_values() {
        for (entries, expected) in [
            (Vec::new(), "missing required env var: RSS_TOPOLOGY"),
            (
                vec![("RSS_TOPOLOGY", "   ")],
                "unknown RSS_TOPOLOGY ''; expected demo | durable-shared | durable-isolated",
            ),
        ] {
            let snapshot = crate::config::test_snapshot(&entries)
                .unwrap_or_else(|_| unreachable!("topology snapshot fixture"));
            let mapper = crate::config::ServingConfigMapper::for_test(snapshot.view());
            let error = EventTransportConfig::from_mapper(&mapper)
                .err()
                .unwrap_or_else(|| unreachable!("invalid topology must fail"));

            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn event_transport_durable_snapshot_missing_ca_fails_fast() {
        let snapshot = crate::config::test_snapshot(&[
            ("RSS_TOPOLOGY", "durable-shared"),
            ("RSS_AMQP_URL", "amqps://su:sp@host/shared"),
            (
                TENANT_AUTHORITY_HMAC_KEY_ENV,
                "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI",
            ),
            (DLX_PAYLOAD_KEY_NAME_ENV, "dlx-payload"),
            (VAULT_ADDR_ENV, "https://vault.example:8200"),
            (DLX_HOT_VAULT_TOKEN_ENV, "s.dlx-hot-testtoken"),
            (DLX_ARCHIVE_VAULT_TOKEN_ENV, "s.dlx-archive-testtoken"),
            (VAULT_TRANSIT_MOUNT_ENV, "transit"),
        ])
        .unwrap_or_else(|_| unreachable!());

        let mapper = crate::config::ServingConfigMapper::for_test(snapshot.view());
        let err = EventTransportConfig::from_mapper(&mapper)
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        assert!(
            err.contains(AMQP_CA_CERT_PEM_PATH_ENV),
            "durable topology without AMQP CA must fail-fast: {err}"
        );
    }

    // ── required_domains ──────────────────────────────────────────────────────

    #[test]
    fn required_domains_includes_publishing_domains_without_subscribers() {
        // 无 subscriber → 仍含 generated producer domain（relay 需 per-domain vhost）。
        let expected = generated::event::PRODUCER_DOMAINS
            .iter()
            .map(|domain| domain.as_str().to_string())
            .collect::<Vec<_>>();
        assert_eq!(required_domains(&[]), expected);
    }

    #[allow(clippy::unwrap_used)]
    // reason: generated 测试 fixture 必须存在；缺失即 codegen 漂移。
    #[test]
    fn required_domains_deduplicates_and_sorts() {
        let bindings = vec![test_subscription(
            generated::event::identity_v1::session_created::SPEC.contract_id(),
            generated::event::identity_v1::session_created::SPEC.topic(),
            "audit",
            "audit.session-created",
        )];
        let domains = required_domains(&bindings);
        let mut expected = generated::event::PRODUCER_DOMAINS
            .iter()
            .map(|domain| domain.as_str().to_string())
            .collect::<Vec<_>>();
        expected.push("identity".to_string());
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(domains, expected);
    }

    #[allow(clippy::unwrap_used)]
    // reason: 测试 helper 构造合法 consumer group；parse 失败即测试写错。
    #[test]
    fn consumer_meta_uses_subscription_consumer_not_topic_owner() {
        let subscription = test_subscription(
            generated::event::identity_v1::session_created::SPEC.contract_id(),
            generated::event::identity_v1::session_created::SPEC.topic(),
            "audit",
            "audit.session-created",
        );

        assert_eq!(subscription.topic_owner(), "identity");
        assert_eq!(
            consumer_meta_parts_for_subscription(&subscription),
            (
                "audit",
                "identity.session-created",
                "identity.session-created"
            )
        );
    }

    #[test]
    fn generated_subscriptions_all_resolve_to_consumer_tx_plans() {
        let missing: Vec<String> = generated::event::EVENTS
            .iter()
            .flat_map(|event| {
                event
                    .subscriptions()
                    .iter()
                    .map(move |spec| (*event, *spec))
            })
            .filter(|(_, spec)| consumer_tx_plan_for_spec(*spec).is_err())
            .map(|(event, spec)| {
                format!(
                    "{}:{}:{}:{}",
                    event.contract_id(),
                    event.topic(),
                    spec.consumer(),
                    spec.group()
                )
            })
            .collect();

        assert!(
            missing.is_empty(),
            "generated subscriptions missing ConsumerTx mapping: {missing:?}"
        );
    }

    #[test]
    fn consumer_tx_plan_preserves_generated_policy_through_capability_resolution() {
        let audit = generated::event::identity_v1::session_created::SPEC.subscriptions()[0];
        let audit_plan = eventing_composition::GeneratedDispatchToken::resolve(
            audit,
            SubscriberCapability::AdapterNativeTransactional,
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            audit_plan.policy(),
            vocab::ExternalEffectPolicy::TransactionalOnly
        );
        assert_eq!(
            audit_plan.dispatch(),
            SubscriptionDispatchKey::IdentitySessionCreatedV1Audit
        );

        let settings = generated::event::settings_v1::SPEC.subscriptions()[0];
        let settings_plan =
            eventing_composition::GeneratedDispatchToken::resolve(settings, reconcile_capability())
                .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            settings_plan.policy(),
            vocab::ExternalEffectPolicy::Reconcile
        );
        assert_eq!(
            settings_plan.dispatch(),
            SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings
        );
    }

    #[test]
    fn consumer_tx_plan_rejects_generated_execution_capability_mismatch() {
        let audit = generated::event::identity_v1::session_created::SPEC.subscriptions()[0];
        assert!(
            eventing_composition::GeneratedDispatchToken::resolve(audit, reconcile_capability())
                .is_err(),
            "adapter-native generated execution must reject a reconcile capability"
        );

        let settings = generated::event::settings_v1::SPEC.subscriptions()[0];
        assert!(
            eventing_composition::GeneratedDispatchToken::resolve(
                settings,
                SubscriberCapability::AdapterNativeTransactional,
            )
            .is_err(),
            "domain-reconcile generated execution must reject a transactional capability"
        );
    }

    #[test]
    fn all_active_generated_handlers_select_their_policy_bound_plan() -> anyhow::Result<()> {
        let mut transactional = 0;
        let mut reconcile = 0;

        for spec in generated::event::EVENTS
            .iter()
            .flat_map(|event| event.subscriptions())
        {
            let capability = match spec.external_effect_policy() {
                vocab::ExternalEffectPolicy::TransactionalOnly => {
                    SubscriberCapability::AdapterNativeTransactional
                }
                vocab::ExternalEffectPolicy::Reconcile => reconcile_capability(),
                vocab::ExternalEffectPolicy::IdempotencyKey
                | vocab::ExternalEffectPolicy::Compensated => {
                    anyhow::bail!("inactive policy unexpectedly appears in generated topology");
                }
            };
            let plan = eventing_composition::GeneratedDispatchToken::resolve(*spec, capability)
                .context("active generated handler must resolve")?;
            match plan.policy() {
                vocab::ExternalEffectPolicy::TransactionalOnly => transactional += 1,
                vocab::ExternalEffectPolicy::Reconcile => reconcile += 1,
                vocab::ExternalEffectPolicy::IdempotencyKey
                | vocab::ExternalEffectPolicy::Compensated => {
                    anyhow::bail!("unsupported policy unexpectedly selected an active handler");
                }
            }
        }

        assert_eq!(transactional, 5);
        assert_eq!(reconcile, 1);
        Ok(())
    }

    #[allow(clippy::unwrap_used)]
    // reason: 测试构造合法 consumer group；parse 失败即测试写错。
    #[test]
    fn bridge_generated_subscriptions_rejects_missing_spec() {
        let binding = test_binding(
            "identity.session-created",
            "identity.session-created",
            "audit",
            "audit.session-created",
        );
        let result = bridge_subscriptions_with_events(vec![binding], &[]);
        assert!(
            result.is_err(),
            "expected missing generated topology spec error"
        );
        let err = result.err().unwrap();
        assert!(err.to_string().contains("no generated topology spec"));
    }

    #[allow(clippy::unwrap_used)]
    // reason: 测试构造合法 consumer group；parse 失败即测试写错。
    #[test]
    fn bridge_generated_subscriptions_rejects_group_mismatch() {
        let event = generated::event::identity_v1::session_created::SPEC;
        let binding = test_binding(event.contract_id(), event.topic(), "audit", "audit.other");
        let result = bridge_subscriptions_with_events(vec![binding], &[event]);
        assert!(result.is_err(), "expected group mismatch error");
        let err = result.err().unwrap();
        assert!(err.to_string().contains("subscriber group drift"));
    }

    #[allow(clippy::unwrap_used)]
    // reason: preceding assertion proves the fail-closed result is Err.
    #[test]
    fn bridge_generated_subscriptions_rejects_settings_without_reconcile_capability() {
        let event = generated::event::settings_v1::SPEC;
        let spec = event.subscriptions()[0];
        let binding = test_binding_with_capability(
            event.contract_id(),
            event.topic(),
            spec.consumer(),
            spec.group(),
            SubscriberCapability::AdapterNativeTransactional,
        );

        let result = bridge_subscriptions_with_events(vec![binding], &[event]);
        assert!(result.is_err(), "binding must fail closed");
        let error = result.err().unwrap();

        assert!(error.to_string().contains(
            "config-version refresh subscription dispatch or runtime capability mismatch"
        ));
    }

    #[allow(clippy::unwrap_used)]
    // reason: preceding assertion proves the fail-closed result is Err.
    #[test]
    fn bridge_generated_subscriptions_rejects_audit_reconcile_capability() {
        let event = generated::event::identity_v1::session_created::SPEC;
        let spec = event.subscriptions()[0];
        let binding = test_binding_with_capability(
            event.contract_id(),
            event.topic(),
            spec.consumer(),
            spec.group(),
            reconcile_capability(),
        );

        let result = bridge_subscriptions_with_events(vec![binding], &[event]);
        assert!(result.is_err(), "binding must fail closed");
        let error = result.err().unwrap();

        assert!(
            error
                .to_string()
                .contains("adapter-native subscription dispatch or runtime capability mismatch")
        );
    }

    #[allow(clippy::unwrap_used)]
    // reason: 测试构造合法 consumer group；parse 失败即测试写错。
    #[test]
    fn bridge_generated_subscriptions_rejects_duplicate_specs() {
        let event = generated::event::identity_v1::session_created::SPEC;
        let binding = test_binding(
            event.contract_id(),
            event.topic(),
            "audit",
            "audit.session-created",
        );
        let result = bridge_subscriptions_with_events(vec![binding], &[event, event]);
        assert!(
            result.is_err(),
            "expected duplicate generated topology spec error"
        );
        let err = result.err().unwrap();
        assert!(
            err.to_string()
                .contains("duplicate generated topology specs")
        );
    }

    #[allow(clippy::unwrap_used)]
    // reason: 测试构造合法 consumer group；parse 失败即测试写错。
    #[test]
    fn bridge_generated_subscriptions_rejects_duplicate_runtime_bindings() {
        let event = generated::event::identity_v1::session_created::SPEC;
        let binding = || {
            test_binding(
                event.contract_id(),
                event.topic(),
                "audit",
                "audit.session-created",
            )
        };
        let result = bridge_subscriptions_with_events(vec![binding(), binding()], &[event]);
        assert!(
            result.is_err(),
            "expected duplicate runtime subscriber binding error"
        );
        let err = result.err().unwrap();
        assert!(
            err.to_string()
                .contains("duplicates generated topology spec")
        );
    }

    #[allow(clippy::unwrap_used)]
    // reason: 测试构造合法 consumer group；parse 失败即测试写错。
    #[test]
    fn bridge_generated_subscriptions_rejects_unbound_generated_spec() {
        let event = generated::event::identity_v1::session_created::SPEC;
        let result = bridge_subscriptions_with_events(Vec::new(), &[event]);
        assert!(
            result.is_err(),
            "expected unbound generated topology spec error"
        );
        let err = result.err().unwrap();
        assert!(
            err.to_string()
                .contains("generated topology spec has no subscriber binding")
        );
    }

    // ── parse_topology ────────────────────────────────────────────────────────

    #[allow(clippy::unwrap_used)]
    // reason: 枚举值合法则 parse 必须 Ok，失败即测试意图写错；item-level carve-out。
    #[test]
    fn parse_topology_valid_values() {
        assert_eq!(parse_topology("demo").unwrap(), bootstrap::Topology::Demo);
        assert_eq!(
            parse_topology("durable-shared").unwrap(),
            bootstrap::Topology::DurableShared
        );
        assert_eq!(
            parse_topology("durable-isolated").unwrap(),
            bootstrap::Topology::DurableIsolated
        );
    }

    #[allow(clippy::unwrap_used)]
    // reason: 无效 key 必须 Err，unwrap_err 失败即测试意图写错；item-level carve-out。
    #[test]
    fn parse_topology_invalid_value_errors() {
        let err = parse_topology("unknown").unwrap_err();
        assert!(err.to_string().contains("unknown RSS_TOPOLOGY"));
    }

    // ── explicit test values / snapshot-only production builders ─────────────

    #[test]
    fn explicit_demo_values_do_not_require_durable_security() {
        assert!(EventTransportTestValues::demo().build().is_ok());
    }

    #[test]
    fn explicit_durable_shared_values_resolve_shared_transport() {
        let config = EventTransportTestValues::durable_shared("amqps://su:sp@host/shared")
            .build()
            .unwrap_or_else(|_| unreachable!());
        assert!(matches!(config.decision, EventDecision::Durable { .. }));
    }

    #[test]
    fn explicit_plaintext_amqp_urls_are_rejected_under_deny() {
        assert!(
            EventTransportTestValues::durable_shared("amqp://su:sp@broker/shared")
                .build()
                .is_err()
        );
        assert!(
            EventTransportTestValues::durable_shared("amqp://su:sp@127.0.0.1/shared")
                .build()
                .is_err(),
            "loopback plaintext amqp:// is also banned after #1710"
        );
    }

    #[test]
    fn explicit_durable_missing_transport_fails_in_resolver() {
        let error = EventTransportTestValues::durable_shared("amqps://su:sp@host/shared")
            .without_shared_url()
            .build()
            .err()
            .map(|error| format!("{error:#}"))
            .unwrap_or_default();
        assert_eq!(
            error,
            "resolve event transport: durable transport requires a broker url for domain IDENTITY (set RSS_IDENTITY_AMQP_URL)"
        );
    }

    #[test]
    fn isolated_shared_transport_returns_exact_rejection() {
        let error =
            EventTransportTestValues::durable_isolated_with_shared("amqps://su:sp@host/shared")
                .build()
                .err()
                .map(|error| format!("{error:#}"))
                .unwrap_or_default();
        assert_eq!(
            error,
            "resolve event transport: isolated topology must not be configured with a shared broker url (RSS_AMQP_URL)"
        );
    }

    #[test]
    fn event_worker_snapshot_defaults_and_strict_budget_are_typed() {
        let snapshot = crate::config::test_snapshot(&[]).unwrap_or_else(|_| unreachable!());
        let mapper = crate::config::ServingConfigMapper::for_test(snapshot.view());
        let worker = EventWorkerConfig::from_mapper(&mapper).unwrap_or_else(|_| unreachable!());
        assert_eq!(worker.relay_poll_interval(), Duration::from_millis(200));
        assert_eq!(worker.relay_max_in_flight(), 16);
        assert_eq!(
            worker.relay_sample_interval(),
            Duration::from_millis(30_000)
        );
        assert_eq!(
            worker.outbox_sweep_interval(),
            Duration::from_millis(300_000)
        );
        assert_eq!(worker.outbox_retain_seconds(), 604_800);
        assert_eq!(
            worker.relay_budget().required_budget().as_millis() as i64,
            50_000
        );
    }

    #[test]
    fn event_worker_snapshot_maps_each_relay_budget_field_without_swaps() {
        let snapshot = crate::config::test_snapshot(&[
            ("RSS_RELAY_LEASE_TTL_MS", "61000"),
            ("RSS_RELAY_PUBLISH_TIMEOUT_MS", "17000"),
            ("RSS_RELAY_SETTLE_TIMEOUT_MS", "9000"),
            ("RSS_RELAY_SAFETY_MARGIN_MS", "3000"),
        ])
        .unwrap_or_else(|_| unreachable!());
        let mapper = crate::config::ServingConfigMapper::for_test(snapshot.view());
        let worker = EventWorkerConfig::from_mapper(&mapper).unwrap_or_else(|_| unreachable!());
        let budget = worker.relay_budget();

        assert_eq!(budget.lease_ttl(), Duration::from_millis(61_000));
        assert_eq!(budget.publish_timeout(), Duration::from_millis(17_000));
        assert_eq!(budget.settle_timeout(), Duration::from_millis(9_000));
        assert_eq!(budget.safety_margin(), Duration::from_millis(3_000));
    }

    #[test]
    fn event_worker_snapshot_relay_budget_invalid_values_fail_fast() {
        for (name, value) in [
            ("RSS_RELAY_LEASE_TTL_MS", "86400001"),
            ("RSS_RELAY_PUBLISH_TIMEOUT_MS", "86400001"),
            ("RSS_RELAY_SETTLE_TIMEOUT_MS", "86400001"),
            ("RSS_RELAY_SAFETY_MARGIN_MS", "86400001"),
        ] {
            let snapshot =
                crate::config::test_snapshot(&[(name, value)]).unwrap_or_else(|_| unreachable!());
            let mapper = crate::config::ServingConfigMapper::for_test(snapshot.view());
            assert!(
                EventWorkerConfig::from_mapper(&mapper).is_err(),
                "{name} must reject the governed maximum plus one"
            );
        }
        let snapshot = crate::config::test_snapshot(&[("RSS_RELAY_MAX_IN_FLIGHT", "0")])
            .unwrap_or_else(|_| unreachable!());
        let mapper = crate::config::ServingConfigMapper::for_test(snapshot.view());
        assert!(
            EventWorkerConfig::from_mapper(&mapper).is_err(),
            "invalid worker shape must fail before provider setup or migrations"
        );
    }

    #[test]
    fn archive_key_is_required_and_must_differ_from_hot_key() {
        let missing = build_dlx_archive_key_name_from(&|name| match name {
            DLX_PAYLOAD_KEY_NAME_ENV => Some("dlx-hot".to_owned()),
            _ => None,
        });
        assert!(missing.is_err());

        let reused = build_dlx_archive_key_name_from(&|name| match name {
            DLX_PAYLOAD_KEY_NAME_ENV | DLX_ARCHIVE_KEY_NAME_ENV => Some("dlx-hot".to_owned()),
            _ => None,
        });
        assert!(reused.is_err());

        let distinct = build_dlx_archive_key_name_from(&|name| match name {
            DLX_PAYLOAD_KEY_NAME_ENV => Some("dlx-hot".to_owned()),
            DLX_ARCHIVE_KEY_NAME_ENV => Some("dlx-archive".to_owned()),
            _ => None,
        });
        assert!(distinct.is_ok());
    }

    #[test]
    fn projection_replay_hot_vault_provider_needs_no_archive_secret() {
        let unrelated_secret_requested = std::cell::Cell::new(false);
        let hot_only = build_projection_replay_vault_key_provider_from(&|name| match name {
            VAULT_ADDR_ENV => Some("https://vault.example.test".to_owned()),
            VAULT_TRANSIT_MOUNT_ENV => Some("transit".to_owned()),
            DLX_HOT_VAULT_TOKEN_ENV => Some("hot-token".to_owned()),
            DLX_ARCHIVE_VAULT_TOKEN_ENV | "RSS_VAULT_TOKEN" => {
                unrelated_secret_requested.set(true);
                Some("unrelated-token".to_owned())
            }
            _ => None,
        });
        assert!(hot_only.is_ok());
        assert!(!unrelated_secret_requested.get());

        let generic_only = build_projection_replay_vault_key_provider_from(&|name| match name {
            VAULT_ADDR_ENV => Some("https://vault.example.test".to_owned()),
            VAULT_TRANSIT_MOUNT_ENV => Some("transit".to_owned()),
            "RSS_VAULT_TOKEN" => Some("generic-token".to_owned()),
            _ => None,
        });
        let error = generic_only.err().map(|error| format!("{error:#}"));
        assert!(error.is_some_and(|error| error.contains(DLX_HOT_VAULT_TOKEN_ENV)));
    }

    #[test]
    fn serving_dlx_vault_key_providers_require_distinct_workload_tokens() {
        let reused = build_dlx_vault_key_providers_from(&|name| match name {
            VAULT_ADDR_ENV => Some("https://vault.example.test".to_owned()),
            VAULT_TRANSIT_MOUNT_ENV => Some("transit".to_owned()),
            DLX_HOT_VAULT_TOKEN_ENV | DLX_ARCHIVE_VAULT_TOKEN_ENV => Some("same-token".to_owned()),
            _ => None,
        });
        let error = reused.err().map(|error| format!("{error:#}"));
        assert!(error.is_some_and(|error| error.contains("must differ")));

        let reused_general = build_dlx_archive_vault_key_provider_from(&|name| match name {
            VAULT_ADDR_ENV => Some("https://vault.example.test".to_owned()),
            VAULT_TRANSIT_MOUNT_ENV => Some("transit".to_owned()),
            DLX_HOT_VAULT_TOKEN_ENV => Some("hot-token".to_owned()),
            DLX_ARCHIVE_VAULT_TOKEN_ENV | "RSS_VAULT_TOKEN" => {
                Some("shared-general-token".to_owned())
            }
            _ => None,
        });
        let error = reused_general.err().map(|error| format!("{error:#}"));
        assert!(error.is_some_and(|error| error.contains("RSS_VAULT_TOKEN")));
    }

    #[derive(Clone)]
    struct FakeDlxTickRunner {
        observation: DlxTickObservation,
        epochs: Arc<std::sync::Mutex<Vec<i64>>>,
        cancel_after_tick: Option<tokio_util::sync::CancellationToken>,
        tick_signal: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    }

    impl FakeDlxTickRunner {
        fn new(observation: DlxTickObservation) -> Self {
            Self {
                observation,
                epochs: Arc::new(std::sync::Mutex::new(Vec::new())),
                cancel_after_tick: None,
                tick_signal: None,
            }
        }

        fn cancelling(
            observation: DlxTickObservation,
            token: tokio_util::sync::CancellationToken,
        ) -> Self {
            Self {
                observation,
                epochs: Arc::new(std::sync::Mutex::new(Vec::new())),
                cancel_after_tick: Some(token),
                tick_signal: None,
            }
        }

        fn signalling(
            observation: DlxTickObservation,
            token: tokio_util::sync::CancellationToken,
            tick_signal: tokio::sync::mpsc::UnboundedSender<()>,
        ) -> Self {
            Self {
                observation,
                epochs: Arc::new(std::sync::Mutex::new(Vec::new())),
                cancel_after_tick: Some(token),
                tick_signal: Some(tick_signal),
            }
        }

        fn epochs(&self) -> Vec<i64> {
            self.epochs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl DlxTickRunner for FakeDlxTickRunner {
        async fn tick_observation(&self, now_epoch_secs: i64) -> DlxTickObservation {
            self.epochs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(now_epoch_secs);
            if let Some(token) = &self.cancel_after_tick {
                token.cancel();
            }
            if let Some(signal) = &self.tick_signal {
                let _ignored = signal.send(());
            }
            self.observation
        }
    }

    struct NeverCompletingDlxTickRunner;

    impl DlxTickRunner for NeverCompletingDlxTickRunner {
        async fn tick_observation(&self, _now_epoch_secs: i64) -> DlxTickObservation {
            std::future::pending().await
        }
    }

    #[derive(Clone, Copy)]
    enum FakeArchiveReadinessOutcome {
        Healthy,
        ProviderFailure,
        InvariantFailure,
    }

    struct CancellingArchiveReadiness {
        outcome: FakeArchiveReadinessOutcome,
        token: tokio_util::sync::CancellationToken,
    }

    impl DlxArchiveReadiness for CancellingArchiveReadiness {
        async fn probe_archive_readiness(&self) -> Result<(), s3::S3DlxArchiveCapabilityError> {
            self.token.cancel();
            match self.outcome {
                FakeArchiveReadinessOutcome::Healthy => Ok(()),
                FakeArchiveReadinessOutcome::ProviderFailure => {
                    Err(s3::S3DlxArchiveCapabilityError::Provider)
                }
                FakeArchiveReadinessOutcome::InvariantFailure => {
                    Err(s3::S3DlxArchiveCapabilityError::VersioningRequired)
                }
            }
        }
    }

    struct NeverCompletingArchiveReadiness;

    impl DlxArchiveReadiness for NeverCompletingArchiveReadiness {
        async fn probe_archive_readiness(&self) -> Result<(), s3::S3DlxArchiveCapabilityError> {
            std::future::pending().await
        }
    }

    struct CancellingArchiveKeyReadiness {
        result: Result<(), &'static str>,
        token: tokio_util::sync::CancellationToken,
    }

    impl DlxArchiveKeyReadiness for CancellingArchiveKeyReadiness {
        async fn probe_archive_key_readiness(&self) -> anyhow::Result<()> {
            self.token.cancel();
            self.result.map_err(anyhow::Error::msg)
        }
    }

    struct NeverCompletingArchiveKeyReadiness;

    impl DlxArchiveKeyReadiness for NeverCompletingArchiveKeyReadiness {
        async fn probe_archive_key_readiness(&self) -> anyhow::Result<()> {
            std::future::pending().await
        }
    }

    #[derive(Clone, Copy)]
    struct FakeDlxBacklogReader(Result<DlxArchiveBacklog, DlxLifecycleError>);

    impl DlxBacklogReader for FakeDlxBacklogReader {
        async fn read_archive_backlog(&self) -> Result<DlxArchiveBacklog, DlxLifecycleError> {
            self.0
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    struct RecordedSweep {
        target: RetentionTarget,
        outcome: RetentionOutcome,
        deleted: u64,
        duration_seconds: f64,
    }

    #[derive(Default)]
    struct RecordingDlxMetrics {
        sweeps: std::sync::Mutex<Vec<RecordedSweep>>,
        backlogs: std::sync::Mutex<Vec<DlxArchiveBacklog>>,
    }

    impl RetentionMetrics for RecordingDlxMetrics {
        fn record_sweep(
            &self,
            target: RetentionTarget,
            outcome: RetentionOutcome,
            deleted: u64,
            duration_seconds: f64,
        ) {
            self.sweeps
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(RecordedSweep {
                    target,
                    outcome,
                    deleted,
                    duration_seconds,
                });
        }

        fn record_archive_backlog(&self, backlog: DlxArchiveBacklog) {
            self.backlogs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(backlog);
        }

        fn record_retention_backlog(
            &self,
            _target: RetentionTarget,
            _observation: eventexec::RetentionBacklogObservation,
        ) {
        }
    }

    struct SequenceClock(std::sync::Mutex<std::collections::VecDeque<SystemTime>>);

    impl SequenceClock {
        fn new(times: impl IntoIterator<Item = SystemTime>) -> Self {
            Self(std::sync::Mutex::new(times.into_iter().collect()))
        }
    }

    impl Clock for SequenceClock {
        fn now(&self) -> SystemTime {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .unwrap_or(SystemTime::UNIX_EPOCH)
        }
    }

    struct ClockAdvancingBacklogReader {
        clock: Arc<SequenceClock>,
        backlog: DlxArchiveBacklog,
    }

    impl DlxBacklogReader for ClockAdvancingBacklogReader {
        async fn read_archive_backlog(&self) -> Result<DlxArchiveBacklog, DlxLifecycleError> {
            let _after_backlog = self.clock.now();
            Ok(self.backlog)
        }
    }

    fn observation(health: DlxLifecycleHealth) -> DlxTickObservation {
        DlxTickObservation {
            health,
            archived: 2,
            purged: 3,
            receipts_reconciled: 4,
            primary_failure: None,
        }
    }

    #[test]
    fn dlx_primary_failure_metric_and_log_share_closed_labels() {
        let failure = DlxLifecycleError::new(
            DlxLifecycleOperation::VerifyArchive,
            DlxLifecycleReason::ChecksumMismatch,
        );
        assert_eq!(
            DlxFailureLabels::from(failure),
            DlxFailureLabels {
                operation: "verify_archive",
                reason: "checksum_mismatch",
            }
        );
    }

    #[tokio::test]
    async fn dlx_tick_records_bounded_work_backlog_and_healthy_state() {
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let clock = Arc::new(SequenceClock::new([
            started,
            started + Duration::from_millis(250),
            started + Duration::from_millis(750),
        ]));
        let lifecycle = FakeDlxTickRunner::new(observation(DlxLifecycleHealth::Healthy));
        let backlog = DlxArchiveBacklog::new(7, 11);
        let metrics = RecordingDlxMetrics::default();
        let health = WorkerHealth::starting();

        run_dlx_lifecycle_tick(
            &lifecycle,
            &ClockAdvancingBacklogReader {
                clock: Arc::clone(&clock),
                backlog,
            },
            &health,
            &metrics,
            clock.as_ref(),
        )
        .await;

        assert_eq!(lifecycle.epochs(), vec![100]);
        assert_eq!(health.status(), primitives::healthz::HealthStatus::Healthy);
        assert_eq!(health.detail(), "worker");
        assert_eq!(
            metrics
                .sweeps
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice(),
            &[RecordedSweep {
                target: RetentionTarget::DeadLetter,
                outcome: RetentionOutcome::Success,
                deleted: 3,
                duration_seconds: 0.75,
            }]
        );
        assert_eq!(
            metrics
                .backlogs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice(),
            &[backlog]
        );
    }

    #[tokio::test]
    async fn dlx_tick_backlog_failure_degrades_an_otherwise_healthy_tick() {
        let lifecycle = FakeDlxTickRunner::new(observation(DlxLifecycleHealth::Healthy));
        let metrics = RecordingDlxMetrics::default();
        let health = WorkerHealth::starting();
        let clock = SequenceClock::new([SystemTime::UNIX_EPOCH; 2]);

        run_dlx_lifecycle_tick(
            &lifecycle,
            &FakeDlxBacklogReader(Err(DlxLifecycleError::new(
                DlxLifecycleOperation::ArchiveBacklog,
                DlxLifecycleReason::ProviderUnavailable,
            ))),
            &health,
            &metrics,
            &clock,
        )
        .await;

        assert_eq!(health.status(), primitives::healthz::HealthStatus::Degraded);
        assert_eq!(health.detail(), "degraded");
        assert!(
            metrics
                .backlogs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
        assert_eq!(
            metrics
                .sweeps
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)[0]
                .outcome,
            RetentionOutcome::Transient
        );
    }

    #[tokio::test]
    async fn dlx_tick_invariant_health_is_not_masked_by_backlog_failure() {
        let lifecycle = FakeDlxTickRunner::new(observation(DlxLifecycleHealth::Unhealthy));
        let metrics = RecordingDlxMetrics::default();
        let health = WorkerHealth::starting();
        let clock = SequenceClock::new([SystemTime::UNIX_EPOCH; 2]);

        run_dlx_lifecycle_tick(
            &lifecycle,
            &FakeDlxBacklogReader(Err(DlxLifecycleError::new(
                DlxLifecycleOperation::ArchiveBacklog,
                DlxLifecycleReason::ProviderUnavailable,
            ))),
            &health,
            &metrics,
            &clock,
        )
        .await;

        assert_eq!(
            health.status(),
            primitives::healthz::HealthStatus::Unhealthy
        );
        assert_eq!(health.detail(), "invariant");
        assert_eq!(
            metrics
                .sweeps
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)[0]
                .outcome,
            RetentionOutcome::Invariant
        );
    }

    #[tokio::test]
    async fn dlx_loop_runs_immediate_tick_then_observes_cancellation() {
        let token = tokio_util::sync::CancellationToken::new();
        let lifecycle =
            FakeDlxTickRunner::cancelling(observation(DlxLifecycleHealth::Degraded), token.clone());
        let epochs = Arc::clone(&lifecycle.epochs);
        let metrics = Arc::new(RecordingDlxMetrics::default());
        let health = Arc::new(WorkerHealth::starting());

        dlx_lifecycle_loop(
            lifecycle,
            FakeDlxBacklogReader(Ok(DlxArchiveBacklog::new(1, 2))),
            DlxLoopContext {
                token,
                health: Arc::clone(&health),
                metrics,
                clock: Arc::new(SequenceClock::new([SystemTime::UNIX_EPOCH; 2])),
                config: DlxWorkerConfig::canonical(),
                write_admission: open_write_admission(),
            },
        )
        .await;

        assert_eq!(
            epochs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice(),
            &[0]
        );
        assert_eq!(health.status(), primitives::healthz::HealthStatus::Degraded);
    }

    #[tokio::test]
    async fn dlx_loop_cancels_an_in_flight_tick_that_never_returns_io() {
        let token = tokio_util::sync::CancellationToken::new();
        let loop_token = token.clone();
        let handle = tokio::spawn(dlx_lifecycle_loop(
            NeverCompletingDlxTickRunner,
            FakeDlxBacklogReader(Ok(DlxArchiveBacklog::new(0, 0))),
            DlxLoopContext {
                token: loop_token,
                health: Arc::new(WorkerHealth::starting()),
                metrics: Arc::new(RecordingDlxMetrics::default()),
                clock: Arc::new(SequenceClock::new([SystemTime::UNIX_EPOCH])),
                config: DlxWorkerConfig::canonical(),
                write_admission: open_write_admission(),
            },
        ));
        tokio::task::yield_now().await;
        token.cancel();

        let stopped = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert!(matches!(stopped, Ok(Ok(()))));
    }

    #[tokio::test(start_paused = true)]
    async fn dlx_loop_degrades_when_total_tick_io_budget_expires() {
        let token = tokio_util::sync::CancellationToken::new();
        let health = WorkerHealth::starting();
        let metrics = RecordingDlxMetrics::default();

        let step = run_bounded_dlx_lifecycle_tick(
            &NeverCompletingDlxTickRunner,
            &FakeDlxBacklogReader(Ok(DlxArchiveBacklog::new(0, 0))),
            &token,
            &health,
            &metrics,
            &SequenceClock::new([SystemTime::UNIX_EPOCH]),
            DlxWorkerConfig::canonical(),
        )
        .await;

        assert_eq!(step, DlxLoopStep::Continue);
        assert_eq!(health.status(), primitives::healthz::HealthStatus::Degraded);
        assert_eq!(
            metrics
                .sweeps
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)[0]
                .outcome,
            RetentionOutcome::Transient
        );
    }

    #[tokio::test]
    async fn dlx_archive_readiness_has_an_independent_degraded_carrier() {
        for (outcome, expected) in [
            (
                FakeArchiveReadinessOutcome::Healthy,
                primitives::healthz::HealthStatus::Healthy,
            ),
            (
                FakeArchiveReadinessOutcome::ProviderFailure,
                primitives::healthz::HealthStatus::Degraded,
            ),
            (
                FakeArchiveReadinessOutcome::InvariantFailure,
                primitives::healthz::HealthStatus::Unhealthy,
            ),
        ] {
            let token = tokio_util::sync::CancellationToken::new();
            let health = Arc::new(WorkerHealth::starting());
            dlx_archive_readiness_loop(
                CancellingArchiveReadiness {
                    outcome,
                    token: token.clone(),
                },
                token,
                Arc::clone(&health),
                DlxWorkerConfig::canonical(),
            )
            .await;
            assert_eq!(health.status(), expected);
        }
    }

    #[tokio::test]
    async fn dlx_archive_invariant_failure_is_sticky_and_keeps_readyz_non_healthy() {
        let health = WorkerHealth::starting();
        let token = tokio_util::sync::CancellationToken::new();
        let invariant = CancellingArchiveReadiness {
            outcome: FakeArchiveReadinessOutcome::InvariantFailure,
            token: token.clone(),
        };
        assert_eq!(
            run_bounded_dlx_archive_readiness_probe(
                &invariant,
                &token,
                &health,
                DlxWorkerConfig::canonical(),
            )
            .await,
            DlxLoopStep::Continue
        );
        assert_eq!(
            health.status(),
            primitives::healthz::HealthStatus::Unhealthy
        );

        let recovered = CancellingArchiveReadiness {
            outcome: FakeArchiveReadinessOutcome::Healthy,
            token: tokio_util::sync::CancellationToken::new(),
        };
        let live_token = tokio_util::sync::CancellationToken::new();
        assert_eq!(
            run_bounded_dlx_archive_readiness_probe(
                &recovered,
                &live_token,
                &health,
                DlxWorkerConfig::canonical(),
            )
            .await,
            DlxLoopStep::Continue
        );
        assert_eq!(
            health.status(),
            primitives::healthz::HealthStatus::Unhealthy
        );
    }

    #[tokio::test]
    async fn dlx_archive_readiness_cancels_an_in_flight_provider_probe() {
        let token = tokio_util::sync::CancellationToken::new();
        let health = Arc::new(WorkerHealth::starting());
        let handle = tokio::spawn(dlx_archive_readiness_loop(
            NeverCompletingArchiveReadiness,
            token.clone(),
            Arc::clone(&health),
            DlxWorkerConfig::canonical(),
        ));
        tokio::task::yield_now().await;
        token.cancel();

        let stopped = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert!(matches!(stopped, Ok(Ok(()))));
    }

    #[tokio::test]
    async fn dlx_archive_key_readiness_has_an_independent_continuous_carrier() {
        for (result, expected) in [
            (Ok(()), primitives::healthz::HealthStatus::Healthy),
            (
                Err("vault key unavailable"),
                primitives::healthz::HealthStatus::Degraded,
            ),
        ] {
            let token = tokio_util::sync::CancellationToken::new();
            let health = Arc::new(WorkerHealth::starting());
            dlx_archive_key_readiness_loop(
                CancellingArchiveKeyReadiness {
                    result,
                    token: token.clone(),
                },
                token,
                Arc::clone(&health),
                DlxWorkerConfig::canonical(),
            )
            .await;
            assert_eq!(health.status(), expected);
        }
    }

    #[tokio::test]
    async fn dlx_archive_key_readiness_cancels_an_in_flight_canary() {
        let token = tokio_util::sync::CancellationToken::new();
        let health = Arc::new(WorkerHealth::starting());
        let handle = tokio::spawn(dlx_archive_key_readiness_loop(
            NeverCompletingArchiveKeyReadiness,
            token.clone(),
            Arc::clone(&health),
            DlxWorkerConfig::canonical(),
        ));
        tokio::task::yield_now().await;
        token.cancel();

        let stopped = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert!(matches!(stopped, Ok(Ok(()))));
    }

    #[tokio::test]
    async fn dlx_worker_builder_runs_tick_on_owned_runtime_and_stops_cleanly() {
        let token = tokio_util::sync::CancellationToken::new();
        let (tick_signal, mut tick_observed) = tokio::sync::mpsc::unbounded_channel();
        let lifecycle = FakeDlxTickRunner::signalling(
            observation(DlxLifecycleHealth::Healthy),
            token.clone(),
            tick_signal,
        );
        let epochs = Arc::clone(&lifecycle.epochs);
        let health = Arc::new(WorkerHealth::starting());
        let worker = build_dlx_lifecycle_worker(
            lifecycle,
            FakeDlxBacklogReader(Ok(DlxArchiveBacklog::new(0, 0))),
            Arc::clone(&health),
            DlxWorkerConfig::canonical(),
            open_write_admission(),
        );

        let mut stack = bootstrap::shutdown::ShutdownStack::new(token);
        worker.register_into(&mut stack);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), tick_observed.recv()).await,
            Ok(Some(()))
        );
        assert!(stack.shutdown().await.is_empty());
        assert_eq!(
            epochs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1
        );
        assert_eq!(
            health.status(),
            primitives::healthz::HealthStatus::Unhealthy
        );
        assert_eq!(health.detail(), "stopped");
    }

    #[test]
    fn dlx_probe_builder_exposes_closed_name_and_worker_health() {
        let health = Arc::new(WorkerHealth::starting());
        let name = ProbeName::parse(DLX_LIFECYCLE_PROBE).unwrap_or_else(|_| unreachable!());
        let probe = build_dlx_lifecycle_probe(name.clone(), Arc::clone(&health));
        assert_eq!(name.as_str(), DLX_LIFECYCLE_PROBE);
        assert_eq!(
            probe.check().status(),
            primitives::healthz::HealthStatus::Unhealthy
        );

        apply_dlx_lifecycle_health(&health, DlxLifecycleHealth::Healthy);
        assert_eq!(
            probe.check().status(),
            primitives::healthz::HealthStatus::Healthy
        );
    }

    #[test]
    fn dlx_elapsed_seconds_clamps_backwards_time() {
        assert_eq!(
            elapsed_seconds(
                SystemTime::UNIX_EPOCH + Duration::from_secs(2),
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            ),
            0.0
        );
        assert_eq!(
            elapsed_seconds(
                SystemTime::UNIX_EPOCH,
                SystemTime::UNIX_EPOCH + Duration::from_millis(125),
            ),
            0.125
        );
    }

    #[test]
    fn config_builder_durable_missing_tenant_authority_key_fails_fast() {
        let result = EventTransportTestValues::durable_shared("amqps://su:sp@host/shared")
            .without_tenant_authority_key()
            .build();
        assert!(
            result.is_err(),
            "missing tenant authority key must fail fast"
        );
        let err = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            err.contains(TENANT_AUTHORITY_HMAC_KEY_ENV),
            "missing tenant authority key must fail fast"
        );
    }

    #[test]
    fn config_builder_durable_short_tenant_authority_key_fails_fast() {
        let short_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42u8; 8]);
        let result = EventTransportTestValues::durable_shared("amqps://su:sp@host/shared")
            .with_tenant_authority_key_b64url(short_key)
            .build();
        assert!(result.is_err(), "short tenant authority key must fail fast");
        let err = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            err.contains("tenant authority config error"),
            "short tenant authority key must fail fast"
        );
    }

    #[test]
    fn config_builder_durable_oversized_tenant_authority_clock_skew_fails_fast() {
        let result = EventTransportTestValues::durable_shared("amqps://su:sp@host/shared")
            .with_tenant_clock_skew_secs(301)
            .build();
        assert!(
            result.is_err(),
            "oversized tenant authority clock skew must fail fast"
        );
        let err = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            err.contains("tenant authority config error"),
            "oversized tenant authority clock skew must fail fast: {err}"
        );
    }

    #[test]
    fn config_builder_durable_missing_dlx_payload_key_name_fails_fast() {
        let result = EventTransportTestValues::durable_shared("amqps://su:sp@host/shared")
            .without_dlx_payload_key()
            .build();
        assert!(
            result.is_err(),
            "missing DLX payload key name must fail fast"
        );
        let err = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            err.contains(DLX_PAYLOAD_KEY_NAME_ENV),
            "missing DLX payload key name must fail fast"
        );
    }

    #[test]
    fn active_settings_event_is_in_generated_producer_domains() {
        assert!(
            generated::event::PRODUCER_DOMAINS
                .iter()
                .any(|domain| domain.as_str() == "settings"),
            "settings.config-version-changed is active and has subscriber topology; production relay must publish settings outbox rows"
        );
        assert!(
            primitives::ProbeName::parse(OUTBOX_SAMPLER_PROBE).is_ok(),
            "outbox sampler probe name must remain readyz-compatible"
        );
        assert!(
            primitives::ProbeName::parse(OUTBOX_SWEEPER_PROBE).is_ok(),
            "outbox sweeper probe name must remain readyz-compatible"
        );
        assert!(
            primitives::ProbeName::parse(INBOX_SAMPLER_PROBE).is_ok(),
            "inbox sampler probe name must remain readyz-compatible"
        );
    }

    #[test]
    fn inbox_sampler_registration_follows_local_generated_subscription_inventory() {
        let empty = InboxBacklogSelection::from_generated(&[])
            .unwrap_or_else(|error| unreachable!("empty generated selection: {error}"));
        assert!(
            inbox_sampler_registration(empty, Duration::from_secs(30))
                .unwrap_or_else(|error| unreachable!("empty registration: {error}"))
                .is_none(),
            "a runtime without local subscriptions must not register a worker or probe"
        );

        let local = InboxBacklogSelection::from_generated(&[
            generated::event::settings_v1::SETTINGS_SUBSCRIPTION,
        ])
        .unwrap_or_else(|error| unreachable!("local generated selection: {error}"));
        let registration = inbox_sampler_registration(local, Duration::from_secs(30))
            .unwrap_or_else(|error| unreachable!("local registration: {error}"))
            .unwrap_or_else(|| unreachable!("local subscriptions register one sampler"));
        assert_eq!(registration.selection().groups().len(), 1);
        assert_eq!(registration.sample_interval(), Duration::from_secs(30));
    }

    // ── resolve_event_decision（纯函数；无 PG/infra 依赖）────────────────────

    /// (a) Demo topology → EventDecision::Demo。
    #[allow(clippy::unwrap_used)]
    // reason: 测试 Ok 臂断言 Demo 变体，unwrap 失败即 test 意图写错；item-level carve-out。
    #[test]
    fn resolve_decision_demo_topology_returns_demo() {
        let result = resolve_event_decision(
            bootstrap::Topology::Demo,
            bootstrap::eventtransport::TransportConfig::default(),
            &[] as &[&str],
        );
        assert!(result.is_ok(), "Demo topology must succeed: {result:?}");
        assert!(
            matches!(result.unwrap(), EventDecision::Demo),
            "Demo topology must return EventDecision::Demo"
        );
    }

    /// (b) DurableShared + identity url → EventDecision::Durable。
    #[allow(clippy::unwrap_used)]
    // reason: 测试 Ok 臂断言 Durable 变体，unwrap 失败即 test 意图写错；item-level carve-out。
    #[test]
    fn resolve_decision_durable_topology_returns_durable() {
        let url_result = bootstrap::AmqpUrl::parse(
            "amqps://user:pass@host/vhost",
            secure::PlaintextEndpointPolicy::Deny,
        );
        assert!(url_result.is_ok(), "{url_result:?}");
        let transport = bootstrap::eventtransport::TransportConfig::default()
            .with_domain_url("identity", url_result.unwrap());
        let result =
            resolve_event_decision(bootstrap::Topology::DurableShared, transport, &["identity"]);
        assert!(result.is_ok(), "Durable topology must succeed: {result:?}");
        assert!(
            matches!(result.unwrap(), EventDecision::Durable { .. }),
            "Durable topology must return EventDecision::Durable"
        );
    }

    /// (c) DurableShared + empty TransportConfig → Err（无 AMQP URL 供所需 domain）。
    #[test]
    fn resolve_decision_missing_amqp_url_errors() {
        let result = resolve_event_decision(
            bootstrap::Topology::DurableShared,
            bootstrap::eventtransport::TransportConfig::default(), // 无 domain url
            &["identity"],
        );
        assert!(result.is_err(), "missing AMQP URL must return Err");
    }

    // ── parse helpers ─────────────────────────────────────────────────────────

    #[test]
    fn parse_duration_ms_env_uses_default_when_absent() {
        let d = parse_duration_ms_env(None, "TEST_VAR", 500);
        assert_eq!(d, Duration::from_millis(500));
    }

    #[test]
    fn parse_duration_ms_env_parses_valid_value() {
        let d = parse_duration_ms_env(Some("1234".into()), "TEST_VAR", 500);
        assert_eq!(d, Duration::from_millis(1234));
    }

    #[test]
    fn parse_duration_ms_env_falls_back_on_invalid() {
        let d = parse_duration_ms_env(Some("not-a-number".into()), "TEST_VAR", 100);
        assert_eq!(d, Duration::from_millis(100));
    }

    #[test]
    fn parse_usize_env_uses_default_when_absent() {
        assert_eq!(parse_usize_env(None, "TEST_VAR", 42), 42);
    }

    #[test]
    fn parse_u64_env_uses_default_when_absent() {
        assert_eq!(parse_u64_env(None, "TEST_VAR", 42), 42);
    }

    #[test]
    fn parse_u64_env_parses_valid_value() {
        assert_eq!(parse_u64_env(Some("1234".into()), "TEST_VAR", 42), 1234);
    }

    #[test]
    fn parse_u64_env_falls_back_on_invalid() {
        assert_eq!(parse_u64_env(Some("bad".into()), "TEST_VAR", 42), 42);
    }

    #[test]
    fn parse_usize_env_parses_valid_value() {
        assert_eq!(parse_usize_env(Some("32".into()), "TEST_VAR", 8), 32);
    }

    #[test]
    fn parse_usize_env_falls_back_on_invalid() {
        assert_eq!(parse_usize_env(Some("oops".into()), "TEST_VAR", 8), 8);
    }

    #[allow(clippy::panic)]
    #[tokio::test]
    async fn threaded_event_worker_marks_health_stopped_on_thread_exit() {
        let health = Arc::new(WorkerHealth::healthy());
        let token = tokio_util::sync::CancellationToken::new();
        let worker = ManagedBlockingWorker::spawn(
            "test-threaded-worker",
            token,
            Arc::clone(&health),
            EVENT_WORKER_SHUTDOWN_BUDGET,
            move |_| Ok(()),
        );

        if let Err(err) = worker.shutdown().await {
            panic!("thread joins: {err}");
        }
        assert_eq!(
            health.status(),
            primitives::healthz::HealthStatus::Unhealthy
        );
        assert_eq!(health.detail(), "stopped");
    }

    // ── make_consumer_probe（FIX 7）────────────────────────────────────────────

    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path，parse 失败即 const 写错；item-level carve-out。
    #[test]
    fn make_consumer_probe_single_binding_uses_base_name() {
        let health = Arc::new(WorkerHealth::healthy());
        let subscription = test_subscription(
            "identity.session-created",
            "identity.session-created",
            "audit",
            "audit.session-created",
        );
        let (name, _probe) = make_consumer_probe(1, &subscription, health).unwrap();
        assert_eq!(
            name.as_str(),
            EVENT_CONSUMER_PROBE,
            "单 binding 探针名应等于 EVENT_CONSUMER_PROBE"
        );
    }

    #[allow(clippy::unwrap_used)]
    // reason: 同上。
    #[test]
    fn make_consumer_probe_multi_binding_includes_subscription_identity() {
        let health = Arc::new(WorkerHealth::healthy());
        let subscription = test_subscription(
            "identity.session-created",
            "identity.session-created",
            "audit",
            "audit.session-created",
        );
        let (name, _probe) = make_consumer_probe(2, &subscription, health).unwrap();
        let expected = format!(
            "{EVENT_CONSUMER_PROBE}:identity_session-created__audit__audit_session-created"
        );
        assert_eq!(
            name.as_str(),
            expected,
            "多 binding 探针名应含完整 subscription identity"
        );
        // 验证 ProbeName::parse 接受生成的名称。
        assert!(
            primitives::ProbeName::parse(&expected).is_ok(),
            "生成的多 binding 探针名须通过 ProbeName::parse"
        );
    }

    #[allow(clippy::unwrap_used)]
    // reason: 同上。
    #[test]
    fn make_consumer_probe_multi_binding_distinguishes_generated_subscriptions() {
        let first = test_subscription(
            "identity.session-created",
            "identity.session-created",
            "audit",
            "audit.session-created",
        );
        let second = test_subscription(
            "identity.role-assigned",
            "identity.role-assigned",
            "audit",
            "audit.role-assigned",
        );
        let (first_name, _first_probe) =
            make_consumer_probe(2, &first, Arc::new(WorkerHealth::healthy())).unwrap();
        let (second_name, _second_probe) =
            make_consumer_probe(2, &second, Arc::new(WorkerHealth::healthy())).unwrap();

        assert_ne!(
            first_name.as_str(),
            second_name.as_str(),
            "不同 generated subscription 的 probe name 必须不撞"
        );
        assert!(
            first_name
                .as_str()
                .contains("__audit__audit_session-created")
        );
        assert!(
            second_name
                .as_str()
                .contains("identity_role-assigned__audit__audit_role-assigned")
        );
    }
}
