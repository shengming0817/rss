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
//! 解法（与 `eventexec::ConsumerWorker` 对称）：`std::thread::spawn` 把 `PgOutbox`（`Send`）移入
//! 专用 OS 线程，线程内建 current-thread tokio runtime + `block_on(relay_loop(Arc::new(outbox), ...))`；
//! `Arc<PgOutbox>`（`!Send`）始终在单一线程内构建与持有，不跨线程，无需 `Send`。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use audit::ports::AuditChainHasher;
use base64::Engine as _;
#[cfg(test)]
use bootstrap::ReconcileSubscriberOwner;
use bootstrap::{DomainModuleResult, SubscriberBinding, SubscriberCapability, WorkerSpec};
use consistency::{ConsumerGroup, RetentionSweeper};
use crypto::RustCryptoMacVerifier;
use diport::{
    Clock, DlxArchiveBacklog, DlxLifecycleError, DlxLifecycleRepository, DynDeadLetterStore,
    DynKeyProvider, DynManagedResource, ManagedResource, ShutdownError, Topic,
};
use eventexec::{
    ConsumerMeta, DlxArchiveKeyName, DlxHotKeyName, DlxLifecycle, DlxLifecycleHealth,
    DlxLifecycleMetrics, DlxLifecycleTickReport, EVENT_CONSUMER_PROBE, LeaseConfig,
    MetricsDlxLifecycleMetrics, MetricsOutboxMetrics, OUTBOX_RELAY_PROBE, OUTBOX_SAMPLER_PROBE,
    OUTBOX_SWEEPER_PROBE, RelayBudget, RelayConfig, RetentionOutcome, RetentionTarget,
    SWEEPER_WORKER_NAME, SamplerConfig, SweeperConfig, SweeperWorker, TenantAuthority,
    WorkerHealth, apply_dlx_lifecycle_health, backlog_sampler_loop, spawn_relay, sweeper_loop,
};
use generated::event::{
    EventSpec, SubscriberReadiness, SubscriptionDispatchKey, SubscriptionEffect,
    SubscriptionExecution, SubscriptionSpec,
};
use postgres::{
    DlxPayloadProtector, PgDlxLifecycleRepository, PgDlxLifecycleRuntime, PgRuntimeHandle, caps,
};
use primitives::{HealthCheck, MacKey, ProbeName};
use vault::VaultKeyProvider;
use vocab::ExternalEffectPolicy;

use crate::consumer_tx::{ConsumerTxHandler, policy, spawn_consumer_ackable_tx_subscriber};
use crate::distributed_runtime::{
    CoordinatedOutboxBacklog, CoordinatedRetentionSweeper, DistributedRuntimeDeps,
};
use crate::infra::plaintext_endpoint_policy_from;
use crate::infra::vault::{DEFAULT_VAULT_TIMEOUT, build_vault_tls_client_from};
use crate::{EnvSecret, ServingConfigMapper, SnapshotConfig, SystemClock};

// ── 对外类型 ──────────────────────────────────────────────────────────────────

pub struct EventTransportConfig {
    topology: bootstrap::Topology,
    decision: EventDecision,
    tenant_authority: Option<Arc<TenantAuthority>>,
    dlx_payload_protector: Option<DlxPayloadProtector>,
}

impl EventTransportConfig {
    pub(crate) fn from_mapper(mapper: &ServingConfigMapper<'_>) -> anyhow::Result<Self> {
        map_event_transport_from_snapshot(mapper.config())
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

    pub(crate) const fn relay_budget(&self) -> RelayBudget {
        self.relay.budget
    }

    #[cfg(test)]
    pub(crate) fn relay_sample_interval(&self) -> Duration {
        self.relay.sampler.sample_interval()
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
    plaintext_policy: Option<String>,
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
            plaintext_policy: None,
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

    pub fn without_shared_url(mut self) -> Self {
        self.shared = None;
        self
    }

    pub fn with_domain_url(mut self, domain: impl Into<String>, url: impl Into<String>) -> Self {
        self.per_domain.insert(domain.into(), url.into());
        self
    }

    pub fn with_plaintext_policy(mut self, policy: impl Into<String>) -> Self {
        self.plaintext_policy = Some(policy.into());
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
        let plaintext = |name: &str| {
            if name == AMQP_ALLOW_PLAINTEXT_ENV {
                self.plaintext_policy.clone()
            } else {
                None
            }
        };
        let policy = plaintext_endpoint_policy_from(plaintext, AMQP_ALLOW_PLAINTEXT_ENV)?;
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
            });
        }

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
        })
    }
}

#[cfg(any(test, feature = "integration"))]
pub struct EventWorkerTestValues {
    poll: Duration,
    max_in_flight: usize,
    budget: RelayBudget,
    sample: Duration,
    sweep: Duration,
    retain_seconds: u64,
}

#[cfg(any(test, feature = "integration"))]
impl EventWorkerTestValues {
    pub fn canonical() -> anyhow::Result<Self> {
        Ok(Self {
            poll: Duration::from_millis(200),
            max_in_flight: 16,
            budget: RelayBudget::new(
                Duration::from_millis(DEFAULT_RELAY_LEASE_TTL_MS),
                Duration::from_millis(DEFAULT_RELAY_PUBLISH_TIMEOUT_MS),
                Duration::from_millis(DEFAULT_RELAY_SETTLE_TIMEOUT_MS),
                Duration::from_millis(DEFAULT_RELAY_SAFETY_MARGIN_MS),
            )?,
            sample: Duration::from_millis(30_000),
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
const DLX_LIFECYCLE_INTERVAL: Duration = Duration::from_secs(30);
const DLX_LIFECYCLE_TICK_TIMEOUT: Duration = Duration::from_secs(25);
const DLX_ARCHIVE_READINESS_INTERVAL: Duration = Duration::from_secs(60);
const DLX_ARCHIVE_READINESS_TIMEOUT: Duration = Duration::from_secs(5);
const TENANT_AUTHORITY_HMAC_KEY_ENV: &str = "RSS_TENANT_AUTHORITY_HMAC_KEY_B64URL";
const TENANT_AUTHORITY_TTL_ENV: &str = "RSS_TENANT_AUTHORITY_TTL_SECS";
const DEFAULT_TENANT_AUTHORITY_TTL_SECS: u64 = 3600;
const TENANT_AUTHORITY_CLOCK_SKEW_ENV: &str = "RSS_TENANT_AUTHORITY_CLOCK_SKEW_SECS";
const DEFAULT_TENANT_AUTHORITY_CLOCK_SKEW_SECS: u64 = 60;
const DLX_PAYLOAD_KEY_NAME_ENV: &str = "RSS_DLX_PAYLOAD_KEY_NAME";
const DLX_ARCHIVE_KEY_NAME_ENV: &str = "RSS_DLX_ARCHIVE_KEY_NAME";
const AMQP_ALLOW_PLAINTEXT_ENV: &str = "RSS_AMQP_ALLOW_PLAINTEXT";
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

#[derive(Debug, thiserror::Error)]
#[error("threaded event worker failed")]
struct ThreadedWorkerError;

struct ThreadedEventWorker {
    name: &'static str,
    token: tokio_util::sync::CancellationToken,
    handle: tokio::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl ThreadedEventWorker {
    fn spawn<F>(name: &'static str, token: tokio_util::sync::CancellationToken, run: F) -> Self
    where
        F: FnOnce(tokio_util::sync::CancellationToken) + Send + 'static,
    {
        let thread_token = token.clone();
        let handle = std::thread::spawn(move || run(thread_token));
        Self {
            name,
            token,
            handle: tokio::sync::Mutex::new(Some(handle)),
        }
    }
}

impl ManagedResource for ThreadedEventWorker {
    fn name(&self) -> &str {
        self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        let Some(handle) = self.handle.lock().await.take() else {
            return Ok(());
        };
        tokio::task::spawn_blocking(move || handle.join())
            .await
            .map_err(ShutdownError::new)?
            .map_err(|_| ShutdownError::new(ThreadedWorkerError))?;
        Ok(())
    }
}

/// Relay 时序参数聚合（减少 [`wire_durable`] 参数列表长度）。
struct RelayTiming {
    relay: RelayConfig,
    budget: RelayBudget,
    sampler: SamplerConfig,
    outbox_sweeper: SweeperConfig,
}

impl RelayTiming {
    fn from_snapshot(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        let budget = RelayBudget::new(
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
        budget: RelayBudget,
        sample: Duration,
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
    lifecycle:
        DlxLifecycle<PgDlxLifecycleRepository, s3::VerifiedS3DlxArchiveStore, VaultKeyProvider>,
}

impl DlxLifecycleRuntimeDeps {
    pub(crate) fn new(
        pg_owner: PgDlxLifecycleRuntime,
        archive_store: s3::VerifiedS3DlxArchiveStore,
        archive_key_provider: VaultKeyProvider,
        archive_key: DlxArchiveKeyName,
    ) -> Self {
        let repository = pg_owner.repository();
        Self {
            pg_owner,
            backlog_repository: repository.clone(),
            archive_store_readiness: archive_store.clone(),
            lifecycle: DlxLifecycle::new(
                repository,
                archive_store,
                archive_key_provider,
                archive_key,
            ),
        }
    }

    fn into_rollback_module(self) -> DomainModuleResult {
        DomainModuleResult {
            resources: vec![DynManagedResource::new_box(self.pg_owner)],
            ..DomainModuleResult::default()
        }
    }
}

#[derive(Clone)]
struct EventSecurity {
    tenant_authority: Arc<TenantAuthority>,
    dlx_payload_protector: DlxPayloadProtector,
}

pub struct BridgedSubscription {
    event: EventSpec,
    subscription: SubscriptionSpec,
    group: ConsumerGroup,
    consumer_tx: ConsumerTxPlan,
}

impl BridgedSubscription {
    fn contract_id(&self) -> &'static str {
        self.event.contract_id()
    }

    fn topic(&self) -> &'static str {
        self.event.topic()
    }

    fn schema_version(&self) -> &'static str {
        self.event.schema_version()
    }

    fn schema_hash(&self) -> &'static str {
        self.event.schema_hash()
    }

    fn consumer(&self) -> &'static str {
        self.subscription.consumer()
    }

    fn group(&self) -> &ConsumerGroup {
        &self.group
    }

    fn readiness(&self) -> SubscriberReadiness {
        self.subscription.readiness()
    }

    fn topic_owner(&self) -> String {
        topic_owner(self.topic())
    }

    fn identity_slug(&self) -> String {
        format!(
            "{}__{}__{}",
            self.topic().replace('.', "_"),
            self.consumer().replace('.', "_"),
            self.group().as_str().replace('.', "_")
        )
    }
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

fn topic_owner(topic: &str) -> String {
    topic
        .split('.')
        .next()
        .unwrap_or(topic)
        .to_ascii_lowercase()
}

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
    let (consumer, contract_id, topic) = consumer_meta_parts_for_subscription(subscription);
    ConsumerMeta::new(
        consumer,
        subscription.topic_owner(),
        contract_id,
        topic,
        subscription.group().as_str(),
        tenant_authority,
    )
    .with_expected_schema(subscription.schema_version(), subscription.schema_hash())
}

pub fn bridge_generated_subscriptions(
    bindings: Vec<SubscriberBinding>,
) -> anyhow::Result<Vec<BridgedSubscription>> {
    bridge_subscriptions_with_events(bindings, generated::event::EVENTS)
}

fn bridge_subscriptions_with_events(
    bindings: Vec<SubscriberBinding>,
    events: &[EventSpec],
) -> anyhow::Result<Vec<BridgedSubscription>> {
    let specs: Vec<(EventSpec, SubscriptionSpec)> = events
        .iter()
        .flat_map(|event| {
            event
                .subscriptions()
                .iter()
                .map(move |subscription| (*event, *subscription))
        })
        .collect();
    let mut bridged = Vec::with_capacity(bindings.len());
    let mut matched_specs = vec![false; specs.len()];
    for binding in bindings {
        let (contract_id, topic, consumer, binding_group, capability) = binding.into_parts();
        let mut matches = specs.iter().enumerate().filter(|(_, (event, spec))| {
            event.contract_id() == contract_id
                && event.topic() == topic
                && spec.consumer() == consumer
        });
        let Some((matched_index, (event, spec))) = matches.next() else {
            anyhow::bail!(
                "subscriber binding has no generated topology spec: contract={} topic={} consumer={} group={}",
                contract_id,
                topic,
                consumer,
                binding_group.as_str()
            );
        };
        if matches.next().is_some() {
            anyhow::bail!(
                "subscriber binding matches duplicate generated topology specs: contract={} topic={} consumer={} group={}",
                contract_id,
                topic,
                consumer,
                binding_group.as_str()
            );
        }
        let event = *event;
        let spec = *spec;
        let group = ConsumerGroup::parse(spec.group()).map_err(|_| {
            anyhow::anyhow!(
                "generated subscription group is invalid: contract={} consumer={} group={}",
                event.contract_id(),
                spec.consumer(),
                spec.group()
            )
        })?;
        anyhow::ensure!(
            group == binding_group,
            "subscriber group drift after generated topology parse: contract={} consumer={} group={}",
            event.contract_id(),
            spec.consumer(),
            spec.group()
        );
        anyhow::ensure!(
            !matched_specs[matched_index],
            "subscriber binding duplicates generated topology spec: contract={} topic={} consumer={} group={}",
            event.contract_id(),
            event.topic(),
            spec.consumer(),
            spec.group()
        );
        let consumer_tx = resolve_consumer_tx_plan(spec, capability)?;
        matched_specs[matched_index] = true;
        bridged.push(BridgedSubscription {
            event,
            subscription: spec,
            group,
            consumer_tx,
        });
    }
    for ((event, spec), matched) in specs.iter().zip(matched_specs) {
        anyhow::ensure!(
            matched,
            "generated topology spec has no subscriber binding: contract={} topic={} consumer={} group={}",
            event.contract_id(),
            event.topic(),
            spec.consumer(),
            spec.group()
        );
    }
    Ok(bridged)
}

/// topology 接线决策（纯函数，不依赖 PG/infra；可脱离容器单测）。
///
/// 从 transport config resolve：
/// - Demo → [`EventDecision::Demo`]
/// - Durable → [`EventDecision::Durable`]
#[derive(Debug)]
enum EventDecision {
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
pub(crate) async fn wire_event_transport(
    pg: &PgRuntimeHandle,
    distributed: DistributedRuntimeDeps,
    subscribers: Vec<BridgedSubscription>,
    cfg: EventTransportConfig,
    worker: EventWorkerConfig,
    audit_key: MacKey,
) -> anyhow::Result<DomainModuleResult> {
    let timing = worker.relay;
    let security = event_security_for_topology(cfg.topology, &cfg)?;
    match cfg.decision {
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
                distributed,
                subscribers,
                per_domain,
                timing,
                security,
                audit_key,
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
) -> Result<DomainModuleResult, DlxLifecycleWireFailure> {
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
    let DlxLifecycleRuntimeDeps {
        pg_owner,
        backlog_repository,
        archive_store_readiness,
        lifecycle,
    } = deps;
    let health = Arc::new(WorkerHealth::starting());
    let lifecycle_worker =
        build_dlx_lifecycle_worker(lifecycle, backlog_repository, Arc::clone(&health), worker);
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
    Ok(DomainModuleResult {
        probes: vec![(probe_name, probe), (archive_probe_name, archive_probe)],
        resources: vec![DynManagedResource::new_box(pg_owner)],
        workers: vec![lifecycle_worker, archive_worker],
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
    Box::new(move |token| {
        DynManagedResource::new_box(ThreadedEventWorker::spawn(
            DLX_ARCHIVE_READINESS_WORKER_NAME,
            token,
            move |thread_token| {
                let _stopped = health.stopped_on_exit();
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .enable_io()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        tracing::error!(error = %error, "DLX archive readiness runtime build failed");
                        return;
                    }
                };
                runtime.block_on(dlx_archive_readiness_loop(
                    store,
                    thread_token,
                    Arc::clone(&health),
                    config,
                ));
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
) -> WorkerSpec
where
    L: DlxTickRunner + Send + 'static,
    B: DlxBacklogReader + Send + 'static,
{
    Box::new(move |token| {
        DynManagedResource::new_box(ThreadedEventWorker::spawn(
            DLX_LIFECYCLE_WORKER_NAME,
            token,
            move |thread_token| {
                let _stopped = health.stopped_on_exit();
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .enable_io()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        tracing::error!(error = %error, "DLX lifecycle runtime build failed");
                        return;
                    }
                };
                runtime.block_on(dlx_lifecycle_loop(
                    lifecycle,
                    backlog_repository,
                    thread_token,
                    Arc::clone(&health),
                    Arc::new(MetricsDlxLifecycleMetrics),
                    Arc::new(SystemClock),
                    config,
                ));
            },
        ))
    })
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
    for DlxLifecycle<PgDlxLifecycleRepository, s3::VerifiedS3DlxArchiveStore, VaultKeyProvider>
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

async fn dlx_lifecycle_loop<L, B>(
    lifecycle: L,
    backlog_repository: B,
    token: tokio_util::sync::CancellationToken,
    health: Arc<WorkerHealth>,
    metrics: Arc<dyn DlxLifecycleMetrics>,
    clock: Arc<dyn Clock>,
    config: DlxWorkerConfig,
) where
    L: DlxTickRunner,
    B: DlxBacklogReader,
{
    let mut ticker = tokio::time::interval(config.lifecycle_interval);
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
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
    metrics: &dyn DlxLifecycleMetrics,
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
    metrics: &dyn DlxLifecycleMetrics,
    clock: &dyn Clock,
) where
    L: DlxTickRunner,
    B: DlxBacklogReader,
{
    let started = clock.now();
    let report = lifecycle
        .tick_observation(epoch_secs_from_system_time(started))
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
        let policy = plaintext_endpoint_policy_from(get, AMQP_ALLOW_PLAINTEXT_ENV)?;
        let mut per_domain = BTreeMap::new();
        for domain in generated::event::PRODUCER_DOMAINS {
            let domain = domain.as_str();
            let env = format!("RSS_{}_AMQP_URL", domain.to_ascii_uppercase());
            if let Some(url) = get(&env) {
                let parsed = bootstrap::AmqpUrl::parse(url, policy).with_context(|| {
                    format!(
                        "{env} must be amqps:// or loopback amqp:// with explicit plaintext opt-in"
                    )
                })?;
                per_domain.insert(domain.to_string(), parsed);
            }
        }
        let shared = get("RSS_AMQP_URL")
            .map(|url| {
                bootstrap::AmqpUrl::parse(url, policy).context(
                    "RSS_AMQP_URL must be amqps:// or loopback amqp:// with explicit plaintext opt-in",
                )
            })
            .transpose()?;
        bootstrap::eventtransport::TransportConfig::new(per_domain, shared)
    };
    let decision = resolve_event_decision(topology, transport, &generated_required_domains())?;
    let (tenant_authority, dlx_payload_protector) = if topology == bootstrap::Topology::Demo {
        (None, None)
    } else {
        (
            Some(build_tenant_authority_from(&get)?),
            Some(build_dlx_payload_protector(config)?),
        )
    };

    Ok(EventTransportConfig {
        topology,
        decision,
        tenant_authority,
        dlx_payload_protector,
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
    }))
}

// ── 内部函数 ──────────────────────────────────────────────────────────────────

/// durable 拓扑接线内核（Shared / Isolated）：建立 AMQP，spawn relay + PG inbox consumer workers。
#[allow(clippy::cognitive_complexity)]
// reason: wire_durable 是顺序聚合函数，步骤严格有序（AMQP resources → relay → consumers）；
// 拆分会把 module channel 填充顺序散布到多处，隐藏通用 resources → workers 注册约束。
async fn wire_durable(
    pg: &PgRuntimeHandle,
    distributed: DistributedRuntimeDeps,
    subscribers: Vec<BridgedSubscription>,
    per_domain: BTreeMap<String, bootstrap::AmqpUrl>,
    timing: RelayTiming,
    security: EventSecurity,
    audit_key: MacKey,
) -> anyhow::Result<DomainModuleResult> {
    let mut module = DomainModuleResult::default();
    // projection replay / shadow-swap 由 `rss projections` 离线控制面处理；本函数只装配在线传输 worker。
    // 每个 required 域（generated producer domain ∪ subscriber 订阅 topic owner）由 resolver 保证有已校验
    // AMQP URL → 下方 amqp_map 逐域连接；任一步失败都先异步关闭 module 已拥有的连接。
    let mut amqp_map: BTreeMap<String, amqp::AmqpRuntimeDeps> = BTreeMap::new();
    for (domain_upper, url) in &per_domain {
        let domain = domain_upper.to_ascii_lowercase();
        let amqp_deps = match amqp::AmqpRuntimeDeps::connect(
            url.as_ref(),
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
        module.resources.extend(amqp_deps.runtime_resources());
        tracing::info!(domain, "durable event transport: amqp connected");
        amqp_map.insert(domain, amqp_deps);
    }

    // Relay workers：generated producer registry 是迭代单源；闭枚举 match 把每个 producer 映射到
    // postgres sealed capability。新增 producer 变体若未接 PG capability 会在此编译失败。
    for producer in generated::event::PRODUCER_DOMAINS.iter().copied() {
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
        if let Err(primary) = wire_domain_relay(domain, outbox, &timing, &mut module) {
            return Err(crate::provider_output::abort_uncommitted(module, primary).await);
        }
    }
    if let Err(primary) = wire_outbox_maintenance(pg, distributed, &timing, &mut module) {
        return Err(crate::provider_output::abort_uncommitted(module, primary).await);
    }

    // Consumer resource bundle（per binding PG inbox + DLX + subscriber + worker + probe + inbox sweeper）。
    if let Err(primary) = wire_consumer_resource_bundle(
        pg,
        subscribers,
        &amqp_map,
        &security,
        &timing,
        &audit_key,
        &mut module,
    ) {
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
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let relay_cfg = timing.relay.clone();
    let health = Arc::new(WorkerHealth::healthy());
    let worker_name = format!("outbox-relay-{domain}");
    let worker_health = Arc::clone(&health);
    let worker: WorkerSpec = Box::new(move |token| {
        DynManagedResource::new_box(spawn_relay(
            worker_name,
            outbox,
            relay_cfg,
            Arc::new(SystemClock),
            token,
            worker_health,
            Arc::new(MetricsOutboxMetrics),
        ))
    });
    module.workers.push(worker);
    // per-domain 探针名（多 relay 各自唯一）：`{OUTBOX_RELAY_PROBE}_{domain}`。
    let probe_name = ProbeName::parse(&format!("{OUTBOX_RELAY_PROBE}_{domain}"))
        .context("parse relay probe name")?;
    module.probes.push((
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
    distributed: DistributedRuntimeDeps,
    timing: &RelayTiming,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let sampler_cfg = timing.sampler.clone();
    let sweeper_cfg = timing.outbox_sweeper.clone();

    let maintenance = pg.infra().outbox_maintenance();
    let coordinator = distributed.outbox_maintenance_coordinator();
    wire_sampler_worker(
        CoordinatedOutboxBacklog::new(maintenance.clone(), coordinator.clone()),
        sampler_cfg,
        module,
    )?;
    wire_sweeper_worker(
        CoordinatedRetentionSweeper::new(maintenance, coordinator),
        sweeper_cfg,
        SWEEPER_WORKER_NAME,
        OUTBOX_SWEEPER_PROBE,
        RetentionTarget::OutboxPublished,
        module,
    )?;

    Ok(())
}

fn wire_sampler_worker(
    maintenance: CoordinatedOutboxBacklog<postgres::PgOutboxMaintenance>,
    config: SamplerConfig,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let health = Arc::new(WorkerHealth::healthy());
    let worker_health = Arc::clone(&health);
    let worker: WorkerSpec = Box::new(move |token| {
        DynManagedResource::new_box(ThreadedEventWorker::spawn(
            "outbox-sampler",
            token,
            move |thread_token| {
                let _stopped = worker_health.stopped_on_exit();
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .enable_io()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        tracing::error!(error = %err, "outbox sampler runtime build failed");
                        return;
                    }
                };
                runtime.block_on(backlog_sampler_loop(
                    Arc::new(maintenance),
                    config,
                    thread_token,
                    Arc::clone(&worker_health),
                    Arc::new(MetricsOutboxMetrics),
                ));
            },
        ))
    });
    module.workers.push(worker);

    let probe_name =
        ProbeName::parse(OUTBOX_SAMPLER_PROBE).context("parse outbox sampler probe name")?;
    module.probes.push((
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
    module: &mut DomainModuleResult,
) -> anyhow::Result<()>
where
    S: RetentionSweeper + Send + Sync + 'static,
{
    let health = Arc::new(WorkerHealth::healthy());
    let worker_health = Arc::clone(&health);
    let worker: WorkerSpec = Box::new(move |token| {
        DynManagedResource::new_box(ThreadedEventWorker::spawn(
            worker_name,
            token,
            move |thread_token| {
                let _stopped = worker_health.stopped_on_exit();
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .enable_io()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        tracing::error!(error = %err, "outbox sweeper runtime build failed");
                        return;
                    }
                };
                runtime.block_on(sweeper_loop(
                    Arc::new(maintenance),
                    config,
                    Arc::new(SystemClock),
                    thread_token,
                    Arc::clone(&worker_health),
                    target,
                ));
            },
        ))
    });
    module.workers.push(worker);

    let probe_name = ProbeName::parse(probe_name).context("parse sweeper probe name")?;
    module.probes.push((
        probe_name.clone(),
        Box::new(WorkerHealthProbe {
            name: probe_name,
            health,
        }),
    ));
    Ok(())
}

/// Consumer resource bundle 接线（PG inbox + DLX + subscriber + worker + probe + inbox sweeper）。
fn wire_consumer_resource_bundle(
    pg: &PgRuntimeHandle,
    subscribers: Vec<BridgedSubscription>,
    amqp_map: &BTreeMap<String, amqp::AmqpRuntimeDeps>,
    security: &EventSecurity,
    timing: &RelayTiming,
    audit_key: &MacKey,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
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
            ConsumerTxWorkerInputs {
                worker_name,
                subscriber,
                topic,
                idempotency,
                dlx,
                meta,
                lease_cfg,
                health: Arc::clone(&consumer_health),
            },
        )?;
        tracing::info!(
            consumer,
            contract_id,
            topic = topic_name,
            external_effect_policy = ?subscription.consumer_tx.policy(),
            "durable event transport: pg consumer-tx worker registered"
        );
        match subscription.readiness() {
            SubscriberReadiness::Required => {
                // Required 是 generated topology 的强制服务语义：worker 与 readyz probe 必须成对注册。
                // 穷尽 match 让未来新增 readiness variant 在组合根编译失败，而不是静默降级。
                module.workers.push(worker);
                module.probes.push(consumer_probe);
            }
        }
    }
    wire_inbox_sweeper(pg, timing, module)?;
    Ok(())
}

enum ConsumerTxPlan {
    AuditSessionCreated,
    AuditRoleAssigned,
    AuditRoleRevoked,
    AuditPolicyUpdated,
    SettingsConfigVersionChanged(Arc<settings::ConfigVersionReconciler>),
}

impl ConsumerTxPlan {
    const fn policy(&self) -> ExternalEffectPolicy {
        match self {
            Self::AuditSessionCreated
            | Self::AuditRoleAssigned
            | Self::AuditRoleRevoked
            | Self::AuditPolicyUpdated => ExternalEffectPolicy::TransactionalOnly,
            Self::SettingsConfigVersionChanged(_) => ExternalEffectPolicy::Reconcile,
        }
    }
}

#[cfg(test)]
fn test_capability_for_spec(spec: SubscriptionSpec) -> anyhow::Result<SubscriberCapability> {
    let invalid = || {
        anyhow::anyhow!(
            "generated subscription capability is inactive or invalid: consumer={} execution={:?} effect={:?} policy={:?}",
            spec.consumer(),
            spec.execution(),
            spec.effect(),
            spec.external_effect_policy()
        )
    };
    let capability = match spec.external_effect_policy() {
        ExternalEffectPolicy::TransactionalOnly => match (spec.execution(), spec.effect()) {
            (SubscriptionExecution::AdapterNative, None) => {
                SubscriberCapability::AdapterNativeTransactional
            }
            (
                SubscriptionExecution::AdapterNative,
                Some(SubscriptionEffect::SettingsConfigVersionRefresh),
            )
            | (SubscriptionExecution::DomainEffect, None)
            | (
                SubscriptionExecution::DomainEffect,
                Some(SubscriptionEffect::SettingsConfigVersionRefresh),
            ) => return Err(invalid()),
        },
        ExternalEffectPolicy::Reconcile => match (spec.execution(), spec.effect()) {
            (
                SubscriptionExecution::DomainEffect,
                Some(SubscriptionEffect::SettingsConfigVersionRefresh),
            ) => SubscriberCapability::DomainReconcile(ReconcileSubscriberOwner::from_owner(
                settings::ConfigVersionReconciler::test_ack(),
            )),
            (SubscriptionExecution::AdapterNative, None)
            | (
                SubscriptionExecution::AdapterNative,
                Some(SubscriptionEffect::SettingsConfigVersionRefresh),
            )
            | (SubscriptionExecution::DomainEffect, None) => return Err(invalid()),
        },
        ExternalEffectPolicy::IdempotencyKey | ExternalEffectPolicy::Compensated => {
            return Err(invalid());
        }
    };
    Ok(capability)
}

#[cfg(test)]
fn consumer_tx_plan_for_spec(spec: SubscriptionSpec) -> anyhow::Result<ConsumerTxPlan> {
    let capability = test_capability_for_spec(spec)?;
    resolve_consumer_tx_plan(spec, capability)
}

fn resolve_consumer_tx_plan(
    spec: SubscriptionSpec,
    capability: SubscriberCapability,
) -> anyhow::Result<ConsumerTxPlan> {
    resolve_consumer_tx_plan_parts(
        spec.dispatch(),
        spec.execution(),
        spec.effect(),
        spec.external_effect_policy(),
        capability,
    )
}

fn resolve_consumer_tx_plan_parts(
    dispatch: SubscriptionDispatchKey,
    execution: SubscriptionExecution,
    effect: Option<SubscriptionEffect>,
    policy: ExternalEffectPolicy,
    capability: SubscriberCapability,
) -> anyhow::Result<ConsumerTxPlan> {
    match policy {
        ExternalEffectPolicy::TransactionalOnly | ExternalEffectPolicy::Reconcile => {}
        ExternalEffectPolicy::IdempotencyKey | ExternalEffectPolicy::Compensated => {
            anyhow::bail!(
                "unsupported active ConsumerTx external-effect policy: dispatch={dispatch:?} policy={policy:?}"
            );
        }
    }
    match dispatch {
        SubscriptionDispatchKey::IdentitySessionCreatedV1Audit => adapter_native_plan(
            dispatch,
            execution,
            effect,
            policy,
            capability,
            ConsumerTxPlan::AuditSessionCreated,
        ),
        SubscriptionDispatchKey::IdentityRoleAssignedV1Audit => adapter_native_plan(
            dispatch,
            execution,
            effect,
            policy,
            capability,
            ConsumerTxPlan::AuditRoleAssigned,
        ),
        SubscriptionDispatchKey::IdentityRoleRevokedV1Audit => adapter_native_plan(
            dispatch,
            execution,
            effect,
            policy,
            capability,
            ConsumerTxPlan::AuditRoleRevoked,
        ),
        SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit => adapter_native_plan(
            dispatch,
            execution,
            effect,
            policy,
            capability,
            ConsumerTxPlan::AuditPolicyUpdated,
        ),
        SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings => {
            settings_config_refresh_plan(dispatch, execution, effect, policy, capability)
        }
    }
}

fn adapter_native_plan(
    dispatch: SubscriptionDispatchKey,
    execution: SubscriptionExecution,
    effect: Option<SubscriptionEffect>,
    policy: ExternalEffectPolicy,
    capability: SubscriberCapability,
    plan: ConsumerTxPlan,
) -> anyhow::Result<ConsumerTxPlan> {
    let generated_matches = match execution {
        SubscriptionExecution::AdapterNative => match effect {
            None => match policy {
                ExternalEffectPolicy::TransactionalOnly => true,
                ExternalEffectPolicy::IdempotencyKey
                | ExternalEffectPolicy::Reconcile
                | ExternalEffectPolicy::Compensated => false,
            },
            Some(SubscriptionEffect::SettingsConfigVersionRefresh) => false,
        },
        SubscriptionExecution::DomainEffect => false,
    };
    match capability {
        SubscriberCapability::AdapterNativeTransactional if generated_matches => Ok(plan),
        SubscriberCapability::AdapterNativeTransactional
        | SubscriberCapability::DomainReconcile(_) => anyhow::bail!(
            "adapter-native subscription dispatch or runtime capability mismatch: dispatch={dispatch:?} execution={execution:?} effect={effect:?} policy={policy:?}"
        ),
    }
}

fn settings_config_refresh_plan(
    dispatch: SubscriptionDispatchKey,
    execution: SubscriptionExecution,
    effect: Option<SubscriptionEffect>,
    policy: ExternalEffectPolicy,
    capability: SubscriberCapability,
) -> anyhow::Result<ConsumerTxPlan> {
    let generated_matches = match execution {
        SubscriptionExecution::AdapterNative => false,
        SubscriptionExecution::DomainEffect => match effect {
            None => false,
            Some(SubscriptionEffect::SettingsConfigVersionRefresh) => match policy {
                ExternalEffectPolicy::Reconcile => true,
                ExternalEffectPolicy::TransactionalOnly
                | ExternalEffectPolicy::IdempotencyKey
                | ExternalEffectPolicy::Compensated => false,
            },
        },
    };
    match capability {
        SubscriberCapability::DomainReconcile(effect) if generated_matches => effect
            .into_owner::<settings::ConfigVersionReconciler>()
            .map(ConsumerTxPlan::SettingsConfigVersionChanged)
            .map_err(|_| {
                anyhow::anyhow!(
                    "settings config-version refresh owner capability mismatch: dispatch={dispatch:?}"
                )
            }),
        SubscriberCapability::AdapterNativeTransactional
        | SubscriberCapability::DomainReconcile(_) => anyhow::bail!(
            "settings config-version refresh subscription dispatch or runtime capability mismatch: dispatch={dispatch:?} execution={execution:?} effect={effect:?} policy={policy:?}"
        ),
    }
}

struct ConsumerTxWorkerInputs {
    worker_name: String,
    subscriber: Box<diport::DynAckableSubscriber<'static>>,
    topic: Topic,
    idempotency: Arc<postgres::PgInboxStore>,
    dlx: Box<DynDeadLetterStore<'static>>,
    meta: ConsumerMeta,
    lease_cfg: LeaseConfig,
    health: Arc<WorkerHealth>,
}

fn consumer_tx_worker_for_subscription(
    pg: &PgRuntimeHandle,
    subscription: &BridgedSubscription,
    audit_key: &MacKey,
    inputs: ConsumerTxWorkerInputs,
) -> anyhow::Result<WorkerSpec> {
    let audit_hasher = || {
        AuditChainHasher::new(RustCryptoMacVerifier, audit_key.clone()).ok_or_else(|| {
            anyhow::anyhow!(
                "audit chain key must be at least 32 bytes (weak key, see audit-ledger.md)"
            )
        })
    };
    match &subscription.consumer_tx {
        ConsumerTxPlan::AuditSessionCreated => {
            let hasher = audit_hasher().context("audit session-created consumer tx chain key")?;
            let handler = pg
                .for_domain::<caps::Audit>()
                .session_created_consumer_tx(hasher);
            Ok(consumer_tx_worker_spec::<policy::TransactionalOnly, _>(
                inputs, handler,
            ))
        }
        ConsumerTxPlan::AuditRoleAssigned => {
            let hasher = audit_hasher().context("audit role-assigned consumer tx chain key")?;
            let handler = pg
                .for_domain::<caps::Audit>()
                .role_assigned_consumer_tx(hasher);
            Ok(consumer_tx_worker_spec::<policy::TransactionalOnly, _>(
                inputs, handler,
            ))
        }
        ConsumerTxPlan::AuditRoleRevoked => {
            let hasher = audit_hasher().context("audit role-revoked consumer tx chain key")?;
            let handler = pg
                .for_domain::<caps::Audit>()
                .role_revoked_consumer_tx(hasher);
            Ok(consumer_tx_worker_spec::<policy::TransactionalOnly, _>(
                inputs, handler,
            ))
        }
        ConsumerTxPlan::AuditPolicyUpdated => {
            let hasher = audit_hasher().context("audit policy-updated consumer tx chain key")?;
            let handler = pg
                .for_domain::<caps::Audit>()
                .policy_updated_consumer_tx(hasher);
            Ok(consumer_tx_worker_spec::<policy::TransactionalOnly, _>(
                inputs, handler,
            ))
        }
        ConsumerTxPlan::SettingsConfigVersionChanged(effect) => {
            let handler = pg
                .for_domain::<caps::Settings>()
                .config_version_changed_consumer_tx(effect.clone());
            Ok(consumer_tx_worker_spec::<policy::Reconcile, _>(
                inputs, handler,
            ))
        }
    }
}

fn consumer_tx_worker_spec<P, H>(inputs: ConsumerTxWorkerInputs, handler: H) -> WorkerSpec
where
    P: policy::Policy,
    H: ConsumerTxHandler<P>,
{
    let ConsumerTxWorkerInputs {
        worker_name,
        subscriber,
        topic,
        idempotency,
        dlx,
        meta,
        lease_cfg,
        health,
    } = inputs;
    Box::new(move |token| {
        DynManagedResource::new_box(spawn_consumer_ackable_tx_subscriber(
            worker_name,
            subscriber,
            topic,
            idempotency,
            dlx,
            meta,
            handler,
            lease_cfg,
            token,
            health,
        ))
    })
}

fn wire_inbox_sweeper(
    pg: &PgRuntimeHandle,
    timing: &RelayTiming,
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
    let worker: WorkerSpec = Box::new(move |token| {
        let loop_health = Arc::clone(&worker_health);
        let loop_token = token.clone();
        let handle = tokio::spawn(async move {
            let _stopped = loop_health.stopped_on_exit();
            sweeper_loop(
                Arc::new(sweeper),
                config,
                Arc::new(SystemClock),
                loop_token,
                Arc::clone(&loop_health),
                RetentionTarget::InboxReceipts,
            )
            .await;
        });
        DynManagedResource::new_box(SweeperWorker::adopt(
            INBOX_SWEEPER_WORKER_NAME,
            handle,
            worker_health,
            token,
        ))
    });
    module.workers.push(worker);

    let probe_name =
        ProbeName::parse(INBOX_SWEEPER_PROBE).context("parse inbox sweeper probe name")?;
    module.probes.push((
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
fn parse_topology(s: &str) -> anyhow::Result<bootstrap::Topology> {
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
    epoch_secs_from_system_time(SystemClock.now())
}

fn epoch_secs_from_system_time(now: SystemTime) -> i64 {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
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

fn build_dlx_payload_protector_from(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<DlxPayloadProtector> {
    let key_name = get(DLX_PAYLOAD_KEY_NAME_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {DLX_PAYLOAD_KEY_NAME_ENV}"))?;
    let key_name = DlxHotKeyName::try_new(key_name.trim().to_string())
        .map_err(|e| anyhow::anyhow!("{DLX_PAYLOAD_KEY_NAME_ENV} is invalid: {e}"))?;
    let provider = build_dlx_hot_vault_key_provider_from(get)?;
    Ok(DlxPayloadProtector::new(
        DynKeyProvider::new_box(provider),
        key_name,
    ))
}

pub(crate) fn build_dlx_hot_vault_key_provider_from(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<VaultKeyProvider> {
    build_dlx_vault_key_providers_from(get).map(|(hot, _archive)| hot)
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

        let Err(error) = resolve_consumer_tx_plan(spec, capability) else {
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
        let mut registry = bootstrap::Registry::new();
        registry
            .subscriber(
                contract_id,
                topic,
                consumer,
                consistency::ConsumerGroup::parse(group).unwrap(),
                capability,
            )
            .unwrap();
        registry.drain_subscribers().pop().unwrap()
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
        bridge_subscriptions_with_events(
            vec![test_binding(contract_id, topic, consumer, group)],
            &[event],
        )
        .unwrap()
        .pop()
        .unwrap()
    }

    #[test]
    fn event_worker_config_reads_one_snapshot_generation() {
        let snapshot = crate::config::test_snapshot(&[
            ("RSS_RELAY_POLL_INTERVAL_MS", "201"),
            ("RSS_RELAY_MAX_IN_FLIGHT", "17"),
            ("RSS_RELAY_SAMPLE_INTERVAL_MS", "30001"),
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
            worker.outbox_sweep_interval(),
            Duration::from_millis(300_001)
        );
        assert_eq!(worker.outbox_retain_seconds(), 604_801);
    }

    #[test]
    fn event_transport_config_is_minted_from_snapshot_capability() {
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
        let config = EventTransportConfig::from_mapper(&mapper).unwrap_or_else(|_| unreachable!());

        assert!(matches!(config.decision, EventDecision::Durable { .. }));
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
        let audit_plan = resolve_consumer_tx_plan_parts(
            audit.dispatch(),
            audit.execution(),
            audit.effect(),
            vocab::ExternalEffectPolicy::TransactionalOnly,
            SubscriberCapability::AdapterNativeTransactional,
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            audit_plan.policy(),
            vocab::ExternalEffectPolicy::TransactionalOnly
        );
        assert!(matches!(audit_plan, ConsumerTxPlan::AuditSessionCreated));

        let settings = generated::event::settings_v1::SPEC.subscriptions()[0];
        let settings_plan = resolve_consumer_tx_plan_parts(
            settings.dispatch(),
            settings.execution(),
            settings.effect(),
            vocab::ExternalEffectPolicy::Reconcile,
            reconcile_capability(),
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            settings_plan.policy(),
            vocab::ExternalEffectPolicy::Reconcile
        );
        assert!(matches!(
            settings_plan,
            ConsumerTxPlan::SettingsConfigVersionChanged(_)
        ));
    }

    #[test]
    fn consumer_tx_plan_rejects_generated_execution_capability_mismatch() {
        let audit = generated::event::identity_v1::session_created::SPEC.subscriptions()[0];
        assert!(
            resolve_consumer_tx_plan_parts(
                audit.dispatch(),
                audit.execution(),
                audit.effect(),
                vocab::ExternalEffectPolicy::TransactionalOnly,
                reconcile_capability(),
            )
            .is_err(),
            "adapter-native generated execution must reject a reconcile capability"
        );

        let settings = generated::event::settings_v1::SPEC.subscriptions()[0];
        assert!(
            resolve_consumer_tx_plan_parts(
                settings.dispatch(),
                settings.execution(),
                settings.effect(),
                vocab::ExternalEffectPolicy::Reconcile,
                SubscriberCapability::AdapterNativeTransactional,
            )
            .is_err(),
            "domain-reconcile generated execution must reject a transactional capability"
        );
    }

    #[test]
    fn inactive_external_effect_policies_fail_closed_before_worker_activation() -> anyhow::Result<()>
    {
        let audit = generated::event::identity_v1::session_created::SPEC.subscriptions()[0];
        for policy in [
            vocab::ExternalEffectPolicy::IdempotencyKey,
            vocab::ExternalEffectPolicy::Compensated,
        ] {
            let Err(error) = resolve_consumer_tx_plan_parts(
                audit.dispatch(),
                audit.execution(),
                audit.effect(),
                policy,
                SubscriberCapability::AdapterNativeTransactional,
            ) else {
                anyhow::bail!("{policy:?} must not produce an active ConsumerTx plan");
            };
            assert!(
                error.to_string().contains("unsupported") || error.to_string().contains("mismatch"),
                "inactive policy must fail closed with an actionable error: {error:#}"
            );
        }
        Ok(())
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
            let plan = resolve_consumer_tx_plan(*spec, capability)
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

        assert_eq!(transactional, 4);
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
    fn explicit_plaintext_values_require_loopback_and_opt_in() {
        assert!(
            EventTransportTestValues::durable_shared("amqp://su:sp@broker/shared")
                .with_plaintext_policy("true")
                .build()
                .is_err()
        );
        assert!(
            EventTransportTestValues::durable_shared("amqp://su:sp@127.0.0.1/shared")
                .with_plaintext_policy("true")
                .build()
                .is_ok()
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
        assert_eq!(worker.relay_budget().required_budget_millis(), 50_000);
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
    fn dlx_vault_key_providers_require_distinct_workload_tokens() {
        let reused = build_dlx_hot_vault_key_provider_from(&|name| match name {
            VAULT_ADDR_ENV => Some("https://vault.example.test".to_owned()),
            VAULT_TRANSIT_MOUNT_ENV => Some("transit".to_owned()),
            DLX_HOT_VAULT_TOKEN_ENV | DLX_ARCHIVE_VAULT_TOKEN_ENV => Some("same-token".to_owned()),
            _ => None,
        });
        let error = reused.err().map(|error| format!("{error:#}"));
        assert!(error.is_some_and(|error| error.contains("must differ")));

        let generic_only = build_dlx_hot_vault_key_provider_from(&|name| match name {
            VAULT_ADDR_ENV => Some("https://vault.example.test".to_owned()),
            VAULT_TRANSIT_MOUNT_ENV => Some("transit".to_owned()),
            "RSS_VAULT_TOKEN" => Some("generic-token".to_owned()),
            _ => None,
        });
        let error = generic_only.err().map(|error| format!("{error:#}"));
        assert!(error.is_some_and(|error| error.contains(DLX_HOT_VAULT_TOKEN_ENV)));

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
        tick_signal: Option<std::sync::mpsc::Sender<()>>,
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
            tick_signal: std::sync::mpsc::Sender<()>,
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

    impl DlxLifecycleMetrics for RecordingDlxMetrics {
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
            token,
            Arc::clone(&health),
            metrics,
            Arc::new(SequenceClock::new([SystemTime::UNIX_EPOCH; 2])),
            DlxWorkerConfig::canonical(),
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
            loop_token,
            Arc::new(WorkerHealth::starting()),
            Arc::new(RecordingDlxMetrics::default()),
            Arc::new(SequenceClock::new([SystemTime::UNIX_EPOCH])),
            DlxWorkerConfig::canonical(),
        ));
        tokio::task::yield_now().await;
        token.cancel();

        let stopped = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert!(matches!(stopped, Ok(Ok(()))));
    }

    #[tokio::test(start_paused = true)]
    async fn dlx_loop_degrades_when_total_tick_io_budget_expires() {
        let token = tokio_util::sync::CancellationToken::new();
        let health = Arc::new(WorkerHealth::starting());
        let metrics = Arc::new(RecordingDlxMetrics::default());
        let handle = tokio::spawn(dlx_lifecycle_loop(
            NeverCompletingDlxTickRunner,
            FakeDlxBacklogReader(Ok(DlxArchiveBacklog::new(0, 0))),
            token.clone(),
            Arc::clone(&health),
            Arc::clone(&metrics) as Arc<dyn DlxLifecycleMetrics>,
            Arc::new(SequenceClock::new([SystemTime::UNIX_EPOCH])),
            DlxWorkerConfig::canonical(),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(DLX_LIFECYCLE_TICK_TIMEOUT).await;
        tokio::task::yield_now().await;

        assert_eq!(health.status(), primitives::healthz::HealthStatus::Degraded);
        assert_eq!(
            metrics
                .sweeps
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)[0]
                .outcome,
            RetentionOutcome::Transient
        );
        token.cancel();
        assert!(handle.await.is_ok());
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
    async fn dlx_worker_builder_runs_tick_on_owned_runtime_and_stops_cleanly() {
        let token = tokio_util::sync::CancellationToken::new();
        let (tick_signal, tick_observed) = std::sync::mpsc::channel();
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
        );

        let resource = worker(token);
        assert!(tick_observed.recv_timeout(Duration::from_secs(2)).is_ok());
        assert!(resource.shutdown().await.is_ok());
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
    fn dlx_clock_helpers_fail_closed_for_pre_epoch_and_backwards_time() {
        assert_eq!(
            epoch_secs_from_system_time(SystemTime::UNIX_EPOCH - Duration::from_secs(1)),
            0
        );
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
        let worker_health = Arc::clone(&health);
        let token = tokio_util::sync::CancellationToken::new();
        let worker = ThreadedEventWorker::spawn("test-threaded-worker", token, move |_| {
            let _stopped = worker_health.stopped_on_exit();
        });

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
