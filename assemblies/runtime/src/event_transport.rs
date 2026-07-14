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
use base64::Engine as _;
use bootstrap::{
    DomainModuleResult, LifecycleChannel, ProviderOutputBinding, SubscriberBinding,
    SubscriberExecution, WorkerSpec,
};
use consistency::{ConsumerGroup, RetentionSweeper};
use crypto::RustCryptoMacVerifier;
use diport::{
    Clock, DlxArchiveBacklog, DlxLifecycleError, DlxLifecycleRepository, DynDeadLetterStore,
    DynKeyProvider, DynManagedResource, ManagedResource, ShutdownError, Topic,
};
use eventexec::{
    ConsumerMeta, ConsumerTxHandlerFn, DlxArchiveKeyName, DlxHotKeyName, DlxLifecycle,
    DlxLifecycleHealth, DlxLifecycleMetrics, DlxLifecycleTickReport, EVENT_CONSUMER_PROBE,
    LeaseConfig, MetricsDlxLifecycleMetrics, MetricsOutboxMetrics, OUTBOX_RELAY_PROBE,
    OUTBOX_SAMPLER_PROBE, OUTBOX_SWEEPER_PROBE, RelayConfig, RetentionOutcome, RetentionTarget,
    SWEEPER_WORKER_NAME, SamplerConfig, SweeperConfig, SweeperWorker, TenantAuthority,
    WorkerHealth, apply_dlx_lifecycle_health, backlog_sampler_loop,
    spawn_consumer_ackable_tx_subscriber, spawn_relay, sweeper_loop,
};
use generated::event::{
    EventSpec, SubscriberReadiness, SubscriptionDispatchKey, SubscriptionEffect,
    SubscriptionExecution, SubscriptionSpec,
};
use postgres::{
    AuditConsumerTxEffect as _, DlxPayloadProtector, PgDlxLifecycleRepository,
    PgDlxLifecycleRuntime, PgRuntimeHandle, caps,
};
use primitives::{HealthCheck, MacKey, ProbeName};
use vault::VaultKeyProvider;

use crate::distributed_runtime::{
    CoordinatedOutboxBacklog, CoordinatedRetentionSweeper, DistributedRuntimeDeps,
};
use crate::infra::plaintext_endpoint_policy_from;
use crate::infra::vault::{DEFAULT_VAULT_TIMEOUT, build_vault_tls_client_from};
use crate::{EnvSecret, SystemClock};

const EVENT_CHANNELS: &[LifecycleChannel] = &[
    LifecycleChannel::Probes,
    LifecycleChannel::Resources,
    LifecycleChannel::Workers,
];
const DLX_STORE_CHANNELS: &[LifecycleChannel] =
    &[LifecycleChannel::Probes, LifecycleChannel::Workers];
const DLX_KEY_PROVIDER_CHANNELS: &[LifecycleChannel] = &[LifecycleChannel::Workers];

pub(crate) const PROVIDER_OUTPUT_BINDINGS: &[ProviderOutputBinding] = &[
    ProviderOutputBinding {
        port: "diport::Publisher",
        provider: "amqp::AmqpPublisher",
        consumer: "eventexec",
        channels: EVENT_CHANNELS,
    },
    ProviderOutputBinding {
        port: "diport::AckableSubscriber",
        provider: "amqp::AmqpSubscriber",
        consumer: "eventexec",
        channels: EVENT_CHANNELS,
    },
    ProviderOutputBinding {
        port: "diport::DlxLifecycleRepository",
        provider: "postgres::PgDlxLifecycleRepository",
        consumer: "eventexec",
        channels: EVENT_CHANNELS,
    },
    ProviderOutputBinding {
        port: "diport::DlxArchiveStore",
        provider: "s3::VerifiedS3DlxArchiveStore",
        consumer: "eventexec",
        channels: DLX_STORE_CHANNELS,
    },
    ProviderOutputBinding {
        port: "diport::KeyProvider",
        provider: "vault::VaultKeyProvider",
        consumer: "eventexec",
        channels: DLX_KEY_PROVIDER_CHANNELS,
    },
];

// ── 对外类型 ──────────────────────────────────────────────────────────────────

/// topology-gated 事件传输接线的完整配置（由 [`build_event_transport_config_from`] 从 env 构造）。
pub struct EventTransportConfig {
    /// 当前拓扑（Demo / DurableShared / DurableIsolated）。
    pub topology: bootstrap::Topology,
    /// AMQP per-domain 传输配置（per-domain URL 集合）。
    pub transport: bootstrap::eventtransport::TransportConfig,
    /// Outbox relay 轮询间隔。
    pub relay_poll_interval: Duration,
    /// Outbox relay 单轮最大在途 claim/publish 数。
    pub relay_max_in_flight: usize,
    /// Outbox relay backlog 采样间隔。
    pub relay_sample_interval: Duration,
    /// Outbox published-row sweeper 扫描间隔。
    pub outbox_sweep_interval: Duration,
    /// Outbox published-row 保留期（秒）。
    pub outbox_retain_seconds: u64,
    /// Tenant authority signer/verifier（durable 必填；Demo 为 `None`）。
    pub tenant_authority: Option<Arc<TenantAuthority>>,
    /// DLX payload protector（durable 必填；Demo 为 `None`）。
    pub dlx_payload_protector: Option<DlxPayloadProtector>,
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
    poll: Duration,
    max_in_flight: usize,
    sample: Duration,
    sweep: Duration,
    retain_seconds: u64,
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
        let (contract_id, topic, consumer, binding_group, execution) = binding.into_parts();
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
        let consumer_tx = resolve_consumer_tx_plan(spec, execution)?;
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
fn resolve_event_decision(
    topology: bootstrap::Topology,
    transport: bootstrap::eventtransport::TransportConfig,
    required: &[&str],
) -> anyhow::Result<EventDecision> {
    let transport = bootstrap::eventtransport::resolve(topology, transport, required)
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
) -> anyhow::Result<DomainModuleResult> {
    let required = required_domains(&subscribers);
    let required_refs: Vec<&str> = required.iter().map(String::as_str).collect();
    let timing = RelayTiming {
        poll: cfg.relay_poll_interval,
        max_in_flight: cfg.relay_max_in_flight,
        sample: cfg.relay_sample_interval,
        sweep: cfg.outbox_sweep_interval,
        retain_seconds: cfg.outbox_retain_seconds,
    };
    let security = event_security_for_topology(cfg.topology, &cfg)?;
    match resolve_event_decision(cfg.topology, cfg.transport, &required_refs)? {
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
            wire_durable(pg, distributed, subscribers, per_domain, timing, security).await
        }
    }
}

/// Wires the single production DLX lifecycle worker. The owner is consumed here so the dedicated
/// PostgreSQL pool and worker are registered through the same lifecycle funnel.
pub(crate) fn wire_dlx_lifecycle(
    deps: DlxLifecycleRuntimeDeps,
) -> anyhow::Result<DomainModuleResult> {
    let DlxLifecycleRuntimeDeps {
        pg_owner,
        backlog_repository,
        archive_store_readiness,
        lifecycle,
    } = deps;
    let health = Arc::new(WorkerHealth::starting());
    let worker = build_dlx_lifecycle_worker(lifecycle, backlog_repository, Arc::clone(&health));
    let (probe_name, probe) = build_dlx_lifecycle_probe(health)?;
    let archive_health = Arc::new(WorkerHealth::starting());
    let archive_worker =
        build_dlx_archive_readiness_worker(archive_store_readiness, Arc::clone(&archive_health));
    let archive_probe_name = ProbeName::parse(DLX_ARCHIVE_READINESS_PROBE)
        .context("parse DLX archive readiness probe name")?;
    let archive_probe = Box::new(WorkerHealthProbe::new(
        archive_probe_name.clone(),
        archive_health,
    ));
    Ok(DomainModuleResult {
        probes: vec![(probe_name, probe), (archive_probe_name, archive_probe)],
        resources: vec![DynManagedResource::new_box(pg_owner)],
        workers: vec![worker, archive_worker],
    })
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

fn build_dlx_archive_readiness_worker<S>(store: S, health: Arc<WorkerHealth>) -> WorkerSpec
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
                ));
            },
        ))
    })
}

async fn dlx_archive_readiness_loop<S>(
    store: S,
    token: tokio_util::sync::CancellationToken,
    health: Arc<WorkerHealth>,
) where
    S: DlxArchiveReadiness,
{
    let mut ticker = tokio::time::interval(DLX_ARCHIVE_READINESS_INTERVAL);
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                if run_bounded_dlx_archive_readiness_probe(&store, &token, &health).await
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
) -> DlxLoopStep
where
    S: DlxArchiveReadiness,
{
    tokio::select! {
        biased;
        () = token.cancelled() => DlxLoopStep::Cancelled,
        probe = tokio::time::timeout(
            DLX_ARCHIVE_READINESS_TIMEOUT,
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
                ));
            },
        ))
    })
}

fn build_dlx_lifecycle_probe(
    health: Arc<WorkerHealth>,
) -> anyhow::Result<(ProbeName, Box<dyn bootstrap::HealthProbe>)> {
    let probe_name =
        ProbeName::parse(DLX_LIFECYCLE_PROBE).context("parse DLX lifecycle probe name")?;
    let probe = Box::new(WorkerHealthProbe::new(probe_name.clone(), health));
    Ok((probe_name, probe))
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
) where
    L: DlxTickRunner,
    B: DlxBacklogReader,
{
    let mut ticker = tokio::time::interval(DLX_LIFECYCLE_INTERVAL);
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
) -> DlxLoopStep
where
    L: DlxTickRunner,
    B: DlxBacklogReader,
{
    tokio::select! {
        biased;
        () = token.cancelled() => DlxLoopStep::Cancelled,
        result = tokio::time::timeout(
            DLX_LIFECYCLE_TICK_TIMEOUT,
            run_dlx_lifecycle_tick(lifecycle, backlog_repository, health, metrics, clock),
        ) => {
            if result.is_err() {
                apply_dlx_lifecycle_health(health, DlxLifecycleHealth::Degraded);
                metrics.record_sweep(
                    RetentionTarget::DeadLetter,
                    RetentionOutcome::Transient,
                    0,
                    DLX_LIFECYCLE_TICK_TIMEOUT.as_secs_f64(),
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

/// 从注入式 getter 构造 [`EventTransportConfig`]（无 env 侧效应，单测友好）。
///
/// 必填 env var：
/// - `RSS_TOPOLOGY`：`demo` | `durable-shared` | `durable-isolated`（必填）
///
/// AMQP broker URL（非 Demo；至少一个，否则 `eventtransport::resolve` per-domain fail-closed）：
/// - `RSS_<DOMAIN>_AMQP_URL`（如 `RSS_IDENTITY_AMQP_URL`）：per-domain broker URL（优先）。
/// - `RSS_AMQP_URL`：共享回退（`durable-shared` 缺 per-domain 时回退；`durable-isolated` 配此即 fail-closed）。
///
/// 可选 env var（缺失时使用括号内默认值）：
/// - `RSS_RELAY_POLL_INTERVAL_MS`（200ms）
/// - `RSS_RELAY_MAX_IN_FLIGHT`（16）
/// - `RSS_RELAY_SAMPLE_INTERVAL_MS`（30000ms）
/// - `RSS_OUTBOX_SWEEP_INTERVAL_MS`（300000ms）
/// - `RSS_OUTBOX_RETAIN_SECONDS`（604800s）
///
/// Durable 必填安全配置：
/// - `RSS_TENANT_AUTHORITY_HMAC_KEY_B64URL`（base64url no-pad，解码后至少 32 bytes）
/// - `RSS_DLX_PAYLOAD_KEY_NAME`（Vault Transit key name）
/// - `RSS_VAULT_ADDR` / `RSS_DLX_HOT_VAULT_TOKEN` / `RSS_DLX_ARCHIVE_VAULT_TOKEN` /
///   `RSS_VAULT_TRANSIT_MOUNT`（DLX payload/archive 独立 Vault Transit workloads）
pub fn build_event_transport_config_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<EventTransportConfig> {
    let topo_raw = get("RSS_TOPOLOGY")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_TOPOLOGY"))?;
    let topology = parse_topology(topo_raw.trim())?;

    let transport = if topology == bootstrap::Topology::Demo {
        bootstrap::eventtransport::TransportConfig::default()
    } else {
        // env 只把 AMQP 配置完整映射成 typed config——per-domain（`RSS_<DOMAIN>_AMQP_URL`，优先）+ 共享回退
        // （`RSS_AMQP_URL`）；per-domain/shared 完备性与隔离由 `eventtransport::resolve` 单源 fail-closed 强制，
        // env builder 不提前收窄语义（review #342 F1：durable-shared 仅配 RSS_AMQP_URL 也应可启动）。
        let policy = plaintext_endpoint_policy_from(&get, AMQP_ALLOW_PLAINTEXT_ENV)?;
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
    let (tenant_authority, dlx_payload_protector) = if topology == bootstrap::Topology::Demo {
        (None, None)
    } else {
        (
            Some(build_tenant_authority_from(&get)?),
            Some(build_dlx_payload_protector_from(&get)?),
        )
    };

    Ok(EventTransportConfig {
        topology,
        transport,
        relay_poll_interval: parse_duration_ms_env(
            get("RSS_RELAY_POLL_INTERVAL_MS"),
            "RSS_RELAY_POLL_INTERVAL_MS",
            200,
        ),
        relay_max_in_flight: parse_usize_env(
            get("RSS_RELAY_MAX_IN_FLIGHT"),
            "RSS_RELAY_MAX_IN_FLIGHT",
            16,
        ),
        relay_sample_interval: parse_duration_ms_env(
            get("RSS_RELAY_SAMPLE_INTERVAL_MS"),
            "RSS_RELAY_SAMPLE_INTERVAL_MS",
            30_000,
        ),
        outbox_sweep_interval: parse_duration_ms_env(
            get("RSS_OUTBOX_SWEEP_INTERVAL_MS"),
            "RSS_OUTBOX_SWEEP_INTERVAL_MS",
            300_000,
        ),
        outbox_retain_seconds: parse_u64_env(
            get("RSS_OUTBOX_RETAIN_SECONDS"),
            "RSS_OUTBOX_RETAIN_SECONDS",
            604_800,
        ),
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
) -> anyhow::Result<DomainModuleResult> {
    // projection replay / shadow-swap 由 `rss projections` 离线控制面处理；本函数只装配在线传输 worker。

    let mut module = DomainModuleResult::default();

    // 每个 required 域（generated producer domain ∪ subscriber 订阅 topic owner）由 resolver 保证有已校验
    // AMQP URL → 下方 amqp_map 逐域连接；relay/consumer 取连接时 `.context(...)` 兜底 fail-closed，无需额外 guard。

    // AMQP per-domain 连接（relay 发布 + consumer 订阅共用同一 vhost 连接）。
    let mut amqp_map: BTreeMap<String, amqp::AmqpRuntimeDeps> = BTreeMap::new();
    for (domain_upper, url) in &per_domain {
        let domain = domain_upper.to_ascii_lowercase();
        let amqp_deps = amqp::AmqpRuntimeDeps::connect(url.as_ref(), &domain)
            .await
            .with_context(|| format!("connect amqp for domain '{domain}'"))?;
        module.resources.extend(amqp_deps.runtime_resources());
        tracing::info!(domain, "durable event transport: amqp connected");
        amqp_map.insert(domain, amqp_deps);
    }

    // Relay workers：generated producer registry 是迭代单源；闭枚举 match 把每个 producer 映射到
    // postgres sealed capability。新增 producer 变体若未接 PG capability 会在此编译失败。
    for producer in generated::event::PRODUCER_DOMAINS.iter().copied() {
        let domain = producer.as_str();
        let publisher = relay_publisher(&amqp_map, domain)?;
        let outbox = match producer {
            generated::event::ProducerDomain::Identity => pg.for_domain::<caps::Identity>().outbox(
                publisher,
                Arc::clone(&security.tenant_authority),
                security.dlx_payload_protector.clone(),
            ),
            generated::event::ProducerDomain::Settings => pg.for_domain::<caps::Settings>().outbox(
                publisher,
                Arc::clone(&security.tenant_authority),
                security.dlx_payload_protector.clone(),
            ),
        };
        wire_domain_relay(domain, outbox, &timing, &mut module)?;
    }
    wire_outbox_maintenance(pg, distributed, &timing, &mut module)?;

    // Consumer resource bundle（per binding PG inbox + DLX + subscriber + worker + probe + inbox sweeper）。
    wire_consumer_resource_bundle(pg, subscribers, &amqp_map, &security, &timing, &mut module)?;

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
    let relay_cfg =
        RelayConfig::new(timing.poll, timing.max_in_flight).context("build relay config")?;
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
    let sampler_cfg = SamplerConfig::new(
        generated::event::PRODUCER_DOMAINS
            .iter()
            .map(|domain| domain.as_str().to_string())
            .collect(),
        timing.sample,
    )
    .context("build outbox sampler config")?;
    let sweeper_cfg = SweeperConfig::new(timing.retain_seconds, timing.sweep)
        .context("build outbox sweeper config")?;

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
        let handler = consumer_tx_handler_for_subscription(pg, &subscription)?;
        tracing::info!(
            consumer,
            contract_id,
            topic = topic_name,
            "durable event transport: pg consumer-tx worker registered"
        );
        let health = Arc::clone(&consumer_health);
        let worker: WorkerSpec = Box::new(move |token| {
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
        });
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
    SettingsConfigVersionChanged(bootstrap::SubscriberEffect),
}

#[cfg(test)]
fn test_execution_for_spec(spec: SubscriptionSpec) -> anyhow::Result<SubscriberExecution> {
    let execution = match (spec.execution(), spec.effect()) {
        (SubscriptionExecution::AdapterNative, None) => SubscriberExecution::AdapterNative,
        (
            SubscriptionExecution::DomainEffect,
            Some(SubscriptionEffect::SettingsConfigVersionRefresh),
        ) => SubscriberExecution::DomainEffect(Arc::new(|_, _| {
            Box::pin(async { consistency::HandleResult::ack() })
        })),
        (
            SubscriptionExecution::AdapterNative,
            Some(SubscriptionEffect::SettingsConfigVersionRefresh),
        )
        | (SubscriptionExecution::DomainEffect, None) => {
            return Err(anyhow::anyhow!(
                "generated subscription execution/effect is invalid: consumer={} execution={:?} effect={:?}",
                spec.consumer(),
                spec.execution(),
                spec.effect()
            ));
        }
    };
    Ok(execution)
}

#[cfg(test)]
fn consumer_tx_plan_for_spec(spec: SubscriptionSpec) -> anyhow::Result<ConsumerTxPlan> {
    let execution = test_execution_for_spec(spec)?;
    resolve_consumer_tx_plan(spec, execution)
}

fn resolve_consumer_tx_plan(
    spec: SubscriptionSpec,
    execution: SubscriberExecution,
) -> anyhow::Result<ConsumerTxPlan> {
    match spec.dispatch() {
        SubscriptionDispatchKey::IdentitySessionCreatedV1Audit => {
            adapter_native_plan(spec, execution, ConsumerTxPlan::AuditSessionCreated)
        }
        SubscriptionDispatchKey::IdentityRoleAssignedV1Audit => {
            adapter_native_plan(spec, execution, ConsumerTxPlan::AuditRoleAssigned)
        }
        SubscriptionDispatchKey::IdentityRoleRevokedV1Audit => {
            adapter_native_plan(spec, execution, ConsumerTxPlan::AuditRoleRevoked)
        }
        SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit => {
            adapter_native_plan(spec, execution, ConsumerTxPlan::AuditPolicyUpdated)
        }
        SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings => {
            settings_config_refresh_plan(spec, execution)
        }
    }
}

fn adapter_native_plan(
    spec: SubscriptionSpec,
    execution: SubscriberExecution,
    plan: ConsumerTxPlan,
) -> anyhow::Result<ConsumerTxPlan> {
    match (spec.execution(), spec.effect(), execution) {
        (SubscriptionExecution::AdapterNative, None, SubscriberExecution::AdapterNative) => {
            Ok(plan)
        }
        _ => anyhow::bail!(
            "adapter-native subscription dispatch or runtime execution mismatch: dispatch={:?} consumer={} group={}",
            spec.dispatch(),
            spec.consumer(),
            spec.group()
        ),
    }
}

fn settings_config_refresh_plan(
    spec: SubscriptionSpec,
    execution: SubscriberExecution,
) -> anyhow::Result<ConsumerTxPlan> {
    match (spec.execution(), spec.effect(), execution) {
        (
            SubscriptionExecution::DomainEffect,
            Some(SubscriptionEffect::SettingsConfigVersionRefresh),
            SubscriberExecution::DomainEffect(effect),
        ) => Ok(ConsumerTxPlan::SettingsConfigVersionChanged(effect)),
        _ => anyhow::bail!(
            "settings config-version refresh subscription dispatch or runtime execution mismatch: dispatch={:?} consumer={} group={}",
            spec.dispatch(),
            spec.consumer(),
            spec.group()
        ),
    }
}

fn consumer_tx_handler_for_subscription(
    pg: &PgRuntimeHandle,
    subscription: &BridgedSubscription,
) -> anyhow::Result<ConsumerTxHandlerFn> {
    match &subscription.consumer_tx {
        ConsumerTxPlan::AuditSessionCreated => {
            let hasher = crate::domains::audit::build_audit_hasher(|name| std::env::var(name).ok())
                .context("audit session-created consumer tx chain key")?;
            Ok(pg
                .for_domain::<caps::Audit>()
                .session_created_consumer_tx(hasher)
                .into_handler())
        }
        ConsumerTxPlan::AuditRoleAssigned => {
            let hasher = crate::domains::audit::build_audit_hasher(|name| std::env::var(name).ok())
                .context("audit role-assigned consumer tx chain key")?;
            Ok(pg
                .for_domain::<caps::Audit>()
                .role_assigned_consumer_tx(hasher)
                .into_handler())
        }
        ConsumerTxPlan::AuditRoleRevoked => {
            let hasher = crate::domains::audit::build_audit_hasher(|name| std::env::var(name).ok())
                .context("audit role-revoked consumer tx chain key")?;
            Ok(pg
                .for_domain::<caps::Audit>()
                .role_revoked_consumer_tx(hasher)
                .into_handler())
        }
        ConsumerTxPlan::AuditPolicyUpdated => {
            let hasher = crate::domains::audit::build_audit_hasher(|name| std::env::var(name).ok())
                .context("audit policy-updated consumer tx chain key")?;
            Ok(pg
                .for_domain::<caps::Audit>()
                .policy_updated_consumer_tx(hasher)
                .into_handler())
        }
        ConsumerTxPlan::SettingsConfigVersionChanged(effect) => Ok(pg
            .for_domain::<caps::Settings>()
            .config_version_changed_consumer_tx(Arc::clone(effect))
            .into_handler()),
    }
}

fn wire_inbox_sweeper(
    pg: &PgRuntimeHandle,
    timing: &RelayTiming,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let sweeper = pg.infra().inbox_sweeper();
    let config = SweeperConfig::new(sweeper.retention_seconds(), timing.sweep)
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

pub(crate) fn build_dlx_payload_protector_from(
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
        hot_token.expose() != archive_token.expose(),
        "{DLX_HOT_VAULT_TOKEN_ENV} must differ from {DLX_ARCHIVE_VAULT_TOKEN_ENV}"
    );
    if let Some(general_token) = EnvSecret::optional(get, "RSS_VAULT_TOKEN")? {
        anyhow::ensure!(
            hot_token.expose() != general_token.expose(),
            "{DLX_HOT_VAULT_TOKEN_ENV} must differ from RSS_VAULT_TOKEN"
        );
        anyhow::ensure!(
            archive_token.expose() != general_token.expose(),
            "{DLX_ARCHIVE_VAULT_TOKEN_ENV} must differ from RSS_VAULT_TOKEN"
        );
    }
    let mount = get(VAULT_TRANSIT_MOUNT_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_TRANSIT_MOUNT_ENV}"))?;
    let hot = VaultKeyProvider::new(
        build_vault_tls_client_from(get)?,
        addr.clone(),
        hot_token.into_string(),
        mount.clone(),
        DEFAULT_VAULT_TIMEOUT,
    )
    .map_err(|e| anyhow::anyhow!("DLX hot Vault key provider config error: {e}"))?;
    let archive = VaultKeyProvider::new(
        build_vault_tls_client_from(get)?,
        addr,
        archive_token.into_string(),
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
        let execution = test_execution_for_spec(spec).unwrap();
        test_binding_with_execution(contract_id, topic, consumer, group, execution)
    }

    #[allow(clippy::unwrap_used)]
    fn test_binding_with_execution(
        contract_id: &'static str,
        topic: &'static str,
        consumer: &'static str,
        group: &'static str,
        execution: SubscriberExecution,
    ) -> SubscriberBinding {
        let mut registry = bootstrap::Registry::new();
        registry
            .subscriber(
                contract_id,
                topic,
                consumer,
                consistency::ConsumerGroup::parse(group).unwrap(),
                execution,
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

    fn test_hmac_key_b64url() -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42u8; 32])
    }

    fn durable_security_env(name: &str) -> Option<String> {
        match name {
            TENANT_AUTHORITY_HMAC_KEY_ENV => Some(test_hmac_key_b64url()),
            DLX_PAYLOAD_KEY_NAME_ENV => Some("dlx-payload".to_string()),
            VAULT_ADDR_ENV => Some("https://vault.example:8200".to_string()),
            DLX_HOT_VAULT_TOKEN_ENV => Some("s.dlx-hot-testtoken".to_string()),
            DLX_ARCHIVE_VAULT_TOKEN_ENV => Some("s.dlx-archive-testtoken".to_string()),
            VAULT_TRANSIT_MOUNT_ENV => Some("transit".to_string()),
            _ => None,
        }
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
    fn bridge_generated_subscriptions_rejects_settings_without_domain_effect() {
        let event = generated::event::settings_v1::SPEC;
        let spec = event.subscriptions()[0];
        let binding = test_binding_with_execution(
            event.contract_id(),
            event.topic(),
            spec.consumer(),
            spec.group(),
            SubscriberExecution::AdapterNative,
        );

        let result = bridge_subscriptions_with_events(vec![binding], &[event]);
        assert!(result.is_err(), "binding must fail closed");
        let error = result.err().unwrap();

        assert!(error.to_string().contains(
            "config-version refresh subscription dispatch or runtime execution mismatch"
        ));
    }

    #[allow(clippy::unwrap_used)]
    // reason: preceding assertion proves the fail-closed result is Err.
    #[test]
    fn bridge_generated_subscriptions_rejects_audit_domain_effect() {
        let event = generated::event::identity_v1::session_created::SPEC;
        let spec = event.subscriptions()[0];
        let binding = test_binding_with_execution(
            event.contract_id(),
            event.topic(),
            spec.consumer(),
            spec.group(),
            SubscriberExecution::DomainEffect(Arc::new(|_, _| {
                Box::pin(async { consistency::HandleResult::ack() })
            })),
        );

        let result = bridge_subscriptions_with_events(vec![binding], &[event]);
        assert!(result.is_err(), "binding must fail closed");
        let error = result.err().unwrap();

        assert!(
            error
                .to_string()
                .contains("adapter-native subscription dispatch or runtime execution mismatch")
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

    // ── build_event_transport_config_from ─────────────────────────────────────

    #[allow(clippy::panic)]
    // reason: 测试 Ok 臂等价 unreachable；panic! 是标准测试断言手段；item-level carve-out。
    #[test]
    fn config_builder_missing_topology_fails_fast() {
        let result = build_event_transport_config_from(|_| None);
        match result {
            Err(e) => assert!(e.to_string().contains("RSS_TOPOLOGY")),
            Ok(_) => panic!("expected error for missing RSS_TOPOLOGY"),
        }
    }

    #[test]
    fn config_builder_demo_topology_does_not_require_amqp() {
        let result = build_event_transport_config_from(|name| {
            if name == "RSS_TOPOLOGY" {
                Some("demo".into())
            } else {
                None
            }
        });
        assert!(result.is_ok(), "demo topology: no AMQP vars required");
    }

    /// review #342 F1 修复：durable-shared 仅配共享 `RSS_AMQP_URL`（无 per-domain）也应可启动——env
    /// builder 完整映射 → resolver 用共享回退（修复前硬要 RSS_AMQP_IDENTITY_URL，按文档配共享 URL 直接 Err）。
    #[allow(clippy::unwrap_used)]
    // reason: 配置齐备必构造成功；item-level carve-out。
    #[test]
    fn config_builder_durable_shared_url_only_resolves_durable() {
        let cfg = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_AMQP_URL" => Some("amqps://su:sp@host/shared".into()),
            _ => durable_security_env(name),
        })
        .unwrap();
        let decision = resolve_event_decision(cfg.topology, cfg.transport, &["identity"]);
        assert!(
            matches!(decision, Ok(EventDecision::Durable { .. })),
            "durable-shared 仅配共享 URL 应回退成 Durable，实得 {decision:?}"
        );
    }

    #[test]
    fn config_builder_rejects_plaintext_amqp_by_default() {
        let result = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_AMQP_URL" => Some("amqp://su:sp@broker/shared".into()),
            _ => durable_security_env(name),
        });
        let err = result.err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(err.contains("RSS_AMQP_URL"), "{err}");
        assert!(err.contains("amqps://"), "{err}");
    }

    #[allow(clippy::unwrap_used)]
    // reason: loopback + explicit opt-in 是测试 fixture 路径，必须构造成功。
    #[test]
    fn config_builder_allows_loopback_plaintext_amqp_with_explicit_opt_in() {
        let cfg = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_AMQP_URL" => Some("amqp://su:sp@127.0.0.1:5672/shared".into()),
            AMQP_ALLOW_PLAINTEXT_ENV => Some("true".into()),
            _ => durable_security_env(name),
        })
        .unwrap();
        let decision = resolve_event_decision(cfg.topology, cfg.transport, &["identity"]);
        assert!(matches!(decision, Ok(EventDecision::Durable { .. })));
    }

    #[test]
    fn config_builder_rejects_non_loopback_plaintext_amqp_even_with_opt_in() {
        let result = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_AMQP_URL" => Some("amqp://su:sp@broker.internal/shared".into()),
            AMQP_ALLOW_PLAINTEXT_ENV => Some("true".into()),
            _ => durable_security_env(name),
        });
        let err = result.err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(err.contains("loopback"), "{err}");
    }

    #[allow(clippy::unwrap_used)]
    // reason: dev-container policy 是 compose 演示栈的显式 opt-in，配置齐备应构造成功。
    #[test]
    fn config_builder_allows_dev_container_plaintext_amqp_with_explicit_policy() {
        let cfg = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_AMQP_URL" => Some("amqp://su:sp@rabbitmq:5672/shared".into()),
            AMQP_ALLOW_PLAINTEXT_ENV => Some("dev-container".into()),
            _ => durable_security_env(name),
        })
        .unwrap();
        let decision = resolve_event_decision(cfg.topology, cfg.transport, &["identity"]);
        assert!(matches!(decision, Ok(EventDecision::Durable { .. })));
    }

    #[test]
    fn config_builder_rejects_invalid_amqp_plaintext_opt_in() {
        let result = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_AMQP_URL" => Some("amqps://su:sp@broker/shared".into()),
            AMQP_ALLOW_PLAINTEXT_ENV => Some("enabled".into()),
            _ => durable_security_env(name),
        });
        let err = result.err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(err.contains(AMQP_ALLOW_PLAINTEXT_ENV), "{err}");
    }

    /// durable 缺所有 AMQP URL（per-domain + shared 均无）→ env builder 不报错（只映射），由 resolver
    /// 单源 fail-closed（per-domain MissingBrokerUrl）。
    #[allow(clippy::unwrap_used)]
    // reason: topology 齐备 → build 必成功；item-level carve-out。
    #[test]
    fn config_builder_durable_missing_amqp_resolves_fail_closed() {
        let cfg = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            _ => durable_security_env(name),
        })
        .unwrap();
        let decision = resolve_event_decision(cfg.topology, cfg.transport, &["identity"]);
        assert!(
            decision.is_err(),
            "durable 缺所有 AMQP URL → resolver fail-closed"
        );
    }

    /// durable-isolated 配共享 `RSS_AMQP_URL` → resolver fail-closed（IsolatedFallbackForbidden）：
    /// 隔离拓扑禁回退共享凭据，env builder 照常映射、resolver 单源拒。
    #[allow(clippy::unwrap_used)]
    // reason: topology+shared 齐备 → build 必成功；item-level carve-out。
    #[test]
    fn config_builder_durable_isolated_with_shared_fails_closed() {
        let cfg = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-isolated".into()),
            "RSS_AMQP_URL" => Some("amqps://su:sp@host/shared".into()),
            _ => durable_security_env(name),
        })
        .unwrap();
        let decision = resolve_event_decision(cfg.topology, cfg.transport, &["identity"]);
        assert!(
            decision.is_err(),
            "durable-isolated 配共享 URL → resolver fail-closed"
        );
    }

    #[test]
    fn config_builder_durable_defaults_timing_when_absent() {
        let result = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_IDENTITY_AMQP_URL" => Some("amqps://user:pass@host/vhost".into()),
            _ => durable_security_env(name),
        });
        assert!(result.is_ok(), "full durable config should succeed");
        let cfg = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(cfg.relay_poll_interval, Duration::from_millis(200));
        assert_eq!(cfg.relay_max_in_flight, 16);
        assert_eq!(cfg.relay_sample_interval, Duration::from_millis(30_000));
        assert_eq!(cfg.outbox_sweep_interval, Duration::from_millis(300_000));
        assert_eq!(cfg.outbox_retain_seconds, 604_800);
        assert!(cfg.tenant_authority.is_some());
        assert!(cfg.dlx_payload_protector.is_some());
    }

    #[test]
    fn config_builder_uses_only_relay_max_in_flight_env() {
        let result = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_IDENTITY_AMQP_URL" => Some("amqps://user:pass@host/vhost".into()),
            "RSS_RELAY_MAX_IN_FLIGHT" => Some("32".into()),
            "RSS_RELAY_BATCH_SIZE" => Some("63".into()),
            _ => durable_security_env(name),
        });
        assert!(result.is_ok(), "full durable config should succeed");
        let cfg = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(cfg.relay_max_in_flight, 32);
    }

    #[test]
    fn config_builder_does_not_alias_legacy_relay_batch_size() {
        let result = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_IDENTITY_AMQP_URL" => Some("amqps://user:pass@host/vhost".into()),
            "RSS_RELAY_BATCH_SIZE" => Some("32".into()),
            _ => durable_security_env(name),
        });
        assert!(result.is_ok(), "full durable config should succeed");
        let cfg = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(cfg.relay_max_in_flight, 16);
    }

    #[test]
    fn config_builder_durable_parses_outbox_maintenance_timing() {
        let result = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_IDENTITY_AMQP_URL" => Some("amqps://user:pass@host/vhost".into()),
            "RSS_OUTBOX_SWEEP_INTERVAL_MS" => Some("120000".into()),
            "RSS_OUTBOX_RETAIN_SECONDS" => Some("86400".into()),
            _ => durable_security_env(name),
        });
        assert!(result.is_ok(), "full durable config should succeed");
        let cfg = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(cfg.outbox_sweep_interval, Duration::from_millis(120_000));
        assert_eq!(cfg.outbox_retain_seconds, 86_400);
    }

    #[test]
    fn config_builder_invalid_outbox_maintenance_timing_falls_back() {
        let result = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_IDENTITY_AMQP_URL" => Some("amqps://user:pass@host/vhost".into()),
            "RSS_OUTBOX_SWEEP_INTERVAL_MS" => Some("bad-ms".into()),
            "RSS_OUTBOX_RETAIN_SECONDS" => Some("bad-seconds".into()),
            _ => durable_security_env(name),
        });
        assert!(result.is_ok(), "invalid optional timing falls back");
        let cfg = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(cfg.outbox_sweep_interval, Duration::from_millis(300_000));
        assert_eq!(cfg.outbox_retain_seconds, 604_800);
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
            run_bounded_dlx_archive_readiness_probe(&invariant, &token, &health).await,
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
            run_bounded_dlx_archive_readiness_probe(&recovered, &live_token, &health).await,
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
        let built = build_dlx_lifecycle_probe(Arc::clone(&health));
        assert!(built.is_ok());
        let (name, probe) = built.unwrap_or_else(|_| unreachable!());
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
        let result = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_AMQP_URL" => Some("amqps://su:sp@host/shared".into()),
            TENANT_AUTHORITY_HMAC_KEY_ENV => None,
            _ => durable_security_env(name),
        });
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
        let result = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_AMQP_URL" => Some("amqps://su:sp@host/shared".into()),
            TENANT_AUTHORITY_HMAC_KEY_ENV => Some(short_key.clone()),
            _ => durable_security_env(name),
        });
        assert!(result.is_err(), "short tenant authority key must fail fast");
        let err = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            err.contains("tenant authority config error"),
            "short tenant authority key must fail fast"
        );
    }

    #[test]
    fn config_builder_durable_oversized_tenant_authority_clock_skew_fails_fast() {
        let result = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_AMQP_URL" => Some("amqps://su:sp@host/shared".into()),
            TENANT_AUTHORITY_CLOCK_SKEW_ENV => Some("301".into()),
            _ => durable_security_env(name),
        });
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
        let result = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_AMQP_URL" => Some("amqps://su:sp@host/shared".into()),
            DLX_PAYLOAD_KEY_NAME_ENV => None,
            _ => durable_security_env(name),
        });
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
            &[],
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
