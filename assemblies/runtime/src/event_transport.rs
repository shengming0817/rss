//! event_transport — topology-gated 事件传输组合根接线（issue #1251）。
//!
//! [`wire_event_transport`] 是 `run()` 事件传输单入口：根据 [`EventTransportConfig`] 中的拓扑决策
//! 连接 AMQP（per-domain），spawn relay worker + PG inbox consumer workers，并返回 [`EventRuntime`]
//! 交给 `run()` merge/drain 标准 [`bootstrap::DomainModuleResult`]。
//!
//! LIFO 注册顺序（由 `run()` 负责执行）：
//! - `infra_guards`（AMQP 连接 guard）先注册 ⇒ LIFO 最后关（workers drain 后再断连接）。
//! - `module.resources/module.workers`（relay + consumers + outbox sampler/sweeper）后注册 ⇒ LIFO 最先 drain。
//!
//! Demo 拓扑：`wire_event_transport` 返回空 [`EventRuntime`]（无 env/容器即可单测）；生产 Demo
//! 时组合根 `run()` 在此前已 `anyhow::bail!`（TOPO-INMEM-SEAL-01 组合根层保证）。
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
use std::time::Duration;

use anyhow::Context as _;
use bootstrap::{DomainModuleResult, SubscriberBinding, WorkerSpec, adapt_subscriber_handler};
use diport::{DynDeadLetterStore, DynManagedResource, Topic};
use eventexec::{
    ConsumerMeta, EVENT_CONSUMER_PROBE, LeaseConfig, MetricsOutboxMetrics, OUTBOX_RELAY_PROBE,
    OUTBOX_SAMPLER_PROBE, OUTBOX_SWEEPER_PROBE, RelayConfig, SWEEPER_WORKER_NAME, SamplerWorker,
    SweeperConfig, SweeperWorker, WorkerHealth, backlog_sampler_loop,
    spawn_consumer_ackable_subscriber, spawn_relay, sweeper_loop,
};
use postgres::{PgRuntimeDeps, caps};
use primitives::{HealthCheck, ProbeName};

use crate::SystemClock;

// ── 对外类型 ──────────────────────────────────────────────────────────────────

/// topology-gated 事件传输接线的完整配置（由 [`build_event_transport_config_from`] 从 env 构造）。
pub struct EventTransportConfig {
    /// 当前拓扑（Demo / DurableShared / DurableIsolated）。
    pub topology: bootstrap::Topology,
    /// AMQP per-domain 传输配置（per-domain URL 集合）。
    pub transport: bootstrap::eventtransport::TransportConfig,
    /// Outbox relay 轮询间隔。
    pub relay_poll_interval: Duration,
    /// Outbox relay 单次批量大小。
    pub relay_batch: usize,
    /// Outbox relay backlog 采样间隔。
    pub relay_sample_interval: Duration,
    /// Outbox published-row sweeper 扫描间隔。
    pub outbox_sweep_interval: Duration,
    /// Outbox published-row 保留期（秒）。
    pub outbox_retain_seconds: u64,
}

/// 事件传输接线产物（交 `run()` 装配进 [`bootstrap::ShutdownStack`]）。
pub struct EventRuntime {
    /// infra 连接守卫（AMQP）：先注册 ⇒ LIFO 最后关（workers drain 后再断连接）。
    pub infra_guards: Vec<Box<DynManagedResource<'static>>>,
    /// 标准 module 产物：probes/resources/workers 由 runtime 统一 merge/drain。
    pub module: DomainModuleResult,
}

impl EventRuntime {
    /// 空产物（Demo 拓扑：无 infra 连接 / worker / probe）。
    // reason: Demo 拓扑 `wire_event_transport` 返回空 EventRuntime——函数可脱离 env/容器单测；
    // 生产走 Demo 时组合根 `run()` 已在此前 fail-fast（TOPO-INMEM-SEAL-01）。
    pub fn empty() -> Self {
        Self {
            infra_guards: Vec::new(),
            module: DomainModuleResult::default(),
        }
    }
}

impl Default for EventRuntime {
    fn default() -> Self {
        Self::empty()
    }
}

// ── 内部类型 ──────────────────────────────────────────────────────────────────

/// L2 OutboxFact **发布域集**（producer-side）：identity（`identity.session-created`）+ settings
/// （`settings.config-version-changed`）。每个发布域各起一个 relay（per-domain vhost publisher + caps marker）——
/// 未列入的发布域 outbox 会在 durable runtime 静默积压（#1251 F2）。新增 L2 发布域时在此追加 + 在 `wire_durable`
/// 显式接一个 relay（caps::* 是编译期 marker，无法对 domain 字符串泛型循环）。
const RELAY_DOMAINS: &[&str] = &["identity", "settings"];
const INBOX_SWEEPER_WORKER_NAME: &str = "inbox-sweeper";
const INBOX_SWEEPER_PROBE: &str = "inbox_sweeper";

/// worker 健康 → readyz `HealthCheck` 适配探针。
struct WorkerHealthProbe {
    name: ProbeName,
    health: Arc<WorkerHealth>,
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
    poll: Duration,
    batch: usize,
    sample: Duration,
    sweep: Duration,
    retain_seconds: u64,
}

// ── 公开函数 ──────────────────────────────────────────────────────────────────

/// 需要 per-domain AMQP vhost 连接的域集 = **relay 发布域（[`RELAY_DOMAINS`]）∪ consumer 订阅 topic owner**
/// （topic 首 '.' 前的前缀段）。两类都要 vhost：relay 往发布域 vhost 发布 outbox，consumer 从订阅 topic owner
/// vhost 拉取。转小写、去重、排序。
pub(crate) fn required_domains(subscribers: &[SubscriberBinding]) -> Vec<String> {
    let mut domains: Vec<String> = RELAY_DOMAINS.iter().map(|d| (*d).to_string()).collect();
    domains.extend(subscribers.iter().map(|b| topic_owner(b.topic)));
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

fn consumer_meta_parts_for_binding(
    binding: &SubscriberBinding,
) -> (&'static str, &'static str, &'static str) {
    (binding.consumer, binding.contract_id, binding.topic)
}

fn consumer_meta_for_binding(binding: &SubscriberBinding) -> ConsumerMeta {
    let (consumer, contract_id, topic) = consumer_meta_parts_for_binding(binding);
    ConsumerMeta::new(consumer, contract_id, topic)
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
/// - Demo 拓扑：返回 [`EventRuntime::empty`]（不建连接/不 spawn；生产 Demo fail-fast 由 `run()` 保证）。
/// - Durable 拓扑（Shared / Isolated）：连接 per-domain AMQP → spawn relay + PG inbox consumer workers。
///
/// `cfg` 按值消费（`TransportConfig` 不 impl Clone）。
pub async fn wire_event_transport(
    pg: &PgRuntimeDeps,
    subscribers: Vec<SubscriberBinding>,
    cfg: EventTransportConfig,
) -> anyhow::Result<EventRuntime> {
    let required = required_domains(&subscribers);
    let required_refs: Vec<&str> = required.iter().map(String::as_str).collect();
    let timing = RelayTiming {
        poll: cfg.relay_poll_interval,
        batch: cfg.relay_batch,
        sample: cfg.relay_sample_interval,
        sweep: cfg.outbox_sweep_interval,
        retain_seconds: cfg.outbox_retain_seconds,
    };
    match resolve_event_decision(cfg.topology, cfg.transport, &required_refs)? {
        EventDecision::Demo => {
            // reason: Demo 拓扑返回空产物——函数可在无 env/容器下单测；生产走 Demo 时
            // 组合根 `run()` 在此函数调用前已 fail-fast（TOPO-INMEM-SEAL-01）。
            tracing::warn!(
                stage = "event-transport",
                "Demo 拓扑：事件传输不接线（组合根 fail-fast 保证生产路径不进此臂）"
            );
            Ok(EventRuntime::empty())
        }
        EventDecision::Durable { per_domain } => {
            wire_durable(pg, subscribers, per_domain, timing).await
        }
    }
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
/// - `RSS_RELAY_BATCH_SIZE`（16）
/// - `RSS_RELAY_SAMPLE_INTERVAL_MS`（30000ms）
/// - `RSS_OUTBOX_SWEEP_INTERVAL_MS`（300000ms）
/// - `RSS_OUTBOX_RETAIN_SECONDS`（604800s）
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
        let mut per_domain = BTreeMap::new();
        for domain in RELAY_DOMAINS {
            let env = format!("RSS_{}_AMQP_URL", domain.to_ascii_uppercase());
            if let Some(url) = get(&env) {
                per_domain.insert((*domain).to_string(), bootstrap::AmqpUrl::new(url));
            }
        }
        let shared = get("RSS_AMQP_URL").map(bootstrap::AmqpUrl::new);
        bootstrap::eventtransport::TransportConfig::new(per_domain, shared)
    };

    Ok(EventTransportConfig {
        topology,
        transport,
        relay_poll_interval: parse_duration_ms_env(
            get("RSS_RELAY_POLL_INTERVAL_MS"),
            "RSS_RELAY_POLL_INTERVAL_MS",
            200,
        ),
        relay_batch: parse_usize_env(get("RSS_RELAY_BATCH_SIZE"), "RSS_RELAY_BATCH_SIZE", 16),
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
    })
}

// ── 内部函数 ──────────────────────────────────────────────────────────────────

/// durable 拓扑接线内核（Shared / Isolated）：建立 AMQP，spawn relay + PG inbox consumer workers。
#[allow(clippy::cognitive_complexity)]
// reason: wire_durable 是顺序聚合函数，步骤严格有序（guard → AMQP → relay → consumers）以
// 保证 LIFO 关闭顺序（infra_guards 最后关 = AMQP 连接在 workers drain 后才断开）；
// 拆分为子函数会把 Vec push 顺序散布到多处并隐藏 LIFO 约束，复杂度来自不可压缩的业务顺序。
async fn wire_durable(
    pg: &PgRuntimeDeps,
    subscribers: Vec<SubscriberBinding>,
    per_domain: BTreeMap<String, bootstrap::AmqpUrl>,
    timing: RelayTiming,
) -> anyhow::Result<EventRuntime> {
    // saga/projection 投影重建 defer → 见 #1251 follow-up issue（executor body 仍 todo!()，#1121/#1122）

    let mut infra_guards: Vec<Box<DynManagedResource<'static>>> = Vec::new();
    let mut module = DomainModuleResult::default();

    // 每个 required 域（[`RELAY_DOMAINS`] 发布域 ∪ subscriber 订阅 topic owner）由 resolver 保证有已校验
    // AMQP URL → 下方 amqp_map 逐域连接；relay/consumer 取连接时 `.context(...)` 兜底 fail-closed，无需额外 guard。

    // AMQP per-domain 连接（relay 发布 + consumer 订阅共用同一 vhost 连接）。
    let mut amqp_map: BTreeMap<String, amqp::AmqpRuntimeDeps> = BTreeMap::new();
    for (domain_upper, url) in &per_domain {
        let domain = domain_upper.to_ascii_lowercase();
        #[allow(clippy::disallowed_methods)]
        // reason: 凭据原文仅在组合根 AMQP broker-connect callsite 调用 expose()（CREDENTIAL-EXPOSE-COMPOSITIONROOT-01）。
        let raw_url = url.expose();
        // FIX 8 — TLS startup warn：cleartext amqp = 凭据 + payload 明文传输，生产必须 amqps://。
        if !raw_url.starts_with("amqps://") {
            tracing::warn!(
                domain,
                "amqp connection is cleartext (credentials+payload unencrypted); production must use amqps:// TLS"
            );
        }
        let amqp_deps = amqp::AmqpRuntimeDeps::connect(raw_url, &domain)
            .await
            .with_context(|| format!("connect amqp for domain '{domain}'"))?;
        infra_guards.extend(amqp_deps.runtime_resources());
        tracing::info!(domain, "durable event transport: amqp connected");
        amqp_map.insert(domain, amqp_deps);
    }

    // Relay workers：每个 L2 发布域（[`RELAY_DOMAINS`]）一个 relay——往该域 vhost 发布其 outbox（否则该域
    // outbox 在 durable runtime 静默积压，#1251 F2）。caps::* 是编译期 marker、无法对 domain 字符串泛型循环
    // → 显式 identity + settings（新增 L2 发布域时在此加一块 + 在 RELAY_DOMAINS 追加）。
    {
        let publisher = relay_publisher(&amqp_map, "identity")?;
        let outbox = pg.for_domain::<caps::Identity>().outbox(publisher);
        wire_domain_relay("identity", outbox, &timing, &mut module)?;
    }
    {
        let publisher = relay_publisher(&amqp_map, "settings")?;
        let outbox = pg.for_domain::<caps::Settings>().outbox(publisher);
        wire_domain_relay("settings", outbox, &timing, &mut module)?;
    }
    wire_outbox_maintenance(pg, &timing, &mut module)?;

    // Consumer resource bundle（per binding PG inbox + DLX + subscriber + worker + probe + inbox sweeper）。
    wire_consumer_resource_bundle(pg, subscribers, &amqp_map, &timing, &mut module)?;

    Ok(EventRuntime {
        infra_guards,
        module,
    })
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

/// 为单个 L2 发布域声明一个 outbox relay worker（`eventexec::spawn_relay`：专用 OS 线程 + `StoppedOnExit`
/// panic-safety 守卫，与 ConsumerWorker 对称）+ 一个 per-domain readyz 探针，收进 module。
///
/// `outbox` 已绑该域 vhost publisher（调用方按 `caps::*` marker 构造，编译期防跨域错插）；`PgOutbox: Send+!Sync`
/// → `spawn_relay` 接 `store: A`（`A: Send`），在专用线程内 `Arc::new(store)`；relay_loop 经 `RelayConfig` 的
/// domain 过滤 outbox 表行。
fn wire_domain_relay(
    domain: &str,
    outbox: postgres::PgOutbox,
    timing: &RelayTiming,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let relay_cfg = RelayConfig::new(
        vec![domain.to_string()],
        timing.poll,
        timing.batch,
        timing.sample,
    )
    .context("build relay config")?;
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
    pg: &PgRuntimeDeps,
    timing: &RelayTiming,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let relay_cfg = RelayConfig::new(
        RELAY_DOMAINS.iter().map(|d| (*d).to_string()).collect(),
        timing.poll,
        timing.batch,
        timing.sample,
    )
    .context("build outbox sampler config")?;
    let sweeper_cfg = SweeperConfig::new(timing.retain_seconds, timing.sweep)
        .context("build outbox sweeper config")?;

    let maintenance = pg.infra().outbox_maintenance();
    wire_sampler_worker(maintenance.clone(), relay_cfg, module)?;
    wire_sweeper_worker(maintenance, sweeper_cfg, module)?;
    Ok(())
}

fn wire_sampler_worker(
    maintenance: postgres::PgOutboxMaintenance,
    config: RelayConfig,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let health = Arc::new(WorkerHealth::healthy());
    let worker_health = Arc::clone(&health);
    let worker: WorkerSpec = Box::new(move |token| {
        let handle = tokio::spawn(backlog_sampler_loop(
            Arc::new(maintenance),
            config,
            token.clone(),
            Arc::clone(&worker_health),
            Arc::new(MetricsOutboxMetrics),
        ));
        DynManagedResource::new_box(SamplerWorker::adopt(handle, worker_health, token))
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

fn wire_sweeper_worker(
    maintenance: postgres::PgOutboxMaintenance,
    config: SweeperConfig,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let health = Arc::new(WorkerHealth::healthy());
    let worker_health = Arc::clone(&health);
    let worker: WorkerSpec = Box::new(move |token| {
        let handle = tokio::spawn(sweeper_loop(
            Arc::new(maintenance),
            config,
            token.clone(),
            Arc::clone(&worker_health),
            "outbox",
        ));
        DynManagedResource::new_box(SweeperWorker::adopt(
            SWEEPER_WORKER_NAME,
            handle,
            worker_health,
            token,
        ))
    });
    module.workers.push(worker);

    let probe_name =
        ProbeName::parse(OUTBOX_SWEEPER_PROBE).context("parse outbox sweeper probe name")?;
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
    pg: &PgRuntimeDeps,
    subscribers: Vec<SubscriberBinding>,
    amqp_map: &BTreeMap<String, amqp::AmqpRuntimeDeps>,
    timing: &RelayTiming,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let binding_count = subscribers.len();
    for binding in subscribers {
        let group = binding.group.clone();
        let owner = topic_owner(binding.topic);
        let amqp_conn = amqp_map
            .get(&owner)
            .with_context(|| format!("no amqp connection for topic owner '{owner}'"))?;
        let subscriber = amqp_conn.infra().subscriber();
        let topic = Topic::new(binding.topic);
        let meta = consumer_meta_for_binding(&binding);
        let handler = adapt_subscriber_handler(binding.handler);
        let inbox = pg.infra().inbox(group);
        let lease_cfg = LeaseConfig::from_ttl(inbox.lease_ttl());
        let idempotency = Arc::new(inbox);
        let consumer_health = Arc::new(WorkerHealth::starting());
        let dlx = DynDeadLetterStore::new_box(pg.infra().dead_letter());
        let worker_name = format!("event-consumer:{}:{}", binding.consumer, binding.topic);
        tracing::info!(
            consumer = binding.consumer,
            topic = binding.topic,
            "durable event transport: pg inbox consumer worker registered"
        );
        let health = Arc::clone(&consumer_health);
        let worker: WorkerSpec = Box::new(move |token| {
            DynManagedResource::new_box(spawn_consumer_ackable_subscriber(
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
        module.workers.push(worker);
        module.probes.push(make_consumer_probe(
            binding_count,
            binding.topic,
            consumer_health,
        )?);
    }
    wire_inbox_sweeper(pg, timing, module)?;
    Ok(())
}

fn wire_inbox_sweeper(
    pg: &PgRuntimeDeps,
    timing: &RelayTiming,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let config = SweeperConfig::new(postgres::INBOX_DEDUP_RETENTION_SECONDS, timing.sweep)
        .context("build inbox sweeper config")?;
    let health = Arc::new(WorkerHealth::healthy());
    let worker_health = Arc::clone(&health);
    let sweeper = pg.infra().inbox_sweeper();
    let worker: WorkerSpec = Box::new(move |token| {
        let handle = tokio::spawn(sweeper_loop(
            Arc::new(sweeper),
            config,
            token.clone(),
            Arc::clone(&worker_health),
            "inbox_dedup",
        ));
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

/// consumer readyz 探针：单 binding 用 `EVENT_CONSUMER_PROBE`，多 binding 用 `{probe}:{topic_snake}` 区分。
fn make_consumer_probe(
    binding_count: usize,
    topic: &'static str,
    health: Arc<WorkerHealth>,
) -> anyhow::Result<(ProbeName, Box<dyn bootstrap::HealthProbe>)> {
    let probe_name_str = if binding_count == 1 {
        EVENT_CONSUMER_PROBE.to_string()
    } else {
        format!("{EVENT_CONSUMER_PROBE}:{}", topic.replace('.', "_"))
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

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── required_domains ──────────────────────────────────────────────────────

    #[test]
    fn required_domains_includes_publishing_domains_without_subscribers() {
        // 无 subscriber → 仍含 RELAY_DOMAINS 发布域（relay 需 per-domain vhost；否则该域 outbox 静默积压）。
        assert_eq!(
            required_domains(&[]),
            vec!["identity".to_string(), "settings".to_string()]
        );
    }

    #[allow(clippy::unwrap_used)]
    // reason: 测试 helper nop_binding 用，parse 失败即测试写错；item-level carve-out。
    #[test]
    fn required_domains_deduplicates_and_sorts() {
        use bootstrap::{SubscriberBinding, SubscriberHandlerError};
        use futures::future::BoxFuture;

        struct NopHandler;
        impl bootstrap::SubscriberHandler for NopHandler {
            fn handle(
                &self,
                _: diport::Message,
            ) -> BoxFuture<'static, Result<(), SubscriberHandlerError>> {
                Box::pin(async { Ok(()) })
            }
        }

        fn nop_binding(topic: &'static str) -> SubscriberBinding {
            SubscriberBinding {
                contract_id: "test.event",
                topic,
                consumer: "test-consumer",
                group: consistency::ConsumerGroup::parse("test.group").unwrap(),
                handler: Box::new(NopHandler),
            }
        }

        let bindings = vec![
            nop_binding("identity.session-created"),
            nop_binding("identity.token-refreshed"),
            nop_binding("audit.entry-written"),
        ];
        // subscriber owner {identity, audit} ∪ RELAY_DOMAINS {identity, settings} → 去重排序。
        let domains = required_domains(&bindings);
        assert_eq!(domains, vec!["audit", "identity", "settings"]);
    }

    #[allow(clippy::unwrap_used)]
    // reason: 测试 helper 构造合法 consumer group；parse 失败即测试写错。
    #[test]
    fn consumer_meta_uses_subscription_consumer_not_topic_owner() {
        use bootstrap::{SubscriberBinding, SubscriberHandlerError};
        use futures::future::BoxFuture;

        struct NopHandler;
        impl bootstrap::SubscriberHandler for NopHandler {
            fn handle(
                &self,
                _: diport::Message,
            ) -> BoxFuture<'static, Result<(), SubscriberHandlerError>> {
                Box::pin(async { Ok(()) })
            }
        }

        let binding = SubscriberBinding {
            contract_id: "identity.session-created",
            topic: "identity.session-created",
            consumer: "audit",
            group: consistency::ConsumerGroup::parse("audit.session-created").unwrap(),
            handler: Box::new(NopHandler),
        };

        assert_eq!(topic_owner(binding.topic), "identity");
        assert_eq!(
            consumer_meta_parts_for_binding(&binding),
            (
                "audit",
                "identity.session-created",
                "identity.session-created"
            )
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
            "RSS_AMQP_URL" => Some("amqp://su:sp@host/shared".into()),
            _ => None,
        })
        .unwrap();
        let decision = resolve_event_decision(cfg.topology, cfg.transport, &["identity"]);
        assert!(
            matches!(decision, Ok(EventDecision::Durable { .. })),
            "durable-shared 仅配共享 URL 应回退成 Durable，实得 {decision:?}"
        );
    }

    /// durable 缺所有 AMQP URL（per-domain + shared 均无）→ env builder 不报错（只映射），由 resolver
    /// 单源 fail-closed（per-domain MissingBrokerUrl）。
    #[allow(clippy::unwrap_used)]
    // reason: topology 齐备 → build 必成功；item-level carve-out。
    #[test]
    fn config_builder_durable_missing_amqp_resolves_fail_closed() {
        let cfg = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            _ => None,
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
            "RSS_AMQP_URL" => Some("amqp://su:sp@host/shared".into()),
            _ => None,
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
            "RSS_IDENTITY_AMQP_URL" => Some("amqp://user:pass@host/vhost".into()),
            _ => None,
        });
        assert!(result.is_ok(), "full durable config should succeed");
        let cfg = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(cfg.relay_poll_interval, Duration::from_millis(200));
        assert_eq!(cfg.relay_batch, 16);
        assert_eq!(cfg.relay_sample_interval, Duration::from_millis(30_000));
        assert_eq!(cfg.outbox_sweep_interval, Duration::from_millis(300_000));
        assert_eq!(cfg.outbox_retain_seconds, 604_800);
    }

    #[test]
    fn config_builder_durable_parses_outbox_maintenance_timing() {
        let result = build_event_transport_config_from(|name| match name {
            "RSS_TOPOLOGY" => Some("durable-shared".into()),
            "RSS_IDENTITY_AMQP_URL" => Some("amqp://user:pass@host/vhost".into()),
            "RSS_OUTBOX_SWEEP_INTERVAL_MS" => Some("120000".into()),
            "RSS_OUTBOX_RETAIN_SECONDS" => Some("86400".into()),
            _ => None,
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
            "RSS_IDENTITY_AMQP_URL" => Some("amqp://user:pass@host/vhost".into()),
            "RSS_OUTBOX_SWEEP_INTERVAL_MS" => Some("bad-ms".into()),
            "RSS_OUTBOX_RETAIN_SECONDS" => Some("bad-seconds".into()),
            _ => None,
        });
        assert!(result.is_ok(), "invalid optional timing falls back");
        let cfg = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(cfg.outbox_sweep_interval, Duration::from_millis(300_000));
        assert_eq!(cfg.outbox_retain_seconds, 604_800);
    }

    // ── EventRuntime::empty() constructor ─────────────────────────────────────

    /// Demo 路径不接线：EventRuntime::empty() 产出空产物（无 infra guard / worker / probe）。
    #[test]
    fn event_runtime_empty_constructor_is_empty() {
        let runtime = EventRuntime::empty();
        assert!(runtime.infra_guards.is_empty());
        assert!(runtime.module.probes.is_empty());
        assert!(runtime.module.resources.is_empty());
        assert!(runtime.module.workers.is_empty());
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
        let transport = bootstrap::eventtransport::TransportConfig::default().with_domain_url(
            "identity",
            bootstrap::AmqpUrl::new("amqp://user:pass@host/vhost".to_string()),
        );
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

    // ── make_consumer_probe（FIX 7）────────────────────────────────────────────

    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path，parse 失败即 const 写错；item-level carve-out。
    #[test]
    fn make_consumer_probe_single_binding_uses_base_name() {
        let health = Arc::new(WorkerHealth::healthy());
        let (name, _probe) = make_consumer_probe(1, "identity.session-created", health).unwrap();
        assert_eq!(
            name.as_str(),
            EVENT_CONSUMER_PROBE,
            "单 binding 探针名应等于 EVENT_CONSUMER_PROBE"
        );
    }

    #[allow(clippy::unwrap_used)]
    // reason: 同上。
    #[test]
    fn make_consumer_probe_multi_binding_includes_topic_snake() {
        let health = Arc::new(WorkerHealth::healthy());
        let (name, _probe) = make_consumer_probe(2, "identity.session-created", health).unwrap();
        let expected = format!("{EVENT_CONSUMER_PROBE}:identity_session-created");
        assert_eq!(
            name.as_str(),
            expected,
            "多 binding 探针名应含 topic（点换下划线）"
        );
        // 验证 ProbeName::parse 接受生成的名称。
        assert!(
            primitives::ProbeName::parse(&expected).is_ok(),
            "生成的多 binding 探针名须通过 ProbeName::parse"
        );
    }
}
