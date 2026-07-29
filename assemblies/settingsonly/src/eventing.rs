//! Durable, isolated Settings event transport.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use bootstrap::DomainModuleResult;
use diport::{DynDeadLetterStore, DynManagedResource, ManagedResource, ShutdownError, Topic};
use eventexec::{
    EVENT_CONSUMER_PROBE, LeaseConfig, MetricsOutboxMetrics, OUTBOX_RELAY_PROBE, RelayBudget,
    RelayConfig, RetentionTarget, SamplerConfig, SweeperConfig, SweeperWorker, WorkerHealth,
    backlog_sampler_loop, spawn_relay, sweeper_loop,
};
use generated::event::{SubscriberReadiness, SubscriptionDispatchKey};
use vocab::ExternalEffectPolicy;

const RELAY_POLL_INTERVAL: Duration = Duration::from_millis(250);
const RELAY_MAX_IN_FLIGHT: usize = 32;
const RELAY_LEASE_TTL: Duration = Duration::from_secs(60);
const RELAY_PUBLISH_TIMEOUT: Duration = Duration::from_secs(40);
const RELAY_SETTLE_TIMEOUT: Duration = Duration::from_secs(5);
const RELAY_SAFETY_MARGIN: Duration = Duration::from_secs(5);
const INBOX_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const OUTBOX_SAMPLE_INTERVAL: Duration = Duration::from_secs(30);
const OUTBOX_SWEEP_INTERVAL: Duration = Duration::from_secs(300);
const OUTBOX_RETAIN_SECONDS: u64 = 604_800;
const OUTBOX_MAINTENANCE_TTL: Duration = Duration::from_secs(30);
const EVENT_WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(45);
const AMQP_READINESS_INTERVAL: Duration = Duration::from_secs(2);

/// Complete, non-optional production inputs for the settings event transport.
///
/// Provider construction owns connectivity and readiness. This value transfers only typed runtime
/// capabilities into the activation funnel; none of its fields can be replaced after construction.
pub(crate) struct EventingInputs {
    pg: postgres::PgRuntimeHandle,
    redis: redis::RedisRuntimeDeps,
    amqp: amqp::AmqpRuntimeDeps,
    amqp_resources: Vec<Box<diport::DynManagedResource<'static>>>,
    tenant_authority: Arc<eventexec::TenantAuthority>,
    dlx_payload_protector: postgres::DlxPayloadProtector,
    consumer_runtime: postgres::PgConsumerRuntimeBundle,
}

impl EventingInputs {
    #[must_use]
    pub(crate) fn new(
        pg: postgres::PgRuntimeHandle,
        redis: redis::RedisRuntimeDeps,
        amqp: amqp::AmqpRuntimeDeps,
        amqp_resources: Vec<Box<diport::DynManagedResource<'static>>>,
        tenant_authority: Arc<eventexec::TenantAuthority>,
        dlx_payload_protector: postgres::DlxPayloadProtector,
    ) -> Self {
        let consumer_runtime = pg
            .infra()
            .consumer_runtime_bundle(dlx_payload_protector.clone());
        Self {
            pg,
            redis,
            amqp,
            amqp_resources,
            tenant_authority,
            dlx_payload_protector,
            consumer_runtime,
        }
    }
}

/// Exact provider-role outputs produced by Settings eventing activation.
///
/// Keeping the three outputs distinct prevents a publisher lifecycle or relay worker from being
/// transferred into the subscriber role (and vice versa). The distributed role owns only the
/// Redis-lock/PG-CAS maintenance workers and their readiness probes.
pub(crate) struct EventingRoleOutputs {
    pub(crate) distributed_cas: DomainModuleResult,
    pub(crate) event_publisher: DomainModuleResult,
    pub(crate) event_subscriber: DomainModuleResult,
}

/// Activate the one generated Settings reconciliation subscription and its supporting workers.
pub(crate) fn wire(
    mut inputs: EventingInputs,
    bindings: Vec<bootstrap::SubscriberBinding>,
) -> anyhow::Result<EventingRoleOutputs> {
    let subscriptions = eventing_composition::bridge_generated_settings_subscriptions(bindings)
        .context("bridge settingsonly generated subscription")?;
    validate_settings_closure(&subscriptions)?;

    let budget = relay_budget()?;
    inputs
        .pg
        .validate_relay_budget(budget)
        .context("settingsonly relay budget disagrees with database policy")?;

    let (publisher_resource, subscriber_resource) =
        split_amqp_resources(std::mem::take(&mut inputs.amqp_resources))?;
    let mut event_publisher = DomainModuleResult {
        resources: vec![publisher_resource],
        ..Default::default()
    };
    let mut event_subscriber = DomainModuleResult {
        resources: vec![subscriber_resource],
        ..Default::default()
    };
    let mut distributed_cas = DomainModuleResult::default();
    wire_relay(&inputs, budget, &mut event_publisher)?;
    let EventingInputs {
        pg,
        redis,
        amqp,
        amqp_resources: _,
        tenant_authority,
        dlx_payload_protector: _,
        consumer_runtime,
    } = inputs;
    wire_consumer(
        &pg,
        &amqp,
        tenant_authority,
        consumer_runtime,
        subscriptions,
        &mut event_subscriber,
    )?;
    wire_amqp_readiness(&amqp, &mut event_publisher, &mut event_subscriber)?;
    wire_inbox_sweeper(&pg, &mut event_subscriber)?;
    wire_outbox_maintenance(&pg, &redis, &mut distributed_cas)?;
    Ok(assemble_role_outputs(
        distributed_cas,
        event_publisher,
        event_subscriber,
    ))
}

fn wire_amqp_readiness(
    amqp: &amqp::AmqpRuntimeDeps,
    publisher: &mut DomainModuleResult,
    subscriber: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let publisher_ready = Arc::new(std::sync::atomic::AtomicBool::new(
        amqp.publisher_readiness().is_ready(),
    ));
    let publisher_name = primitives::ProbeName::parse("settingsonly_amqp_publisher_ready")
        .context("build settingsonly AMQP publisher readiness probe name")?;
    publisher.probes.push((
        publisher_name.clone(),
        Box::new(TransportProbe::new(
            publisher_name,
            Arc::clone(&publisher_ready),
        )),
    ));
    let publisher_amqp = amqp.clone();
    publisher.workers.push(Box::new(move |token| {
        DynManagedResource::new_box(AmqpReadinessWorker::spawn(
            publisher_amqp,
            AmqpReadinessRole::Publisher,
            publisher_ready,
            token,
        ))
    }));

    let subscriber_ready = Arc::new(std::sync::atomic::AtomicBool::new(
        amqp.subscriber_readiness().is_ready(),
    ));
    let subscriber_name = primitives::ProbeName::parse("settingsonly_amqp_subscriber_ready")
        .context("build settingsonly AMQP subscriber readiness probe name")?;
    subscriber.probes.push((
        subscriber_name.clone(),
        Box::new(TransportProbe::new(
            subscriber_name,
            Arc::clone(&subscriber_ready),
        )),
    ));
    let subscriber_amqp = amqp.clone();
    subscriber.workers.push(Box::new(move |token| {
        DynManagedResource::new_box(AmqpReadinessWorker::spawn(
            subscriber_amqp,
            AmqpReadinessRole::Subscriber,
            subscriber_ready,
            token,
        ))
    }));
    Ok(())
}

#[derive(Clone, Copy)]
enum AmqpReadinessRole {
    Publisher,
    Subscriber,
}

struct TransportProbe {
    name: primitives::ProbeName,
    ready: Arc<std::sync::atomic::AtomicBool>,
}

impl TransportProbe {
    fn new(name: primitives::ProbeName, ready: Arc<std::sync::atomic::AtomicBool>) -> Self {
        Self { name, ready }
    }
}

impl bootstrap::HealthProbe for TransportProbe {
    fn check(&self) -> primitives::HealthCheck {
        use std::sync::atomic::Ordering;
        let (status, detail) = if self.ready.load(Ordering::Acquire) {
            (primitives::HealthStatus::Healthy, "ready")
        } else {
            (primitives::HealthStatus::Unhealthy, "down")
        };
        primitives::HealthCheck::new(self.name.clone(), status, detail)
    }
}

struct AmqpReadinessWorker {
    name: &'static str,
    token: tokio_util::sync::CancellationToken,
    handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl AmqpReadinessWorker {
    fn spawn(
        amqp: amqp::AmqpRuntimeDeps,
        role: AmqpReadinessRole,
        ready: Arc<std::sync::atomic::AtomicBool>,
        token: tokio_util::sync::CancellationToken,
    ) -> Self {
        use std::sync::atomic::Ordering;
        let name = match role {
            AmqpReadinessRole::Publisher => "settingsonly-amqp-publisher-readiness",
            AmqpReadinessRole::Subscriber => "settingsonly-amqp-subscriber-readiness",
        };
        let worker_token = token.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(AMQP_READINESS_INTERVAL);
            loop {
                tokio::select! {
                    biased;
                    () = worker_token.cancelled() => break,
                    _ = ticker.tick() => {
                        let healthy = match role {
                            AmqpReadinessRole::Publisher => amqp.publisher_readiness().is_ready(),
                            AmqpReadinessRole::Subscriber => amqp.subscriber_readiness().is_ready(),
                        };
                        ready.store(healthy, Ordering::Release);
                    }
                }
            }
        });
        Self {
            name,
            token,
            handle: tokio::sync::Mutex::new(Some(handle)),
        }
    }
}

impl ManagedResource for AmqpReadinessWorker {
    fn name(&self) -> &str {
        self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        if let Some(handle) = self.handle.lock().await.take() {
            handle.await.map_err(ShutdownError::new)?;
        }
        Ok(())
    }
}

fn assemble_role_outputs(
    distributed_cas: DomainModuleResult,
    event_publisher: DomainModuleResult,
    event_subscriber: DomainModuleResult,
) -> EventingRoleOutputs {
    EventingRoleOutputs {
        distributed_cas,
        event_publisher,
        event_subscriber,
    }
}

fn split_amqp_resources(
    resources: Vec<Box<diport::DynManagedResource<'static>>>,
) -> anyhow::Result<(
    Box<diport::DynManagedResource<'static>>,
    Box<diport::DynManagedResource<'static>>,
)> {
    let mut resources = resources.into_iter();
    let publisher = resources
        .next()
        .context("settingsonly AMQP omitted publisher lifecycle")?;
    let subscriber = resources
        .next()
        .context("settingsonly AMQP omitted subscriber lifecycle")?;
    anyhow::ensure!(
        resources.next().is_none(),
        "settingsonly AMQP produced an undeclared lifecycle resource"
    );
    Ok((publisher, subscriber))
}

fn relay_budget() -> anyhow::Result<RelayBudget> {
    RelayBudget::new(
        RELAY_LEASE_TTL,
        RELAY_PUBLISH_TIMEOUT,
        RELAY_SETTLE_TIMEOUT,
        RELAY_SAFETY_MARGIN,
    )
    .context("build settingsonly relay budget")
}

fn wire_relay(
    inputs: &EventingInputs,
    budget: RelayBudget,
    output: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let relay = RelayConfig::new(RELAY_POLL_INTERVAL, RELAY_MAX_IN_FLIGHT)
        .context("build settingsonly relay config")?;
    let outbox = inputs.pg.for_domain::<postgres::caps::Settings>().outbox(
        inputs.amqp.infra().publisher(),
        budget,
        Arc::clone(&inputs.tenant_authority),
        inputs.dlx_payload_protector.clone(),
    );
    let health = Arc::new(WorkerHealth::starting());
    let worker_health = Arc::clone(&health);
    output.workers.push(Box::new(move |token| {
        DynManagedResource::new_box(spawn_relay(
            "settingsonly-outbox-relay-settings".to_owned(),
            outbox,
            relay,
            Arc::new(crate::SystemClock),
            token,
            worker_health,
            Arc::new(MetricsOutboxMetrics),
        ))
    }));
    let name = primitives::ProbeName::parse(&format!("{OUTBOX_RELAY_PROBE}_settings"))
        .context("build settingsonly relay probe name")?;
    output
        .probes
        .push((name.clone(), Box::new(WorkerProbe::new(name, health))));
    Ok(())
}

fn wire_consumer(
    pg: &postgres::PgRuntimeHandle,
    amqp: &amqp::AmqpRuntimeDeps,
    tenant_authority: Arc<eventexec::TenantAuthority>,
    consumer_runtime: postgres::PgConsumerRuntimeBundle,
    subscriptions: Vec<eventing_composition::BridgedSubscription>,
    output: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let [subscription] = subscriptions.as_slice() else {
        anyhow::bail!("settingsonly requires exactly one bridged settings subscription");
    };
    let (inbox, dead_letter) = consumer_runtime.into_parts();
    let lease = LeaseConfig::from_ttl(inbox.lease_ttl());
    let health = Arc::new(WorkerHealth::starting());
    let worker_name = format!(
        "settingsonly-event-consumer:{}:{}",
        subscription.consumer(),
        subscription.topic()
    );
    let probe_name = primitives::ProbeName::parse(&format!(
        "{EVENT_CONSUMER_PROBE}_{}",
        subscription.identity_slug()
    ))
    .context("build settingsonly consumer probe name")?;
    let worker = eventing_composition::SettingsConsumerFactory::new(pg).worker(
        subscription.dispatch_token().clone(),
        eventing_composition::WorkerInputs::new(
            worker_name,
            amqp.infra().subscriber(),
            Topic::new(subscription.topic()),
            Arc::new(inbox),
            DynDeadLetterStore::new_box(dead_letter),
            subscription.consumer_meta(tenant_authority),
            lease,
            Arc::clone(&health),
        ),
    )?;
    match subscription.readiness() {
        SubscriberReadiness::Required => {
            output.workers.push(worker);
            output.probes.push((
                probe_name.clone(),
                Box::new(WorkerProbe::new(probe_name, health)),
            ));
        }
    }
    Ok(())
}

fn wire_inbox_sweeper(
    pg: &postgres::PgRuntimeHandle,
    output: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let sweeper = pg.infra().inbox_sweeper();
    let config = SweeperConfig::new(sweeper.retention_seconds(), INBOX_SWEEP_INTERVAL)
        .context("build settingsonly inbox sweeper config")?;
    let health = Arc::new(WorkerHealth::starting());
    let worker_health = Arc::clone(&health);
    output.workers.push(Box::new(move |token| {
        let loop_health = Arc::clone(&worker_health);
        let loop_token = token.clone();
        let handle = tokio::spawn(async move {
            let _stopped = loop_health.stopped_on_exit();
            sweeper_loop(
                Arc::new(sweeper),
                config,
                Arc::new(crate::SystemClock),
                loop_token,
                Arc::clone(&loop_health),
                RetentionTarget::InboxReceipts,
            )
            .await;
        });
        DynManagedResource::new_box(SweeperWorker::adopt(
            "settingsonly-inbox-dedup-sweeper",
            handle,
            worker_health,
            token,
        ))
    }));
    let name = primitives::ProbeName::parse("settingsonly_inbox_sweeper")
        .context("build settingsonly inbox sweeper probe name")?;
    output
        .probes
        .push((name.clone(), Box::new(WorkerProbe::new(name, health))));
    Ok(())
}

fn wire_outbox_maintenance(
    pg: &postgres::PgRuntimeHandle,
    redis: &redis::RedisRuntimeDeps,
    output: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let coordinator = distributed::OutboxMaintenanceCoordinator::from_ports(
        redis.infra().lock_store(),
        pg.infra().cas_store(),
        OUTBOX_MAINTENANCE_TTL,
    );
    let maintenance = pg.infra().outbox_maintenance();
    let sampler =
        distributed::CoordinatedOutboxBacklog::new(maintenance.clone(), coordinator.clone());
    let sweeper = distributed::CoordinatedRetentionSweeper::new(maintenance, coordinator);
    let sampler_config = SamplerConfig::new(vec!["settings".to_owned()], OUTBOX_SAMPLE_INTERVAL)
        .context("build settingsonly outbox sampler config")?;
    let sweeper_config = SweeperConfig::new(OUTBOX_RETAIN_SECONDS, OUTBOX_SWEEP_INTERVAL)
        .context("build settingsonly outbox sweeper config")?;

    let sampler_health = Arc::new(WorkerHealth::starting());
    let sampler_worker_health = Arc::clone(&sampler_health);
    output.workers.push(Box::new(move |token| {
        DynManagedResource::new_box(ThreadedEventWorker::spawn(
            "settingsonly-outbox-sampler",
            token,
            move |thread_token| {
                let _stopped = sampler_worker_health.stopped_on_exit();
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    tracing::error!("settingsonly sampler runtime failed");
                    return;
                };
                runtime.block_on(backlog_sampler_loop(
                    Arc::new(sampler),
                    sampler_config,
                    thread_token,
                    Arc::clone(&sampler_worker_health),
                    Arc::new(MetricsOutboxMetrics),
                ));
            },
        ))
    }));
    let sampler_name = primitives::ProbeName::parse("settingsonly_outbox_sampler")
        .context("build settingsonly sampler probe name")?;
    output.probes.push((
        sampler_name.clone(),
        Box::new(WorkerProbe::new(sampler_name, sampler_health)),
    ));

    let sweeper_health = Arc::new(WorkerHealth::starting());
    let sweeper_worker_health = Arc::clone(&sweeper_health);
    output.workers.push(Box::new(move |token| {
        DynManagedResource::new_box(ThreadedEventWorker::spawn(
            "settingsonly-outbox-sweeper",
            token,
            move |thread_token| {
                let _stopped = sweeper_worker_health.stopped_on_exit();
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    tracing::error!("settingsonly sweeper runtime failed");
                    return;
                };
                runtime.block_on(sweeper_loop(
                    Arc::new(sweeper),
                    sweeper_config,
                    Arc::new(crate::SystemClock),
                    thread_token,
                    Arc::clone(&sweeper_worker_health),
                    RetentionTarget::OutboxPublished,
                ));
            },
        ))
    }));
    let sweeper_name = primitives::ProbeName::parse("settingsonly_outbox_sweeper")
        .context("build settingsonly sweeper probe name")?;
    output.probes.push((
        sweeper_name.clone(),
        Box::new(WorkerProbe::new(sweeper_name, sweeper_health)),
    ));
    Ok(())
}

fn validate_settings_closure(
    subscriptions: &[eventing_composition::BridgedSubscription],
) -> anyhow::Result<()> {
    let [subscription] = subscriptions else {
        anyhow::bail!("settingsonly settings subscription closure is not singular");
    };
    anyhow::ensure!(
        subscription.contract_id() == generated::event::settings_v1::CONTRACT_ID
            && subscription.topic() == generated::event::settings_v1::TOPIC
            && subscription.schema_version() == "v1"
            && subscription.consumer() == "settings"
            && subscription.group().as_str() == generated::event::settings_v1::TOPIC
            && subscription.readiness() == SubscriberReadiness::Required
            && subscription.dispatch_token().dispatch()
                == SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings
            && subscription.dispatch_token().policy() == ExternalEffectPolicy::Reconcile,
        "settingsonly settings subscription closure drift"
    );
    Ok(())
}

struct WorkerProbe {
    name: primitives::ProbeName,
    health: Arc<WorkerHealth>,
}

impl WorkerProbe {
    fn new(name: primitives::ProbeName, health: Arc<WorkerHealth>) -> Self {
        Self { name, health }
    }
}

impl bootstrap::HealthProbe for WorkerProbe {
    fn check(&self) -> primitives::HealthCheck {
        primitives::HealthCheck::new(
            self.name.clone(),
            required_health_status(self.health.status()),
            self.health.detail(),
        )
    }
}

fn required_health_status(status: primitives::HealthStatus) -> primitives::HealthStatus {
    match status {
        primitives::HealthStatus::Healthy => primitives::HealthStatus::Healthy,
        primitives::HealthStatus::Degraded | primitives::HealthStatus::Unhealthy => {
            primitives::HealthStatus::Unhealthy
        }
        _ => primitives::HealthStatus::Unhealthy,
    }
}

#[derive(Debug)]
struct ThreadedWorkerError;

impl std::fmt::Display for ThreadedWorkerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("settingsonly threaded event worker failed")
    }
}

impl std::error::Error for ThreadedWorkerError {}

struct ThreadedEventWorker {
    name: &'static str,
    token: tokio_util::sync::CancellationToken,
    completion:
        tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<Result<(), ThreadedWorkerError>>>>,
}

impl ThreadedEventWorker {
    fn spawn<F>(name: &'static str, token: tokio_util::sync::CancellationToken, run: F) -> Self
    where
        F: FnOnce(tokio_util::sync::CancellationToken) + Send + 'static,
    {
        let thread_token = token.clone();
        let (completed, completion) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run(thread_token);
            }))
            .map_err(|_| ThreadedWorkerError);
            let _ = completed.send(result);
        });
        Self {
            name,
            token,
            completion: tokio::sync::Mutex::new(Some(completion)),
        }
    }
}

impl ManagedResource for ThreadedEventWorker {
    fn name(&self) -> &str {
        self.name
    }

    fn shutdown_timeout(&self) -> Duration {
        EVENT_WORKER_SHUTDOWN_TIMEOUT
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        let Some(completion) = self.completion.lock().await.take() else {
            return Ok(());
        };
        completion
            .await
            .map_err(ShutdownError::new)?
            .map_err(ShutdownError::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generated_binding_is_exact_required_settings_reconcile() -> anyhow::Result<()> {
        let binding = settings_composition::test_support::binding().await?;
        let (mut registry, _output) = bootstrap::compose_bindings(&mut vec![binding])?;
        let subscriptions = eventing_composition::bridge_generated_settings_subscriptions(
            registry.drain_subscribers(),
        )?;
        validate_settings_closure(&subscriptions)?;
        let [subscription] = subscriptions.as_slice() else {
            unreachable!("validated singular subscription")
        };
        assert_eq!(subscription.readiness(), SubscriberReadiness::Required);
        assert_eq!(
            subscription.dispatch_token().policy(),
            ExternalEffectPolicy::Reconcile
        );
        assert!(validate_settings_closure(&[]).is_err());
        Ok(())
    }

    #[test]
    fn required_worker_probes_start_fail_closed() -> anyhow::Result<()> {
        let name = primitives::ProbeName::parse("settingsonly_event_test")?;
        let health = Arc::new(WorkerHealth::starting());
        let probe = WorkerProbe::new(name, Arc::clone(&health));
        assert_eq!(
            bootstrap::HealthProbe::check(&probe).status(),
            primitives::HealthStatus::Unhealthy
        );
        health.mark_healthy();
        assert_eq!(
            bootstrap::HealthProbe::check(&probe).status(),
            primitives::HealthStatus::Healthy
        );
        Ok(())
    }

    #[test]
    fn required_worker_probe_promotes_degraded_to_unhealthy() {
        assert_eq!(
            required_health_status(primitives::HealthStatus::Degraded),
            primitives::HealthStatus::Unhealthy
        );
    }

    #[test]
    fn relay_budget_fits_total_drain_contract() -> anyhow::Result<()> {
        let budget = relay_budget()?;
        assert_eq!(budget.publish_timeout(), RELAY_PUBLISH_TIMEOUT);
        assert_eq!(
            crate::runtime::total_drain_duration(),
            Duration::from_secs(60)
        );
        Ok(())
    }

    #[test]
    fn eventing_outputs_keep_role_readiness_disjoint() -> anyhow::Result<()> {
        let probe = |name: &'static str| -> anyhow::Result<_> {
            let name = primitives::ProbeName::parse(name)?;
            Ok((
                name.clone(),
                Box::new(WorkerProbe::new(name, Arc::new(WorkerHealth::healthy())))
                    as Box<dyn bootstrap::HealthProbe>,
            ))
        };
        let outputs = assemble_role_outputs(
            DomainModuleResult {
                probes: vec![probe("settingsonly_outbox_sampler")?],
                ..Default::default()
            },
            DomainModuleResult {
                probes: vec![probe("outbox_relay_settings")?],
                ..Default::default()
            },
            DomainModuleResult {
                probes: vec![
                    probe("event_consumer_settings_config_version_changed_v1_settings")?,
                    probe("settingsonly_inbox_sweeper")?,
                ],
                ..Default::default()
            },
        );
        assert_eq!(outputs.distributed_cas.probes.len(), 1);
        assert_eq!(outputs.event_publisher.probes.len(), 1);
        assert_eq!(outputs.event_subscriber.probes.len(), 2);
        assert_eq!(
            outputs.event_publisher.probes[0].0.as_str(),
            "outbox_relay_settings"
        );
        assert!(
            outputs.event_subscriber.probes[0]
                .0
                .as_str()
                .starts_with(EVENT_CONSUMER_PROBE)
        );
        Ok(())
    }
}
