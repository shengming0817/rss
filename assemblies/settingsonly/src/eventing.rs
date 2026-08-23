//! Durable, isolated Settings event transport.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use bootstrap::DomainModuleResult;
use diport::{
    AckableSubscriber as _, DynDeadLetterStore, DynManagedResource, ManagedResource, ShutdownError,
    Topic,
};
#[cfg(test)]
use eventexec::EVENT_CONSUMER_PROBE;
use eventexec::{
    LeaseConfig, MetricsOutboxMetrics, RelayBudget, RelayConfig, RetentionTarget, SamplerConfig,
    SweeperConfig, SweeperWorker, WorkerHealth, spawn_on_dedicated_runtime, spawn_relay,
    sweeper_loop,
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
const MAINTENANCE_TTL: Duration = Duration::from_secs(30);
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
    admission_control: primitives::ProcessAdmissionControl,
    relay_admission: primitives::RelayAdmission,
    consumer_admission: primitives::ConsumerAdmission,
    write_admission: primitives::WriteAdmission,
    admission_identity: Option<eventexec::DrAdmissionProcessIdentity>,
}

impl EventingInputs {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    // reason: sealed assembly input owns the exact provider set and all three typed admission lanes.
    pub(crate) fn new(
        pg: postgres::PgRuntimeHandle,
        redis: redis::RedisRuntimeDeps,
        amqp: amqp::AmqpRuntimeDeps,
        amqp_resources: Vec<Box<diport::DynManagedResource<'static>>>,
        tenant_authority: Arc<eventexec::TenantAuthority>,
        dlx_payload_protector: postgres::DlxPayloadProtector,
        admission_control: primitives::ProcessAdmissionControl,
        relay_admission: primitives::RelayAdmission,
        consumer_admission: primitives::ConsumerAdmission,
        write_admission: primitives::WriteAdmission,
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
            admission_control,
            relay_admission,
            consumer_admission,
            write_admission,
            admission_identity: None,
        }
    }

    pub(crate) fn bind_admission_identity(
        mut self,
        identity: eventexec::DrAdmissionProcessIdentity,
    ) -> anyhow::Result<Self> {
        if let Some(epoch) = identity.required_admission_epoch() {
            self.admission_control
                .pause_all(epoch)
                .context("arm settingsonly required DR admission epoch")?;
        }
        self.admission_identity = Some(identity);
        Ok(self)
    }

    pub(crate) fn projection_payload_protector(&self) -> postgres::DlxPayloadProtector {
        self.dlx_payload_protector.clone()
    }

    pub(crate) fn write_admission(&self) -> primitives::WriteAdmission {
        self.write_admission.clone()
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
pub(crate) async fn wire(
    mut inputs: EventingInputs,
    bindings: Vec<bootstrap::SubscriberBinding>,
) -> anyhow::Result<EventingRoleOutputs> {
    let subscriptions = eventing_composition::bridge_generated_settings_subscriptions(bindings)
        .context("bridge settingsonly generated subscription")?;
    validate_settings_closure(subscriptions.subscriptions())?;
    let (subscriptions, _) = subscriptions.into_runtime_parts();

    let budget = relay_budget()?;
    inputs
        .pg
        .validate_relay_budget(budget)
        .context("settingsonly relay budget disagrees with database policy")?;

    let (publisher_resource, subscriber_resource) =
        split_amqp_resources(std::mem::take(&mut inputs.amqp_resources))?;
    let mut event_publisher = DomainModuleResult::default();
    event_publisher.push_resource(publisher_resource);
    let mut event_subscriber = DomainModuleResult::default();
    event_subscriber.push_resource(subscriber_resource);
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
        admission_control,
        relay_admission: _,
        consumer_admission,
        write_admission,
        admission_identity,
    } = inputs;
    wire_consumer(
        &pg,
        &amqp,
        tenant_authority,
        consumer_runtime,
        consumer_admission,
        subscriptions,
        &mut event_subscriber,
    )
    .await?;
    wire_amqp_readiness(&amqp, &mut event_publisher, &mut event_subscriber)?;
    wire_inbox_sweeper(&pg, write_admission.clone(), &mut event_subscriber)?;
    wire_outbox_maintenance(&pg, &redis, write_admission, &mut distributed_cas)?;
    retain_admission_authority(
        pg.clone(),
        admission_control,
        admission_identity.context("settingsonly DR admission identity was not bound")?,
        &mut distributed_cas,
    )?;
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
    let publisher_name = primitives::ProbeName::parse(crate::readiness::AMQP_PUBLISHER)
        .context("build settingsonly AMQP publisher readiness probe name")?;
    publisher.push_probe((
        publisher_name.clone(),
        Box::new(TransportProbe::new(
            publisher_name,
            Arc::clone(&publisher_ready),
        )),
    ));
    let publisher_amqp = amqp.clone();
    publisher.push_worker(bootstrap::WorkerSpec::observational_phase_one(
        "assemblies.settingsonly.src.eventing.01",
        move |token| {
            DynManagedResource::new_box(AmqpReadinessWorker::spawn(
                publisher_amqp,
                AmqpReadinessRole::Publisher,
                publisher_ready,
                token,
            ))
        },
    ));

    let subscriber_ready = Arc::new(std::sync::atomic::AtomicBool::new(
        amqp.subscriber_readiness().is_ready(),
    ));
    let subscriber_name = primitives::ProbeName::parse(crate::readiness::AMQP_SUBSCRIBER)
        .context("build settingsonly AMQP subscriber readiness probe name")?;
    subscriber.push_probe((
        subscriber_name.clone(),
        Box::new(TransportProbe::new(
            subscriber_name,
            Arc::clone(&subscriber_ready),
        )),
    ));
    let subscriber_amqp = amqp.clone();
    subscriber.push_worker(bootstrap::WorkerSpec::observational_phase_one(
        "assemblies.settingsonly.src.eventing.02",
        move |token| {
            DynManagedResource::new_box(AmqpReadinessWorker::spawn(
                subscriber_amqp,
                AmqpReadinessRole::Subscriber,
                subscriber_ready,
                token,
            ))
        },
    ));
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
    handle: tokio::sync::Mutex<Option<diport::OwnedTask<()>>>,
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
            handle: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(handle))),
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
            handle
                .join()
                .await
                .map_err(ShutdownError::from_join_error)?;
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
    let admission = inputs.relay_admission.clone();
    output.push_worker(bootstrap::WorkerSpec::relay_deferred(
        "assemblies.settingsonly.src.eventing.03",
        &admission,
        move |token, relay_admission| {
            DynManagedResource::new_box(spawn_relay(
                "settingsonly-outbox-relay-settings".to_owned(),
                outbox,
                relay,
                Arc::new(crate::SystemClock),
                token,
                worker_health,
                Arc::new(MetricsOutboxMetrics),
                relay_admission,
            ))
        },
    ));
    let name = primitives::ProbeName::parse(crate::readiness::OUTBOX_RELAY)
        .context("build settingsonly relay probe name")?;
    output.push_probe((name.clone(), Box::new(WorkerProbe::new(name, health))));
    Ok(())
}

async fn wire_consumer(
    pg: &postgres::PgRuntimeHandle,
    amqp: &amqp::AmqpRuntimeDeps,
    tenant_authority: Arc<eventexec::TenantAuthority>,
    consumer_runtime: postgres::PgConsumerRuntimeBundle,
    admission: primitives::ConsumerAdmission,
    subscriptions: Vec<eventing_composition::BridgedSubscription>,
    output: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let [subscription] = subscriptions.as_slice() else {
        anyhow::bail!("settingsonly requires exactly one bridged settings subscription");
    };
    let topic = Topic::new(subscription.topic());
    amqp.infra()
        .subscriber()
        .prepare_ackable(topic.clone())
        .await
        .with_context(|| {
            format!(
                "prepare settingsonly durable consumer topology for '{}'",
                subscription.topic()
            )
        })?;
    let (inbox, dead_letter) = consumer_runtime.into_parts();
    let lease = LeaseConfig::from_ttl(inbox.lease_ttl());
    let health = Arc::new(WorkerHealth::starting());
    let worker_name = format!(
        "settingsonly-event-consumer:{}:{}",
        subscription.consumer(),
        subscription.topic()
    );
    let probe_name = primitives::ProbeName::parse(crate::readiness::EVENT_CONSUMER)
        .context("build settingsonly consumer probe name")?;
    let worker = eventing_composition::SettingsConsumerFactory::new(pg).worker(
        subscription.dispatch_token().clone(),
        eventing_composition::WorkerInputs::new(
            worker_name,
            amqp.infra().subscriber(),
            topic,
            Arc::new(inbox),
            DynDeadLetterStore::new_box(dead_letter),
            subscription.consumer_meta(tenant_authority),
            lease,
            Arc::clone(&health),
            admission,
        ),
    )?;
    match subscription.readiness() {
        SubscriberReadiness::Required => {
            output.push_worker(worker);
            output.push_probe((
                probe_name.clone(),
                Box::new(WorkerProbe::new(probe_name, health)),
            ));
        }
    }
    Ok(())
}

fn wire_inbox_sweeper(
    pg: &postgres::PgRuntimeHandle,
    admission: primitives::WriteAdmission,
    output: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let sweeper = pg.infra().inbox_sweeper();
    let config = SweeperConfig::new(sweeper.retention_seconds(), INBOX_SWEEP_INTERVAL)
        .context("build settingsonly inbox sweeper config")?;
    let health = Arc::new(WorkerHealth::starting());
    let worker_health = Arc::clone(&health);
    output.push_worker(bootstrap::WorkerSpec::writes_phase_one(
        "assemblies.settingsonly.src.eventing.04",
        &admission,
        move |token, worker_admission| {
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
                    worker_admission,
                )
                .await;
            });
            DynManagedResource::new_box(SweeperWorker::adopt(
                "settingsonly-inbox-dedup-sweeper",
                handle,
                worker_health,
                token,
            ))
        },
    ));
    let name = primitives::ProbeName::parse(crate::readiness::INBOX_SWEEPER)
        .context("build settingsonly inbox sweeper probe name")?;
    output.push_probe((name.clone(), Box::new(WorkerProbe::new(name, health))));
    Ok(())
}

fn wire_outbox_maintenance(
    pg: &postgres::PgRuntimeHandle,
    redis: &redis::RedisRuntimeDeps,
    admission: primitives::WriteAdmission,
    output: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let sampler_config = SamplerConfig::new(vec!["settings".to_owned()], OUTBOX_SAMPLE_INTERVAL)
        .context("build settingsonly outbox sampler config")?;
    let sampler_coordinator =
        distributed::MaintenanceCoordinator::<distributed::OutboxBacklogMaintenance>::for_domains(
            redis.infra().lock_store(),
            pg.infra().cas_store(),
            MAINTENANCE_TTL,
            sampler_config.domains(),
        )?;
    let retention_coordinator = distributed::MaintenanceCoordinator::<
        distributed::OutboxRetentionMaintenance,
    >::for_retention(
        redis.infra().lock_store(),
        pg.infra().cas_store(),
        MAINTENANCE_TTL,
    );
    let maintenance = pg.infra().outbox_maintenance();
    let sweeper =
        distributed::CoordinatedRetentionSweeper::new(maintenance.clone(), retention_coordinator);
    let sweeper_config = SweeperConfig::new(OUTBOX_RETAIN_SECONDS, OUTBOX_SWEEP_INTERVAL)
        .context("build settingsonly outbox sweeper config")?;

    let sampler_health = Arc::new(WorkerHealth::starting());
    let sampler_worker_health = Arc::clone(&sampler_health);
    output.push_worker(bootstrap::WorkerSpec::observational_phase_one(
        "assemblies.settingsonly.src.eventing.05",
        move |token| {
            DynManagedResource::new_box(spawn_on_dedicated_runtime(
                "settingsonly-outbox-sampler",
                token,
                Arc::clone(&sampler_worker_health),
                EVENT_WORKER_SHUTDOWN_TIMEOUT,
                move |thread_token| async move {
                    eventing_composition::coordinated_outbox_backlog_sampler_loop(
                        Arc::new(maintenance),
                        sampler_coordinator,
                        sampler_config,
                        thread_token,
                        Arc::clone(&sampler_worker_health),
                        Arc::new(MetricsOutboxMetrics),
                    )
                    .await;
                    Ok(())
                },
            ))
        },
    ));
    let sampler_name = primitives::ProbeName::parse(crate::readiness::OUTBOX_SAMPLER)
        .context("build settingsonly sampler probe name")?;
    output.push_probe((
        sampler_name.clone(),
        Box::new(WorkerProbe::new(sampler_name, sampler_health)),
    ));

    let sweeper_health = Arc::new(WorkerHealth::starting());
    let sweeper_worker_health = Arc::clone(&sweeper_health);
    output.push_worker(bootstrap::WorkerSpec::writes_phase_one(
        "assemblies.settingsonly.src.eventing.06",
        &admission,
        move |token, worker_admission| {
            DynManagedResource::new_box(spawn_on_dedicated_runtime(
                "settingsonly-outbox-sweeper",
                token,
                Arc::clone(&sweeper_worker_health),
                EVENT_WORKER_SHUTDOWN_TIMEOUT,
                move |thread_token| async move {
                    sweeper_loop(
                        Arc::new(sweeper),
                        sweeper_config,
                        Arc::new(crate::SystemClock),
                        thread_token,
                        Arc::clone(&sweeper_worker_health),
                        RetentionTarget::OutboxPublished,
                        worker_admission,
                    )
                    .await;
                    Ok(())
                },
            ))
        },
    ));
    let sweeper_name = primitives::ProbeName::parse(crate::readiness::OUTBOX_SWEEPER)
        .context("build settingsonly sweeper probe name")?;
    output.push_probe((
        sweeper_name.clone(),
        Box::new(WorkerProbe::new(sweeper_name, sweeper_health)),
    ));
    Ok(())
}

fn retain_admission_authority(
    pg: postgres::PgRuntimeHandle,
    control: primitives::ProcessAdmissionControl,
    identity: eventexec::DrAdmissionProcessIdentity,
    output: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let health = Arc::new(WorkerHealth::starting());
    let probe_name = primitives::ProbeName::parse(crate::readiness::DR_ADMISSION)
        .context("build settingsonly DR admission probe name")?;
    output.push_probe((
        probe_name.clone(),
        Box::new(WorkerProbe::new(probe_name, Arc::clone(&health))),
    ));
    output.push_worker(bootstrap::WorkerSpec::observational_phase_one(
        "assemblies.settingsonly.src.eventing.07",
        move |token| {
            DynManagedResource::new_box(spawn_on_dedicated_runtime(
                "settingsonly-dr-admission-owner",
                token,
                Arc::clone(&health),
                EVENT_WORKER_SHUTDOWN_TIMEOUT,
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
        validate_settings_closure(subscriptions.subscriptions())?;
        let [subscription] = subscriptions.subscriptions() else {
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
            DomainModuleResult::from_parts([probe(crate::readiness::OUTBOX_SAMPLER)?], [], []),
            DomainModuleResult::from_parts([probe(crate::readiness::OUTBOX_RELAY)?], [], []),
            DomainModuleResult::from_parts(
                [
                    probe(crate::readiness::EVENT_CONSUMER)?,
                    probe(crate::readiness::INBOX_SWEEPER)?,
                ],
                [],
                [],
            ),
        );
        assert_eq!(outputs.distributed_cas.probe_count(), 1);
        assert_eq!(outputs.event_publisher.probe_count(), 1);
        assert_eq!(outputs.event_subscriber.probe_count(), 2);
        let (publisher_probe, _) = outputs
            .event_publisher
            .probes()
            .next()
            .context("settingsonly event publisher output omitted its probe")?;
        assert_eq!(publisher_probe.as_str(), crate::readiness::OUTBOX_RELAY);
        let (subscriber_probe, _) = outputs
            .event_subscriber
            .probes()
            .next()
            .context("settingsonly event subscriber output omitted its probe")?;
        assert!(subscriber_probe.as_str().starts_with(EVENT_CONSUMER_PROBE));
        Ok(())
    }
}
