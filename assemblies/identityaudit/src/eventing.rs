//! Durable, isolated Identity -> Audit event transport.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use bootstrap::{DomainModuleResult, WorkerSpec};
#[cfg(test)]
use diport::ShutdownError;
use diport::{AckableSubscriber as _, DynDeadLetterStore, DynManagedResource, Topic};
#[cfg(test)]
use eventexec::ManagedBlockingWorker;
use eventexec::{
    EVENT_CONSUMER_PROBE, LeaseConfig, MetricsOutboxMetrics, OUTBOX_RELAY_PROBE, RelayConfig,
    RetentionTarget, SamplerConfig, SweeperConfig, SweeperWorker, WorkerHealth,
    spawn_on_dedicated_runtime, spawn_relay, sweeper_loop,
};
use eventing::delivery::DeliveryBudget;
use generated::event::{SubscriberReadiness, SubscriptionDispatchKey};

const RELAY_POLL_INTERVAL: Duration = Duration::from_millis(250);
const RELAY_MAX_IN_FLIGHT: usize = 32;
const RELAY_LEASE_TTL: Duration = Duration::from_secs(60);
const RELAY_PUBLISH_TIMEOUT: Duration = Duration::from_secs(40);
const RELAY_SETTLE_TIMEOUT: Duration = Duration::from_secs(5);
const RELAY_SAFETY_MARGIN: Duration = Duration::from_secs(5);
const INBOX_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const INBOX_SWEEPER_NAME: &str = "identityaudit-inbox-dedup-sweeper";
const OUTBOX_SAMPLE_INTERVAL: Duration = Duration::from_secs(30);
const OUTBOX_SWEEP_INTERVAL: Duration = Duration::from_secs(300);
const OUTBOX_RETAIN_SECONDS: u64 = 604_800;
const MAINTENANCE_TTL: Duration = Duration::from_secs(30);
const EVENT_WORKER_SHUTDOWN_BUDGET: eventing::lifecycle::ShutdownBudget =
    eventing::lifecycle::ShutdownBudget::STANDARD;
type LifecycleProbe = (primitives::ProbeName, Box<dyn bootstrap::HealthProbe>);

#[allow(clippy::too_many_arguments)]
// reason: assembly composition takes the exact generated transport capabilities plus three typed lanes.
pub(crate) async fn wire(
    pg: &postgres::PgRuntimeHandle,
    redis: &redis::RedisRuntimeDeps,
    bindings: Vec<bootstrap::SubscriberBinding>,
    amqp_endpoint: &secure::AmqpEndpoint,
    amqp_ca: amqp::AmqpPrivateCa,
    audit_key: &primitives::MacKey,
    tenant_authority: Arc<eventexec::TenantAuthority>,
    dlx_payload_protector: postgres::DlxPayloadProtector,
    admission_identity: eventexec::DrAdmissionProcessIdentity,
    admission_control: primitives::ProcessAdmissionControl,
    relay_admission: primitives::RelayAdmission,
    consumer_admission: primitives::ConsumerAdmission,
    write_admission: primitives::WriteAdmission,
) -> anyhow::Result<crate::providers::EventingRoleOutputs> {
    let subscriptions = eventing_composition::bridge_generated_audit_subscriptions(bindings)
        .context("bridge identityaudit generated subscriptions")?;
    validate_audit_closure(subscriptions.subscriptions())?;
    let (subscriptions, _) = subscriptions.into_runtime_parts();
    let budget = relay_budget()?;
    pg.validate_relay_budget(budget)
        .context("identityaudit relay budget disagrees with database policy")?;

    let publisher_endpoint = amqp::AmqpPublisherEndpoint::new(amqp_endpoint.clone());
    let subscriber_endpoint = amqp::AmqpSubscriberEndpoint::new(amqp_endpoint.clone());
    let amqp = amqp::AmqpRuntimeDeps::connect_with_private_ca(
        &publisher_endpoint,
        &subscriber_endpoint,
        amqp_ca,
        "identityaudit-identity",
        budget.publish_timeout(),
    )
    .await
    .context("connect identityaudit AMQP")?;
    let rollback = amqp.clone();
    let mut resources = amqp.runtime_resources().into_iter();
    let publisher_resource = resources
        .next()
        .context("identityaudit AMQP omitted publisher lifecycle")?;
    let subscriber_resource = resources
        .next()
        .context("identityaudit AMQP omitted subscriber lifecycle")?;
    anyhow::ensure!(
        resources.next().is_none(),
        "identityaudit AMQP produced undeclared lifecycle resource"
    );

    let result = wire_connected(
        pg,
        redis,
        subscriptions,
        amqp.infra(),
        audit_key,
        tenant_authority,
        dlx_payload_protector,
        budget,
        publisher_resource,
        subscriber_resource,
        admission_control,
        relay_admission,
        consumer_admission,
        write_admission,
        admission_identity,
    )
    .await;
    match result {
        Ok(outputs) => Ok(outputs),
        Err(error) => {
            rollback_amqp(rollback).await;
            Err(error)
        }
    }
}

async fn rollback_amqp(amqp: amqp::AmqpRuntimeDeps) {
    rollback_resources(amqp.runtime_resources()).await;
}

async fn rollback_resources(resources: Vec<Box<DynManagedResource<'static>>>) {
    let mut stack =
        bootstrap::shutdown::ShutdownStack::new(tokio_util::sync::CancellationToken::new());
    for resource in resources {
        stack.register_detached(resource);
    }
    for failure in stack.shutdown().await {
        tracing::warn!(error = %failure, "identityaudit AMQP startup rollback failed");
    }
}

#[allow(clippy::too_many_arguments)]
async fn wire_connected(
    pg: &postgres::PgRuntimeHandle,
    redis: &redis::RedisRuntimeDeps,
    subscriptions: Vec<eventing_composition::BridgedSubscription>,
    amqp: amqp::AmqpInfraDeps,
    audit_key: &primitives::MacKey,
    tenant_authority: Arc<eventexec::TenantAuthority>,
    dlx_payload_protector: postgres::DlxPayloadProtector,
    budget: DeliveryBudget,
    publisher_resource: Box<DynManagedResource<'static>>,
    subscriber_resource: Box<DynManagedResource<'static>>,
    admission_control: primitives::ProcessAdmissionControl,
    relay_admission: primitives::RelayAdmission,
    consumer_admission: primitives::ConsumerAdmission,
    write_admission: primitives::WriteAdmission,
    admission_identity: eventexec::DrAdmissionProcessIdentity,
) -> anyhow::Result<crate::providers::EventingRoleOutputs> {
    let event_publisher = wire_publisher(
        pg,
        &amqp,
        budget,
        Arc::clone(&tenant_authority),
        dlx_payload_protector.clone(),
        publisher_resource,
        relay_admission,
    )?;
    let event_subscriber = wire_subscribers(
        pg,
        subscriptions,
        &amqp,
        audit_key,
        tenant_authority,
        dlx_payload_protector,
        subscriber_resource,
        consumer_admission,
        write_admission.clone(),
    )
    .await?;
    let mut distributed_cas = wire_distributed_maintenance(pg, redis, write_admission)?;
    retain_admission_authority(
        pg.clone(),
        admission_control,
        admission_identity,
        &mut distributed_cas,
    )?;
    Ok(assemble_role_outputs(
        distributed_cas,
        event_publisher,
        event_subscriber,
    ))
}

fn assemble_role_outputs(
    distributed_cas: DomainModuleResult,
    event_publisher: DomainModuleResult,
    event_subscriber: DomainModuleResult,
) -> crate::providers::EventingRoleOutputs {
    crate::providers::EventingRoleOutputs {
        distributed_cas,
        event_publisher,
        event_subscriber,
    }
}

fn relay_budget() -> anyhow::Result<DeliveryBudget> {
    DeliveryBudget::new(
        RELAY_LEASE_TTL,
        RELAY_PUBLISH_TIMEOUT,
        RELAY_SETTLE_TIMEOUT,
        RELAY_SAFETY_MARGIN,
    )
    .context("build identityaudit relay budget")
}

fn wire_publisher(
    pg: &postgres::PgRuntimeHandle,
    amqp: &amqp::AmqpInfraDeps,
    budget: DeliveryBudget,
    tenant_authority: Arc<eventexec::TenantAuthority>,
    dlx_payload_protector: postgres::DlxPayloadProtector,
    resource: Box<DynManagedResource<'static>>,
    admission: primitives::RelayAdmission,
) -> anyhow::Result<DomainModuleResult> {
    let (relay, probe_name) = publisher_plan()?;
    let outbox = pg.for_domain::<postgres::caps::Identity>().outbox(
        amqp.publisher(),
        budget,
        tenant_authority,
        dlx_payload_protector,
    );
    let health = Arc::new(WorkerHealth::healthy());
    let worker_health = Arc::clone(&health);
    let worker = WorkerSpec::relay_deferred(
        "assemblies.identityaudit.src.eventing.01",
        &admission,
        move |token, relay_admission| {
            DynManagedResource::new_box(spawn_relay(
                "identityaudit-outbox-relay-identity".to_owned(),
                outbox,
                relay,
                Arc::new(crate::SystemClock),
                token,
                worker_health,
                Arc::new(MetricsOutboxMetrics),
                relay_admission,
                EVENT_WORKER_SHUTDOWN_BUDGET,
            ))
        },
    );
    Ok(DomainModuleResult::from_parts(
        [(
            probe_name.clone(),
            Box::new(WorkerProbe::new(probe_name, health)) as Box<dyn bootstrap::HealthProbe>,
        )],
        [resource],
        [worker],
    ))
}

fn publisher_plan() -> anyhow::Result<(RelayConfig, primitives::ProbeName)> {
    let relay = RelayConfig::new(RELAY_POLL_INTERVAL, RELAY_MAX_IN_FLIGHT)
        .context("build identityaudit relay config")?;
    let probe_name = primitives::ProbeName::parse(&format!("{OUTBOX_RELAY_PROBE}_identity"))
        .context("build identityaudit relay probe name")?;
    Ok((relay, probe_name))
}

#[allow(clippy::too_many_arguments)]
async fn wire_subscribers(
    pg: &postgres::PgRuntimeHandle,
    subscriptions: Vec<eventing_composition::BridgedSubscription>,
    amqp: &amqp::AmqpInfraDeps,
    audit_key: &primitives::MacKey,
    tenant_authority: Arc<eventexec::TenantAuthority>,
    dlx_payload_protector: postgres::DlxPayloadProtector,
    resource: Box<DynManagedResource<'static>>,
    admission: primitives::ConsumerAdmission,
    write_admission: primitives::WriteAdmission,
) -> anyhow::Result<DomainModuleResult> {
    let mut output = DomainModuleResult::from_parts([], [resource], []);
    for subscription in subscriptions {
        let topic = Topic::new(subscription.topic());
        amqp.subscriber()
            .prepare_ackable(topic.clone())
            .await
            .with_context(|| {
                format!(
                    "prepare identityaudit durable consumer topology for '{}'",
                    subscription.topic()
                )
            })?;
        let inbox = pg.infra().inbox();
        let lease = LeaseConfig::from_ttl(inbox.lease_ttl());
        let health = Arc::new(WorkerHealth::starting());
        let (worker_name, probe_name) = consumer_plan(&subscription)?;
        let worker = eventing_composition::AuditConsumerFactory::new(pg, audit_key).worker(
            subscription.dispatch_token().clone(),
            eventing_composition::WorkerInputs::new(
                worker_name,
                amqp.subscriber(),
                topic,
                Arc::new(inbox),
                DynDeadLetterStore::new_box(pg.infra().dead_letter(dlx_payload_protector.clone())),
                subscription.consumer_meta(Arc::clone(&tenant_authority)),
                lease,
                Arc::clone(&health),
                admission.clone(),
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
    }
    wire_inbox_sweeper(pg, write_admission, &mut output)?;
    Ok(output)
}

fn consumer_plan(
    subscription: &eventing_composition::BridgedSubscription,
) -> anyhow::Result<(String, primitives::ProbeName)> {
    let worker_name = format!(
        "identityaudit-event-consumer:{}:{}",
        subscription.consumer(),
        subscription.topic()
    );
    let probe_name = primitives::ProbeName::parse(&format!(
        "{EVENT_CONSUMER_PROBE}_{}",
        subscription.identity_slug()
    ))
    .context("build identityaudit consumer probe name")?;
    Ok((worker_name, probe_name))
}

fn wire_inbox_sweeper(
    pg: &postgres::PgRuntimeHandle,
    admission: primitives::WriteAdmission,
    output: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let sweeper = pg.infra().inbox_sweeper();
    let (config, name) = inbox_sweeper_plan(sweeper.retention_seconds())?;
    let health = Arc::new(WorkerHealth::healthy());
    let worker_health = Arc::clone(&health);
    output.push_worker(WorkerSpec::writes_phase_one(
        "assemblies.identityaudit.src.eventing.02",
        &admission,
        move |token, write_admission| {
            let loop_health = Arc::clone(&worker_health);
            let make = move |loop_token| async move {
                let _stopped = loop_health.stopped_on_exit();
                sweeper_loop(
                    Arc::new(sweeper),
                    config,
                    Arc::new(crate::SystemClock),
                    loop_token,
                    Arc::clone(&loop_health),
                    RetentionTarget::InboxReceipts,
                    write_admission,
                )
                .await;
            };
            DynManagedResource::new_box(SweeperWorker::spawn(
                INBOX_SWEEPER_NAME,
                make,
                worker_health,
                token,
                EVENT_WORKER_SHUTDOWN_BUDGET,
            ))
        },
    ));
    output.push_probe((name.clone(), Box::new(WorkerProbe::new(name, health))));
    Ok(())
}

fn inbox_sweeper_plan(
    retention_seconds: u64,
) -> anyhow::Result<(SweeperConfig, primitives::ProbeName)> {
    let config = SweeperConfig::new(retention_seconds, INBOX_SWEEP_INTERVAL)
        .context("build identityaudit inbox sweeper config")?;
    let name = primitives::ProbeName::parse("identityaudit_inbox_sweeper")
        .context("build identityaudit inbox sweeper probe name")?;
    Ok((config, name))
}

fn wire_distributed_maintenance(
    pg: &postgres::PgRuntimeHandle,
    redis: &redis::RedisRuntimeDeps,
    admission: primitives::WriteAdmission,
) -> anyhow::Result<DomainModuleResult> {
    let (sampler_config, sweeper_config, sampler_name, sweeper_name) = maintenance_plan()?;
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
    let sampler_health = Arc::new(WorkerHealth::healthy());
    let sampler_worker_health = Arc::clone(&sampler_health);
    let sampler_worker = WorkerSpec::observational_phase_one(
        "assemblies.identityaudit.src.eventing.03",
        move |token| {
            DynManagedResource::new_box(spawn_on_dedicated_runtime(
                "identityaudit-outbox-sampler",
                token,
                Arc::clone(&sampler_worker_health),
                EVENT_WORKER_SHUTDOWN_BUDGET,
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
    );

    let sweeper_health = Arc::new(WorkerHealth::healthy());
    let sweeper_worker_health = Arc::clone(&sweeper_health);
    let sweeper_worker = WorkerSpec::writes_phase_one(
        "assemblies.identityaudit.src.eventing.04",
        &admission,
        move |token, write_admission| {
            DynManagedResource::new_box(spawn_on_dedicated_runtime(
                "identityaudit-outbox-sweeper",
                token,
                Arc::clone(&sweeper_worker_health),
                EVENT_WORKER_SHUTDOWN_BUDGET,
                move |thread_token| async move {
                    sweeper_loop(
                        Arc::new(sweeper),
                        sweeper_config,
                        Arc::new(crate::SystemClock),
                        thread_token,
                        Arc::clone(&sweeper_worker_health),
                        RetentionTarget::OutboxPublished,
                        write_admission,
                    )
                    .await;
                    Ok(())
                },
            ))
        },
    );
    let probes: Vec<LifecycleProbe> = vec![
        (
            sampler_name.clone(),
            Box::new(WorkerProbe::new(sampler_name, sampler_health)),
        ),
        (
            sweeper_name.clone(),
            Box::new(WorkerProbe::new(sweeper_name, sweeper_health)),
        ),
    ];
    Ok(DomainModuleResult::from_parts(
        probes,
        [],
        [sampler_worker, sweeper_worker],
    ))
}

fn maintenance_plan() -> anyhow::Result<(
    SamplerConfig,
    SweeperConfig,
    primitives::ProbeName,
    primitives::ProbeName,
)> {
    let sampler_config = SamplerConfig::new(vec!["identity".to_owned()], OUTBOX_SAMPLE_INTERVAL)
        .context("build identityaudit outbox sampler config")?;
    let sweeper_config = SweeperConfig::new(OUTBOX_RETAIN_SECONDS, OUTBOX_SWEEP_INTERVAL)
        .context("build identityaudit outbox sweeper config")?;
    let sampler_name = primitives::ProbeName::parse("identityaudit_outbox_sampler")
        .context("build identityaudit outbox sampler probe name")?;
    let sweeper_name = primitives::ProbeName::parse("identityaudit_outbox_sweeper")
        .context("build identityaudit outbox sweeper probe name")?;
    Ok((sampler_config, sweeper_config, sampler_name, sweeper_name))
}

fn retain_admission_authority(
    pg: postgres::PgRuntimeHandle,
    control: primitives::ProcessAdmissionControl,
    identity: eventexec::DrAdmissionProcessIdentity,
    output: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    let health = Arc::new(WorkerHealth::starting());
    let probe_name = primitives::ProbeName::parse("identityaudit_dr_admission")
        .context("build identityaudit DR admission probe name")?;
    output.push_probe((
        probe_name.clone(),
        Box::new(WorkerProbe::new(probe_name, Arc::clone(&health))),
    ));
    output.push_worker(WorkerSpec::observational_phase_one(
        "assemblies.identityaudit.src.eventing.05",
        move |token| {
            DynManagedResource::new_box(spawn_on_dedicated_runtime(
                "identityaudit-dr-admission-owner",
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

fn validate_audit_closure(
    subscriptions: &[eventing_composition::BridgedSubscription],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        subscriptions.len() == 5,
        "identityaudit requires exactly five generated Identity-to-Audit subscriptions"
    );
    let mut dispatches = subscriptions
        .iter()
        .map(|subscription| subscription.dispatch_token().dispatch())
        .collect::<Vec<_>>();
    dispatches.sort_by_key(|dispatch| format!("{dispatch:?}"));
    let mut expected = vec![
        SubscriptionDispatchKey::IdentitySessionCreatedV1Audit,
        SubscriptionDispatchKey::IdentityRoleAssignedV1Audit,
        SubscriptionDispatchKey::IdentityRoleRevokedV1Audit,
        SubscriptionDispatchKey::IdentitySecurityEventV1Audit,
        SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit,
    ];
    expected.sort_by_key(|dispatch| format!("{dispatch:?}"));
    anyhow::ensure!(
        dispatches == expected,
        "identityaudit audit dispatch closure drift"
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
            self.health.status(),
            self.health.detail(),
        )
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use diport::ManagedResource;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct RollbackResource(Arc<std::sync::atomic::AtomicUsize>);

    impl ManagedResource for RollbackResource {
        fn name(&self) -> &str {
            "identityaudit-rollback-test"
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            self.0.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    #[tokio::test]
    async fn generated_subscriptions_form_the_exact_audit_closure() -> anyhow::Result<()> {
        let mut bindings = crate::modules_gen::wire_test_domains().await?;
        let (mut registry, _output) = bootstrap::compose_bindings(&mut bindings)?;
        let subscriptions = eventing_composition::bridge_generated_audit_subscriptions(
            registry.drain_subscribers(),
        )?;
        validate_audit_closure(subscriptions.subscriptions())?;
        assert_eq!(subscriptions.subscriptions().len(), 5);
        assert!(subscriptions.subscriptions().iter().all(|subscription| {
            subscription.readiness() == SubscriberReadiness::Required
                && !subscription.identity_slug().is_empty()
                && !subscription.topic_owner().is_empty()
        }));
        for subscription in subscriptions.subscriptions() {
            let (worker, probe) = consumer_plan(subscription)?;
            assert!(worker.starts_with("identityaudit-event-consumer:"));
            assert!(probe.as_str().starts_with(EVENT_CONSUMER_PROBE));
        }
        assert!(validate_audit_closure(&subscriptions.subscriptions()[..3]).is_err());
        Ok(())
    }

    #[test]
    fn relay_budget_and_role_output_merge_are_closed() -> anyhow::Result<()> {
        let budget = relay_budget()?;
        assert_eq!(budget.publish_timeout(), RELAY_PUBLISH_TIMEOUT);
        let (_relay, publisher_probe) = publisher_plan()?;
        assert_eq!(publisher_probe.as_str(), "outbox_relay_identity");
        let (_inbox, inbox_probe) = inbox_sweeper_plan(86_400)?;
        assert_eq!(inbox_probe.as_str(), "identityaudit_inbox_sweeper");
        let (_sampler, _sweeper, sampler_probe, sweeper_probe) = maintenance_plan()?;
        assert_eq!(sampler_probe.as_str(), "identityaudit_outbox_sampler");
        assert_eq!(sweeper_probe.as_str(), "identityaudit_outbox_sweeper");

        let name = primitives::ProbeName::parse("maintenance-test")?;
        let health = Arc::new(WorkerHealth::healthy());
        let outputs = assemble_role_outputs(
            DomainModuleResult::from_parts(
                [(
                    name.clone(),
                    Box::new(WorkerProbe::new(name.clone(), Arc::clone(&health))) as _,
                )],
                [],
                [],
            ),
            DomainModuleResult::default(),
            DomainModuleResult::default(),
        );
        assert_eq!(outputs.distributed_cas.probe_count(), 1);
        assert!(outputs.event_publisher.probe_count() == 0);
        assert!(outputs.event_subscriber.probe_count() == 0);
        let (_, probe) = outputs
            .distributed_cas
            .probes()
            .next()
            .context("identityaudit distributed CAS output omitted its probe")?;
        let check = probe.check();
        assert_eq!(check.name(), &name);
        assert_eq!(check.status(), primitives::HealthStatus::Healthy);

        let starting = Arc::new(WorkerHealth::starting());
        let starting_probe = WorkerProbe::new(name, Arc::clone(&starting));
        assert_eq!(
            bootstrap::HealthProbe::check(&starting_probe).status(),
            primitives::HealthStatus::Unhealthy
        );
        starting.mark_healthy();
        assert_eq!(
            bootstrap::HealthProbe::check(&starting_probe).status(),
            primitives::HealthStatus::Healthy
        );
        Ok(())
    }

    #[tokio::test]
    async fn rollback_drains_every_connected_resource_in_lifo_owner() {
        let shutdowns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        rollback_resources(vec![
            DynManagedResource::new_box(RollbackResource(Arc::clone(&shutdowns))),
            DynManagedResource::new_box(RollbackResource(Arc::clone(&shutdowns))),
        ])
        .await;
        assert_eq!(shutdowns.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    #[allow(clippy::panic)]
    // reason: panic is the behavior under test for the supervised worker boundary.
    async fn managed_worker_reports_completion_error_panic_and_repeat_shutdown() {
        let completed = ManagedBlockingWorker::spawn(
            "identityaudit-completed-worker",
            tokio_util::sync::CancellationToken::new(),
            Arc::new(WorkerHealth::starting()),
            EVENT_WORKER_SHUTDOWN_BUDGET,
            |_token| Ok(()),
        );
        assert_eq!(completed.name(), "identityaudit-completed-worker");
        assert_eq!(
            completed.shutdown_timeout(),
            EVENT_WORKER_SHUTDOWN_BUDGET.timeout()
        );
        assert!(completed.shutdown().await.is_ok());
        assert!(completed.shutdown().await.is_ok());

        let saw_cancel = Arc::new(AtomicBool::new(false));
        let thread_saw_cancel = Arc::clone(&saw_cancel);
        let cancelled = ManagedBlockingWorker::spawn(
            "identityaudit-cancelled-worker",
            tokio_util::sync::CancellationToken::new(),
            Arc::new(WorkerHealth::starting()),
            EVENT_WORKER_SHUTDOWN_BUDGET,
            move |token| {
                while !token.is_cancelled() {
                    std::thread::yield_now();
                }
                thread_saw_cancel.store(true, Ordering::Release);
                Ok(())
            },
        );
        assert!(cancelled.shutdown().await.is_ok());
        assert!(saw_cancel.load(Ordering::Acquire));

        let failed = ManagedBlockingWorker::spawn(
            "identityaudit-failed-worker",
            tokio_util::sync::CancellationToken::new(),
            Arc::new(WorkerHealth::starting()),
            EVENT_WORKER_SHUTDOWN_BUDGET,
            |_token| Err(ShutdownError::new(std::io::Error::other("runner failed"))),
        );
        assert!(failed.shutdown().await.is_err());

        let panicked = ManagedBlockingWorker::spawn(
            "identityaudit-panicked-worker",
            tokio_util::sync::CancellationToken::new(),
            Arc::new(WorkerHealth::starting()),
            EVENT_WORKER_SHUTDOWN_BUDGET,
            |_token| -> Result<(), ShutdownError> { panic!("intentional worker panic") },
        );
        assert!(panicked.shutdown().await.is_err());
    }

    #[test]
    #[allow(clippy::panic)]
    // reason: thread/runtime harness failures must fail this lifecycle regression test.
    fn stalled_sampler_shutdown_does_not_block_runtime_drop() {
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let thread_started = Arc::clone(&started);
        let thread_release = Arc::clone(&release);
        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();
        let harness = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|error| panic!("test runtime: {error}"));
            runtime.block_on(async move {
                let worker = ManagedBlockingWorker::spawn(
                    "identityaudit-stalled-sampler",
                    tokio_util::sync::CancellationToken::new(),
                    Arc::new(WorkerHealth::starting()),
                    EVENT_WORKER_SHUTDOWN_BUDGET,
                    move |_token| {
                        thread_started.store(true, Ordering::Release);
                        while !thread_release.load(Ordering::Acquire) {
                            std::thread::yield_now();
                        }
                        Ok(())
                    },
                );
                while !started.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), worker.shutdown())
                        .await
                        .is_err(),
                    "stalled sampler must exercise cancelled shutdown"
                );
            });
            drop(runtime);
            let _ = dropped_tx.send(());
        });

        let dropped_without_release = dropped_rx.recv_timeout(Duration::from_millis(200)).is_ok();
        release.store(true, Ordering::Release);
        harness
            .join()
            .unwrap_or_else(|_| panic!("runtime-drop harness panicked"));
        assert!(
            dropped_without_release,
            "runtime drop waited for the dedicated worker after shutdown cancellation"
        );
    }
}
