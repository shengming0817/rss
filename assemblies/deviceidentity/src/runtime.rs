//! Production startup seam. Provider construction is owned by the signal-first StartupPlan.

use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use anyhow::Context as _;

pub(crate) const EXTERNAL_CSR_RESOLVER_READY_PROBE_NAME: &str = "external_csr_resolver_ready";

pub async fn run(path: &Path) -> anyhow::Result<()> {
    let captured = crate::config::capture(path)?;
    let budget = runtimeexec::TotalDrainBudget::new(Duration::from_millis(
        captured.config.workers.shutdown_ms,
    ))?;
    let startup = ProductionStartup {
        captured,
        plan: crate::plan::DeviceIdentityPlan::bundled()?,
    };
    let _completed =
        runtimeexec::launch_startup(runtimeexec::StartupPlan::new(startup, budget)).await?;
    Ok(())
}

async fn build_production(
    captured: crate::config::CapturedConfig,
    plan: crate::plan::DeviceIdentityPlan,
    transaction: &mut runtimeexec::StartupTransaction<'_>,
) -> anyhow::Result<PreparedProductionStartup> {
    let crate::config::CapturedConfig {
        config,
        secrets,
        build_metadata,
    } = captured;
    let mut closer: crate::providers::ProviderRoleCloser =
        crate::providers::ProviderRoleCloser::new(plan.provider_build()?)?;
    let token = tokio_util::sync::CancellationToken::new();
    let oidc = crate::providers::build_federated_access_provider(
        config.oidc.issuer.clone(),
        config.oidc.audience.clone(),
        config.oidc.jwks_path.clone(),
        config.oidc_refresh(),
        token.clone(),
    )?;
    let verifier = oidc.provider();
    closer.stage_listener_pdp(
        crate::providers::listener_pdp_lifecycle(&oidc),
        transaction.provider_output_mut(),
    )?;
    let local =
        authn::SpiffeId::parse(&config.csr.local_spiffe_id).context("parse local CSR SPIFFE ID")?;
    let servers = authn::MtlsAllowSet::new(&config.csr.remote_spiffe_allow_set)
        .context("parse CSR server allow-set")?;
    let trust_domains =
        authn::MtlsTrustDomainAllowSet::new(servers.iter().map(|id| id.trust_domain().to_string()))
            .context("derive CSR trust-domain allow-set")?;
    let policy = authn::OutboundMtlsPolicy::new(local, servers, trust_domains)
        .context("bind CSR mTLS policy")?;
    let endpoint =
        secure::DomainHttpEndpoint::parse(&config.csr.url).context("parse CSR HTTPS endpoint")?;
    let resolver = Arc::new(
        httpd::SpiffeMtlsExternalCsrResolver::from_spire(endpoint, policy, None)
            .await
            .context("construct CSR SPIFFE resolver")?,
    );
    closer.stage_external_csr_resolver(
        external_csr_readiness(Arc::clone(&resolver))?,
        transaction.provider_output_mut(),
    )?;
    let internal_allow_set =
        authn::MtlsAllowSet::new(&config.listeners.internal_client_spiffe_allow_set)
            .context("parse Internal client allow-set")?;
    let internal_mtls = httpd::MtlsServerConfig::from_spire(internal_allow_set, None)
        .await
        .context("construct Internal SPIFFE listener")?;
    let mut internal_mtls_resource = None;
    let internal_mtls = internal_mtls.stage_with(|resource| {
        internal_mtls_resource = Some(resource);
    });
    let internal_mtls_resource =
        internal_mtls_resource.context("Internal SPIFFE preparation omitted its lifecycle")?;
    transaction.stage_domain_output(bootstrap::DomainModuleResult::from_parts(
        [],
        [internal_mtls_resource],
        [],
    ));
    let build = build_remaining_providers(
        config,
        verifier,
        resolver,
        internal_mtls,
        token,
        plan.workflow_runtime().projection_capture(),
        secrets,
        &mut closer,
        transaction,
    )
    .await?;
    let ProductionBuild { limiter, launch } = build;
    let completed = closer.finish(transaction.provider_output_mut())?;
    let seed = match build_metadata {
        Some(metadata) => plan
            .inventory_seed(completed)?
            .with_build_metadata(metadata),
        None => plan.inventory_seed(completed)?,
    };
    ProductionBuild::into_startup(
        seed,
        transaction.provider_output_mut(),
        limiter,
        launch,
        plan.expected_workers()?,
    )
}

struct ProductionBuild {
    limiter: redis::RedisRateLimiter,
    launch: LaunchInputs,
}

impl ProductionBuild {
    fn into_startup(
        seed: runtimeexec::inventory::RuntimeInventorySeed,
        inventory: &bootstrap::DomainModuleResult,
        limiter: redis::RedisRateLimiter,
        launch: LaunchInputs,
        expected_workers: bootstrap::ExpectedWorkerInventory,
    ) -> anyhow::Result<PreparedProductionStartup> {
        bootstrap::validate_worker_inventory_closed(inventory.workers(), &expected_workers)
            .context("join exact deviceidentity worker inventory")?;
        Ok(PreparedProductionStartup {
            seed,
            limiter,
            launch,
            expected_workers,
        })
    }
}

struct LaunchInputs {
    components: identity_composition::DevicePolicyCandidateComponents,
    verifier: crate::auth_bridge::FederatedVerifier,
    audit_sink: httpserve::AuditSinkHandle,
    metrics: Arc<dyn diport::MetricsExporter>,
    internal_mtls: httpd::MtlsServerConfig,
    primary: std::net::SocketAddr,
    internal: std::net::SocketAddr,
    health: std::net::SocketAddr,
    request_budget: Duration,
    trusted_proxy_config: httpserve::TrustedProxyConfig,
}

struct ProductionStartup {
    captured: crate::config::CapturedConfig,
    plan: crate::plan::DeviceIdentityPlan,
}

struct PreparedProductionStartup {
    seed: runtimeexec::inventory::RuntimeInventorySeed,
    limiter: redis::RedisRateLimiter,
    launch: LaunchInputs,
    expected_workers: bootstrap::ExpectedWorkerInventory,
}

type ReadyFuture = Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>;
type ReadyHook = Box<dyn FnOnce(crate::listeners::ListenerInventory) -> ReadyFuture + Send>;

impl runtimeexec::StartupAdapter for ProductionStartup {
    type Adapter = crate::listeners::LaunchAdapter;
    type ProbeReceipt = Arc<bootstrap::HealthReporter>;
    type ReadyHook = ReadyHook;
    type Ready = ReadyFuture;

    async fn prepare(
        self,
        transaction: &mut runtimeexec::StartupTransaction<'_>,
    ) -> anyhow::Result<
        runtimeexec::PreparedLaunch<Self::Adapter, Self::ProbeReceipt, Self::ReadyHook>,
    > {
        let prepared = build_production(self.captured, self.plan, transaction).await?;
        transaction.expect_workers(prepared.expected_workers)?;
        let mut registry = bootstrap::Registry::new();
        let (provider, domain) = transaction.outputs_mut();
        register_probes(&mut registry, provider)?;
        register_probes(&mut registry, domain)?;
        let listener_probe = runtimeexec::ListenerLifecycleRegistration::install(&mut registry)?;
        let reporter = Arc::clone(listener_probe.assembly_receipt());
        let (inventory_publisher, _inventory_reader) =
            runtimeexec::inventory::inventory_channel(prepared.seed, Arc::clone(&reporter));
        let (admission, _, _, writes) = primitives::prepare_dr_admission_controls().into_parts();
        let admission = Arc::new(admission);
        transaction.stage_domain_output(bootstrap::DomainModuleResult::from_parts(
            [],
            [diport::DynManagedResource::new_box(AdmissionLifecycle(
                Arc::clone(&admission),
            ))],
            [],
        ));
        let listeners = crate::listeners::finalize(
            prepared.launch.components,
            writes,
            prepared.launch.verifier,
            Arc::new(prepared.limiter),
            prepared.launch.audit_sink,
            Arc::clone(&reporter),
            prepared.launch.metrics,
            prepared.launch.trusted_proxy_config,
        )?;
        let adapter = crate::listeners::LaunchAdapter::new(
            listeners,
            prepared.launch.primary,
            prepared.launch.internal,
            prepared.launch.health,
            prepared.launch.request_budget,
            prepared.launch.internal_mtls,
            inventory_publisher,
        )?;
        let ready: ReadyHook = Box::new(move |inventory| {
            Box::pin(async move {
                tokio::time::timeout(Duration::from_secs(30), wait_until_healthy(&reporter))
                    .await
                    .context("deviceidentity readiness startup timed out")?;
                admission
                    .start_running()
                    .context("open deviceidentity admission after complete readiness")?;
                tracing::info!(
                    primary = %inventory.primary,
                    internal = %inventory.internal,
                    health = %inventory.health,
                    state = "ready",
                    "deviceidentity candidate ready"
                );
                Ok(())
            })
        });
        Ok(runtimeexec::PreparedLaunch::new(
            adapter,
            listener_probe,
            ready,
            None,
        ))
    }
}

struct AdmissionLifecycle(Arc<primitives::ProcessAdmissionControl>);

impl diport::ManagedResource for AdmissionLifecycle {
    fn name(&self) -> &str {
        "deviceidentity-admission"
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        self.0.stop();
        Ok(())
    }
}

fn register_probes(
    registry: &mut bootstrap::Registry,
    output: &mut bootstrap::DomainModuleResult,
) -> anyhow::Result<()> {
    let mut retained = bootstrap::DomainModuleResult::default();
    for lifecycle in output.drain_outputs() {
        match lifecycle {
            bootstrap::DomainLifecycleOutput::Probe(name, probe) => registry.probe(name, probe)?,
            bootstrap::DomainLifecycleOutput::Resource(resource) => {
                retained.push_resource(resource)
            }
            bootstrap::DomainLifecycleOutput::Worker(worker) => retained.push_worker(worker),
        }
    }
    *output = retained;
    Ok(())
}

async fn wait_until_healthy(reporter: &bootstrap::HealthReporter) {
    while reporter.report().overall() != primitives::HealthStatus::Healthy {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn build_remaining_providers(
    config: crate::config::DeviceIdentityConfig,
    verifier: Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>,
    resolver: Arc<httpd::SpiffeMtlsExternalCsrResolver>,
    internal_mtls: httpd::MtlsServerConfig,
    _token: tokio_util::sync::CancellationToken,
    projection_capture: eventexec::ProjectionCaptureView<'_>,
    secrets: crate::config::ServingSecrets,
    closer: &mut crate::providers::ProviderRoleCloser,
    transaction: &mut runtimeexec::StartupTransaction<'_>,
) -> anyhow::Result<ProductionBuild> {
    let pg_owner = connect_postgres(&config.postgres, &secrets, projection_capture).await?;
    let pg = pg_owner.handle();
    let identity_pg = pg.for_domain::<postgres::caps::Identity>();
    let components = identity_composition::device_policy_production_candidate_components(
        &identity_pg,
        Arc::new(ProcessClock),
    );
    let audit_sink = httpserve::AuditSinkHandle::new(pg.auth_audit_sink());
    let pg_readiness = pg.readiness_handle();
    let pg_probe_name = primitives::ProbeName::parse("deviceidentity_postgres_ready")?;
    let pg_probe = (
        pg_probe_name.clone(),
        Box::new(PostgresReadyProbe {
            name: pg_probe_name,
            readiness: pg_readiness,
        }) as Box<dyn bootstrap::HealthProbe>,
    );
    let (pg_resources, pg_monitor) =
        pg_owner.into_runtime_parts(postgres::PgRuntimeMonitorConfig::new(
            postgres::PgReadinessInterval::try_new(std::time::Duration::from_secs(5))
                .map_err(anyhow::Error::msg)?,
            postgres::PgRlsAttestationInterval::default(),
        ));
    let auth_audit_sink = bootstrap::DomainModuleResult::from_parts(
        [pg_probe],
        pg_resources,
        [bootstrap::WorkerSpec::observational_phase_one(
            "assemblies.deviceidentity.src.providers.pg-monitor",
            move |token| diport::DynManagedResource::new_box(pg_monitor.spawn(token)),
        )],
    );
    closer.stage_auth_audit_sink(auth_audit_sink, transaction.provider_output_mut())?;

    closer.stage_device_certificate_store(
        bootstrap::DomainModuleResult::from_parts(
            [postgres_probe(
                "deviceidentity_certificate_store_ready",
                pg.readiness_handle(),
            )?],
            [],
            [],
        ),
        transaction.provider_output_mut(),
    )?;
    closer.stage_device_command_store(
        bootstrap::DomainModuleResult::from_parts(
            [postgres_probe(
                "deviceidentity_command_store_ready",
                pg.readiness_handle(),
            )?],
            [],
            [dependency_worker(
                "assemblies.deviceidentity.src.providers.command-store",
                pg.readiness_handle(),
            )],
        ),
        transaction.provider_output_mut(),
    )?;
    closer.stage_device_revocation_store(
        bootstrap::DomainModuleResult::from_parts(
            [postgres_probe(
                "deviceidentity_revocation_store_ready",
                pg.readiness_handle(),
            )?],
            [],
            [dependency_worker(
                "assemblies.deviceidentity.src.providers.revocation-store",
                pg.readiness_handle(),
            )],
        ),
        transaction.provider_output_mut(),
    )?;

    let redis_ca = redis::RedisPrivateCa::from_pem(
        std::fs::read(&config.redis.ca_pem_path).context("read Redis private CA")?,
    )
    .context("parse Redis private CA")?;
    let redis_endpoint = secure::RedisEndpoint::parse(
        config.redis.url.clone(),
        secure::PlaintextEndpointPolicy::Deny,
    )
    .context("parse Redis TLS endpoint")?;
    let redis = redis::RedisRuntimeDeps::connect_with_private_ca(&redis_endpoint, redis_ca)
        .context("connect Redis")?;
    transaction.stage_domain_output(bootstrap::DomainModuleResult::from_parts(
        [],
        redis.runtime_resources(),
        [],
    ));
    redis.ping().await.context("Redis startup self-check")?;
    let rate_limiter_capability = redis
        .infra()
        .rate_limiter_capability(
            crate::providers_gen::ASSEMBLY_NAMESPACE,
            diport::RateLimitQuota::try_new(10, 20)?,
        )
        .await
        .context("verify Redis GCRA capability")?;
    let rate_limiter = closer
        .stage_listener_rate_limiter(rate_limiter_capability, transaction.provider_output_mut())?;

    let mqtt = build_mqtt(&config, &secrets).await?;
    let vault_roots = std::fs::read(&config.vault.ca_pem_path).context("read Vault CA")?;
    let vault_client = vault::VaultPkiHttpClient::with_root_certificates([&vault_roots])
        .context("build Vault PKI HTTPS client")?;
    let vault_config = vault::VaultPkiTransportConfig::new(
        config.vault.url.clone(),
        secrets.vault_token.to_string(),
        vault::VaultPkiMount::try_new(&config.vault.mount).context("parse Vault PKI mount")?,
        vault::VaultPkiRole::try_new(&config.vault.role).context("parse Vault PKI role")?,
        vec![diport::RedactedBytes::new(vault_roots)],
        std::time::Duration::from_secs(10),
    );
    let vault = Arc::new(
        vault::VaultExternalPkiProviderClosure::new(
            Arc::new(ProcessClock),
            vault_client,
            vault_config,
        )
        .context("construct Vault external PKI closure")?,
    );
    let source = identity_composition::ExternalPkiArtifactSource::new(
        Arc::clone(&resolver),
        Arc::clone(&vault),
    );
    let source_capability =
        crate::providers::DeviceProductionArtifactSourceCapability::new(&source);
    closer.stage_device_production_artifact_source(
        source_capability,
        transaction.provider_output_mut(),
    )?;
    let candidate_config = candidate_runtime_config(&config, &secrets)?;
    let lifecycle = identity_composition::DeviceIdentityCandidateLifecycle::start(
        pg.device_identity_production_runtime(),
        source,
        Arc::clone(&mqtt),
        candidate_config,
    )?;
    let (_handle, adoption) = lifecycle.into_parts();
    let trusted_proxy_config = config.trusted_proxy_config()?;
    let mut mqtt_lifecycle = adoption.into_domain_output()?;
    mqtt_lifecycle.push_resource(diport::DynManagedResource::new_box(CapabilityLease::new(
        Arc::clone(&mqtt),
        "deviceidentity-mqtt-capability",
    )));
    closer.stage_device_mqtt_session(mqtt_lifecycle, transaction.provider_output_mut())?;
    let vault_external_pki = vault_pki_readiness(Arc::clone(&vault))?;
    closer.stage_vault_external_pki(vault_external_pki, transaction.provider_output_mut())?;
    Ok(ProductionBuild {
        limiter: rate_limiter,
        launch: LaunchInputs {
            components,
            verifier: crate::auth_bridge::FederatedVerifier::production(verifier),
            audit_sink,
            metrics: Arc::new(
                prometheus_adapter::PromExporter::install()
                    .context("install deviceidentity metrics exporter")?,
            ),
            internal_mtls,
            primary: config.listeners.primary,
            internal: config.listeners.internal,
            health: config.listeners.health,
            request_budget: Duration::from_millis(config.listeners.request_budget_ms),
            trusted_proxy_config,
        },
    })
}

fn postgres_probe(
    name: &'static str,
    readiness: Arc<postgres::PgDbReadiness>,
) -> anyhow::Result<(primitives::ProbeName, Box<dyn bootstrap::HealthProbe>)> {
    let name = primitives::ProbeName::parse(name)?;
    Ok((
        name.clone(),
        Box::new(PostgresReadyProbe { name, readiness }),
    ))
}

fn dependency_worker(
    name: &'static str,
    readiness: Arc<postgres::PgDbReadiness>,
) -> bootstrap::WorkerSpec {
    let (start, _status) = diport::ManagedTask::prepare(name, diport::DEFAULT_SHUTDOWN_TIMEOUT);
    bootstrap::WorkerSpec::managed_observational_phase_one(name, move |token| {
        start
            .spawn(token, move |run_token| async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        () = run_token.cancelled() => return Ok(()),
                        _ = interval.tick() => {
                            if matches!(readiness.snapshot(), postgres::PoolReadiness::Down) {
                                return Err(diport::ShutdownError::new(DependencyUnavailable));
                            }
                        }
                    }
                }
            })
            .into_registration()
    })
}

#[derive(Debug, thiserror::Error)]
#[error("required provider unavailable")]
struct DependencyUnavailable;

struct CapabilityLease<T> {
    _value: Arc<T>,
    name: &'static str,
}

impl<T> CapabilityLease<T> {
    const fn new(value: Arc<T>, name: &'static str) -> Self {
        Self {
            _value: value,
            name,
        }
    }
}

impl<T> diport::ManagedResource for CapabilityLease<T>
where
    T: Send + Sync,
{
    fn name(&self) -> &str {
        self.name
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        Ok(())
    }
}

struct CapabilityReadinessProbe {
    name: primitives::ProbeName,
    state: Arc<AtomicU8>,
    unavailable_detail: &'static str,
}

impl bootstrap::HealthProbe for CapabilityReadinessProbe {
    fn check(&self) -> primitives::HealthCheck {
        let (status, detail) = match self.state.load(Ordering::Acquire) {
            1 => (primitives::HealthStatus::Healthy, "ready"),
            2 => (primitives::HealthStatus::Unhealthy, self.unavailable_detail),
            _ => (primitives::HealthStatus::Unhealthy, "unknown"),
        };
        primitives::HealthCheck::new(self.name.clone(), status, detail)
    }
}

fn vault_pki_readiness(
    vault: Arc<vault::VaultExternalPkiProviderClosure>,
) -> anyhow::Result<bootstrap::DomainModuleResult> {
    let name = primitives::ProbeName::parse("deviceidentity_vault_pki_ready")?;
    let state = Arc::new(AtomicU8::new(0));
    let task_state = Arc::clone(&state);
    let task_vault = Arc::clone(&vault);
    let (start, _) = diport::ManagedTask::prepare(
        "deviceidentity-vault-pki-readiness",
        diport::DEFAULT_SHUTDOWN_TIMEOUT,
    );
    let task = start.spawn(
        tokio_util::sync::CancellationToken::new(),
        move |token| async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    () = token.cancelled() => return Ok(()),
                    _ = interval.tick() => {
                        task_state.store(
                            if task_vault.is_capability_ready().await { 1 } else { 2 },
                            Ordering::Release,
                        );
                    }
                }
            }
        },
    );
    Ok(bootstrap::DomainModuleResult::from_parts(
        [(
            name.clone(),
            Box::new(CapabilityReadinessProbe {
                name,
                state,
                unavailable_detail: "vault-pki-capability-unavailable",
            }) as Box<dyn bootstrap::HealthProbe>,
        )],
        [
            diport::DynManagedResource::new_box(CapabilityLease::new(
                vault,
                "deviceidentity-vault-pki-capability",
            )),
            diport::DynManagedResource::new_box(task),
        ],
        [],
    ))
}

fn external_csr_readiness(
    resolver: Arc<httpd::SpiffeMtlsExternalCsrResolver>,
) -> anyhow::Result<bootstrap::DomainModuleResult> {
    let name = primitives::ProbeName::parse(EXTERNAL_CSR_RESOLVER_READY_PROBE_NAME)?;
    let state = Arc::new(AtomicU8::new(0));
    let task_state = Arc::clone(&state);
    let task_resolver = Arc::clone(&resolver);
    let (start, _) = diport::ManagedTask::prepare(
        "deviceidentity-external-csr-readiness",
        diport::DEFAULT_SHUTDOWN_TIMEOUT,
    );
    let task = start.spawn(
        tokio_util::sync::CancellationToken::new(),
        move |token| async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    () = token.cancelled() => return Ok(()),
                    _ = interval.tick() => {
                        task_state.store(
                            if task_resolver.is_capability_ready().await { 1 } else { 2 },
                            Ordering::Release,
                        );
                    }
                }
            }
        },
    );
    Ok(bootstrap::DomainModuleResult::from_parts(
        [(
            name.clone(),
            Box::new(CapabilityReadinessProbe {
                name,
                state,
                unavailable_detail: "external-csr-capability-unavailable",
            }) as Box<dyn bootstrap::HealthProbe>,
        )],
        [
            crate::providers::shared_managed_resource(resolver),
            diport::DynManagedResource::new_box(task),
        ],
        [],
    ))
}

async fn connect_postgres(
    config: &crate::config::Postgres,
    secrets: &crate::config::ServingSecrets,
    projection_capture: eventexec::ProjectionCaptureView<'_>,
) -> anyhow::Result<postgres::PgRuntimeDeps> {
    let ca = postgres::PgPrivateCa::from_pem(
        std::fs::read(&config.ca_pem_path).context("read PostgreSQL private CA")?,
    )
    .context("parse PostgreSQL private CA")?;
    let make = |username: String, password: String| {
        postgres::PgConfig::new(
            config.host.clone(),
            config.port,
            config.database.clone(),
            username,
            postgres::PgPassword::new(password),
            ca.clone(),
        )
    };
    let writer = make(
        secrets.pg_writer_username.clone(),
        secrets.pg_writer_password.to_string(),
    );
    let reader = postgres::PgTenantReadConfig::new(make(
        secrets.pg_reader_username.clone(),
        secrets.pg_reader_password.to_string(),
    ));
    let audit = make(
        secrets.pg_audit_username.clone(),
        secrets.pg_audit_password.to_string(),
    );
    postgres::PgRuntimeDeps::connect_serving(&writer, &reader, Some(&audit), projection_capture)
        .await
        .context("connect PostgreSQL production bundle")
}

async fn build_mqtt(
    config: &crate::config::DeviceIdentityConfig,
    secrets: &crate::config::ServingSecrets,
) -> anyhow::Result<Arc<mqtt::MqttSession>> {
    let public_key = decode_fixed_hex::<32>(&config.mqtt.broker_assertion_public_key_hex)?;
    let scopes = config
        .mqtt
        .scopes
        .iter()
        .map(|scope| {
            Ok(mqtt::DeviceScope::new(
                rss_request_context::TenantId::parse(&scope.tenant)?,
                ids::DeviceId::parse(&scope.device)?,
                mqtt::CredentialGeneration::new(scope.generation)?,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let session = mqtt::MqttSession::connect(mqtt::MqttSessionConfig::new(
        mqtt::MqttsEndpoint::parse(&config.mqtt.url)?,
        secrets.mqtt_client_id.clone(),
        mqtt::MqttTlsMaterial::new(
            diport::SecretMaterial::new(
                std::fs::read(&config.mqtt.ca_pem_path).context("read MQTT private CA")?,
            ),
            diport::SecretMaterial::new(secrets.mqtt_certificate_pem.expose().to_vec()),
            diport::SecretMaterial::new(secrets.mqtt_private_key_pem.expose().to_vec()),
        ),
        mqtt::BrokerAssertionVerifier::new(public_key)?,
        mqtt::MqttTopicPolicy::new(scopes)?,
        mqtt::SessionExpiry::new(std::time::Duration::from_secs(
            config.mqtt.session_expiry_seconds,
        ))?,
        mqtt::CredentialRevision::new(1)?,
    )?)
    .await?;
    Ok(Arc::new(session))
}

fn candidate_runtime_config(
    config: &crate::config::DeviceIdentityConfig,
    secrets: &crate::config::ServingSecrets,
) -> anyhow::Result<identity_composition::DeviceIdentityRuntimeConfig> {
    use eventexec::reconcile::{BackoffPolicy, ReconcileMaxInFlight, Tenancy, Trigger};
    let tenant = rss_request_context::TenantId::parse(&config.identity.tenant)?;
    let keyring = Arc::new(eventexec::command::CommandIdempotencyKeyring::new(
        eventexec::command::CommandAliasKey::new(
            "deviceidentity-production-v1",
            secrets.command_idempotency_key.to_vec(),
        )?,
        Vec::new(),
    )?);
    let scheduler = identity_composition::DeviceIdentitySchedulerConfig::new(
        Arc::new(ProcessClock),
        keyring,
        eventexec::reconcile::DeviceCertificateSystemProducer::install(),
        tenant,
        config.identity.holder_id.clone(),
        Tenancy::tenant_scoped(),
        identity_composition::DeviceIdentitySchedulerTiming::new(
            Trigger::interval(std::time::Duration::from_millis(
                config.workers.reconcile_ms,
            ))?,
            BackoffPolicy::new(
                std::time::Duration::from_millis(100),
                std::time::Duration::from_secs(30),
            )?,
            std::time::Duration::from_secs(60),
            ReconcileMaxInFlight::try_new(16)?,
        ),
    );
    let relay_budget = eventexec::RelayBudget::new(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(5),
    )?;
    let relays = identity_composition::DeviceIdentityRelayConfig::new(
        identity_composition::DeviceCertificateCommandTtl::try_new(
            std::time::Duration::from_secs(3600),
        )?,
        eventexec::RelayConfig::new(
            std::time::Duration::from_millis(config.workers.command_relay_ms),
            64,
        )?,
        eventexec::RelayConfig::new(
            std::time::Duration::from_millis(config.workers.receipt_relay_ms),
            64,
        )?,
        relay_budget,
    );
    Ok(identity_composition::DeviceIdentityRuntimeConfig::new(
        scheduler,
        relays,
        std::time::Duration::from_millis(config.workers.shutdown_ms),
    ))
}

fn decode_fixed_hex<const N: usize>(value: &str) -> anyhow::Result<[u8; N]> {
    anyhow::ensure!(value.len() == N * 2, "invalid fixed hex length");
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("invalid fixed hex"))?;
    }
    Ok(output)
}

struct PostgresReadyProbe {
    name: primitives::ProbeName,
    readiness: Arc<postgres::PgDbReadiness>,
}

impl bootstrap::HealthProbe for PostgresReadyProbe {
    fn check(&self) -> primitives::HealthCheck {
        let (status, detail) = match self.readiness.snapshot() {
            postgres::PoolReadiness::Ready => (primitives::HealthStatus::Healthy, "ready"),
            postgres::PoolReadiness::Saturated => (primitives::HealthStatus::Degraded, "saturated"),
            postgres::PoolReadiness::Down => (primitives::HealthStatus::Unhealthy, "down"),
            _ => (primitives::HealthStatus::Unhealthy, "unknown"),
        };
        primitives::HealthCheck::new(self.name.clone(), status, detail)
    }
}

pub(crate) struct ProcessClock;

impl diport::Clock for ProcessClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::now()
    }
}
