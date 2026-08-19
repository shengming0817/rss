//! Production provider construction for the closed settingsonly runtime plan.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context as _;
use diport::{DynKeyProvider, DynManagedResource, ManagedResource, ShutdownError};

use crate::config;
use crate::runtime::SharedManagedResource;

pub(crate) struct ProviderBundle {
    pub(crate) pg: postgres::PgRuntimeHandle,
    pub(crate) projection_worker_config: postgres::PgProjectionWorkerConfig,
    pub(crate) vault: vault::VaultRuntimeDeps,
    pub(crate) settings_key: diport::KeyName,
    pub(crate) verifier: crate::auth_bridge::FederatedVerifier,
    pub(crate) audit_sink: httpserve::AuditSinkHandle,
    pub(crate) metrics: Arc<dyn diport::MetricsExporter>,
    pub(crate) limiter: Arc<redis::RedisRateLimiter>,
    pub(crate) settings_readiness: settings_composition::SettingsReadinessDeps,
    pub(crate) eventing: crate::eventing::EventingInputs,
    pub(crate) role_closer: ProviderRoleCloser,
    pub(crate) readiness_startup_timeout: std::time::Duration,
}

/// Closed production infrastructure; every field is a mandatory move-only capability or receipt.
struct SettingsOnlyProductionInfra {
    rate_limiter: Arc<redis::RedisRateLimiter>,
    listener_rate_limiter: crate::providers_gen::ListenerRateLimiterReceipt,
    eventing: crate::eventing::EventingInputs,
    distributed_lock_store: crate::providers_gen::DistributedLockStoreReceipt,
    dlx_archive_key_provider: crate::providers_gen::DlxArchiveKeyProviderReceipt,
    dlx_archive_store: crate::providers_gen::DlxArchiveStoreReceipt,
    dlx_hot_key_provider: crate::providers_gen::DlxHotKeyProviderReceipt,
    dlx_lifecycle_repository: crate::providers_gen::DlxLifecycleRepositoryReceipt,
    readiness_startup_timeout: std::time::Duration,
    amqp_publisher_activation: StartupActivationReceipt,
    amqp_subscriber_activation: StartupActivationReceipt,
    provider_activations: Vec<StartupActivationReceipt>,
}

pub(crate) struct CompletedProviderBuild {
    providers: ProviderBundle,
    listeners: config::ListenersConfig,
}

impl CompletedProviderBuild {
    pub(crate) fn into_parts(self) -> (ProviderBundle, config::ListenersConfig) {
        (self.providers, self.listeners)
    }
}

/// Move-only proof that every production provider role was constructed exactly once.
pub(crate) struct ProviderRoleCloser {
    roles: crate::providers_gen::ProviderRoleBatches,
    auth_audit_sink: crate::providers_gen::AuthAuditSinkReceipt,
    distributed_lock_store: crate::providers_gen::DistributedLockStoreReceipt,
    dlx_archive_key_provider: crate::providers_gen::DlxArchiveKeyProviderReceipt,
    dlx_archive_store: crate::providers_gen::DlxArchiveStoreReceipt,
    dlx_hot_key_provider: crate::providers_gen::DlxHotKeyProviderReceipt,
    dlx_lifecycle_repository: crate::providers_gen::DlxLifecycleRepositoryReceipt,
    listener_pdp: crate::providers_gen::ListenerPdpReceipt,
    listener_rate_limiter: crate::providers_gen::ListenerRateLimiterReceipt,
    settings_key_provider: crate::providers_gen::SettingsKeyProviderReceipt,
    settings_secret_resolver: crate::providers_gen::SettingsSecretResolverReceipt,
    distributed_cas_constructor: crate::providers_gen::DistributedCasStoreConstructor,
    event_publisher_constructor: crate::providers_gen::EventPublisherConstructor,
    event_subscriber_constructor: crate::providers_gen::EventSubscriberConstructor,
    cas_resource: Box<DynManagedResource<'static>>,
    amqp_publisher_activation: StartupActivationReceipt,
    amqp_subscriber_activation: StartupActivationReceipt,
    provider_activations: Vec<StartupActivationReceipt>,
}

impl ProviderRoleCloser {
    pub(crate) fn finish(
        self,
        outputs: crate::eventing::EventingRoleOutputs,
        inventory: &mut bootstrap::DomainModuleResult,
    ) -> anyhow::Result<crate::providers_gen::CompletedProviderRoles> {
        let mut cas = outputs.distributed_cas;
        cas.push_resource(self.cas_resource);
        let distributed_cas_store = self
            .distributed_cas_constructor
            .finish(cas)?
            .transfer(inventory);
        let event_publisher = self
            .event_publisher_constructor
            .finish(outputs.event_publisher)?
            .transfer(inventory);
        let event_subscriber = self
            .event_subscriber_constructor
            .finish(outputs.event_subscriber)?
            .transfer(inventory);
        let completed = self.roles.finish(
            inventory,
            self.auth_audit_sink,
            distributed_cas_store,
            self.distributed_lock_store,
            self.dlx_archive_key_provider,
            self.dlx_archive_store,
            self.dlx_hot_key_provider,
            self.dlx_lifecycle_repository,
            event_publisher,
            event_subscriber,
            self.listener_pdp,
            self.listener_rate_limiter,
            self.settings_key_provider,
            self.settings_secret_resolver,
        )?;
        self.amqp_publisher_activation.activate();
        self.amqp_subscriber_activation.activate();
        for activation in self.provider_activations {
            activation.activate();
        }
        Ok(completed)
    }
}

pub(crate) async fn build(
    mut roles: crate::providers_gen::ProviderRoleBatches,
    projection_capture: eventexec::ProjectionCaptureView<'_>,
    config: config::SettingsOnlyConfig,
    secrets: config::ResolvedSecrets,
    rate_limit_quota: diport::RateLimitQuota,
    transaction: &mut runtimeexec::StartupTransaction<'_>,
) -> anyhow::Result<CompletedProviderBuild> {
    let (admission_control, relay_admission, consumer_admission, write_admission) =
        primitives::prepare_dr_admission_controls().into_parts();
    let config::SettingsOnlyConfigSections {
        listeners,
        federated,
        postgres,
        vault: vault_config,
        production_infra,
    } = config.into_sections();
    let (vault_inputs, secrets) = secrets.into_production_material(vault_config);
    let auth_audit_sink = roles.auth_audit_sink()?;
    let distributed_cas_constructor = roles.distributed_cas_store()?;
    let distributed_lock_constructor = roles.distributed_lock_store()?;
    let dlx_archive_key_constructor = roles.dlx_archive_key_provider()?;
    let dlx_archive_store_constructor = roles.dlx_archive_store()?;
    let dlx_hot_key_constructor = roles.dlx_hot_key_provider()?;
    let dlx_lifecycle_constructor = roles.dlx_lifecycle_repository()?;
    let event_publisher_constructor = roles.event_publisher()?;
    let event_subscriber_constructor = roles.event_subscriber()?;
    let listener_pdp = roles.listener_pdp()?;
    let listener_rate_limiter = roles.listener_rate_limiter()?;
    let settings_key_provider = roles.settings_key_provider()?;
    let settings_secret_resolver = roles.settings_secret_resolver()?;

    let PostgresBuild {
        owner: pg,
        dlx_archiver,
        dlx_verifier,
        dlx_purger,
        projection_worker,
        readiness: pg_readiness,
    } = build_postgres(postgres, &secrets, projection_capture).await?;
    let pg_handle = pg.handle();
    let monitor_config = postgres::PgRuntimeMonitorConfig::new(
        postgres::PgReadinessInterval::try_new(pg_readiness)
            .map_err(anyhow::Error::msg)
            .context("build settingsonly Postgres readiness interval")?,
        postgres::PgRlsAttestationInterval::default(),
    );
    let (pg_resources, pg_monitor) = pg.into_runtime_parts(monitor_config);
    let (mut pg_resources, pg_activations) = stage_postgres_resources(transaction, pg_resources);
    let cas_resource = pg_resources
        .pop()
        .context("settingsonly Postgres omitted distributed CAS lifecycle resource")?;
    let mut pg_output = bootstrap::DomainModuleResult::default();
    pg_output.extend_resources(pg_resources);
    pg_output.push_worker(bootstrap::WorkerSpec::observational_phase_one(
        "assemblies.settingsonly.src.providers.01",
        move |token| DynManagedResource::new_box(pg_monitor.spawn(token)),
    ));
    let audit_sink = httpserve::AuditSinkHandle::new(pg_handle.auth_audit_sink());

    let vault = build_vault(
        vault_inputs,
        settings_key_provider,
        settings_secret_resolver,
    )?;
    let readiness_interval =
        settings_composition::KeyProviderReadinessInterval::try_new(vault.readiness)?;
    let settings_provider_readiness = settings_composition::SettingsProviderReadiness::new(
        &vault.deps.for_domain::<vault::caps::Settings>(),
        vault.settings_key.clone(),
        readiness_interval,
    )
    .await?;
    let (pending_readiness, key_readiness, resolver_readiness) =
        settings_provider_readiness.into_vault_parts();
    let (settings_readiness, postgres_readiness) =
        pending_readiness.bind_postgres(pg_handle.readiness_handle())?;
    pg_output.merge(postgres_readiness.into_output());
    let rls_probe_name = primitives::ProbeName::parse(crate::readiness::RLS)
        .context("parse settingsonly rls_ready probe name")?;
    pg_output.push_probe((
        rls_probe_name.clone(),
        Box::new(RlsReadyProbe {
            name: rls_probe_name,
            readiness: pg_handle.rls_readiness(),
        }),
    ));
    let auth_audit_sink = auth_audit_sink
        .finish(pg_output)?
        .transfer(transaction.provider_output_mut());
    let mut key_output = vault.settings_key_output;
    key_output.merge(key_readiness.into_output());
    let settings_key_provider = vault
        .settings_key_provider
        .finish(key_output)?
        .transfer(transaction.provider_output_mut());
    let mut resolver_output = vault.settings_secret_resolver_output;
    resolver_output.merge(resolver_readiness.into_output());
    let settings_secret_resolver = vault
        .settings_secret_resolver
        .finish(resolver_output)?
        .transfer(transaction.provider_output_mut());

    let federated = build_federated_access_provider(federated, listener_pdp)?;
    let verifier = crate::auth_bridge::FederatedVerifier::production(federated.provider());
    let (provider_constructor, federated_lifecycle) =
        self::build_federated_listener_pdp_jwks_lifecycle(federated);
    let listener_pdp =
        self::commit_listener_pdp_jwks_lifecycle(provider_constructor, federated_lifecycle)?
            .transfer(transaction.provider_output_mut());

    let metrics = Arc::new(
        prometheus_adapter::PromExporter::install()
            .context("install settingsonly metrics exporter")?,
    );
    let mut metrics_output = bootstrap::DomainModuleResult::default();
    metrics_output.push_resource(SharedManagedResource::boxed(
        Arc::clone(&metrics),
        "settingsonly-prometheus",
    ));
    transaction.stage_domain_output(metrics_output);
    let metrics_port: Arc<dyn diport::MetricsExporter> = metrics;
    let production = build_production_infra(
        production_infra,
        secrets,
        vault.dlx_connection,
        &pg_handle,
        dlx_archiver,
        dlx_verifier,
        dlx_purger,
        distributed_lock_constructor,
        dlx_hot_key_constructor,
        dlx_archive_key_constructor,
        dlx_archive_store_constructor,
        dlx_lifecycle_constructor,
        listener_rate_limiter,
        rate_limit_quota,
        admission_control,
        relay_admission,
        consumer_admission,
        write_admission.clone(),
        transaction,
    )
    .await?;
    Ok(CompletedProviderBuild {
        providers: ProviderBundle {
            pg: pg_handle,
            projection_worker_config: projection_worker,
            vault: vault.deps,
            settings_key: vault.settings_key,
            verifier,
            audit_sink,
            metrics: metrics_port,
            limiter: production.rate_limiter,
            settings_readiness,
            eventing: production.eventing,
            role_closer: ProviderRoleCloser {
                roles,
                auth_audit_sink,
                distributed_lock_store: production.distributed_lock_store,
                dlx_archive_key_provider: production.dlx_archive_key_provider,
                dlx_archive_store: production.dlx_archive_store,
                dlx_hot_key_provider: production.dlx_hot_key_provider,
                dlx_lifecycle_repository: production.dlx_lifecycle_repository,
                listener_pdp,
                listener_rate_limiter: production.listener_rate_limiter,
                settings_key_provider,
                settings_secret_resolver,
                distributed_cas_constructor,
                event_publisher_constructor,
                event_subscriber_constructor,
                cas_resource,
                amqp_publisher_activation: production.amqp_publisher_activation,
                amqp_subscriber_activation: production.amqp_subscriber_activation,
                provider_activations: pg_activations
                    .into_iter()
                    .chain(production.provider_activations)
                    .collect(),
            },
            readiness_startup_timeout: production.readiness_startup_timeout,
        },
        listeners,
    })
}

#[allow(clippy::too_many_arguments)]
async fn build_production_infra(
    config: config::ProductionInfraConfig,
    secrets: config::ProductionSecretMaterial,
    vault_connection: DlxVaultConnection,
    pg: &postgres::PgRuntimeHandle,
    dlx_archiver: postgres::PgConfig,
    dlx_verifier: postgres::PgConfig,
    dlx_purger: postgres::PgConfig,
    distributed_lock_constructor: crate::providers_gen::DistributedLockStoreConstructor,
    dlx_hot_key_constructor: crate::providers_gen::DlxHotKeyProviderConstructor,
    dlx_archive_key_constructor: crate::providers_gen::DlxArchiveKeyProviderConstructor,
    dlx_archive_store_constructor: crate::providers_gen::DlxArchiveStoreConstructor,
    dlx_lifecycle_constructor: crate::providers_gen::DlxLifecycleRepositoryConstructor,
    listener_rate_limiter_constructor: crate::providers_gen::ListenerRateLimiterConstructor,
    rate_limit_quota: diport::RateLimitQuota,
    admission_control: primitives::ProcessAdmissionControl,
    relay_admission: primitives::RelayAdmission,
    consumer_admission: primitives::ConsumerAdmission,
    write_admission: primitives::WriteAdmission,
    transaction: &mut runtimeexec::StartupTransaction<'_>,
) -> anyhow::Result<SettingsOnlyProductionInfra> {
    let config::ProductionInfraConfig {
        eventing,
        redis,
        tenant_authority,
        dlx,
        s3,
        readiness,
        drain,
    } = config;
    let archive_store = build_s3_archive_store(s3, &secrets).await?;
    anyhow::ensure!(
        drain.into_total_budget() == crate::runtime::total_drain_duration(),
        "settingsonly configured drain budget disagrees with runtime"
    );
    let readiness_startup_timeout = readiness.into_startup_timeout();

    let redis_inputs = redis.into_redis_inputs();
    let redis_readiness = redis_inputs.readiness;
    let redis = tokio::time::timeout(
        redis_inputs.readiness,
        build_redis(secrets.redis_url, redis_inputs.ca_cert_pem_path),
    )
    .await
    .context("settingsonly Redis startup verification timed out")??;
    let rate_limiter_capability = redis
        .infra()
        .rate_limiter_capability(crate::providers_gen::ASSEMBLY_NAMESPACE, rate_limit_quota)
        .await
        .context("verify settingsonly Redis rate-limiter capability")?;
    let (listener_rate_limiter, rate_limiter) = listener_rate_limiter_constructor
        .finish(rate_limiter_capability)?
        .transfer(transaction.provider_output_mut());
    let rate_limiter = Arc::new(rate_limiter);
    let redis_ready = Arc::new(AtomicBool::new(true));
    let redis_probe_name = primitives::ProbeName::parse(crate::readiness::REDIS)
        .context("build settingsonly Redis readiness probe name")?;
    let redis_sampler = redis.clone();
    let sampler_ready = Arc::clone(&redis_ready);
    let mut redis_output = bootstrap::DomainModuleResult::default();
    redis_output.push_probe((
        redis_probe_name.clone(),
        Box::new(RedisReadyProbe {
            name: redis_probe_name,
            ready: Arc::clone(&redis_ready),
        }),
    ));
    redis_output.push_worker(bootstrap::WorkerSpec::observational_phase_one(
        "assemblies.settingsonly.src.providers.02",
        move |token| {
            DynManagedResource::new_box(RedisReadinessWorker::spawn(
                redis_sampler,
                redis_readiness,
                token,
                sampler_ready,
            ))
        },
    ));
    redis_output.extend_resources(redis.runtime_resources());
    let distributed_lock_store = distributed_lock_constructor
        .finish(redis_output)?
        .transfer(transaction.provider_output_mut());

    let eventing_config = eventing.into_eventing_inputs();
    let amqp_ca = amqp::AmqpPrivateCa::from_pem(
        std::fs::read(&eventing_config.amqp_ca_cert_pem_path)
            .context("read settingsonly AMQP CA certificate")?,
    )
    .context("parse settingsonly AMQP CA certificate")?;
    let amqp_publisher_endpoint = amqp::AmqpPublisherEndpoint::new(
        secure::AmqpEndpoint::parse(
            secrets.settings_amqp_publisher_url.to_string(),
            secure::PlaintextEndpointPolicy::Deny,
        )
        .context("parse settingsonly AMQP publisher endpoint")?,
    );
    let amqp_subscriber_endpoint = amqp::AmqpSubscriberEndpoint::new(
        secure::AmqpEndpoint::parse(
            secrets.settings_amqp_subscriber_url.to_string(),
            secure::PlaintextEndpointPolicy::Deny,
        )
        .context("parse settingsonly AMQP subscriber endpoint")?,
    );
    let amqp = amqp::AmqpRuntimeDeps::connect_with_private_ca(
        &amqp_publisher_endpoint,
        &amqp_subscriber_endpoint,
        amqp_ca,
        "settingsonly-settings",
        eventing_config.publisher_confirm_timeout,
    )
    .await
    .context("connect settingsonly dedicated AMQP")?;
    let connected_amqp_resources = amqp.runtime_resources();
    anyhow::ensure!(
        connected_amqp_resources.len() == 2,
        "settingsonly AMQP produced an undeclared lifecycle resource count"
    );
    let mut amqp_resources = Vec::new();
    let mut amqp_activations = Vec::new();
    for (resource, name) in connected_amqp_resources.into_iter().zip([
        "settingsonly-amqp-publisher-startup-stage",
        "settingsonly-amqp-subscriber-startup-stage",
    ]) {
        let (startup, activation, receipt) = split_startup_resource(resource, name);
        let mut startup_output = bootstrap::DomainModuleResult::default();
        startup_output.push_resource(startup);
        transaction.stage_domain_output(startup_output);
        amqp_resources.push(activation);
        amqp_activations.push(receipt);
    }
    let mut amqp_activations = amqp_activations.into_iter();
    let amqp_publisher_activation = amqp_activations
        .next()
        .context("settingsonly AMQP omitted publisher activation receipt")?;
    let amqp_subscriber_activation = amqp_activations
        .next()
        .context("settingsonly AMQP omitted subscriber activation receipt")?;
    anyhow::ensure!(
        amqp_activations.next().is_none(),
        "settingsonly AMQP produced an undeclared activation receipt"
    );

    let (tenant_ttl, tenant_skew) = tenant_authority.into_tenant_authority_inputs();
    let tenant_authority = build_tenant_authority(
        primitives::MacKey::from_bytes(secrets.tenant_authority_key.as_bytes().to_vec()),
        tenant_ttl,
        tenant_skew,
    )?;

    let dlx = dlx.into_dlx_inputs();
    let hot_key = eventexec::DlxHotKeyName::try_new(dlx.hot_key_name)
        .context("build settingsonly DLX hot key name")?;
    let archive_key = eventexec::DlxArchiveKeyName::try_new(dlx.archive_key_name)
        .context("build settingsonly DLX archive key name")?;
    let hot_provider = Arc::new(
        vault::VaultKeyProvider::new(
            vault_connection.client.clone(),
            vault_connection.addr.clone(),
            secrets.dlx_hot_vault_token.to_string(),
            vault_connection.transit_mount.clone(),
            vault_connection.readiness,
        )
        .context("build settingsonly DLX hot Vault provider")?,
    );
    let archive_provider = Arc::new(
        vault::VaultKeyProvider::new(
            vault_connection.client,
            vault_connection.addr,
            secrets.dlx_archive_vault_token.to_string(),
            vault_connection.transit_mount,
            dlx.readiness_interval,
        )
        .context("build settingsonly DLX archive Vault provider")?,
    );
    let (archive_startup, archive_resource, archive_activation) = split_startup_resource(
        SharedManagedResource::boxed(
            Arc::clone(&archive_provider),
            "settingsonly-dlx-archive-vault-key-provider",
        ),
        "settingsonly-dlx-archive-vault-startup-stage",
    );
    let (hot_startup, hot_resource, hot_activation) = split_startup_resource(
        SharedManagedResource::boxed(
            Arc::clone(&hot_provider),
            "settingsonly-dlx-hot-vault-key-provider",
        ),
        "settingsonly-dlx-hot-vault-startup-stage",
    );
    let mut startup_output = bootstrap::DomainModuleResult::default();
    startup_output.extend_resources([archive_startup, hot_startup]);
    transaction.stage_domain_output(startup_output);
    let mut archive_output = bootstrap::DomainModuleResult::default();
    archive_output.push_resource(archive_resource);
    let mut hot_output = bootstrap::DomainModuleResult::default();
    hot_output.push_resource(hot_resource);
    let dlx_payload_protector = postgres::DlxPayloadProtector::new(
        DynKeyProvider::new_box(SharedKeyProvider(Arc::clone(&hot_provider))),
        hot_key.clone(),
    );

    postgres::PgDlxLifecycleRuntime::preflight_identities(
        &dlx_archiver,
        &dlx_verifier,
        &dlx_purger,
    )
    .await
    .context("preflight settingsonly DLX postgres identities")?;
    let pg_dlx = postgres::PgDlxLifecycleRuntime::setup(
        &dlx_archiver,
        &dlx_verifier,
        &dlx_purger,
        dlx_payload_protector.clone(),
    )
    .await
    .context("connect settingsonly DLX lifecycle postgres roles")?;
    let dlx_outputs = crate::dlx::wire(crate::dlx::DlxInputs::new(
        pg_dlx,
        archive_store,
        hot_provider,
        hot_key,
        archive_provider,
        archive_key,
        dlx.readiness_interval,
        write_admission.clone(),
    ))?;
    hot_output.merge(dlx_outputs.dlx_hot_key_provider);
    archive_output.merge(dlx_outputs.dlx_archive_key_provider);
    let dlx_hot_key_provider = dlx_hot_key_constructor
        .finish(hot_output)?
        .transfer(transaction.provider_output_mut());
    let dlx_archive_key_provider = dlx_archive_key_constructor
        .finish(archive_output)?
        .transfer(transaction.provider_output_mut());
    let dlx_archive_store = dlx_archive_store_constructor
        .finish(dlx_outputs.dlx_archive_store)?
        .transfer(transaction.provider_output_mut());
    let dlx_lifecycle_repository = dlx_lifecycle_constructor
        .finish(dlx_outputs.dlx_lifecycle_repository)?
        .transfer(transaction.provider_output_mut());

    Ok(SettingsOnlyProductionInfra {
        rate_limiter,
        listener_rate_limiter,
        eventing: crate::eventing::EventingInputs::new(
            pg.clone(),
            redis,
            amqp,
            amqp_resources,
            tenant_authority,
            dlx_payload_protector,
            admission_control,
            relay_admission,
            consumer_admission,
            write_admission,
        ),
        distributed_lock_store,
        dlx_archive_key_provider,
        dlx_archive_store,
        dlx_hot_key_provider,
        dlx_lifecycle_repository,
        readiness_startup_timeout,
        amqp_publisher_activation,
        amqp_subscriber_activation,
        provider_activations: vec![archive_activation, hot_activation],
    })
}

async fn build_redis(
    url: zeroize::Zeroizing<String>,
    ca_cert_pem_path: std::path::PathBuf,
) -> anyhow::Result<redis::RedisRuntimeDeps> {
    let endpoint =
        secure::RedisEndpoint::parse(url.to_string(), secure::PlaintextEndpointPolicy::Deny)
            .context("parse settingsonly Redis endpoint")?;
    let ca = redis::RedisPrivateCa::from_pem(
        std::fs::read(ca_cert_pem_path).context("read settingsonly Redis CA certificate")?,
    )
    .context("parse settingsonly Redis CA certificate")?;
    let deps = redis::RedisRuntimeDeps::connect_with_private_ca(&endpoint, ca)
        .context("build settingsonly Redis TLS pool")?;
    deps.ping().await.context("verify settingsonly Redis")?;
    Ok(deps)
}

struct RedisReadyProbe {
    name: primitives::ProbeName,
    ready: Arc<AtomicBool>,
}

struct RlsReadyProbe {
    name: primitives::ProbeName,
    readiness: Arc<postgres::PgRlsReadiness>,
}

impl bootstrap::HealthProbe for RlsReadyProbe {
    fn check(&self) -> primitives::HealthCheck {
        let (status, detail) = if self.readiness.is_ready() {
            (primitives::HealthStatus::Healthy, "ready")
        } else {
            (
                primitives::HealthStatus::Unhealthy,
                "attestation-unverified",
            )
        };
        primitives::HealthCheck::new(self.name.clone(), status, detail)
    }
}

impl bootstrap::HealthProbe for RedisReadyProbe {
    fn check(&self) -> primitives::HealthCheck {
        let (status, detail) = if self.ready.load(Ordering::Acquire) {
            (primitives::HealthStatus::Healthy, "ready")
        } else {
            (primitives::HealthStatus::Unhealthy, "down")
        };
        primitives::HealthCheck::new(self.name.clone(), status, detail)
    }
}

struct RedisReadinessWorker {
    token: tokio_util::sync::CancellationToken,
    handle: tokio::sync::Mutex<Option<diport::OwnedTask<()>>>,
}

impl RedisReadinessWorker {
    fn spawn(
        redis: redis::RedisRuntimeDeps,
        period: std::time::Duration,
        token: tokio_util::sync::CancellationToken,
        ready: Arc<AtomicBool>,
    ) -> Self {
        let worker_token = token.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(period);
            loop {
                tokio::select! {
                    biased;
                    () = worker_token.cancelled() => break,
                    _ = ticker.tick() => {
                        let (healthy, reason, error_type) = match tokio::time::timeout(period, redis.ping()).await {
                            Ok(Ok(())) => (true, "ready", "none"),
                            Ok(Err(_)) => (false, "provider", "redis_provider"),
                            Err(_) => (false, "timeout", "redis_timeout"),
                        };
                        let previous = ready.swap(healthy, Ordering::AcqRel);
                        if previous != healthy {
                            tracing::warn!(
                                event = "settingsonly.readiness",
                                component = "redis",
                                probe = "redis_ready",
                                outcome = if healthy { "healthy" } else { "unhealthy" },
                                reason,
                                error_type,
                                "settingsonly readiness transitioned"
                            );
                        }
                    }
                }
            }
        });
        Self {
            token,
            handle: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(handle))),
        }
    }
}

impl ManagedResource for RedisReadinessWorker {
    fn name(&self) -> &str {
        "settingsonly-redis-readiness"
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

fn build_tenant_authority(
    key: primitives::MacKey,
    ttl: std::time::Duration,
    skew: std::time::Duration,
) -> anyhow::Result<Arc<eventexec::TenantAuthority>> {
    Ok(Arc::new(eventexec::TenantAuthority::new(
        Arc::new(crypto::RustCryptoMacVerifier),
        key,
        ttl.as_secs(),
        skew.as_secs(),
        Arc::new(system_epoch_seconds),
    )?))
}

fn system_epoch_seconds() -> i64 {
    use diport::Clock as _;
    crate::SystemClock
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

async fn build_s3_archive_store(
    config: config::S3Config,
    secrets: &config::ProductionSecretMaterial,
) -> anyhow::Result<s3::VerifiedS3DlxArchiveStore> {
    let inputs = config.into_s3_inputs();
    let endpoint =
        secure::S3Endpoint::parse(inputs.endpoint, secure::PlaintextEndpointPolicy::Deny)
            .context("parse settingsonly S3 endpoint")?;
    let pem =
        std::fs::read(inputs.ca_cert_pem_path).context("read settingsonly S3 CA certificate")?;
    let credentials = aws_sdk_s3::config::Credentials::new(
        secrets.s3_access_key_id.to_string(),
        secrets.s3_secret_access_key.to_string(),
        None,
        None,
        "settingsonly-secret-bundle",
    );
    let factory = s3::PrivateCaS3ClientFactory::new(
        endpoint,
        inputs.region,
        credentials,
        inputs.force_path_style,
        pem,
    );
    tokio::time::timeout(
        inputs.readiness_interval,
        factory
            .build_verified_dlx_archive_store(inputs.archive_bucket, Arc::new(crate::SystemClock)),
    )
    .await
    .context("settingsonly S3 WORM verification timed out")?
    .context("verify settingsonly S3 WORM capability")
}

struct SharedKeyProvider(Arc<vault::VaultKeyProvider>);

impl diport::KeyProvider for SharedKeyProvider {
    async fn encrypt(
        &self,
        key: diport::KeyName,
        plaintext: secure::Plaintext,
        aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        diport::KeyProvider::encrypt(self.0.as_ref(), key, plaintext, aad).await
    }

    async fn decrypt(
        &self,
        ciphertext: diport::RedactedBytes,
        key: diport::KeyRef,
        aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, diport::KeyProviderError> {
        diport::KeyProvider::decrypt(self.0.as_ref(), ciphertext, key, aad).await
    }

    async fn rewrap(
        &self,
        ciphertext: diport::RedactedBytes,
        key: diport::KeyRef,
        aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        diport::KeyProvider::rewrap(self.0.as_ref(), ciphertext, key, aad).await
    }

    async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
        Ok(())
    }
}

struct StartupResourceCell {
    resource: tokio::sync::Mutex<Option<Box<DynManagedResource<'static>>>>,
    activated: std::sync::atomic::AtomicBool,
}

struct StartupResourceAlias {
    cell: Arc<StartupResourceCell>,
    name: String,
    shutdown_timeout: std::time::Duration,
    owner: StartupResourceOwner,
}

#[derive(Clone, Copy)]
enum StartupResourceOwner {
    Rollback,
    Activation,
}

struct StartupActivationReceipt {
    cell: Arc<StartupResourceCell>,
}

impl StartupActivationReceipt {
    fn activate(self) {
        self.cell
            .activated
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

fn split_startup_resource(
    resource: Box<DynManagedResource<'static>>,
    name: &'static str,
) -> (
    Box<DynManagedResource<'static>>,
    Box<DynManagedResource<'static>>,
    StartupActivationReceipt,
) {
    let resource_name = resource.name().to_owned();
    let shutdown_timeout = resource.shutdown_timeout();
    let alias_name = format!("{name}:{resource_name}");
    let cell = Arc::new(StartupResourceCell {
        resource: tokio::sync::Mutex::new(Some(resource)),
        activated: std::sync::atomic::AtomicBool::new(false),
    });
    (
        DynManagedResource::new_box(StartupResourceAlias {
            cell: Arc::clone(&cell),
            name: alias_name.clone(),
            shutdown_timeout,
            owner: StartupResourceOwner::Rollback,
        }),
        DynManagedResource::new_box(StartupResourceAlias {
            cell: Arc::clone(&cell),
            name: alias_name,
            shutdown_timeout,
            owner: StartupResourceOwner::Activation,
        }),
        StartupActivationReceipt { cell },
    )
}

fn stage_postgres_resources(
    transaction: &mut runtimeexec::StartupTransaction<'_>,
    resources: Vec<Box<DynManagedResource<'static>>>,
) -> (
    Vec<Box<DynManagedResource<'static>>>,
    Vec<StartupActivationReceipt>,
) {
    let mut activations = Vec::new();
    let mut activated_resources = Vec::new();
    for resource in resources {
        let (startup, activation, receipt) =
            split_startup_resource(resource, "settingsonly-postgres-startup-stage");
        let mut startup_output = bootstrap::DomainModuleResult::default();
        startup_output.push_resource(startup);
        transaction.stage_domain_output(startup_output);
        activated_resources.push(activation);
        activations.push(receipt);
    }
    (activated_resources, activations)
}

impl diport::ManagedResource for StartupResourceAlias {
    fn name(&self) -> &str {
        &self.name
    }

    fn shutdown_timeout(&self) -> std::time::Duration {
        self.shutdown_timeout
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        let activated = self
            .cell
            .activated
            .load(std::sync::atomic::Ordering::Acquire);
        let owns = matches!(
            (self.owner, activated),
            (StartupResourceOwner::Rollback, false) | (StartupResourceOwner::Activation, true)
        );
        if !owns {
            return Ok(());
        }
        match self.cell.resource.lock().await.take() {
            Some(resource) => resource.shutdown().await,
            None => Ok(()),
        }
    }
}

struct PostgresBuild {
    owner: postgres::PgRuntimeDeps,
    dlx_archiver: postgres::PgConfig,
    dlx_verifier: postgres::PgConfig,
    dlx_purger: postgres::PgConfig,
    projection_worker: postgres::PgProjectionWorkerConfig,
    readiness: std::time::Duration,
}

async fn build_postgres(
    config: config::PostgresConfig,
    secrets: &config::ProductionSecretMaterial,
    projection_capture: eventexec::ProjectionCaptureView<'_>,
) -> anyhow::Result<PostgresBuild> {
    let config::PostgresInputs {
        connection,
        writer,
        reader,
        dlx_archiver,
        dlx_verifier,
        dlx_purger,
        projection_worker,
        readiness_interval: readiness,
    } = config.into_postgres_inputs();
    let (host, port, database, ssl_mode, root_cert) = connection.into_connect_options();
    let (writer_name, writer_max) = writer.into_writer_pool();
    let (reader_name, reader_max) = reader.into_reader_pool();
    let make = |username: String, password: String, max_connections: u32| {
        let mut value = postgres::PgConfig::new(
            host.clone(),
            port,
            database.clone(),
            username,
            postgres::PgPassword::new(password),
        )
        .with_ssl_mode(pg_ssl_mode(ssl_mode))
        .with_max_connections(max_connections);
        if let Some(path) = root_cert.clone() {
            value = value.with_ssl_root_cert(path);
        }
        value
    };
    let serving = make(
        writer_name,
        secrets.pg_writer_password.to_string(),
        writer_max,
    );
    let reader = postgres::PgTenantReadConfig::new(make(
        reader_name,
        secrets.pg_reader_password.to_string(),
        reader_max,
    ));
    let (dlx_archiver_name, dlx_archiver_max) = dlx_archiver.into_dlx_archiver_pool();
    let (dlx_verifier_name, dlx_verifier_max) = dlx_verifier.into_dlx_verifier_pool();
    let (dlx_purger_name, dlx_purger_max) = dlx_purger.into_dlx_purger_pool();
    let (projection_worker_name, projection_worker_max) =
        projection_worker.into_projection_worker_pool();
    let dlx_archiver = make(
        dlx_archiver_name,
        secrets.pg_dlx_archiver_password.to_string(),
        dlx_archiver_max,
    );
    let dlx_verifier = make(
        dlx_verifier_name,
        secrets.pg_dlx_verifier_password.to_string(),
        dlx_verifier_max,
    );
    let dlx_purger = make(
        dlx_purger_name,
        secrets.pg_dlx_purger_password.to_string(),
        dlx_purger_max,
    );
    let projection_worker = postgres::PgProjectionWorkerConfig::new(make(
        projection_worker_name,
        secrets.pg_projection_worker_password.to_string(),
        projection_worker_max,
    ));
    let owner =
        postgres::PgRuntimeDeps::connect_serving(&serving, &reader, None, projection_capture)
            .await
            .context("connect settingsonly postgres serving pools")?;
    Ok(PostgresBuild {
        owner,
        dlx_archiver,
        dlx_verifier,
        dlx_purger,
        projection_worker,
        readiness,
    })
}

const fn pg_ssl_mode(mode: config::PgSslMode) -> postgres::PgSslMode {
    match mode {
        config::PgSslMode::VerifyFull => postgres::PgSslMode::VerifyFull,
    }
}

struct VaultProvider {
    deps: vault::VaultRuntimeDeps,
    settings_key: diport::KeyName,
    readiness: std::time::Duration,
    settings_key_provider: crate::providers_gen::SettingsKeyProviderConstructor,
    settings_key_output: bootstrap::DomainModuleResult,
    settings_secret_resolver: crate::providers_gen::SettingsSecretResolverConstructor,
    settings_secret_resolver_output: bootstrap::DomainModuleResult,
    dlx_connection: DlxVaultConnection,
}

struct DlxVaultConnection {
    client: reqwest::Client,
    addr: String,
    transit_mount: String,
    readiness: std::time::Duration,
}

fn build_vault(
    inputs: config::VaultProductionInputs,
    settings_key_provider: crate::providers_gen::SettingsKeyProviderConstructor,
    settings_secret_resolver: crate::providers_gen::SettingsSecretResolverConstructor,
) -> anyhow::Result<VaultProvider> {
    let config::VaultProductionParts {
        addr,
        ca_cert_pem_path,
        transit_mount,
        settings_key_name,
        tenant_store_allowlist,
        readiness_interval,
        token,
    } = inputs.into_parts();
    let client = build_vault_client(Some(ca_cert_pem_path))?;
    let stores = tenant_store_allowlist
        .into_iter()
        .map(|binding| {
            let (tenant, store, mount, kv_path_prefix) = binding.into_store_binding();
            Ok((
                (rss_request_context::TenantId::parse(&tenant)?, store),
                vault::StoreBinding {
                    mount,
                    kv_path_prefix,
                },
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let stores = vault::TenantStoreAllowlist::new(stores)
        .context("build settingsonly Vault store allowlist")?;
    let resolver = vault::VaultSecretResolver::new(
        client.clone(),
        addr.clone(),
        token.to_string(),
        readiness_interval,
        stores,
    )
    .context("build settingsonly Vault secret resolver")?;
    let dlx_connection = DlxVaultConnection {
        client: client.clone(),
        addr: addr.clone(),
        transit_mount: transit_mount.clone(),
        readiness: readiness_interval,
    };
    let key_provider = vault::VaultKeyProvider::new(
        client,
        addr,
        token.to_string(),
        transit_mount,
        readiness_interval,
    )
    .context("build settingsonly Vault key provider")?;
    let key_name = diport::KeyName::try_new(settings_key_name)
        .context("build settingsonly Vault settings key")?;
    let deps = vault::VaultRuntimeDeps::new(resolver, key_provider);
    let mut resources = deps.runtime_resources().into_iter();
    let resolver = resources
        .next()
        .context("settingsonly Vault bundle omitted secret-resolver resource")?;
    let key_provider = resources
        .next()
        .context("settingsonly Vault bundle omitted key-provider resource")?;
    anyhow::ensure!(
        resources.next().is_none(),
        "settingsonly Vault bundle produced an undeclared resource"
    );
    let mut key_output = bootstrap::DomainModuleResult::default();
    key_output.push_resource(key_provider);
    let mut resolver_output = bootstrap::DomainModuleResult::default();
    resolver_output.push_resource(resolver);
    Ok(VaultProvider {
        deps,
        settings_key: key_name,
        readiness: readiness_interval,
        settings_key_provider,
        settings_key_output: key_output,
        settings_secret_resolver,
        settings_secret_resolver_output: resolver_output,
        dlx_connection,
    })
}

fn build_vault_client(ca_path: Option<std::path::PathBuf>) -> anyhow::Result<reqwest::Client> {
    let mut client = reqwest::Client::builder()
        .use_rustls_tls()
        .no_proxy()
        .tls_built_in_root_certs(false)
        .https_only(true);
    if let Some(path) = ca_path {
        let pem = std::fs::read(path).context("read settingsonly Vault CA")?;
        let certificate =
            reqwest::Certificate::from_pem(&pem).context("parse settingsonly Vault CA")?;
        client = client.add_root_certificate(certificate);
    }
    client.build().context("build settingsonly Vault client")
}

struct FederatedProvider {
    provider: Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>,
    provider_constructor: crate::providers_gen::ListenerPdpConstructor,
    probe_name: primitives::ProbeName,
    readiness: oidc::JwksReadinessHandle,
}

impl FederatedProvider {
    fn provider(&self) -> Arc<oidc::OidcProvider<diport::FederatedAccessProfile>> {
        Arc::clone(&self.provider)
    }

    fn managed_resource(&self) -> Box<DynManagedResource<'static>> {
        SharedManagedResource::boxed(
            Arc::clone(&self.provider),
            "settingsonly-federated-verifier",
        )
    }
}

fn build_federated_listener_pdp_jwks_lifecycle(
    federated: FederatedProvider,
) -> (
    crate::providers_gen::ListenerPdpConstructor,
    crate::providers_gen::ListenerPdpJwksLifecycle,
) {
    let managed_resource = federated.managed_resource();
    let ready_probe = AccessTokenJwksReadyProbe::federated_access(
        federated.probe_name.clone(),
        federated.readiness.clone(),
    );
    let FederatedProvider {
        provider: _,
        provider_constructor,
        probe_name,
        readiness: _,
    } = federated;
    (
        provider_constructor,
        crate::providers_gen::ListenerPdpJwksLifecycle::single(
            (probe_name, Box::new(ready_probe)),
            managed_resource,
        ),
    )
}

fn commit_listener_pdp_jwks_lifecycle(
    constructor: crate::providers_gen::ListenerPdpConstructor,
    lifecycle: crate::providers_gen::ListenerPdpJwksLifecycle,
) -> anyhow::Result<crate::providers_gen::ListenerPdpBatch> {
    constructor.finish(lifecycle)
}

fn build_federated_access_provider(
    config: config::FederatedConfig,
    listener_pdp: crate::providers_gen::ListenerPdpConstructor,
) -> anyhow::Result<FederatedProvider> {
    let (issuer, audience, path, refresh, kinds) = config.into_oidc_inputs();
    let source = oidc::JwksKeySource::load_and_watch(
        "settingsonly-federated-access",
        path,
        refresh,
        tokio_util::sync::CancellationToken::new(),
    )
    .context("load settingsonly federated JWKS")?;
    let readiness = source.readiness_handle();
    let permissions = oidc::FederatedPermissionUniverse::try_new([
        vocab::GrantPermission::route(vocab::RoutePermissionId::SettingsConfigPublish),
        vocab::GrantPermission::route(vocab::RoutePermissionId::SettingsConfigDelete),
        vocab::GrantPermission::route(vocab::RoutePermissionId::SettingsConfigRollback),
        vocab::GrantPermission::route(vocab::RoutePermissionId::RuntimeInventoryRead),
    ])
    .context("build settingsonly federated permission universe")?;
    let mut builder = oidc::VerifierConfigBuilder::<diport::FederatedAccessProfile>::new(
        issuer,
        audience,
        permissions,
    )
    .keys_jwks(source);
    for kind in kinds {
        builder = builder.trust_kind(kind.as_str());
    }
    let provider = Arc::new(oidc::OidcProvider::new(
        builder
            .build()
            .context("build settingsonly federated verifier")?,
        Box::new(crate::SystemClock),
    ));
    let name = primitives::ProbeName::parse(crate::readiness::FEDERATED_JWKS)
        .context("build settingsonly federated JWKS probe name")?;
    Ok(FederatedProvider {
        provider,
        provider_constructor: listener_pdp,
        probe_name: name,
        readiness,
    })
}

struct AccessTokenJwksReadyProbe {
    name: primitives::ProbeName,
    readiness: oidc::JwksReadinessHandle,
}

impl AccessTokenJwksReadyProbe {
    fn federated_access(name: primitives::ProbeName, readiness: oidc::JwksReadinessHandle) -> Self {
        Self { name, readiness }
    }
}

impl bootstrap::HealthProbe for AccessTokenJwksReadyProbe {
    fn check(&self) -> primitives::HealthCheck {
        let (status, detail) = if self.readiness.is_ready() {
            (primitives::HealthStatus::Healthy, "ready")
        } else {
            (primitives::HealthStatus::Degraded, "degraded")
        };
        primitives::HealthCheck::new(self.name.clone(), status, detail)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use crate::providers_gen::ListenerPdpJwksLifecycle;
    use diport::ManagedResource as _;

    use super::*;

    fn private_ca() -> rcgen::CertifiedIssuer<'static, rcgen::KeyPair> {
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        CertifiedIssuer::self_signed(params, KeyPair::generate().expect("ca key"))
            .expect("self-signed ca")
    }

    async fn spawn_private_ca_https_server() -> (String, String) {
        use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let ca = private_ca();
        let signing_key = KeyPair::generate().expect("server key");
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().expect("dns"))];
        params.is_ca = IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = params.signed_by(&signing_key, &ca).expect("server cert");
        let server_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert.der().clone()], server_key)
            .expect("server tls config");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind https fixture");
        let port = listener.local_addr().expect("local addr").port();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        tokio::spawn(async move {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            let mut buffer = [0_u8; 1024];
            let _ = tls.read(&mut buffer).await;
            let _ = tls
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        });
        (format!("https://localhost:{port}/"), ca.pem())
    }

    #[tokio::test]
    async fn vault_client_trusts_only_the_configured_private_ca() {
        let (untrusted_url, _) = spawn_private_ca_https_server().await;
        let untrusted = build_vault_client(None)
            .expect("client")
            .get(untrusted_url)
            .send()
            .await;
        assert!(
            untrusted.is_err(),
            "private CA must not be ambiently trusted"
        );

        let (trusted_url, ca_pem) = spawn_private_ca_https_server().await;
        let ca_path = std::env::temp_dir().join(format!(
            "settingsonly-vault-ca-{}-{}.pem",
            std::process::id(),
            diport::Clock::now(&crate::SystemClock)
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::write(&ca_path, ca_pem).expect("write private CA");
        let response = build_vault_client(Some(ca_path.clone()))
            .expect("configured client")
            .get(trusted_url)
            .send()
            .await
            .expect("configured private CA request");
        std::fs::remove_file(ca_path).expect("remove private CA fixture");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }

    struct TestResource;

    impl diport::ManagedResource for TestResource {
        fn name(&self) -> &str {
            "settingsonly-provider-test"
        }

        async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
            Ok(())
        }
    }

    struct CountingResource(Arc<std::sync::atomic::AtomicUsize>);

    impl diport::ManagedResource for CountingResource {
        fn name(&self) -> &str {
            "settingsonly-counting-resource"
        }

        async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            Ok(())
        }
    }

    struct TestProbe(primitives::ProbeName);

    impl bootstrap::HealthProbe for TestProbe {
        fn check(&self) -> primitives::HealthCheck {
            primitives::HealthCheck::new(self.0.clone(), primitives::HealthStatus::Healthy, "ready")
        }
    }

    #[tokio::test]
    async fn startup_resource_rolls_back_before_activation_exactly_once() {
        let shutdowns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (startup, activation, _receipt) = split_startup_resource(
            DynManagedResource::new_box(CountingResource(Arc::clone(&shutdowns))),
            "settingsonly-startup-rollback-test",
        );

        assert_eq!(
            startup.name(),
            "settingsonly-startup-rollback-test:settingsonly-counting-resource"
        );
        assert_eq!(activation.name(), startup.name());

        startup.shutdown().await.expect("startup rollback");
        activation
            .shutdown()
            .await
            .expect("inactive activation no-op");
        startup.shutdown().await.expect("repeated rollback no-op");
        assert_eq!(shutdowns.load(std::sync::atomic::Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn activated_resource_ignores_startup_alias_and_shuts_down_exactly_once() {
        let shutdowns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (startup, activation, receipt) = split_startup_resource(
            DynManagedResource::new_box(CountingResource(Arc::clone(&shutdowns))),
            "settingsonly-activated-owner-test",
        );
        assert_eq!(activation.shutdown_timeout(), startup.shutdown_timeout());
        receipt.activate();

        startup.shutdown().await.expect("activated startup no-op");
        activation.shutdown().await.expect("activation shutdown");
        activation
            .shutdown()
            .await
            .expect("repeated activation no-op");
        assert_eq!(shutdowns.load(std::sync::atomic::Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn production_listener_pdp_jwks_lifecycle_is_exact_probe_and_resource()
    -> anyhow::Result<()> {
        let root = std::env::temp_dir().join(format!(
            "rss-settingsonly-pdp-lifecycle-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root)?;
        let jwks = root.join("federated.jwks.json");
        std::fs::write(
            &jwks,
            r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"settings-federated-es256","alg":"ES256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}]}"#,
        )?;
        let document = include_str!("../settingsonly.example.toml").replace(
            "/run/rss/federated.jwks.json",
            jwks.to_str().context("JWKS path is not UTF-8")?,
        );
        let federated_config = crate::config::federated_production_config_from_document(&document)?;
        let mut roles = crate::plan::SettingsOnlyPlan::bundled()?.provider_build()?;
        let listener_pdp = roles.listener_pdp()?;
        let federated = build_federated_access_provider(federated_config, listener_pdp)?;
        let expected_probe = federated.probe_name.clone();
        let (_constructor, lifecycle) = build_federated_listener_pdp_jwks_lifecycle(federated);
        let output = lifecycle.into_output();
        assert_eq!(expected_probe.as_str(), crate::readiness::FEDERATED_JWKS);
        assert_eq!(output.probe_count(), 1);
        let (actual_probe, _) = output
            .probes()
            .next()
            .context("settingsonly listener PDP lifecycle omitted its probe")?;
        assert_eq!(actual_probe, &expected_probe);
        assert_eq!(output.resource_count(), 1);
        let resource = output
            .resources()
            .next()
            .context("settingsonly listener PDP lifecycle omitted its resource")?;
        assert_eq!(resource.name(), "settingsonly-federated-verifier");
        assert!(output.worker_count() == 0);
        let resource = output
            .into_outputs()
            .find_map(|output| match output {
                bootstrap::DomainLifecycleOutput::Probe(_, _)
                | bootstrap::DomainLifecycleOutput::Worker(_) => None,
                bootstrap::DomainLifecycleOutput::Resource(resource) => Some(resource),
            })
            .context("settingsonly listener PDP lifecycle omitted its shutdown resource")?;
        resource.shutdown().await?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rls_ready_probe_is_fail_closed_with_unverified_detail() {
        let probe = RlsReadyProbe {
            name: primitives::ProbeName::parse(crate::readiness::RLS).expect("valid probe name"),
            readiness: Arc::new(postgres::PgRlsReadiness::for_test(false)),
        };

        let unhealthy = bootstrap::HealthProbe::check(&probe);
        assert_eq!(unhealthy.status(), primitives::HealthStatus::Unhealthy);
        assert_eq!(unhealthy.detail(), "attestation-unverified");
    }

    #[tokio::test]
    async fn access_token_jwks_ready_probe_maps_runtime_false_to_degraded() {
        let root = std::env::temp_dir().join(format!(
            "rss-settingsonly-jwks-degraded-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("temp root");
        let jwks = root.join("federated.jwks.json");
        std::fs::write(
            &jwks,
            r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"settings-federated-es256","alg":"ES256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}]}"#,
        )
        .expect("write JWKS");
        let cancel = tokio_util::sync::CancellationToken::new();
        let source = oidc::JwksKeySource::load_and_watch(
            "settingsonly-federated-degraded-test",
            jwks.clone(),
            std::time::Duration::from_secs(3600),
            cancel.clone(),
        )
        .expect("load JWKS");
        let probe_name = primitives::ProbeName::parse(crate::readiness::FEDERATED_JWKS)
            .expect("valid federated JWKS probe name");
        let probe =
            AccessTokenJwksReadyProbe::federated_access(probe_name, source.readiness_handle());
        let healthy = bootstrap::HealthProbe::check(&probe);
        assert_eq!(healthy.status(), primitives::HealthStatus::Healthy);
        assert_eq!(healthy.detail(), "ready");

        std::fs::remove_file(&jwks).expect("remove JWKS");
        assert!(!source.reload(), "refresh failure marks readiness false");
        let degraded = bootstrap::HealthProbe::check(&probe);
        assert_eq!(degraded.status(), primitives::HealthStatus::Degraded);
        assert_eq!(degraded.detail(), "degraded");

        cancel.cancel();
        drop(source);
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn generated_provider_finish_binds_listener_pdp_jwks_probe_and_resource() {
        let mut roles = crate::plan::SettingsOnlyPlan::bundled()
            .expect("bundled plan")
            .provider_build()
            .expect("exact provider join");
        macro_rules! batch {
            ($method:ident, $role:literal) => {
                roles
                    .$method()
                    .expect(concat!($role, " constructor"))
                    .finish(role_output($role))
                    .expect(concat!($role, " batch"))
            };
        }
        let auth_audit_sink = batch!(auth_audit_sink, "auth-audit-sink");
        let distributed_cas_store = batch!(distributed_cas_store, "distributed-cas-store");
        let distributed_lock_store = batch!(distributed_lock_store, "distributed-lock-store");
        let dlx_archive_key_provider = batch!(dlx_archive_key_provider, "dlx-archive-key-provider");
        let dlx_archive_store = batch!(dlx_archive_store, "dlx-archive-store");
        let dlx_hot_key_provider = batch!(dlx_hot_key_provider, "dlx-hot-key-provider");
        let dlx_lifecycle_repository = batch!(dlx_lifecycle_repository, "dlx-lifecycle-repository");
        let event_publisher = batch!(event_publisher, "event-publisher");
        let event_subscriber = batch!(event_subscriber, "event-subscriber");
        let listener_pdp = roles.listener_pdp().expect("listener-pdp constructor");
        let listener_pdp_probe = primitives::ProbeName::parse(crate::readiness::FEDERATED_JWKS)
            .expect("valid listener-pdp probe name");
        let listener_pdp_output = ListenerPdpJwksLifecycle::single(
            (
                listener_pdp_probe.clone(),
                Box::new(TestProbe(listener_pdp_probe.clone())),
            ),
            DynManagedResource::new_box(TestResource),
        );
        let listener_pdp = commit_listener_pdp_jwks_lifecycle(listener_pdp, listener_pdp_output)
            .expect("listener-pdp JWKS probe and resource batch");
        let listener_rate_limiter = roles
            .listener_rate_limiter()
            .expect("listener-rate-limiter constructor")
            .finish_for_test(role_output("listener-rate-limiter"))
            .expect("listener-rate-limiter batch");
        let settings_key_provider = batch!(settings_key_provider, "settings-key-provider");
        let settings_secret_resolver = batch!(settings_secret_resolver, "settings-secret-resolver");

        let mut inventory = bootstrap::DomainModuleResult::default();
        let auth_audit_sink = auth_audit_sink.transfer(&mut inventory);
        let distributed_cas_store = distributed_cas_store.transfer(&mut inventory);
        let distributed_lock_store = distributed_lock_store.transfer(&mut inventory);
        let dlx_archive_key_provider = dlx_archive_key_provider.transfer(&mut inventory);
        let dlx_archive_store = dlx_archive_store.transfer(&mut inventory);
        let dlx_hot_key_provider = dlx_hot_key_provider.transfer(&mut inventory);
        let dlx_lifecycle_repository = dlx_lifecycle_repository.transfer(&mut inventory);
        let event_publisher = event_publisher.transfer(&mut inventory);
        let event_subscriber = event_subscriber.transfer(&mut inventory);
        let listener_pdp = listener_pdp.transfer(&mut inventory);
        let listener_rate_limiter = listener_rate_limiter.transfer(&mut inventory);
        let settings_key_provider = settings_key_provider.transfer(&mut inventory);
        let settings_secret_resolver = settings_secret_resolver.transfer(&mut inventory);
        let completed = roles
            .finish(
                &inventory,
                auth_audit_sink,
                distributed_cas_store,
                distributed_lock_store,
                dlx_archive_key_provider,
                dlx_archive_store,
                dlx_hot_key_provider,
                dlx_lifecycle_repository,
                event_publisher,
                event_subscriber,
                listener_pdp,
                listener_rate_limiter,
                settings_key_provider,
                settings_secret_resolver,
            )
            .expect("complete role inventory");

        assert_ne!(inventory.resource_count(), 0);
        assert_ne!(inventory.probe_count(), 0);
        assert_ne!(inventory.worker_count(), 0);
        let listener_pdp_binding = completed
            .into_probe_bindings()
            .into_iter()
            .find(|binding| binding.provider_id() == "listener-pdp")
            .expect("listener-pdp provider binding");
        assert_eq!(listener_pdp_binding.probe_names(), &[listener_pdp_probe]);
    }

    fn role_output(role: &str) -> bootstrap::DomainModuleResult {
        use assembly_schema::LifecycleChannel;
        let entry = crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .find(|entry| entry.role().as_str() == role)
            .expect("generated role");
        let mut output = bootstrap::DomainModuleResult::default();
        for channel in entry.evidence().outputs() {
            match channel {
                LifecycleChannel::Probes => {
                    let name = primitives::ProbeName::parse(&format!("{role}_ready"))
                        .expect("test probe name");
                    output.push_probe((name.clone(), Box::new(TestProbe(name))));
                }
                LifecycleChannel::Resources => {
                    output.push_resource(DynManagedResource::new_box(TestResource))
                }
                LifecycleChannel::Workers => {
                    output.push_worker(bootstrap::WorkerSpec::observational_phase_one(
                        "assemblies.settingsonly.src.providers.03",
                        |_token| DynManagedResource::new_box(TestResource),
                    ));
                }
            }
        }
        output
    }
}

#[cfg(test)]
mod production_inputs_tests;
