//! Production provider construction for the sealed identityaudit runtime plan.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context as _;
use diport::{DynKeyProvider, DynManagedResource, ManagedResource, ShutdownError};

use crate::config;
use crate::runtime::SharedManagedResource;

const PG_READINESS_PERIOD: Duration = Duration::from_secs(2);
const REDIS_READINESS_PERIOD: Duration = Duration::from_secs(5);
const AUDIT_CHAIN_KEY_SENTINEL: &[u8] = b"rss.audit-chain-key.identityaudit.v1";
const VAULT_READINESS_CANARY_TENANT: &str = "00000000-0000-4000-8000-000000001797";

pub(crate) struct ProviderBundle {
    pub(crate) pg: postgres::PgRuntimeHandle,
    pub(crate) redis: redis::RedisRuntimeDeps,
    pub(crate) signer: Arc<vault::VaultSigner>,
    pub(crate) verifier: crate::auth_bridge::RssAccessVerifier,
    pub(crate) audit_sink: httpserve::AuditSinkHandle,
    pub(crate) metrics: Arc<dyn diport::MetricsExporter>,
    pub(crate) limiter: Arc<redis::RedisRateLimiter>,
    pub(crate) audit_chain_key: primitives::MacKey,
    pub(crate) identity_pseudonym_keys: Arc<secure::PseudonymKeyRing>,
    pub(crate) tenant_authority: Arc<eventexec::TenantAuthority>,
    pub(crate) dlx_payload_protector: postgres::DlxPayloadProtector,
    pub(crate) identity: IdentityInputs,
}

pub(crate) struct IdentityInputs {
    pub(crate) runtime_config: identity_composition::IdentityRuntimeConfig,
    pub(crate) blocklist: Arc<secure::DigestPasswordBlocklist>,
}

pub(crate) struct BuildResult {
    pub(crate) providers: ProviderBundle,
    pub(crate) listeners: config::ListenersConfig,
    pub(crate) amqp_endpoint: secure::AmqpEndpoint,
    pub(crate) amqp_ca: amqp::AmqpPrivateCa,
    pub(crate) roles: ProviderRoleCloser,
}

pub(crate) struct EventingRoleOutputs {
    pub(crate) distributed_cas: bootstrap::DomainModuleResult,
    pub(crate) event_publisher: bootstrap::DomainModuleResult,
    pub(crate) event_subscriber: bootstrap::DomainModuleResult,
}

pub(crate) struct ProviderRoleCloser {
    roles: crate::providers_gen::ProviderRoleBatches,
    auth_audit_sink: crate::providers_gen::AuthAuditSinkReceipt,
    distributed_lock_store: crate::providers_gen::DistributedLockStoreReceipt,
    identity_signer: crate::providers_gen::IdentitySignerReceipt,
    dlx_archive_key_provider: crate::providers_gen::DlxArchiveKeyProviderReceipt,
    listener_pdp: crate::providers_gen::ListenerPdpReceipt,
    listener_rate_limiter: crate::providers_gen::ListenerRateLimiterReceipt,
    distributed_cas_constructor: crate::providers_gen::DistributedCasStoreConstructor,
    event_publisher_constructor: crate::providers_gen::EventPublisherConstructor,
    event_subscriber_constructor: crate::providers_gen::EventSubscriberConstructor,
    cas_resource: Box<DynManagedResource<'static>>,
}

impl ProviderRoleCloser {
    pub(crate) fn finish(
        self,
        outputs: EventingRoleOutputs,
        inventory: &mut bootstrap::DomainModuleResult,
    ) -> anyhow::Result<crate::providers_gen::CompletedProviderRoles> {
        let mut cas = outputs.distributed_cas;
        cas.resources.push(self.cas_resource);
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
        self.roles.finish(
            inventory,
            self.auth_audit_sink,
            distributed_cas_store,
            self.distributed_lock_store,
            self.dlx_archive_key_provider,
            event_publisher,
            event_subscriber,
            self.identity_signer,
            self.listener_pdp,
            self.listener_rate_limiter,
        )
    }
}

pub(crate) async fn build(
    mut roles: crate::providers_gen::ProviderRoleBatches,
    projection_capture: eventexec::ProjectionCaptureView<'_>,
    config: config::IdentityAuditConfig,
    secrets: config::ResolvedSecrets,
    rate_limit_quota: diport::RateLimitQuota,
    transaction: &mut runtimeexec::StartupTransaction<'_>,
) -> anyhow::Result<BuildResult> {
    let (listeners, identity, oidc, postgres, vault, eventing, redis) = config.into_sections();
    let eventing = eventing.into_eventing_inputs();
    let amqp_ca = load_amqp_private_ca(&eventing.amqp_ca_cert_pem_path)?;
    let redis_ca = load_redis_private_ca(&redis.into_ca_cert_pem_path())?;
    let (
        writer_password,
        reader_password,
        audit_admin_password,
        vault_signer_token,
        vault_dlx_token,
        amqp_url,
        redis_url,
        audit_chain_key,
        tenant_authority_key,
        identity_pseudonym_key,
    ) = secrets.into_secret_material();
    let identity_pseudonym_keys = Arc::new(secure::PseudonymKeyRing::new(
        secure::VersionedPseudonymKey::new(
            secure::PseudonymKeyId::new(std::num::NonZeroU16::MIN),
            identity_pseudonym_key,
        ),
        Vec::new(),
    )?);
    let identity = build_identity(identity)?;
    let identity_signing_binding = identity.runtime_config.jwt_signing_binding().clone();

    let auth_audit_sink_constructor = roles.auth_audit_sink()?;
    let distributed_cas_constructor = roles.distributed_cas_store()?;
    let distributed_lock_constructor = roles.distributed_lock_store()?;
    let event_publisher_constructor = roles.event_publisher()?;
    let event_subscriber_constructor = roles.event_subscriber()?;
    let identity_signer_constructor = roles.identity_signer()?;
    let dlx_archive_key_provider_constructor = roles.dlx_archive_key_provider()?;
    let listener_pdp_constructor = roles.listener_pdp()?;
    let listener_rate_limiter_constructor = roles.listener_rate_limiter()?;

    let pg_owner = build_postgres(
        postgres,
        writer_password,
        reader_password,
        audit_admin_password,
        projection_capture,
    )
    .await?;
    let pg = pg_owner.handle();
    let pg_probe_name = primitives::ProbeName::parse("identityaudit_postgres_ready")
        .context("build identityaudit Postgres probe name")?;
    let pg_probe = (
        pg_probe_name.clone(),
        Box::new(PostgresProbe {
            name: pg_probe_name,
            readiness: pg.readiness_handle(),
            rls_ready: pg.rls_ready_handle(),
        }) as Box<dyn bootstrap::HealthProbe>,
    );
    let (mut pg_resources, pg_sampler) = pg_owner.into_runtime_parts(PG_READINESS_PERIOD);
    let cas_resource = pg_resources
        .pop()
        .context("identityaudit Postgres omitted distributed CAS lifecycle resource")?;
    if pg_resources.is_empty() {
        anyhow::bail!("identityaudit Postgres omitted auth-audit lifecycle resources");
    }
    let mut auth_audit_output = bootstrap::DomainModuleResult {
        probes: Vec::from([pg_probe]),
        resources: pg_resources,
        ..Default::default()
    };
    auth_audit_output
        .workers
        .push(bootstrap::WorkerSpec::observational_phase_one(
            "assemblies.identityaudit.src.providers.01",
            move |token| DynManagedResource::new_box(pg_sampler.spawn(token)),
        ));
    let auth_audit_sink = auth_audit_sink_constructor
        .finish(auth_audit_output)?
        .transfer(transaction.provider_output_mut());
    let (staged_cas_resource, cas_resource) =
        split_startup_resource(cas_resource, "identityaudit-postgres-cas-startup-stage");
    transaction.stage_domain_output(bootstrap::DomainModuleResult {
        resources: Vec::from([staged_cas_resource]),
        ..Default::default()
    });

    verify_audit_chain_key(&pg, eventing.audit_chain_key_id, &audit_chain_key).await?;

    let redis = build_redis(redis_url, redis_ca).await?;
    let redis_ready = Arc::new(AtomicBool::new(true));
    let redis_probe_name = primitives::ProbeName::parse("identityaudit_redis_ready")
        .context("build identityaudit Redis probe name")?;
    let redis_for_worker = redis.clone();
    let redis_worker_ready = Arc::clone(&redis_ready);
    let lock_output = bootstrap::DomainModuleResult {
        probes: Vec::from([(
            redis_probe_name.clone(),
            Box::new(RedisProbe {
                name: redis_probe_name,
                ready: Arc::clone(&redis_ready),
            }) as Box<dyn bootstrap::HealthProbe>,
        )]),
        resources: redis.runtime_resources(),
        workers: Vec::from([bootstrap::WorkerSpec::observational_phase_one(
            "assemblies.identityaudit.src.providers.02",
            move |token| {
                DynManagedResource::new_box(RedisReadinessWorker::spawn(
                    redis_for_worker.clone(),
                    token,
                    Arc::clone(&redis_worker_ready),
                ))
            },
        )]),
    };
    let distributed_lock_store = distributed_lock_constructor
        .finish(lock_output)?
        .transfer(transaction.provider_output_mut());

    let oidc = build_rss_access_provider(oidc, &pg)?;
    let rss_jwks = oidc.jwks_readiness();
    let vault = build_vault(
        vault,
        vault_signer_token,
        vault_dlx_token,
        identity_signing_binding,
        rss_jwks,
    )
    .await?;
    let signer = Arc::clone(&vault.signer);
    let signer_output = bootstrap::DomainModuleResult {
        probes: Vec::from([vault.signer_readiness_probe]),
        resources: Vec::from([SharedManagedResource::boxed(
            Arc::clone(&signer),
            "identityaudit-vault-signer",
        )]),
        workers: Vec::from([vault.signer_readiness_worker]),
    };
    let identity_signer = identity_signer_constructor
        .finish(signer_output)?
        .transfer(transaction.provider_output_mut());
    let dlx_archive_key_provider = dlx_archive_key_provider_constructor
        .finish(bootstrap::DomainModuleResult {
            probes: Vec::from([vault.dlx_readiness_probe]),
            resources: Vec::from([SharedManagedResource::boxed(
                Arc::clone(&vault.dlx_key_provider),
                "identityaudit-vault-dlx-key-provider",
            )]),
            workers: Vec::from([vault.dlx_readiness_worker]),
        })?
        .transfer(transaction.provider_output_mut());
    let dlx_payload_protector = postgres::DlxPayloadProtector::new(
        DynKeyProvider::new_box(SharedKeyProvider(Arc::clone(&vault.dlx_key_provider))),
        eventexec::DlxHotKeyName::try_new(vault.dlx_key_name)
            .context("build identityaudit DLX key name")?,
    );

    let (rss_provider, grants, listener_pdp_lifecycle) =
        self::build_rss_listener_pdp_jwks_lifecycle(oidc);
    let listener_pdp =
        self::commit_listener_pdp_jwks_lifecycle(listener_pdp_constructor, listener_pdp_lifecycle)?
            .transfer(transaction.provider_output_mut());

    let rate_limiter_capability = redis
        .infra()
        .rate_limiter_capability(crate::providers_gen::ASSEMBLY_NAMESPACE, rate_limit_quota)
        .await
        .context("verify identityaudit Redis rate-limiter capability")?;
    let (listener_rate_limiter, limiter) = listener_rate_limiter_constructor
        .finish(rate_limiter_capability)?
        .transfer(transaction.provider_output_mut());
    let limiter = Arc::new(limiter);
    let metrics = Arc::new(
        prometheus_adapter::PromExporter::install()
            .context("install identityaudit metrics exporter")?,
    );
    transaction.stage_domain_output(bootstrap::DomainModuleResult {
        resources: vec![SharedManagedResource::boxed(
            Arc::clone(&metrics),
            "identityaudit-prometheus",
        )],
        ..Default::default()
    });
    let metrics_port: Arc<dyn diport::MetricsExporter> = metrics;

    let tenant_authority = build_tenant_authority(
        tenant_authority_key,
        eventing.tenant_authority_ttl,
        eventing.tenant_authority_clock_skew,
    )?;
    let amqp_endpoint =
        secure::AmqpEndpoint::parse(amqp_url.to_string(), secure::PlaintextEndpointPolicy::Deny)
            .context("parse captured identity AMQP endpoint")?;
    let audit_sink =
        httpserve::AuditSinkHandle::new(pg.for_domain::<postgres::caps::Audit>().auth_audit_sink());

    Ok(BuildResult {
        providers: ProviderBundle {
            verifier: crate::auth_bridge::RssAccessVerifier::new(rss_provider, grants),
            pg,
            redis,
            signer,
            audit_sink,
            metrics: metrics_port,
            limiter,
            audit_chain_key,
            identity_pseudonym_keys,
            tenant_authority,
            dlx_payload_protector,
            identity,
        },
        listeners,
        amqp_endpoint,
        amqp_ca,
        roles: ProviderRoleCloser {
            roles,
            auth_audit_sink,
            distributed_lock_store,
            identity_signer,
            dlx_archive_key_provider,
            listener_pdp,
            listener_rate_limiter,
            distributed_cas_constructor,
            event_publisher_constructor,
            event_subscriber_constructor,
            cas_resource,
        },
    })
}

fn load_amqp_private_ca(path: &std::path::Path) -> anyhow::Result<amqp::AmqpPrivateCa> {
    let pem = std::fs::read(path).context("read identityaudit AMQP CA certificate")?;
    amqp::AmqpPrivateCa::from_pem(pem).context("parse identityaudit AMQP CA certificate")
}

fn load_redis_private_ca(path: &std::path::Path) -> anyhow::Result<redis::RedisPrivateCa> {
    let pem = std::fs::read(path).context("read identityaudit Redis CA certificate")?;
    redis::RedisPrivateCa::from_pem(pem).context("parse identityaudit Redis CA certificate")
}

async fn build_postgres(
    config: config::PostgresConfig,
    writer_password: zeroize::Zeroizing<String>,
    reader_password: zeroize::Zeroizing<String>,
    audit_admin_password: zeroize::Zeroizing<String>,
    projection_capture: eventexec::ProjectionCaptureView<'_>,
) -> anyhow::Result<postgres::PgRuntimeDeps> {
    let (serving, reader, audit_admin) = postgres_setup_configs(
        config,
        writer_password,
        reader_password,
        audit_admin_password,
    );
    let owner = postgres::PgRuntimeDeps::connect_serving(
        &serving,
        &reader,
        Some(&audit_admin),
        projection_capture,
    )
    .await
    .context("setup identityaudit Postgres")?;
    Ok(owner)
}

fn postgres_setup_configs(
    config: config::PostgresConfig,
    writer_password: zeroize::Zeroizing<String>,
    reader_password: zeroize::Zeroizing<String>,
    audit_admin_password: zeroize::Zeroizing<String>,
) -> (
    postgres::PgConfig,
    postgres::PgTenantReadConfig,
    postgres::PgConfig,
) {
    let (connection, writer, reader, audit_admin) = config.into_postgres_inputs();
    let (host, port, database, ssl_mode, root_cert) = connection.into_connect_options();
    let make = |username: String, password: String, max_connections: u32| {
        let mut value = postgres::PgConfig::new(
            host.clone(),
            port,
            database.clone(),
            username,
            postgres::PgPassword::new(password),
        )
        .with_ssl_mode(match ssl_mode {
            config::PgSslMode::Disable => postgres::PgSslMode::Disable,
            config::PgSslMode::VerifyFull => postgres::PgSslMode::VerifyFull,
        })
        .with_max_connections(max_connections);
        if let Some(path) = root_cert.clone() {
            value = value.with_ssl_root_cert(path);
        }
        value
    };
    let (writer_name, writer_max) = writer.into_writer_pool();
    let (reader_name, reader_max) = reader.into_reader_pool();
    let (audit_admin_name, audit_admin_max) = audit_admin.into_audit_admin_pool();
    let serving = make(writer_name, writer_password.to_string(), writer_max);
    let reader = postgres::PgTenantReadConfig::new(make(
        reader_name,
        reader_password.to_string(),
        reader_max,
    ));
    let audit_admin = make(
        audit_admin_name,
        audit_admin_password.to_string(),
        audit_admin_max,
    );
    (serving, reader, audit_admin)
}

async fn build_redis(
    url: zeroize::Zeroizing<String>,
    ca: redis::RedisPrivateCa,
) -> anyhow::Result<redis::RedisRuntimeDeps> {
    let endpoint =
        secure::RedisEndpoint::parse(url.to_string(), secure::PlaintextEndpointPolicy::Deny)
            .context("parse captured identityaudit Redis endpoint")?;
    let deps = redis::RedisRuntimeDeps::connect_with_private_ca(&endpoint, ca)
        .context("build identityaudit Redis TLS pool")?;
    deps.ping().await.context("verify identityaudit Redis")?;
    Ok(deps)
}

struct RedisProbe {
    name: primitives::ProbeName,
    ready: Arc<AtomicBool>,
}

impl bootstrap::HealthProbe for RedisProbe {
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
    handle: tokio::sync::Mutex<Option<diport::OwnedTask<()>>>,
    token: tokio_util::sync::CancellationToken,
}

impl RedisReadinessWorker {
    fn spawn(
        redis: redis::RedisRuntimeDeps,
        parent: tokio_util::sync::CancellationToken,
        ready: Arc<AtomicBool>,
    ) -> Self {
        let token = parent.child_token();
        let worker_token = token.clone();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(REDIS_READINESS_PERIOD);
            loop {
                tokio::select! {
                    _ = worker_token.cancelled() => break,
                    _ = interval.tick() => {
                        ready.store(redis.ping().await.is_ok(), Ordering::Release);
                    }
                }
            }
            ready.store(false, Ordering::Release);
        });
        Self {
            handle: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(handle))),
            token,
        }
    }
}

impl ManagedResource for RedisReadinessWorker {
    fn name(&self) -> &str {
        "identityaudit-redis-readiness-worker"
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

struct StartupResourceCell {
    resource: tokio::sync::Mutex<Option<Box<DynManagedResource<'static>>>>,
}

struct StartupResourceAlias {
    cell: Arc<StartupResourceCell>,
    name: &'static str,
}

fn split_startup_resource(
    resource: Box<DynManagedResource<'static>>,
    name: &'static str,
) -> (
    Box<DynManagedResource<'static>>,
    Box<DynManagedResource<'static>>,
) {
    let cell = Arc::new(StartupResourceCell {
        resource: tokio::sync::Mutex::new(Some(resource)),
    });
    (
        DynManagedResource::new_box(StartupResourceAlias {
            cell: Arc::clone(&cell),
            name,
        }),
        DynManagedResource::new_box(StartupResourceAlias { cell, name }),
    )
}

impl diport::ManagedResource for StartupResourceAlias {
    fn name(&self) -> &str {
        self.name
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        let resource = self.cell.resource.lock().await.take();
        match resource {
            Some(resource) => resource.shutdown().await,
            None => Ok(()),
        }
    }
}

async fn verify_audit_chain_key(
    pg: &postgres::PgRuntimeHandle,
    configured_id: config::AuditChainKeyId,
    key: &primitives::MacKey,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        configured_id.get() == 1,
        "identityaudit only supports audit chain key generation v1"
    );
    use primitives::MacVerifier as _;
    let tag = crypto::RustCryptoMacVerifier.sign(
        key,
        primitives::MacAlgorithm::HmacSha256,
        AUDIT_CHAIN_KEY_SENTINEL,
    );
    pg.for_domain::<postgres::caps::Audit>()
        .verify_audit_chain_key(postgres::AuditChainKeyIdentity::V1, tag.as_bytes())
        .await
        .context("verify durable identityaudit audit-chain key identity")
}

struct VaultProducts {
    signer: Arc<vault::VaultSigner>,
    dlx_key_provider: Arc<vault::VaultKeyProvider>,
    dlx_key_name: String,
    signer_readiness_worker: bootstrap::WorkerSpec,
    signer_readiness_probe: (primitives::ProbeName, Box<dyn bootstrap::HealthProbe>),
    dlx_readiness_worker: bootstrap::WorkerSpec,
    dlx_readiness_probe: (primitives::ProbeName, Box<dyn bootstrap::HealthProbe>),
}

async fn build_vault(
    config: config::VaultConfig,
    signer_token: zeroize::Zeroizing<String>,
    dlx_token: zeroize::Zeroizing<String>,
    signing_binding: diport::JwtSigningBinding<diport::RssAccessProfile>,
    jwks: oidc::JwksReadinessHandle,
) -> anyhow::Result<VaultProducts> {
    let (addr, ca_path, mount, _signing_key_name, dlx_key_name, timeout) =
        config.into_vault_inputs();
    let allow_loopback_http = url::Url::parse(&addr)
        .context("parse captured identityaudit Vault address")?
        .scheme()
        == "http";
    let pem = std::fs::read(ca_path).context("read identityaudit Vault CA")?;
    let certificate =
        reqwest::Certificate::from_pem(&pem).context("parse identityaudit Vault CA")?;
    let client = reqwest::Client::builder()
        .https_only(!allow_loopback_http)
        .add_root_certificate(certificate)
        .build()
        .context("build identityaudit Vault client")?;
    let signer = if allow_loopback_http {
        vault::VaultSigner::new_rss_access_allow_http(
            client.clone(),
            addr.clone(),
            signer_token.to_string(),
            mount.clone(),
            timeout,
            signing_binding.clone(),
        )
    } else {
        vault::VaultSigner::new_rss_access(
            client.clone(),
            addr.clone(),
            signer_token.to_string(),
            mount.clone(),
            timeout,
            signing_binding.clone(),
        )
    }
    .context("build identityaudit Vault signer")?;
    let signer = Arc::new(signer);
    let dlx_key_provider = Arc::new(
        if allow_loopback_http {
            vault::VaultKeyProvider::new_allow_http(
                client,
                addr,
                dlx_token.to_string(),
                mount,
                timeout,
            )
        } else {
            vault::VaultKeyProvider::new(client, addr, dlx_token.to_string(), mount, timeout)
        }
        .context("build identityaudit Vault DLX key provider")?,
    );
    verify_vault_signer(&signer, &signing_binding, &jwks).await?;
    verify_vault_key_provider(&dlx_key_provider, &dlx_key_name).await?;

    let readiness = Arc::new(VaultReadiness::healthy());
    let signer_probe_name = primitives::ProbeName::parse("identityaudit_vault_signer_ready")
        .context("build identityaudit Vault signer readiness probe")?;
    let dlx_probe_name = primitives::ProbeName::parse("identityaudit_vault_dlx_key_ready")
        .context("build identityaudit Vault DLX readiness probe")?;
    let signer_readiness_probe = (
        signer_probe_name.clone(),
        Box::new(VaultCapabilityProbe::signer(
            signer_probe_name,
            Arc::clone(&readiness),
        )) as Box<dyn bootstrap::HealthProbe>,
    );
    let dlx_readiness_probe = (
        dlx_probe_name.clone(),
        Box::new(VaultCapabilityProbe::dlx(
            dlx_probe_name,
            Arc::clone(&readiness),
        )) as Box<dyn bootstrap::HealthProbe>,
    );
    let worker_signer = Arc::clone(&signer);
    let worker_key_provider = Arc::clone(&dlx_key_provider);
    let worker_signing_binding = signing_binding;
    let worker_dlx_key = dlx_key_name.clone();
    let signer_readiness = Arc::clone(&readiness);
    let signer_readiness_worker = bootstrap::WorkerSpec::observational_phase_one(
        "assemblies.identityaudit.src.providers.03",
        move |token| {
            DynManagedResource::new_box(VaultReadinessWorker::spawn_signer(
                token,
                timeout,
                worker_signer,
                worker_signing_binding,
                jwks,
                signer_readiness,
            ))
        },
    );
    let dlx_readiness_worker = bootstrap::WorkerSpec::observational_phase_one(
        "assemblies.identityaudit.src.providers.04",
        move |token| {
            DynManagedResource::new_box(VaultReadinessWorker::spawn_dlx(
                token,
                timeout,
                worker_key_provider,
                worker_dlx_key,
                readiness,
            ))
        },
    );
    Ok(VaultProducts {
        signer,
        dlx_key_provider,
        dlx_key_name,
        signer_readiness_worker,
        signer_readiness_probe,
        dlx_readiness_worker,
        dlx_readiness_probe,
    })
}

async fn verify_vault_signer(
    signer: &vault::VaultSigner,
    binding: &diport::JwtSigningBinding<diport::RssAccessProfile>,
    jwks: &oidc::JwksReadinessHandle,
) -> anyhow::Result<()> {
    oidc::prove_rss_signer_matches_jwks(signer, binding, jwks)
        .await
        .context("verify identityaudit Vault signer and JWKS key pair")?;
    Ok(())
}

async fn verify_vault_key_provider(
    provider: &vault::VaultKeyProvider,
    key_name: &str,
) -> anyhow::Result<()> {
    use diport::KeyProvider as _;
    let tenant = rss_request_context::TenantId::parse(VAULT_READINESS_CANARY_TENANT)
        .context("parse identityaudit Vault readiness tenant")?;
    let aad = secure::ProtectionContext::authorized_maintenance(
        tenant,
        "identityaudit/dlx",
        "readiness-canary",
        1,
    )
    .context("derive identityaudit Vault readiness AAD")?
    .derive();
    let encrypted = provider
        .encrypt(
            diport::KeyName::try_new(key_name.to_owned())
                .context("build identityaudit Vault readiness key name")?,
            secure::Plaintext::new(b"identityaudit-dlx-readiness-v1".to_vec()),
            aad.clone(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("identityaudit Vault DLX encrypt readiness failed"))?;
    let opened = provider
        .decrypt(
            diport::RedactedBytes::new(encrypted.ciphertext().to_vec()),
            encrypted.key().clone(),
            aad,
        )
        .await
        .map_err(|_| anyhow::anyhow!("identityaudit Vault DLX decrypt readiness failed"))?;
    anyhow::ensure!(
        opened.expose() == b"identityaudit-dlx-readiness-v1",
        "identityaudit Vault DLX readiness plaintext mismatch"
    );
    Ok(())
}

struct VaultReadiness {
    signer: AtomicBool,
    dlx: AtomicBool,
}

impl VaultReadiness {
    fn healthy() -> Self {
        Self {
            signer: AtomicBool::new(true),
            dlx: AtomicBool::new(true),
        }
    }
}

#[derive(Clone, Copy)]
enum VaultCapability {
    Signer,
    Dlx,
}

struct VaultCapabilityProbe {
    name: primitives::ProbeName,
    readiness: Arc<VaultReadiness>,
    capability: VaultCapability,
}

impl VaultCapabilityProbe {
    fn signer(name: primitives::ProbeName, readiness: Arc<VaultReadiness>) -> Self {
        Self {
            name,
            readiness,
            capability: VaultCapability::Signer,
        }
    }

    fn dlx(name: primitives::ProbeName, readiness: Arc<VaultReadiness>) -> Self {
        Self {
            name,
            readiness,
            capability: VaultCapability::Dlx,
        }
    }
}

impl bootstrap::HealthProbe for VaultCapabilityProbe {
    fn check(&self) -> primitives::HealthCheck {
        let ready = match self.capability {
            VaultCapability::Signer => self.readiness.signer.load(Ordering::Acquire),
            VaultCapability::Dlx => self.readiness.dlx.load(Ordering::Acquire),
        };
        primitives::HealthCheck::new(
            self.name.clone(),
            if ready {
                primitives::HealthStatus::Healthy
            } else {
                primitives::HealthStatus::Unhealthy
            },
            if ready { "ready" } else { "unavailable" },
        )
    }
}

struct VaultReadinessWorker {
    name: &'static str,
    token: tokio_util::sync::CancellationToken,
    handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

struct AbortReadinessTaskOnDrop {
    handle: tokio::task::JoinHandle<()>,
    armed: bool,
}

#[derive(Debug)]
struct VaultReadinessJoinDeadline;

impl std::fmt::Display for VaultReadinessJoinDeadline {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("identityaudit Vault readiness join deadline exceeded")
    }
}

impl std::error::Error for VaultReadinessJoinDeadline {}

impl AbortReadinessTaskOnDrop {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self {
            handle,
            armed: true,
        }
    }

    fn handle(&mut self) -> &mut tokio::task::JoinHandle<()> {
        &mut self.handle
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for AbortReadinessTaskOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.handle.abort();
        }
    }
}

impl VaultReadinessWorker {
    fn spawn_signer(
        token: tokio_util::sync::CancellationToken,
        period: Duration,
        signer: Arc<vault::VaultSigner>,
        signing_binding: diport::JwtSigningBinding<diport::RssAccessProfile>,
        jwks: oidc::JwksReadinessHandle,
        readiness: Arc<VaultReadiness>,
    ) -> Self {
        let run_token = token.clone();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    () = run_token.cancelled() => break,
                    _ = interval.tick() => {
                        let signer_ready = tokio::select! {
                            () = run_token.cancelled() => break,
                            result = verify_vault_signer(&signer, &signing_binding, &jwks) => result.is_ok(),
                        };
                        readiness.signer.store(
                            signer_ready,
                            Ordering::Release,
                        );
                    }
                }
            }
            readiness.signer.store(false, Ordering::Release);
        });
        Self {
            name: "identityaudit-vault-signer-readiness",
            token,
            handle: tokio::sync::Mutex::new(Some(handle)),
        }
    }

    fn spawn_dlx(
        token: tokio_util::sync::CancellationToken,
        period: Duration,
        key_provider: Arc<vault::VaultKeyProvider>,
        dlx_key: String,
        readiness: Arc<VaultReadiness>,
    ) -> Self {
        let run_token = token.clone();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    () = run_token.cancelled() => break,
                    _ = interval.tick() => {
                        let dlx_ready = tokio::select! {
                            () = run_token.cancelled() => break,
                            result = verify_vault_key_provider(&key_provider, &dlx_key) => result.is_ok(),
                        };
                        readiness.dlx.store(dlx_ready, Ordering::Release);
                    }
                }
            }
            readiness.dlx.store(false, Ordering::Release);
        });
        Self {
            name: "identityaudit-vault-dlx-key-readiness",
            token,
            handle: tokio::sync::Mutex::new(Some(handle)),
        }
    }
}

impl diport::ManagedResource for VaultReadinessWorker {
    fn name(&self) -> &str {
        self.name
    }

    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(2)
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        self.token.cancel();
        let Some(handle) = self.handle.lock().await.take() else {
            return Ok(());
        };
        let mut guard = AbortReadinessTaskOnDrop::new(handle);
        match tokio::time::timeout(Duration::from_secs(1), guard.handle()).await {
            Ok(joined) => {
                guard.disarm();
                joined.map_err(diport::ShutdownError::from_join_error)
            }
            Err(_) => {
                guard.handle().abort();
                let _ = guard.handle().await;
                guard.disarm();
                Err(diport::ShutdownError::deadline_exceeded(
                    VaultReadinessJoinDeadline,
                ))
            }
        }
    }
}

struct OidcProducts {
    provider: Arc<oidc::OidcProvider<diport::RssAccessProfile>>,
    grants: Arc<identity::AuthGrantValidationService>,
    probe_name: primitives::ProbeName,
    probe: AccessTokenJwksReadyProbe,
    jwks: oidc::JwksReadinessHandle,
}

fn build_rss_listener_pdp_jwks_lifecycle(
    products: OidcProducts,
) -> (
    Arc<oidc::OidcProvider<diport::RssAccessProfile>>,
    Arc<identity::AuthGrantValidationService>,
    crate::providers_gen::ListenerPdpJwksLifecycle,
) {
    let provider = products.provider();
    let OidcProducts {
        provider: _,
        grants,
        probe_name,
        probe,
        jwks: _,
    } = products;
    let managed_resource =
        SharedManagedResource::boxed(Arc::clone(&provider), "identityaudit-rss-access-verifier");
    (
        provider,
        grants,
        crate::providers_gen::ListenerPdpJwksLifecycle::single(
            (probe_name, Box::new(probe)),
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

impl OidcProducts {
    fn provider(&self) -> Arc<oidc::OidcProvider<diport::RssAccessProfile>> {
        Arc::clone(&self.provider)
    }

    fn jwks_readiness(&self) -> oidc::JwksReadinessHandle {
        self.jwks.clone()
    }
}

fn build_rss_access_provider(
    config: config::OidcConfig,
    pg: &postgres::PgRuntimeHandle,
) -> anyhow::Result<OidcProducts> {
    let (provider, probe_name, probe, jwks) = build_rss_access_verifier(config)?;
    let clock: Arc<dyn diport::Clock> = Arc::new(crate::SystemClock);
    let grants = identity_composition::access_grant_validation_service(
        &pg.for_domain::<postgres::caps::Identity>(),
        &clock,
    );
    Ok(OidcProducts {
        provider,
        grants,
        probe,
        probe_name,
        jwks,
    })
}

fn build_rss_access_verifier(
    config: config::OidcConfig,
) -> anyhow::Result<(
    Arc<oidc::OidcProvider<diport::RssAccessProfile>>,
    primitives::ProbeName,
    AccessTokenJwksReadyProbe,
    oidc::JwksReadinessHandle,
)> {
    let (issuer, audience, path, refresh) = config.into_oidc_inputs();
    let source = oidc::JwksKeySource::load_and_watch(
        "identityaudit-rss-access",
        path,
        refresh,
        tokio_util::sync::CancellationToken::new(),
    )
    .context("load identityaudit RSS JWKS")?;
    let readiness = source.readiness_handle();
    let provider = Arc::new(oidc::OidcProvider::new(
        oidc::VerifierConfigBuilder::<diport::RssAccessProfile>::new(issuer, audience)
            .keys_jwks(source)
            .build()
            .context("build identityaudit RSS verifier")?,
        Box::new(crate::SystemClock),
    ));
    let probe_name = primitives::ProbeName::parse("identityaudit_rss_jwks_ready")
        .context("build identityaudit JWKS probe name")?;
    let probe = AccessTokenJwksReadyProbe::rss_access(probe_name.clone(), readiness.clone());
    Ok((provider, probe_name, probe, readiness))
}

#[cfg(test)]
pub(crate) fn rss_access_provider_for_test(
    config: config::OidcConfig,
) -> anyhow::Result<Arc<oidc::OidcProvider<diport::RssAccessProfile>>> {
    let (provider, _, _, _) = build_rss_access_verifier(config)?;
    Ok(provider)
}

fn build_identity(config: config::IdentityConfig) -> anyhow::Result<IdentityInputs> {
    let (issuer, audience, key_id, access_ttl, auth_grant_ttl, refresh_ttl, blocklist) =
        config.into_identity_inputs();
    let blocklist = Arc::new(
        crypto::load_password_blocklist(&blocklist)
            .context("load identityaudit password blocklist")?,
    );
    Ok(IdentityInputs {
        runtime_config: identity_composition::IdentityRuntimeConfig::new(
            diport::KeyId::new(key_id),
            issuer,
            audience,
            access_ttl,
            auth_grant_ttl,
            refresh_ttl,
        )?,
        blocklist,
    })
}

fn build_tenant_authority(
    key: primitives::MacKey,
    ttl: Duration,
    clock_skew: Duration,
) -> anyhow::Result<Arc<eventexec::TenantAuthority>> {
    Ok(Arc::new(
        eventexec::TenantAuthority::new(
            Arc::new(crypto::RustCryptoMacVerifier),
            key,
            ttl.as_secs(),
            clock_skew.as_secs(),
            Arc::new(system_epoch_seconds),
        )
        .context("build identityaudit tenant authority")?,
    ))
}

fn system_epoch_seconds() -> i64 {
    use diport::Clock as _;
    crate::SystemClock
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
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
        diport::KeyProvider::shutdown(self.0.as_ref()).await
    }
}

struct AccessTokenJwksReadyProbe {
    name: primitives::ProbeName,
    readiness: oidc::JwksReadinessHandle,
}

impl AccessTokenJwksReadyProbe {
    fn rss_access(name: primitives::ProbeName, readiness: oidc::JwksReadinessHandle) -> Self {
        Self { name, readiness }
    }
}

struct PostgresProbe {
    name: primitives::ProbeName,
    readiness: Arc<postgres::PgDbReadiness>,
    rls_ready: Arc<std::sync::atomic::AtomicBool>,
}

impl bootstrap::HealthProbe for PostgresProbe {
    fn check(&self) -> primitives::HealthCheck {
        use std::sync::atomic::Ordering;

        let ready = matches!(
            self.readiness.snapshot(),
            postgres::PoolReadiness::Ready | postgres::PoolReadiness::Saturated
        ) && self.rls_ready.load(Ordering::Acquire);
        let (status, detail) = if ready {
            (primitives::HealthStatus::Healthy, "ready")
        } else {
            (primitives::HealthStatus::Unhealthy, "degraded")
        };
        primitives::HealthCheck::new(self.name.clone(), status, detail)
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

    use super::*;
    use crate::providers_gen::ListenerPdpJwksLifecycle;
    use axum::{Json, Router, routing::post};
    use base64::Engine as _;
    use diport::KeyProvider as _;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature as P256Signature, SigningKey};

    #[test]
    fn private_ca_loading_fails_closed_without_disclosing_input() -> anyhow::Result<()> {
        let root = std::env::temp_dir().join(format!(
            "rss-identityaudit-private-ca-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root)?;
        let secret_path = root.join("operator-secret-ca-name.pem");
        for load in
            [load_amqp_private_ca as fn(&std::path::Path) -> anyhow::Result<amqp::AmqpPrivateCa>]
        {
            let error = load(&secret_path).err().expect("missing AMQP CA must fail");
            let rendered = format!("{error:#}");
            assert!(rendered.contains("read identityaudit AMQP CA certificate"));
            assert!(!rendered.contains("operator-secret-ca-name"));
        }

        let directory = root.join("ca-directory");
        std::fs::create_dir(&directory)?;
        let error = load_redis_private_ca(&directory)
            .err()
            .expect("directory must fail");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("read identityaudit Redis CA certificate"));
        assert!(!rendered.contains("ca-directory"));

        let malformed = root.join("malformed.pem");
        std::fs::write(&malformed, b"private-ca-credential-sentinel")?;
        let amqp_error = load_amqp_private_ca(&malformed)
            .err()
            .expect("malformed CA must fail");
        let redis_error = load_redis_private_ca(&malformed)
            .err()
            .expect("malformed CA must fail");
        for (error, context) in [
            (amqp_error, "parse identityaudit AMQP CA certificate"),
            (redis_error, "parse identityaudit Redis CA certificate"),
        ] {
            let rendered = format!("{error:#}");
            assert!(rendered.contains(context));
            assert!(!rendered.contains("private-ca-credential-sentinel"));
            assert!(!rendered.contains("malformed.pem"));
        }
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    async fn readiness_workers_propagate_closed_join_failure_kinds() {
        struct DropMarker(Arc<AtomicBool>);
        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let redis = RedisReadinessWorker {
            handle: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(tokio::spawn(async {
                panic!("identityaudit-readiness-plain-panic-secret");
            })))),
            token: tokio_util::sync::CancellationToken::new(),
        };
        let error = redis.shutdown().await.expect_err("panic must propagate");
        assert_eq!(error.kind(), diport::ShutdownErrorKind::TaskPanicked);
        assert!(!format!("{error:?}").contains("plain-panic-secret"));

        let vault_stopped = Arc::new(AtomicBool::new(false));
        let vault = VaultReadinessWorker {
            name: "test-vault-readiness",
            token: tokio_util::sync::CancellationToken::new(),
            handle: tokio::sync::Mutex::new(Some(tokio::spawn({
                let vault_stopped = Arc::clone(&vault_stopped);
                async move {
                    let _marker = DropMarker(vault_stopped);
                    std::future::pending::<()>().await;
                }
            }))),
        };
        tokio::task::yield_now().await;
        let mut stack =
            bootstrap::shutdown::ShutdownStack::new(tokio_util::sync::CancellationToken::new());
        stack.register_detached(diport::DynManagedResource::new_box(vault));
        let failures = stack.shutdown().await;
        assert!(matches!(
            failures.as_slice(),
            [bootstrap::shutdown::ResourceShutdownError {
                kind: bootstrap::shutdown::ShutdownFailureKind::DeadlineExceeded,
                ..
            }]
        ));
        assert!(vault_stopped.load(Ordering::Acquire));
    }

    struct TestResource {
        shutdowns: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl diport::ManagedResource for TestResource {
        fn name(&self) -> &str {
            "identityaudit-provider-test"
        }

        async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
            self.shutdowns.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    struct TestProbe(primitives::ProbeName);

    impl bootstrap::HealthProbe for TestProbe {
        fn check(&self) -> primitives::HealthCheck {
            primitives::HealthCheck::new(self.0.clone(), primitives::HealthStatus::Healthy, "ready")
        }
    }

    fn lifecycle_output(
        probes: bool,
        resources: bool,
        workers: bool,
    ) -> bootstrap::DomainModuleResult {
        let mut output = bootstrap::DomainModuleResult::default();
        if probes {
            let name = primitives::ProbeName::parse("identityaudit-provider-test")
                .expect("valid static probe name");
            output
                .probes
                .push((name.clone(), Box::new(TestProbe(name))));
        }
        if resources {
            output
                .resources
                .push(DynManagedResource::new_box(TestResource {
                    shutdowns: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                }));
        }
        if workers {
            output
                .workers
                .push(bootstrap::WorkerSpec::observational_phase_one(
                    "assemblies.identityaudit.src.providers.05",
                    |_token| {
                        DynManagedResource::new_box(TestResource {
                            shutdowns: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                        })
                    },
                ));
        }
        output
    }

    fn test_listener_pdp_jwks_lifecycle() -> (primitives::ProbeName, ListenerPdpJwksLifecycle) {
        let probe_name = primitives::ProbeName::parse("identityaudit_rss_jwks_ready")
            .expect("valid static JWKS probe name");
        let lifecycle = ListenerPdpJwksLifecycle::single(
            (probe_name.clone(), Box::new(TestProbe(probe_name.clone()))),
            DynManagedResource::new_box(TestResource {
                shutdowns: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }),
        );
        (probe_name, lifecycle)
    }

    async fn vault_sign_response(Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
        let message = body
            .get("input")
            .and_then(serde_json::Value::as_str)
            .map(|input| {
                base64::engine::general_purpose::STANDARD
                    .decode(input)
                    .expect("Vault test request input must be valid base64")
            })
            .expect("Vault test request must contain input");
        let signing =
            SigningKey::from_slice(&[0x42_u8; 32]).expect("fixed P-256 test scalar must be valid");
        let signature: P256Signature = signing.sign(&message);
        Json(serde_json::json!({
            "data": {
                "signature": format!(
                    "vault:v1:{}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
                )
            }
        }))
    }

    static TEST_JWKS_SEQUENCE: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    struct TestJwksFile(std::path::PathBuf);

    impl TestJwksFile {
        fn new(kid: &str) -> anyhow::Result<Self> {
            let signing = SigningKey::from_slice(&[0x42_u8; 32])
                .map_err(|_| anyhow::anyhow!("fixed P-256 test scalar is invalid"))?;
            let point = signing.verifying_key().to_encoded_point(false);
            let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                point
                    .x()
                    .ok_or_else(|| anyhow::anyhow!("missing test P-256 x"))?,
            );
            let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                point
                    .y()
                    .ok_or_else(|| anyhow::anyhow!("missing test P-256 y"))?,
            );
            let path = std::env::temp_dir().join(format!(
                "rss-identityaudit-jwks-{}-{}.json",
                std::process::id(),
                TEST_JWKS_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(
                &path,
                format!(
                    r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{kid}","alg":"ES256","x":"{x}","y":"{y}"}}]}}"#
                ),
            )?;
            Ok(Self(path))
        }

        fn source(&self) -> anyhow::Result<oidc::JwksKeySource> {
            oidc::JwksKeySource::load_and_watch(
                "identityaudit-vault-proof-test",
                &self.0,
                Duration::from_secs(3_600),
                tokio_util::sync::CancellationToken::new(),
            )
            .map_err(anyhow::Error::new)
        }
    }

    impl Drop for TestJwksFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    async fn vault_encrypt_response(
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let plaintext = body
            .get("plaintext")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        Json(serde_json::json!({
            "data": {
                "ciphertext": format!("vault:v1:{plaintext}"),
                "key_version": 1
            }
        }))
    }

    async fn vault_decrypt_response(
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let plaintext = body
            .get("ciphertext")
            .and_then(serde_json::Value::as_str)
            .and_then(|ciphertext| ciphertext.strip_prefix("vault:v1:"))
            .unwrap_or_default();
        Json(serde_json::json!({ "data": { "plaintext": plaintext } }))
    }

    async fn vault_rewrap_response(Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
        let ciphertext = body
            .get("ciphertext")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("vault:v1:Y292ZXJhZ2U=");
        Json(serde_json::json!({
            "data": { "ciphertext": ciphertext, "key_version": 1 }
        }))
    }

    async fn local_vault() -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let routes = Router::new()
            .route("/v1/transit/sign/{key}", post(vault_sign_response))
            .route("/v1/transit/encrypt/{key}", post(vault_encrypt_response))
            .route("/v1/transit/decrypt/{key}", post(vault_decrypt_response))
            .route("/v1/transit/rewrap/{key}", post(vault_rewrap_response));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, routes).await;
        });
        Ok((address, task))
    }

    fn system_ca() -> anyhow::Result<&'static str> {
        ["/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"]
            .into_iter()
            .find(|path| std::path::Path::new(path).is_file())
            .ok_or_else(|| anyhow::anyhow!("system CA bundle unavailable"))
    }

    #[test]
    fn generated_provider_receipts_close_the_exact_lifecycle_inventory() {
        let mut roles = crate::plan::IdentityAuditPlan::bundled()
            .expect("bundled identityaudit plan")
            .provider_build()
            .expect("generated provider exact join");
        let auth_audit_sink = roles
            .auth_audit_sink()
            .expect("auth-audit constructor")
            .finish(lifecycle_output(true, true, true))
            .expect("auth-audit output");
        let distributed_cas = roles
            .distributed_cas_store()
            .expect("CAS constructor")
            .finish(lifecycle_output(true, true, true))
            .expect("CAS output");
        let distributed_lock = roles
            .distributed_lock_store()
            .expect("lock constructor")
            .finish(lifecycle_output(true, true, true))
            .expect("lock output");
        let dlx_key = roles
            .dlx_archive_key_provider()
            .expect("DLX constructor")
            .finish(lifecycle_output(true, true, true))
            .expect("DLX output");
        let event_publisher = roles
            .event_publisher()
            .expect("publisher constructor")
            .finish(lifecycle_output(true, true, true))
            .expect("publisher output");
        let event_subscriber = roles
            .event_subscriber()
            .expect("subscriber constructor")
            .finish(lifecycle_output(true, true, true))
            .expect("subscriber output");
        let identity_signer = roles
            .identity_signer()
            .expect("signer constructor")
            .finish(lifecycle_output(true, true, true))
            .expect("signer output");
        let (listener_pdp_probe_name, listener_pdp_output) = test_listener_pdp_jwks_lifecycle();
        let listener_pdp_constructor = roles.listener_pdp().expect("PDP constructor");
        let listener_pdp =
            commit_listener_pdp_jwks_lifecycle(listener_pdp_constructor, listener_pdp_output)
                .expect("PDP output");
        let listener_rate_limiter = roles
            .listener_rate_limiter()
            .expect("limiter constructor")
            .finish_for_test(lifecycle_output(false, false, false))
            .expect("limiter output");

        let mut inventory = bootstrap::DomainModuleResult::default();
        let auth_audit_sink = auth_audit_sink.transfer(&mut inventory);
        let distributed_cas = distributed_cas.transfer(&mut inventory);
        let distributed_lock = distributed_lock.transfer(&mut inventory);
        let dlx_key = dlx_key.transfer(&mut inventory);
        let event_publisher = event_publisher.transfer(&mut inventory);
        let event_subscriber = event_subscriber.transfer(&mut inventory);
        let identity_signer = identity_signer.transfer(&mut inventory);
        let listener_pdp = listener_pdp.transfer(&mut inventory);
        let listener_rate_limiter = listener_rate_limiter.transfer(&mut inventory);

        let complete = roles
            .finish(
                &inventory,
                auth_audit_sink,
                distributed_cas,
                distributed_lock,
                dlx_key,
                event_publisher,
                event_subscriber,
                identity_signer,
                listener_pdp,
                listener_rate_limiter,
            )
            .expect("all exact provider roles transferred");
        let listener_pdp_binding = complete
            .into_probe_bindings()
            .into_iter()
            .find(|binding| binding.provider_id() == "listener-pdp")
            .expect("listener PDP probe binding");
        assert_eq!(
            listener_pdp_binding.probe_names(),
            std::slice::from_ref(&listener_pdp_probe_name)
        );
        assert_eq!(inventory.probes.len(), 8);
        assert_eq!(inventory.resources.len(), 8);
        assert_eq!(inventory.workers.len(), 7);
    }

    #[test]
    fn generated_provider_roles_fail_closed_on_reused_listener_pdp_output() {
        let mut roles = crate::plan::IdentityAuditPlan::bundled()
            .expect("bundled identityaudit plan")
            .provider_build()
            .expect("generated provider exact join");
        let constructor = roles.listener_pdp().expect("PDP constructor");
        let (_, lifecycle) = test_listener_pdp_jwks_lifecycle();
        commit_listener_pdp_jwks_lifecycle(constructor, lifecycle)
            .expect("typed PDP JWKS lifecycle output");
        assert!(roles.listener_pdp().is_err());

        // Wrong probe/resource shape for listener-pdp is rejected by the Hard
        // ListenerPdpJwksLifecycle type (no DomainModuleResult escape hatch). Missing-channel
        // negatives for loosely typed roles remain covered by event_publisher below and by
        // runtime/xtask assembly validation.
        let publisher = roles.event_publisher().expect("publisher constructor");
        assert!(
            publisher
                .finish(lifecycle_output(false, true, true))
                .is_err()
        );
    }

    #[test]
    fn provider_role_closer_commits_eventing_outputs_into_one_inventory() {
        let mut roles = crate::plan::IdentityAuditPlan::bundled()
            .expect("bundled identityaudit plan")
            .provider_build()
            .expect("generated provider exact join");
        let auth_audit_sink = roles
            .auth_audit_sink()
            .expect("auth-audit constructor")
            .finish(lifecycle_output(true, true, true))
            .expect("auth-audit output");
        let distributed_cas_constructor = roles.distributed_cas_store().expect("CAS constructor");
        let distributed_lock_store = roles
            .distributed_lock_store()
            .expect("lock constructor")
            .finish(lifecycle_output(true, true, true))
            .expect("lock output");
        let dlx_archive_key_provider = roles
            .dlx_archive_key_provider()
            .expect("DLX constructor")
            .finish(lifecycle_output(true, true, true))
            .expect("DLX output");
        let event_publisher_constructor = roles.event_publisher().expect("publisher constructor");
        let event_subscriber_constructor =
            roles.event_subscriber().expect("subscriber constructor");
        let identity_signer = roles
            .identity_signer()
            .expect("signer constructor")
            .finish(lifecycle_output(true, true, true))
            .expect("signer output");
        let (_, listener_pdp_output) = test_listener_pdp_jwks_lifecycle();
        let listener_pdp_constructor = roles.listener_pdp().expect("PDP constructor");
        let listener_pdp =
            commit_listener_pdp_jwks_lifecycle(listener_pdp_constructor, listener_pdp_output)
                .expect("PDP output");
        let listener_rate_limiter = roles
            .listener_rate_limiter()
            .expect("limiter constructor")
            .finish_for_test(lifecycle_output(false, false, false))
            .expect("limiter output");

        let mut inventory = bootstrap::DomainModuleResult::default();
        let closer = ProviderRoleCloser {
            roles,
            auth_audit_sink: auth_audit_sink.transfer(&mut inventory),
            distributed_lock_store: distributed_lock_store.transfer(&mut inventory),
            identity_signer: identity_signer.transfer(&mut inventory),
            dlx_archive_key_provider: dlx_archive_key_provider.transfer(&mut inventory),
            listener_pdp: listener_pdp.transfer(&mut inventory),
            listener_rate_limiter: listener_rate_limiter.transfer(&mut inventory),
            distributed_cas_constructor,
            event_publisher_constructor,
            event_subscriber_constructor,
            cas_resource: lifecycle_output(false, true, false)
                .resources
                .pop()
                .expect("CAS resource"),
        };
        closer
            .finish(
                EventingRoleOutputs {
                    distributed_cas: lifecycle_output(true, false, true),
                    event_publisher: lifecycle_output(true, true, true),
                    event_subscriber: lifecycle_output(true, true, true),
                },
                &mut inventory,
            )
            .expect("eventing roles close exact inventory");
        assert_eq!(inventory.probes.len(), 8);
        assert_eq!(inventory.resources.len(), 8);
        assert_eq!(inventory.workers.len(), 7);
    }

    #[tokio::test]
    async fn split_startup_resource_has_one_shutdown_owner() {
        let shutdowns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let resource = DynManagedResource::new_box(TestResource {
            shutdowns: Arc::clone(&shutdowns),
        });
        let (left, right) = split_startup_resource(resource, "identityaudit-test-alias");
        assert_eq!(left.name(), "identityaudit-test-alias");
        left.shutdown().await.expect("first alias shutdown");
        right.shutdown().await.expect("second alias is idempotent");
        assert_eq!(shutdowns.load(Ordering::Acquire), 1);
    }

    #[test]
    fn tenant_authority_accepts_captured_mac_key() {
        assert!(
            build_tenant_authority(
                primitives::MacKey::from_bytes(vec![7_u8; 32]),
                Duration::from_secs(60),
                Duration::from_secs(5),
            )
            .is_ok()
        );
        assert!(system_epoch_seconds() > 0);
    }

    #[test]
    fn vault_capability_probes_track_each_capability_independently() {
        let readiness = Arc::new(VaultReadiness::healthy());
        let signer_name = primitives::ProbeName::parse("vault-signer").expect("probe name");
        let dlx_name = primitives::ProbeName::parse("vault-dlx").expect("probe name");
        let signer = VaultCapabilityProbe::signer(signer_name, Arc::clone(&readiness));
        let dlx = VaultCapabilityProbe::dlx(dlx_name, Arc::clone(&readiness));
        assert_eq!(
            bootstrap::HealthProbe::check(&signer).status(),
            primitives::HealthStatus::Healthy
        );
        assert_eq!(
            bootstrap::HealthProbe::check(&dlx).status(),
            primitives::HealthStatus::Healthy
        );

        readiness.signer.store(false, Ordering::Release);
        assert_eq!(
            bootstrap::HealthProbe::check(&signer).status(),
            primitives::HealthStatus::Unhealthy
        );
        assert_eq!(
            bootstrap::HealthProbe::check(&dlx).status(),
            primitives::HealthStatus::Healthy
        );
        readiness.dlx.store(false, Ordering::Release);
        assert_eq!(
            bootstrap::HealthProbe::check(&dlx).status(),
            primitives::HealthStatus::Unhealthy
        );
    }

    #[test]
    fn identity_vault_key_mismatch_is_rejected_during_config_parse_before_external_io() {
        let document = include_str!("../identityaudit.example.toml")
            .replace("keyId = \"identity-access-es256\"", "keyId = \"wrong-key\"");
        let Err(error) = crate::config::parse_for_test(&document) else {
            panic!("mismatched identity and Vault key IDs must be rejected");
        };
        assert_eq!(
            error,
            crate::config::ConfigError::InvalidValue("identity.keyId")
        );
    }

    #[tokio::test]
    async fn vault_builder_preflights_both_capabilities_and_worker_drains() -> anyhow::Result<()> {
        let (address, server) = local_vault().await?;
        let document = include_str!("../identityaudit.example.toml")
            .replace(
                "https://vault.example.com:8200",
                &format!("http://{address}"),
            )
            .replace("/run/rss/vault-ca.pem", system_ca()?);
        let config = crate::config::parse_for_test(&document)?;
        let (_, _, _, _, vault_config, _, _) = config.into_sections();
        let jwks_file = TestJwksFile::new("identity-access-es256")?;
        let jwks_source = jwks_file.source()?;
        let products = build_vault(
            vault_config,
            zeroize::Zeroizing::new("signer-token".to_owned()),
            zeroize::Zeroizing::new("dlx-token".to_owned()),
            diport::JwtSigningBinding::rss_access(diport::KeyId::new("identity-access-es256")),
            jwks_source.readiness_handle(),
        )
        .await?;
        assert_eq!(products.dlx_key_name, "identityaudit-dlx-payload");
        assert_eq!(
            products.signer_readiness_probe.1.check().status(),
            primitives::HealthStatus::Healthy
        );
        assert_eq!(
            products.dlx_readiness_probe.1.check().status(),
            primitives::HealthStatus::Healthy
        );

        let tenant = rss_request_context::TenantId::parse(VAULT_READINESS_CANARY_TENANT)?;
        let aad = secure::ProtectionContext::authorized_maintenance(
            tenant,
            "identityaudit/dlx",
            "coverage-test",
            1,
        )?
        .derive();
        let shared = SharedKeyProvider(Arc::clone(&products.dlx_key_provider));
        let encrypted = shared
            .encrypt(
                diport::KeyName::try_new(products.dlx_key_name.clone())?,
                secure::Plaintext::new(b"coverage-payload".to_vec()),
                aad.clone(),
            )
            .await
            .context("test Vault encrypt")?;
        let opened = shared
            .decrypt(
                diport::RedactedBytes::new(encrypted.ciphertext().to_vec()),
                encrypted.key().clone(),
                aad.clone(),
            )
            .await
            .context("test Vault decrypt")?;
        assert_eq!(opened.expose(), b"coverage-payload");
        let rewrapped = shared
            .rewrap(
                diport::RedactedBytes::new(encrypted.ciphertext().to_vec()),
                encrypted.key().clone(),
                aad,
            )
            .await
            .context("test Vault rewrap")?;
        assert!(rewrapped.ciphertext().starts_with(b"vault:v1:"));

        let token = tokio_util::sync::CancellationToken::new();
        let spawn = |worker: bootstrap::WorkerSpec| match worker {
            bootstrap::WorkerSpec::PhaseOne(make) | bootstrap::WorkerSpec::Deferred(make) => {
                make.into_factory()(token.clone())
            }
        };
        let signer_worker = spawn(products.signer_readiness_worker);
        let dlx_worker = spawn(products.dlx_readiness_worker);
        testkit::await_delay(Duration::from_millis(20)).await;
        signer_worker.shutdown().await?;
        dlx_worker.shutdown().await?;
        assert_eq!(
            products.signer_readiness_probe.1.check().status(),
            primitives::HealthStatus::Unhealthy
        );
        assert_eq!(
            products.dlx_readiness_probe.1.check().status(),
            primitives::HealthStatus::Unhealthy
        );
        shared.shutdown().await?;
        server.abort();
        Ok(())
    }

    #[test]
    fn identity_builder_loads_the_declared_blocklist_and_ttls() -> anyhow::Result<()> {
        let blocklist = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/password-blocklist.demo.sha256");
        let document = include_str!("../identityaudit.example.toml").replace(
            "/run/rss/password-blocklist.sha256",
            blocklist
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("blocklist path is not UTF-8"))?,
        );
        let config = crate::config::parse_for_test(&document)?;
        let (_, identity, _, _, _, _, _) = config.into_sections();
        let built = build_identity(identity)?;
        assert_eq!(built.runtime_config.jwt_key_id(), "identity-access-es256");
        assert_eq!(
            built
                .runtime_config
                .jwt_signing_binding()
                .purpose()
                .as_str(),
            "auth.rss-access"
        );
        assert_eq!(
            built.runtime_config.auth_grant_ttl(),
            Duration::from_secs(2_592_000)
        );
        assert_eq!(
            built.runtime_config.refresh_ttl(),
            Duration::from_secs(2_592_000)
        );
        assert_eq!(Arc::strong_count(&built.blocklist), 1);
        Ok(())
    }

    #[tokio::test]
    async fn provider_connection_builders_fail_closed_without_live_backends() -> anyhow::Result<()>
    {
        let document = include_str!("../identityaudit.example.toml")
            .replace("postgres.example.com", "127.0.0.1")
            .replace("sslMode = \"verifyFull\"", "sslMode = \"disable\"")
            .replace("sslRootCertPath = \"/run/rss/postgres-ca.pem\"\n", "");
        let config = crate::config::parse_for_test(&document)?;
        let (_, _, _, postgres, _, _, _) = config.into_sections();
        let secret = || zeroize::Zeroizing::new("coverage-secret".to_owned());
        let configs = postgres_setup_configs(postgres, secret(), secret(), secret());
        let rendered = format!("{:?} {:?} {:?}", configs.0, configs.1, configs.2);
        assert!(rendered.contains("127.0.0.1"));
        assert!(rendered.contains("rss_identity_writer"));
        assert!(rendered.contains("rss_audit_admin"));
        assert!(!rendered.contains("coverage-secret"));
        let ca = redis::RedisPrivateCa::from_pem(
            b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n".to_vec(),
        )?;
        assert!(
            build_redis(
                zeroize::Zeroizing::new("redis://redis.example.test:6379/0".to_owned()),
                ca,
            )
            .await
            .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn oidc_verifier_loads_jwks_and_exports_live_readiness() -> anyhow::Result<()> {
        let root = std::env::temp_dir().join(format!(
            "rss-identityaudit-oidc-coverage-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root)?;
        let jwks = root.join("rss-access.jwks.json");
        std::fs::write(
            &jwks,
            r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"identity-access-es256","alg":"ES256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}]}"#,
        )?;
        let document = include_str!("../identityaudit.example.toml").replace(
            "/run/rss/oidc.jwks.json",
            jwks.to_str()
                .ok_or_else(|| anyhow::anyhow!("JWKS path is not UTF-8"))?,
        );
        let config = crate::config::parse_for_test(&document)?;
        let (_, _, oidc, _, _, _, _) = config.into_sections();
        let (provider, name, probe, _) = build_rss_access_verifier(oidc)?;
        assert_eq!(name.as_str(), "identityaudit_rss_jwks_ready");
        assert_eq!(
            bootstrap::HealthProbe::check(&probe).status(),
            primitives::HealthStatus::Healthy
        );
        let resource = SharedManagedResource::new(provider, "identityaudit-oidc-test");
        resource.shutdown().await?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn production_listener_pdp_jwks_lifecycle_is_exact_probe_and_resource()
    -> anyhow::Result<()> {
        struct AlwaysCurrentGrant;
        impl identity::ports::AuthGrantValidator for AlwaysCurrentGrant {
            async fn is_current(
                &self,
                _: identity::ports::TenantRepoScope,
                _: &authn::AccessGrantValidationInput,
                _: std::time::SystemTime,
            ) -> Result<bool, identity::ports::IdentityError> {
                Ok(true)
            }
        }

        let root = std::env::temp_dir().join(format!(
            "rss-identityaudit-pdp-lifecycle-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root)?;
        let jwks = root.join("rss-access.jwks.json");
        std::fs::write(
            &jwks,
            r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"identity-access-es256","alg":"ES256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}]}"#,
        )?;
        let document = include_str!("../identityaudit.example.toml").replace(
            "/run/rss/oidc.jwks.json",
            jwks.to_str()
                .ok_or_else(|| anyhow::anyhow!("JWKS path is not UTF-8"))?,
        );
        let config = crate::config::parse_for_test(&document)?;
        let (_, _, oidc, _, _, _, _) = config.into_sections();
        let (provider, probe_name, probe, jwks) = build_rss_access_verifier(oidc)?;
        let products = OidcProducts {
            provider,
            grants: Arc::new(identity::AuthGrantValidationService::new(
                identity::ports::DynAuthGrantValidator::new_arc(AlwaysCurrentGrant),
                Box::new(crate::SystemClock),
            )),
            probe_name: probe_name.clone(),
            probe,
            jwks,
        };
        let (provider, _grants, lifecycle) = build_rss_listener_pdp_jwks_lifecycle(products);
        let output = lifecycle.into_output();
        assert_eq!(probe_name.as_str(), "identityaudit_rss_jwks_ready");
        assert_eq!(output.probes.len(), 1);
        assert_eq!(output.probes[0].0, probe_name);
        assert_eq!(output.resources.len(), 1);
        assert_eq!(
            output.resources[0].name(),
            "identityaudit-rss-access-verifier"
        );
        assert!(output.workers.is_empty());
        output.resources[0].shutdown().await?;
        SharedManagedResource::new(provider, "identityaudit-oidc-test")
            .shutdown()
            .await?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn access_token_jwks_ready_probe_maps_runtime_false_to_degraded() -> anyhow::Result<()> {
        let root = std::env::temp_dir().join(format!(
            "rss-identityaudit-jwks-degraded-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root)?;
        let jwks = root.join("rss-access.jwks.json");
        std::fs::write(
            &jwks,
            r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"identity-access-es256","alg":"ES256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}]}"#,
        )?;
        let cancel = tokio_util::sync::CancellationToken::new();
        let source = oidc::JwksKeySource::load_and_watch(
            "identityaudit-rss-access-degraded-test",
            jwks.clone(),
            Duration::from_secs(3600),
            cancel.clone(),
        )?;
        let probe_name = primitives::ProbeName::parse("identityaudit_rss_jwks_ready")
            .expect("valid static JWKS probe name");
        let probe = AccessTokenJwksReadyProbe::rss_access(probe_name, source.readiness_handle());
        let healthy = bootstrap::HealthProbe::check(&probe);
        assert_eq!(healthy.status(), primitives::HealthStatus::Healthy);
        assert_eq!(healthy.detail(), "ready");

        std::fs::remove_file(&jwks)?;
        assert!(!source.reload(), "refresh failure marks readiness false");
        let degraded = bootstrap::HealthProbe::check(&probe);
        assert_eq!(degraded.status(), primitives::HealthStatus::Degraded);
        assert_eq!(degraded.detail(), "degraded");

        cancel.cancel();
        drop(source);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
