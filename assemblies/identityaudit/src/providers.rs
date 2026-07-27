//! Production provider construction for the sealed identityaudit runtime plan.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context as _;
use diport::{DynKeyProvider, DynManagedResource};

use crate::config;
use crate::runtime::SharedManagedResource;

const PG_READINESS_PERIOD: Duration = Duration::from_secs(2);
const AUDIT_CHAIN_KEY_SENTINEL: &[u8] = b"rss.audit-chain-key.identityaudit.v1";
const VAULT_READINESS_CANARY_TENANT: &str = "00000000-0000-4000-8000-000000001797";

pub(crate) struct ProviderBundle {
    pub(crate) pg: postgres::PgRuntimeHandle,
    pub(crate) redis: redis::RedisRuntimeDeps,
    pub(crate) signer: Arc<vault::VaultSigner>,
    pub(crate) verifier: crate::auth_bridge::RssAccessVerifier,
    pub(crate) audit_sink: httpserve::AuditSinkHandle,
    pub(crate) metrics: Arc<dyn diport::MetricsExporter>,
    pub(crate) limiter: Arc<ratelimit::GovernorLimiter>,
    pub(crate) audit_chain_key: primitives::MacKey,
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
    pub(crate) amqp_url: secure::AmqpEndpoint,
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
    config: config::IdentityAuditConfig,
    secrets: config::ResolvedSecrets,
    transaction: &mut runtimeexec::StartupTransaction<'_>,
) -> anyhow::Result<BuildResult> {
    let (listeners, identity, oidc, postgres, vault, eventing) = config.into_sections();
    let eventing = eventing.into_eventing_inputs();
    let _captured_eventing_environment = eventing.environment_names;
    let (
        writer_password,
        reader_password,
        migrator_password,
        audit_admin_password,
        vault_signer_token,
        vault_dlx_token,
        amqp_url,
        redis_url,
        audit_chain_key,
        tenant_authority_key,
    ) = secrets.into_secret_material();

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
        migrator_password,
        audit_admin_password,
    )
    .await?;
    let pg = pg_owner.handle();
    let pg_probe_name = primitives::ProbeName::parse("identityaudit_postgres_ready")
        .context("build identityaudit Postgres probe name")?;
    transaction.provider_output_mut().probes.push((
        pg_probe_name.clone(),
        Box::new(PostgresProbe {
            name: pg_probe_name,
            readiness: pg.readiness_handle(),
            rls_ready: pg.rls_ready_handle(),
        }),
    ));
    let (mut pg_resources, pg_sampler) = pg_owner.into_runtime_parts(PG_READINESS_PERIOD);
    let cas_resource = pg_resources
        .pop()
        .context("identityaudit Postgres omitted distributed CAS lifecycle resource")?;
    anyhow::ensure!(
        !pg_resources.is_empty(),
        "identityaudit Postgres omitted auth-audit lifecycle resources"
    );
    let mut auth_audit_output = bootstrap::DomainModuleResult {
        resources: pg_resources,
        ..Default::default()
    };
    auth_audit_output.workers.push(Box::new(move |token| {
        DynManagedResource::new_box(pg_sampler.spawn(token))
    }));
    let auth_audit_sink = auth_audit_sink_constructor
        .finish(auth_audit_output)?
        .transfer(transaction.provider_output_mut());
    let (staged_cas_resource, cas_resource) =
        split_startup_resource(cas_resource, "identityaudit-postgres-cas-startup-stage");
    transaction
        .provider_output_mut()
        .resources
        .push(staged_cas_resource);

    verify_audit_chain_key(&pg, eventing.audit_chain_key_id, &audit_chain_key).await?;

    let redis = build_redis(redis_url).await?;
    let lock_output = bootstrap::DomainModuleResult {
        resources: redis.runtime_resources(),
        ..Default::default()
    };
    let distributed_lock_store = distributed_lock_constructor
        .finish(lock_output)?
        .transfer(transaction.provider_output_mut());

    let vault = build_vault(vault, vault_signer_token, vault_dlx_token).await?;
    let signer = Arc::clone(&vault.signer);
    let signer_output = bootstrap::DomainModuleResult {
        resources: vec![SharedManagedResource::boxed(
            Arc::clone(&signer),
            "identityaudit-vault-signer",
        )],
        ..Default::default()
    };
    let identity_signer = identity_signer_constructor
        .finish(signer_output)?
        .transfer(transaction.provider_output_mut());
    transaction
        .provider_output_mut()
        .resources
        .push(SharedManagedResource::boxed(
            Arc::clone(&vault.dlx_key_provider),
            "identityaudit-vault-dlx-key-provider",
        ));
    let dlx_archive_key_provider = dlx_archive_key_provider_constructor
        .finish(bootstrap::DomainModuleResult {
            workers: vec![vault.readiness_worker],
            ..Default::default()
        })?
        .transfer(transaction.provider_output_mut());
    for probe in vault.readiness_probes {
        transaction.provider_output_mut().probes.push(probe);
    }
    let dlx_payload_protector = postgres::DlxPayloadProtector::new(
        DynKeyProvider::new_box(SharedKeyProvider(Arc::clone(&vault.dlx_key_provider))),
        eventexec::DlxHotKeyName::try_new(vault.dlx_key_name)
            .context("build identityaudit DLX key name")?,
    );

    let oidc = build_rss_access_provider(oidc, &pg)?;
    let oidc_managed_resource = oidc.managed_resource();
    let pdp_output = bootstrap::DomainModuleResult {
        resources: vec![oidc_managed_resource],
        ..Default::default()
    };
    let listener_pdp = listener_pdp_constructor
        .finish(pdp_output)?
        .transfer(transaction.provider_output_mut());
    transaction.provider_output_mut().probes.push(oidc.probe());

    let limiter = crate::listeners::rate_limiter();
    let listener_rate_limiter = listener_rate_limiter_constructor
        .finish(bootstrap::DomainModuleResult::default())?
        .transfer(transaction.provider_output_mut());
    let metrics = Arc::new(
        prometheus_adapter::PromExporter::install()
            .context("install identityaudit metrics exporter")?,
    );
    transaction
        .provider_output_mut()
        .resources
        .push(SharedManagedResource::boxed(
            Arc::clone(&metrics),
            "identityaudit-prometheus",
        ));
    let metrics_port: Arc<dyn diport::MetricsExporter> = metrics;

    let identity = build_identity(identity)?;
    anyhow::ensure!(
        identity.runtime_config.jwt_key_id() == vault.signing_key_name,
        "identityaudit identity.keyId must equal vault.signingKeyName"
    );
    let tenant_authority = build_tenant_authority(
        tenant_authority_key,
        eventing.tenant_authority_ttl,
        eventing.tenant_authority_clock_skew,
    )?;
    let amqp_url = secure::AmqpEndpoint::parse(
        amqp_url.to_string(),
        secure::PlaintextEndpointPolicy::AllowLoopback,
    )
    .context("parse captured identity AMQP endpoint")?;
    let audit_sink =
        httpserve::AuditSinkHandle::new(pg.for_domain::<postgres::caps::Audit>().auth_audit_sink());

    Ok(BuildResult {
        providers: ProviderBundle {
            verifier: crate::auth_bridge::RssAccessVerifier::new(
                oidc.provider(),
                Arc::clone(&oidc.grants),
            ),
            pg,
            redis,
            signer,
            audit_sink,
            metrics: metrics_port,
            limiter,
            audit_chain_key,
            tenant_authority,
            dlx_payload_protector,
            identity,
        },
        listeners,
        amqp_url,
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

async fn build_postgres(
    config: config::PostgresConfig,
    writer_password: zeroize::Zeroizing<String>,
    reader_password: zeroize::Zeroizing<String>,
    migrator_password: zeroize::Zeroizing<String>,
    audit_admin_password: zeroize::Zeroizing<String>,
) -> anyhow::Result<postgres::PgRuntimeDeps> {
    let (serving, reader, migrator, audit_admin) = postgres_setup_configs(
        config,
        writer_password,
        reader_password,
        migrator_password,
        audit_admin_password,
    );
    let owner = postgres::PgRuntimeDeps::setup_with_audit_admin_config(
        &migrator,
        &serving,
        &reader,
        Some(&audit_admin),
        postgres::LegacyConfigPlaintextPolicy::Deny,
        generated::event::PROJECTION_INPUT_GENERATION,
        generated::event::PROJECTION_INPUTS,
    )
    .await
    .context("setup identityaudit Postgres")?;
    Ok(owner)
}

fn postgres_setup_configs(
    config: config::PostgresConfig,
    writer_password: zeroize::Zeroizing<String>,
    reader_password: zeroize::Zeroizing<String>,
    migrator_password: zeroize::Zeroizing<String>,
    audit_admin_password: zeroize::Zeroizing<String>,
) -> (
    postgres::PgConfig,
    postgres::PgTenantReadConfig,
    postgres::PgConfig,
    postgres::PgConfig,
) {
    let (connection, writer, reader, migrator, audit_admin) = config.into_postgres_inputs();
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
    let migrator = make(migrator.into_username(), migrator_password.to_string(), 1);
    let audit_admin = make(
        audit_admin_name,
        audit_admin_password.to_string(),
        audit_admin_max,
    );
    (serving, reader, migrator, audit_admin)
}

async fn build_redis(url: zeroize::Zeroizing<String>) -> anyhow::Result<redis::RedisRuntimeDeps> {
    let endpoint = secure::RedisEndpoint::parse(
        url.to_string(),
        secure::PlaintextEndpointPolicy::AllowLoopback,
    )
    .context("parse captured identityaudit Redis endpoint")?;
    // reason: the only raw Redis credential exit feeds the pool constructor immediately after
    // typed endpoint validation; it is never formatted or retained separately.
    #[allow(clippy::disallowed_methods)]
    let pool = deadpool_redis::Config::from_url(endpoint.expose())
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .context("build identityaudit Redis pool")?;
    let deps = redis::RedisRuntimeDeps::setup(pool);
    deps.ping().await.context("verify identityaudit Redis")?;
    Ok(deps)
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
    signing_key_name: String,
    dlx_key_name: String,
    readiness_worker: bootstrap::WorkerSpec,
    readiness_probes: Vec<(primitives::ProbeName, Box<dyn bootstrap::HealthProbe>)>,
}

async fn build_vault(
    config: config::VaultConfig,
    signer_token: zeroize::Zeroizing<String>,
    dlx_token: zeroize::Zeroizing<String>,
) -> anyhow::Result<VaultProducts> {
    let (addr, ca_path, mount, signing_key_name, dlx_key_name, timeout) =
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
        vault::VaultSigner::new_allow_http(
            client.clone(),
            addr.clone(),
            signer_token.to_string(),
            mount.clone(),
            timeout,
            vault::SignatureMarshaling::Jws,
        )
    } else {
        vault::VaultSigner::new(
            client.clone(),
            addr.clone(),
            signer_token.to_string(),
            mount.clone(),
            timeout,
            vault::SignatureMarshaling::Jws,
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
    verify_vault_signer(&signer, &signing_key_name).await?;
    verify_vault_key_provider(&dlx_key_provider, &dlx_key_name).await?;

    let readiness = Arc::new(VaultReadiness::healthy());
    let signer_probe_name = primitives::ProbeName::parse("identityaudit_vault_signer_ready")
        .context("build identityaudit Vault signer readiness probe")?;
    let dlx_probe_name = primitives::ProbeName::parse("identityaudit_vault_dlx_key_ready")
        .context("build identityaudit Vault DLX readiness probe")?;
    let readiness_probes: Vec<(primitives::ProbeName, Box<dyn bootstrap::HealthProbe>)> = vec![
        (
            signer_probe_name.clone(),
            Box::new(VaultCapabilityProbe::signer(
                signer_probe_name,
                Arc::clone(&readiness),
            )),
        ),
        (
            dlx_probe_name.clone(),
            Box::new(VaultCapabilityProbe::dlx(
                dlx_probe_name,
                Arc::clone(&readiness),
            )),
        ),
    ];
    let worker_signer = Arc::clone(&signer);
    let worker_key_provider = Arc::clone(&dlx_key_provider);
    let worker_signing_key = signing_key_name.clone();
    let worker_dlx_key = dlx_key_name.clone();
    let readiness_worker: bootstrap::WorkerSpec = Box::new(move |token| {
        DynManagedResource::new_box(VaultReadinessWorker::spawn(
            token,
            timeout,
            worker_signer,
            worker_signing_key,
            worker_key_provider,
            worker_dlx_key,
            readiness,
        ))
    });
    Ok(VaultProducts {
        signer,
        dlx_key_provider,
        signing_key_name,
        dlx_key_name,
        readiness_worker,
        readiness_probes,
    })
}

async fn verify_vault_signer(signer: &vault::VaultSigner, key_name: &str) -> anyhow::Result<()> {
    use diport::Signer as _;
    signer
        .sign(diport::SignRequest {
            key: diport::KeyId::new(key_name),
            purpose: diport::SigningPurpose::new("auth.jwt.access"),
            message: diport::RedactedBytes::new(b"identityaudit-readiness".to_vec()),
        })
        .await
        .context("verify identityaudit Vault signer readiness")?;
    Ok(())
}

async fn verify_vault_key_provider(
    provider: &vault::VaultKeyProvider,
    key_name: &str,
) -> anyhow::Result<()> {
    use diport::KeyProvider as _;
    let tenant = vocab::TenantId::parse(VAULT_READINESS_CANARY_TENANT)
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
    token: tokio_util::sync::CancellationToken,
    handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    shutdown_bound: Duration,
}

impl VaultReadinessWorker {
    #[allow(clippy::too_many_arguments)]
    fn spawn(
        token: tokio_util::sync::CancellationToken,
        period: Duration,
        signer: Arc<vault::VaultSigner>,
        signing_key: String,
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
                        let signer_ready = tokio::select! {
                            () = run_token.cancelled() => break,
                            result = verify_vault_signer(&signer, &signing_key) => result.is_ok(),
                        };
                        readiness.signer.store(
                            signer_ready,
                            Ordering::Release,
                        );
                        let dlx_ready = tokio::select! {
                            () = run_token.cancelled() => break,
                            result = verify_vault_key_provider(&key_provider, &dlx_key) => result.is_ok(),
                        };
                        readiness.dlx.store(
                            dlx_ready,
                            Ordering::Release,
                        );
                    }
                }
            }
            readiness.signer.store(false, Ordering::Release);
            readiness.dlx.store(false, Ordering::Release);
        });
        Self {
            token,
            handle: tokio::sync::Mutex::new(Some(handle)),
            shutdown_bound: Duration::from_secs(1),
        }
    }
}

impl diport::ManagedResource for VaultReadinessWorker {
    fn name(&self) -> &str {
        "identityaudit-vault-readiness"
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        self.token.cancel();
        let Some(mut handle) = self.handle.lock().await.take() else {
            return Ok(());
        };
        if tokio::time::timeout(self.shutdown_bound, &mut handle)
            .await
            .is_err()
        {
            handle.abort();
            let _ = handle.await;
        }
        Ok(())
    }
}

struct OidcProducts {
    provider: Arc<oidc::OidcProvider<diport::RssAccessProfile>>,
    grants: Arc<identity::AuthGrantValidationService>,
    probe_name: primitives::ProbeName,
    probe: AccessTokenJwksReadyProbe,
}

impl OidcProducts {
    fn provider(&self) -> Arc<oidc::OidcProvider<diport::RssAccessProfile>> {
        Arc::clone(&self.provider)
    }

    fn managed_resource(&self) -> Box<DynManagedResource<'static>> {
        SharedManagedResource::boxed(
            Arc::clone(&self.provider),
            "identityaudit-rss-access-verifier",
        )
    }

    fn probe(&self) -> (primitives::ProbeName, Box<dyn bootstrap::HealthProbe>) {
        (self.probe_name.clone(), Box::new(self.probe.clone()))
    }
}

fn build_rss_access_provider(
    config: config::OidcConfig,
    pg: &postgres::PgRuntimeHandle,
) -> anyhow::Result<OidcProducts> {
    let (provider, probe_name, probe) = build_rss_access_verifier(config)?;
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
    })
}

fn build_rss_access_verifier(
    config: config::OidcConfig,
) -> anyhow::Result<(
    Arc<oidc::OidcProvider<diport::RssAccessProfile>>,
    primitives::ProbeName,
    AccessTokenJwksReadyProbe,
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
    let probe = AccessTokenJwksReadyProbe::rss_access(probe_name.clone(), readiness);
    Ok((provider, probe_name, probe))
}

#[cfg(test)]
pub(crate) fn rss_access_provider_for_test(
    config: config::OidcConfig,
) -> anyhow::Result<Arc<oidc::OidcProvider<diport::RssAccessProfile>>> {
    let (provider, _, _) = build_rss_access_verifier(config)?;
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
        ),
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

#[derive(Clone)]
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
            (primitives::HealthStatus::Unhealthy, "degraded")
        };
        primitives::HealthCheck::new(self.name.clone(), status, detail)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use axum::{Json, Router, routing::post};
    use base64::Engine as _;
    use diport::{KeyProvider as _, ManagedResource as _};

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
            output.workers.push(Box::new(|_token| {
                DynManagedResource::new_box(TestResource {
                    shutdowns: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                })
            }));
        }
        output
    }

    async fn vault_sign_response() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "data": {
                "signature": format!(
                    "vault:v1:{}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 64])
                )
            }
        }))
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
            .finish(lifecycle_output(false, true, true))
            .expect("auth-audit output");
        let distributed_cas = roles
            .distributed_cas_store()
            .expect("CAS constructor")
            .finish(lifecycle_output(false, true, true))
            .expect("CAS output");
        let distributed_lock = roles
            .distributed_lock_store()
            .expect("lock constructor")
            .finish(lifecycle_output(false, true, false))
            .expect("lock output");
        let dlx_key = roles
            .dlx_archive_key_provider()
            .expect("DLX constructor")
            .finish(lifecycle_output(false, false, true))
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
            .finish(lifecycle_output(false, true, false))
            .expect("signer output");
        let listener_pdp = roles
            .listener_pdp()
            .expect("PDP constructor")
            .finish(lifecycle_output(false, true, false))
            .expect("PDP output");
        let listener_rate_limiter = roles
            .listener_rate_limiter()
            .expect("limiter constructor")
            .finish(lifecycle_output(false, false, false))
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

        let _complete = roles
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
        assert_eq!(inventory.probes.len(), 2);
        assert_eq!(inventory.resources.len(), 7);
        assert_eq!(inventory.workers.len(), 5);
    }

    #[test]
    fn generated_provider_roles_fail_closed_on_wrong_or_reused_outputs() {
        let mut roles = crate::plan::IdentityAuditPlan::bundled()
            .expect("bundled identityaudit plan")
            .provider_build()
            .expect("generated provider exact join");
        let constructor = roles.listener_pdp().expect("PDP constructor");
        assert!(
            constructor
                .finish(lifecycle_output(true, true, false))
                .is_err()
        );
        assert!(roles.listener_pdp().is_err());

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
            .finish(lifecycle_output(false, true, true))
            .expect("auth-audit output");
        let distributed_cas_constructor = roles.distributed_cas_store().expect("CAS constructor");
        let distributed_lock_store = roles
            .distributed_lock_store()
            .expect("lock constructor")
            .finish(lifecycle_output(false, true, false))
            .expect("lock output");
        let dlx_archive_key_provider = roles
            .dlx_archive_key_provider()
            .expect("DLX constructor")
            .finish(lifecycle_output(false, false, true))
            .expect("DLX output");
        let event_publisher_constructor = roles.event_publisher().expect("publisher constructor");
        let event_subscriber_constructor =
            roles.event_subscriber().expect("subscriber constructor");
        let identity_signer = roles
            .identity_signer()
            .expect("signer constructor")
            .finish(lifecycle_output(false, true, false))
            .expect("signer output");
        let listener_pdp = roles
            .listener_pdp()
            .expect("PDP constructor")
            .finish(lifecycle_output(false, true, false))
            .expect("PDP output");
        let listener_rate_limiter = roles
            .listener_rate_limiter()
            .expect("limiter constructor")
            .finish(lifecycle_output(false, false, false))
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
                    distributed_cas: lifecycle_output(false, false, true),
                    event_publisher: lifecycle_output(true, true, true),
                    event_subscriber: lifecycle_output(true, true, true),
                },
                &mut inventory,
            )
            .expect("eventing roles close exact inventory");
        assert_eq!(inventory.probes.len(), 2);
        assert_eq!(inventory.resources.len(), 7);
        assert_eq!(inventory.workers.len(), 5);
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
        let (_, _, _, _, vault_config, _) = config.into_sections();
        let products = build_vault(
            vault_config,
            zeroize::Zeroizing::new("signer-token".to_owned()),
            zeroize::Zeroizing::new("dlx-token".to_owned()),
        )
        .await?;
        assert_eq!(products.signing_key_name, "identity-access");
        assert_eq!(products.dlx_key_name, "identityaudit-dlx-payload");
        assert!(
            products
                .readiness_probes
                .iter()
                .all(|(_, probe)| probe.check().status() == primitives::HealthStatus::Healthy)
        );

        let tenant = vocab::TenantId::parse(VAULT_READINESS_CANARY_TENANT)?;
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

        let worker = (products.readiness_worker)(tokio_util::sync::CancellationToken::new());
        tokio::time::sleep(Duration::from_millis(20)).await;
        worker.shutdown().await?;
        assert!(
            products
                .readiness_probes
                .iter()
                .all(|(_, probe)| probe.check().status() == primitives::HealthStatus::Unhealthy)
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
        let (_, identity, _, _, _, _) = config.into_sections();
        let built = build_identity(identity)?;
        assert_eq!(built.runtime_config.jwt_key_id(), "identity-access-es256");
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
        let (_, _, _, postgres, _, _) = config.into_sections();
        let secret = || zeroize::Zeroizing::new("coverage-secret".to_owned());
        let configs = postgres_setup_configs(postgres, secret(), secret(), secret(), secret());
        let rendered = format!("{:?} {:?} {:?}", configs.0, configs.2, configs.3);
        assert!(rendered.contains("127.0.0.1"));
        assert!(rendered.contains("rss_identity_writer"));
        assert!(rendered.contains("rss_identity_migrator"));
        assert!(rendered.contains("rss_audit_admin"));
        assert!(!rendered.contains("coverage-secret"));
        assert!(
            build_redis(zeroize::Zeroizing::new(
                "redis://redis.example.test:6379/0".to_owned(),
            ))
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
        let (_, _, oidc, _, _, _) = config.into_sections();
        let (provider, name, probe) = build_rss_access_verifier(oidc)?;
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
}
