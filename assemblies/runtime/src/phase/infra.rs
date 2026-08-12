use super::{
    InfraBuilt, PG_MODULE_COMMITTED_ONCE, ProvidersBuilt, RuntimePhaseState, UncommittedModule,
    phase_result,
};
pub(super) mod dlx;
pub(super) mod domain_transport;
pub(super) mod keyring;

use self::dlx::{DlxLifecycleBootstrapConfig, build_dlx_lifecycle_bootstrap_config_from};
use self::domain_transport::{
    DomainTransportConfig, DomainTransportRuntime, topology_label, wire_domain_transport,
};
use self::keyring::build_command_idempotency_keyring_from;
use super::maintenance::wire_service_token_replay_sweeper;
use crate::SharedRuntimeDeps;
use crate::config::RuntimeServingConfigParts;
use crate::infra::pg::{PgRuntimeConfig, PgRuntimeConfigParts};
use crate::infra::redis::{REDIS_READY_PROBE_NAME, RedisReadyProbe, spawn_redis_readiness_sampler};
use crate::infra::redis::{RedisRuntimeConfig, build_redis_runtime_deps};
use crate::infra::s3::{S3RuntimeConfig, S3RuntimeConfigParts, build_s3_runtime_deps};
use crate::infra::vault::{IdentityVaultRuntimeConfig, SettingsVaultRuntimeConfig};
use crate::support::SystemClock;
use anyhow::Context as _;
use bootstrap::DomainModuleResult;
use postgres::{PgDlxLifecycleRuntime, PgRuntimeDeps};
use std::sync::Arc;
use std::time::Duration;

const SERVICE_TOKEN_REPLAY_STORE_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct RuntimeWiringInputs {
    pub(super) event_transport: crate::event_transport::EventTransportConfig,
    pub(super) event_worker: Option<crate::event_transport::EventWorkerConfig>,
    pub(super) distributed_worker: crate::distributed_runtime::DistributedWorkerConfig,
    pub(super) domain_modules: crate::modules_gen::PreparedLocalDomainInputs,
    pub(super) local_domain_providers: crate::LocalDomainProviderCatalog,
    pub(super) audit_consumer_key: Option<primitives::MacKey>,
    pub(super) auth_grant_sweep_interval: Duration,
}

struct BuiltInfra {
    rate_limiter: Arc<redis::RedisRateLimiter>,
    trusted_proxy_config: httpserve::TrustedProxyConfig,
    deps: SharedRuntimeDeps,
    s3_canary_config: crate::infra::s3::S3CanaryConfig,
    wiring_inputs: RuntimeWiringInputs,
    domain_transport: DomainTransportRuntime,
    metrics_exporter: Arc<dyn diport::MetricsExporter>,
    command_idempotency_keyring: Arc<eventexec::command::CommandIdempotencyKeyring>,
    signing_rotation_probe: Option<crate::infra::signing_rotation::SigningKeyRotationProbe>,
    runtime_service_token: Option<crate::infra::oidc::RuntimeServiceTokenProvider>,
}

pub(crate) async fn after_required_preflight<Capability, Output, Preflight, Migrate>(
    preflight: Preflight,
    migrate: impl FnOnce(Capability) -> Migrate,
) -> anyhow::Result<Output>
where
    Preflight: std::future::Future<Output = anyhow::Result<Capability>>,
    Migrate: std::future::Future<Output = anyhow::Result<Output>>,
{
    let capability = preflight.await?;
    migrate(capability).await
}

struct PhaseBSetupInputs {
    app_pg_config: postgres::PgConfig,
    tenant_read_pg_config: postgres::PgTenantReadConfig,
    audit_admin_config: Option<postgres::PgConfig>,
}

struct PhaseADlxPreflightInputs {
    dlx_archiver_pg_config: postgres::PgConfig,
    dlx_verifier_pg_config: postgres::PgConfig,
    dlx_purger_pg_config: postgres::PgConfig,
    archive_store: s3::S3DlxArchiveStore,
    hot_vault_provider: vault::VaultKeyProvider,
    archive_vault_provider: vault::VaultKeyProvider,
    hot_key: eventexec::DlxHotKeyName,
    archive_key_for_preflight: eventexec::DlxArchiveKeyName,
}

struct PhaseADlxVerified {
    dlx_archiver_pg_config: postgres::PgConfig,
    dlx_verifier_pg_config: postgres::PgConfig,
    dlx_purger_pg_config: postgres::PgConfig,
    archive_store: s3::VerifiedS3DlxArchiveStore,
    archive_vault_provider: vault::VaultKeyProvider,
}

struct PhaseACarried {
    token_profiles: crate::config::TokenProfilesConfig,
    event_transport: crate::event_transport::EventTransportConfig,
    event_worker: Option<crate::event_transport::EventWorkerConfig>,
    dlx_worker: crate::event_transport::DlxWorkerConfig,
    distributed_worker: crate::distributed_runtime::DistributedWorkerConfig,
    domain_modules: crate::modules_gen::PreparedLocalDomainInputs,
    audit_consumer_key: Option<primitives::MacKey>,
    auth_grant_sweep_interval: Duration,
    rate_limiter: Arc<redis::RedisRateLimiter>,
    trusted_proxy_config: httpserve::TrustedProxyConfig,
    local_vault: LocalVaultAwaitingPostgres,
    redis: redis::RedisRuntimeDeps,
    s3: s3::S3RuntimeDeps,
    s3_canary_config: crate::infra::s3::S3CanaryConfig,
    pg_readiness_period: Duration,
    hot_payload_protector: postgres::DlxPayloadProtector,
    archive_key: eventexec::DlxArchiveKeyName,
    auth_audit_sink_permit: crate::provider_output::AuthAuditSinkPermit,
    device_revocation_store_permit: crate::provider_output::DeviceRevocationStorePermit,
    distributed_cas_store_permit: crate::provider_output::DistributedCasStorePermit,
    service_token_replay_store_permit: crate::provider_output::ServiceTokenReplayStorePermit,
    dlx_lifecycle_repository_permit: crate::provider_output::DlxLifecycleRepositoryPermit,
    dlx_archive_store_permit: crate::provider_output::DlxArchiveStorePermit,
    dlx_archive_key_provider_permit: crate::provider_output::DlxArchiveKeyProviderPermit,
}

enum LocalVaultAwaitingPostgres {
    None,
    Identity {
        password_blocklist: Arc<secure::DigestPasswordBlocklist>,
        signer: Arc<vault::VaultSigner>,
    },
    Settings {
        vault: vault::VaultRuntimeDeps,
        key_name: diport::KeyName,
        readiness: settings_composition::SettingsProviderReadinessAwaitingPostgres,
    },
    IdentitySettings {
        password_blocklist: Arc<secure::DigestPasswordBlocklist>,
        signer: Arc<vault::VaultSigner>,
        vault: vault::VaultRuntimeDeps,
        key_name: diport::KeyName,
        readiness: settings_composition::SettingsProviderReadinessAwaitingPostgres,
    },
}

impl LocalVaultAwaitingPostgres {
    fn bind(
        self,
        readiness: Arc<postgres::PgDbReadiness>,
    ) -> anyhow::Result<(crate::LocalDomainProviderCatalog, DomainModuleResult)> {
        let mut module = DomainModuleResult::default();
        let providers = match self {
            Self::None => crate::LocalDomainProviderCatalog::None,
            Self::Identity {
                password_blocklist,
                signer,
            } => crate::LocalDomainProviderCatalog::Identity {
                password_blocklist,
                signer,
            },
            Self::Settings {
                vault,
                key_name,
                readiness: settings,
            } => {
                let (settings, output) = settings.bind_postgres(readiness)?;
                module.merge(output.into_output());
                crate::LocalDomainProviderCatalog::Settings {
                    vault,
                    key_name,
                    readiness: settings,
                }
            }
            Self::IdentitySettings {
                password_blocklist,
                signer,
                vault,
                key_name,
                readiness: settings,
            } => {
                let (settings, output) = settings.bind_postgres(readiness)?;
                module.merge(output.into_output());
                crate::LocalDomainProviderCatalog::IdentitySettings {
                    password_blocklist,
                    signer,
                    vault,
                    key_name,
                    readiness: settings,
                }
            }
        };
        Ok((providers, module))
    }
}

struct PhaseAPrepared {
    pg_setup: PhaseBSetupInputs,
    carried: PhaseACarried,
    dlx_preflight: PhaseADlxPreflightInputs,
}

impl<'a> ProvidersBuilt<'a> {
    pub(super) async fn build_infra(self) -> anyhow::Result<<Self as RuntimePhaseState>::Next> {
        let ProvidersBuilt {
            context,
            mut provider_build,
            mut provider_factories,
            listener_execution_plan,
            local_event_execution_plan,
            placement_execution_plan,
            serving_config,
            runtime_rss_access,
            runtime_federated_access,
            admission_identity,
            admission_control,
            relay_admission,
            consumer_admission,
            write_admission,
        } = self;
        let mut uncommitted_provider_module = UncommittedModule::new(PG_MODULE_COMMITTED_ONCE);
        let result = async {
            let config = context.config();
            let projection_capture = context.runtime_plan.projection_capture();
            let rss_jwks = runtime_rss_access
                .as_ref()
                .map(|provider| provider.jwks_readiness().handle());
            let PhaseAPrepared {
                pg_setup,
                carried,
                dlx_preflight,
            } = Self::phase_a_prove_external_capabilities(
                config,
                &context.domain_execution_plan,
                serving_config,
                rss_jwks,
                &mut provider_build,
                &mut provider_factories,
            )
            .await?;
            // LIVE-01 / dlx-lifecycle-funnel helper expansion only inlines `Self::…` /
            // `self.…` *call expressions*. Keep both preflight proofs and Phase B setup as
            // `Self::…(...)` calls so ordered evidence spans Phase A/B helpers. Return the
            // migrate future directly (no nested `async` closure) to keep rustc layout depth
            // bounded through the rss binary.
            let (pg_owner, verified) = after_required_preflight(
                Self::phase_a_run_dlx_preflight(dlx_preflight),
                |verified| {
                    Self::phase_b_setup_postgres_after_preflight(
                        pg_setup,
                        verified,
                        projection_capture,
                    )
                },
            )
            .await?;
            let PhaseADlxVerified {
                dlx_archiver_pg_config,
                dlx_verifier_pg_config,
                dlx_purger_pg_config,
                archive_store,
                archive_vault_provider,
            } = verified;
            let PhaseACarried {
                token_profiles,
                event_transport,
                event_worker,
                dlx_worker,
                distributed_worker,
                domain_modules,
                audit_consumer_key,
                auth_grant_sweep_interval,
                rate_limiter,
                trusted_proxy_config,
                local_vault,
                redis,
                s3,
                s3_canary_config,
                pg_readiness_period,
                hot_payload_protector,
                archive_key,
                auth_audit_sink_permit,
                device_revocation_store_permit,
                distributed_cas_store_permit,
                service_token_replay_store_permit,
                dlx_lifecycle_repository_permit,
                dlx_archive_store_permit,
                dlx_archive_key_provider_permit,
            } = carried;
            if let Some(event_worker) = event_worker.as_ref() {
                let relay_budget = event_worker.relay_budget();
                tracing::info!(
                    runtime.event_topology = topology_label(event_transport.topology()),
                    relay.lease_ttl_ms = relay_budget.lease_ttl_millis(),
                    relay.publish_timeout_ms = relay_budget.publish_timeout_millis(),
                    relay.settle_timeout_ms = relay_budget.settle_timeout_millis(),
                    relay.safety_margin_ms = relay_budget.safety_margin_millis(),
                    relay.required_budget_ms = relay_budget.required_budget_millis(),
                    "runtime event transport budget loaded"
                );
            }
            if event_transport.topology() == bootstrap::Topology::Demo {
                anyhow::bail!(
                    "RSS_TOPOLOGY=demo is not supported in the production runtime; \
                     use durable-shared or durable-isolated"
                );
            }
            let config_value = |name: &str| config.value(name).map(str::to_owned);
            let runtime_service_token_result = token_profiles
                .service_token()
                .map(|config| {
                    crate::infra::oidc::build_service_token_provider(
                        config,
                        &pg_owner,
                        SERVICE_TOKEN_REPLAY_STORE_TIMEOUT,
                    )
                    .context("build service-token verifier with durable replay")
                })
                .transpose();
            let pg = pg_owner.handle();
            let (local_domain_providers, local_provider_pg_output) =
                local_vault.bind(pg.readiness_handle())?;
            // The unique permit builds both the concrete store and exact probes+workers output
            // from this same verified PostgreSQL handle.
            let revocation_provider = crate::provider_output::BuiltDeviceRevocationProvider::build(
                &pg,
                device_revocation_store_permit,
                &write_admission,
            )
            .context("build typed device revocation provider")?;
            let (revocation_store, revocation_output) = revocation_provider.into_parts();
            let pg_provider_module =
                crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period);
            *uncommitted_provider_module.get_mut() = pg_provider_module;
            uncommitted_provider_module
                .get_mut()
                .merge(local_provider_pg_output);
            tracing::info!(
                sample_interval_secs = pg_readiness_period.as_secs(),
                "pg readiness sampler interval configured"
            );
            let runtime_service_token = runtime_service_token_result?;
            if let Some(provider) = runtime_service_token.as_ref() {
                uncommitted_provider_module
                    .get_mut()
                    .resources
                    .push(provider.managed_resource());
            }
            let replay_sweeper_module = wire_service_token_replay_sweeper(&pg, &write_admission)
                .context("wire service-token replay sweeper")?;
            uncommitted_provider_module
                .get_mut()
                .merge(replay_sweeper_module);
            let pg_provider_module = uncommitted_provider_module.take();
            provider_build
                .record(crate::provider_output::ProviderOutput::postgres(
                    pg_provider_module,
                    revocation_output,
                    auth_audit_sink_permit,
                    distributed_cas_store_permit,
                    service_token_replay_store_permit,
                ))
                .context("record postgres provider output")?;

            let dlx_pg_owner = PgDlxLifecycleRuntime::setup(
                &dlx_archiver_pg_config,
                &dlx_verifier_pg_config,
                &dlx_purger_pg_config,
                hot_payload_protector,
            )
            .await
            .context("verify exact DLX lifecycle postgres ACLs")?;
            let dlx_lifecycle = crate::event_transport::DlxLifecycleRuntimeDeps::new(
                dlx_pg_owner,
                archive_store,
                archive_vault_provider,
                archive_key,
            );
            let dlx_outputs = match crate::event_transport::wire_dlx_lifecycle(
                dlx_lifecycle,
                dlx_worker,
                write_admission.clone(),
            ) {
                Ok(module) => module,
                Err(failure) => {
                    let (module, error) = failure.into_rollback();
                    uncommitted_provider_module.restore(module);
                    return Err(error.context("wire DLX lifecycle"));
                }
            };
            provider_build
                .record(crate::provider_output::ProviderOutput::dlx(
                    dlx_outputs.lifecycle_repository,
                    dlx_outputs.archive_store,
                    dlx_outputs.archive_key_provider,
                    dlx_lifecycle_repository_permit,
                    dlx_archive_store_permit,
                    dlx_archive_key_provider_permit,
                ))
                .context("record DLX provider output")?;
            let domain_transport_config = DomainTransportConfig::from_placement(
                &placement_execution_plan,
                &crate::config::ServingConfigMapper::new(config),
            )
            .context("build placement-backed domain transport config")?;
            let domain_transport = wire_domain_transport(domain_transport_config)
                .await
                .context("wire outbound domain transport")?;
            provider_build.record_domain(domain_transport.module_result());
            let command_idempotency_keyring = build_command_idempotency_keyring_from(config_value)
                .context("build command idempotency keyring")?;

            let deps = SharedRuntimeDeps::from_built_provider(
                pg,
                revocation_store,
                redis,
                s3,
                domain_transport.dispatch_handle(),
            );
            // Pull metrics have no shutdown lifecycle and therefore never enter ShutdownStack.
            let metrics_exporter: Arc<dyn diport::MetricsExporter> = Arc::new(
                prometheus::PromExporter::install().context("install prometheus recorder")?,
            );
            let wiring_inputs = RuntimeWiringInputs {
                event_transport,
                event_worker,
                distributed_worker,
                domain_modules,
                local_domain_providers,
                audit_consumer_key,
                auth_grant_sweep_interval,
            };

            let signing_rotation_probe =
                match (runtime_rss_access.as_ref(), token_profiles.rss_access()) {
                    (Some(provider), Some(rss)) => {
                        Some(crate::infra::signing_rotation::signing_rotation_probe(
                            rss,
                            provider.jwks_readiness().handle(),
                            Box::new(SystemClock),
                        ))
                    }
                    _ => None,
                };

            Ok(BuiltInfra {
                rate_limiter,
                trusted_proxy_config,
                deps,
                s3_canary_config,
                wiring_inputs,
                domain_transport,
                metrics_exporter,
                command_idempotency_keyring,
                signing_rotation_probe,
                runtime_service_token,
            })
        }
        .await;

        let result = match result {
            Ok(built) => Ok(InfraBuilt {
                context,
                provider_build,
                provider_factories,
                listener_execution_plan,
                local_event_execution_plan,
                placement_execution_plan,
                rate_limiter: built.rate_limiter,
                trusted_proxy_config: built.trusted_proxy_config,
                deps: built.deps,
                s3_canary_config: built.s3_canary_config,
                wiring_inputs: built.wiring_inputs,
                domain_transport: built.domain_transport,
                metrics_exporter: built.metrics_exporter,
                command_idempotency_keyring: built.command_idempotency_keyring,
                signing_rotation_probe: built.signing_rotation_probe,
                runtime_rss_access,
                runtime_federated_access,
                runtime_service_token: built.runtime_service_token,
                admission_identity,
                admission_control,
                relay_admission,
                consumer_admission,
                write_admission,
            }),
            Err(error) => {
                let module = uncommitted_provider_module.take_or_default();
                Err(provider_build.abort_with(module, error).await)
            }
        };

        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }

    /// Phase A prepares vault/redis/s3 and DLX bootstrap materials. Capability proofs run later
    /// as the first argument of [`after_required_preflight`].
    async fn phase_a_prove_external_capabilities(
        config: crate::config::SnapshotConfig<'_>,
        domain_execution: &crate::plan::DomainExecutionPlan,
        serving_config: RuntimeServingConfigParts,
        rss_jwks: Option<oidc::JwksReadinessHandle>,
        provider_build: &mut crate::provider_output::ProviderBuild,
        provider_factories: &mut crate::provider_output::ProviderFactoryDispatch,
    ) -> anyhow::Result<PhaseAPrepared> {
        let RuntimeServingConfigParts {
            token_profiles,
            event_transport,
            event_worker,
            dlx_worker,
            distributed_worker,
            domain_modules,
            audit_consumer_key,
            auth_grant_sweep_interval,
            trusted_proxy_config,
            rate_limit_quota,
        } = serving_config;
        let pg_config = PgRuntimeConfig::from_snapshot(config)
            .context("build snapshot-backed postgres config")?;
        let redis_config = RedisRuntimeConfig::from_snapshot(config)
            .context("build snapshot-backed redis config")?;
        let s3_config =
            S3RuntimeConfig::from_snapshot(config).context("build snapshot-backed s3 config")?;
        let PgRuntimeConfigParts {
            serving: app_pg_config,
            tenant_read: tenant_read_pg_config,
            audit_admin: audit_admin_config,
            dlx_archiver: dlx_archiver_pg_config,
            dlx_verifier: dlx_verifier_pg_config,
            dlx_purger: dlx_purger_pg_config,
            readiness_period: pg_readiness_period,
        } = pg_config.into_parts();
        let S3RuntimeConfigParts {
            general: s3_general_config,
            canary: s3_canary_config,
            dlx_archive: s3_dlx_archive_config,
        } = s3_config.into_parts();
        let config_value = |name: &str| config.value(name).map(str::to_owned);

        let local_provider_permits =
            provider_factories.take_local_domain_permits(domain_execution)?;
        let local_vault = match local_provider_permits {
            crate::provider_output::LocalDomainProviderPermits::None => {
                LocalVaultAwaitingPostgres::None
            }
            crate::provider_output::LocalDomainProviderPermits::Identity { signer } => {
                let password_blocklist = crate::domains::identity::load_password_blocklist(config)?;
                let signer = Self::build_identity_vault(
                    config,
                    &token_profiles,
                    rss_jwks,
                    provider_build,
                    signer,
                )
                .await?;
                LocalVaultAwaitingPostgres::Identity {
                    password_blocklist,
                    signer,
                }
            }
            crate::provider_output::LocalDomainProviderPermits::Settings {
                key_provider,
                secret_resolver,
            } => {
                let (vault, key_name, readiness) = Self::build_settings_vault(
                    config,
                    &domain_modules,
                    provider_build,
                    key_provider,
                    secret_resolver,
                )
                .await?;
                LocalVaultAwaitingPostgres::Settings {
                    vault,
                    key_name,
                    readiness,
                }
            }
            crate::provider_output::LocalDomainProviderPermits::IdentitySettings {
                signer: signer_permit,
                key_provider,
                secret_resolver,
            } => {
                let password_blocklist = crate::domains::identity::load_password_blocklist(config)?;
                let signer = Self::build_identity_vault(
                    config,
                    &token_profiles,
                    rss_jwks,
                    provider_build,
                    signer_permit,
                )
                .await?;
                let (vault, key_name, readiness) = Self::build_settings_vault(
                    config,
                    &domain_modules,
                    provider_build,
                    key_provider,
                    secret_resolver,
                )
                .await?;
                LocalVaultAwaitingPostgres::IdentitySettings {
                    password_blocklist,
                    signer,
                    vault,
                    key_name,
                    readiness,
                }
            }
        };

        let distributed_lock_store_permit = provider_factories.distributed_lock_store()?;
        let (redis, redis_readiness_period) = build_redis_runtime_deps(redis_config)
            .await
            .context("setup redis deps")?;
        let listener_rate_limiter_permit = provider_factories.listener_rate_limiter()?;
        let rate_limiter_capability = redis
            .infra()
            .rate_limiter_capability(crate::providers_gen::ASSEMBLY_NAMESPACE, rate_limit_quota)
            .await
            .context("verify Redis listener rate-limiter capability")?;
        let (listener_rate_limiter_output, rate_limiter) =
            crate::provider_output::ProviderOutput::listener_rate_limiter(
                listener_rate_limiter_permit,
                rate_limiter_capability,
            );
        let rate_limiter = Arc::new(rate_limiter);
        provider_build
            .record(listener_rate_limiter_output)
            .context("record listener rate-limiter provider output")?;
        let redis_ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let redis_probe_name = primitives::ProbeName::parse(REDIS_READY_PROBE_NAME)
            .context("parse redis_ready probe name")?;
        let redis_for_sampler = redis.clone();
        let redis_worker_ready = Arc::clone(&redis_ready);
        let redis_readiness_worker = bootstrap::WorkerSpec::observational_phase_one(
            "assemblies.runtime.src.phase.infra.01",
            move |token| {
                diport::DynManagedResource::new_box(spawn_redis_readiness_sampler(
                    redis_for_sampler.clone(),
                    redis_readiness_period,
                    token,
                    Arc::clone(&redis_worker_ready),
                ))
            },
        );
        provider_build
            .record(crate::provider_output::ProviderOutput::redis(
                DomainModuleResult {
                    probes: vec![(
                        redis_probe_name,
                        Box::new(RedisReadyProbe::new(Arc::clone(&redis_ready))),
                    )],
                    resources: redis.runtime_resources(),
                    workers: vec![redis_readiness_worker],
                },
                distributed_lock_store_permit,
            ))
            .context("record redis provider output")?;

        let runtime_object_store_permit = provider_factories.runtime_object_store()?;
        let s3 = build_s3_runtime_deps(s3_general_config).context("setup s3 deps")?;
        provider_build
            .record(crate::provider_output::ProviderOutput::s3(
                DomainModuleResult {
                    resources: s3.runtime_resources(),
                    ..DomainModuleResult::default()
                },
                runtime_object_store_permit,
            ))
            .context("record S3 provider output")?;
        let dlx_bootstrap = build_dlx_lifecycle_bootstrap_config_from(
            dlx_archiver_pg_config,
            dlx_verifier_pg_config,
            dlx_purger_pg_config,
            s3_dlx_archive_config,
            config_value,
            Arc::new(SystemClock),
        )
        .await?;
        let DlxLifecycleBootstrapConfig {
            archiver_pg: dlx_archiver_pg_config,
            verifier_pg: dlx_verifier_pg_config,
            purger_pg: dlx_purger_pg_config,
            archive_store,
            hot_vault_provider,
            archive_vault_provider,
            hot_key,
            archive_key,
        } = dlx_bootstrap;
        let hot_payload_protector = event_transport
            .dlx_payload_protector()
            .context("durable DLX hot payload protector missing")?;
        let archive_key_for_preflight = archive_key.clone();
        let auth_audit_sink_permit = provider_factories.auth_audit_sink()?;
        let device_revocation_store_permit = provider_factories.device_revocation_store()?;
        let distributed_cas_store_permit = provider_factories.distributed_cas_store()?;
        let service_token_replay_store_permit = provider_factories.service_token_replay_store()?;
        let dlx_lifecycle_repository_permit = provider_factories.dlx_lifecycle_repository()?;
        let dlx_archive_store_permit = provider_factories.dlx_archive_store()?;
        let dlx_archive_key_provider_permit = provider_factories.dlx_archive_key_provider()?;

        Ok(PhaseAPrepared {
            pg_setup: PhaseBSetupInputs {
                app_pg_config,
                tenant_read_pg_config,
                audit_admin_config,
            },
            carried: PhaseACarried {
                token_profiles,
                event_transport,
                event_worker,
                dlx_worker,
                distributed_worker,
                domain_modules,
                audit_consumer_key,
                auth_grant_sweep_interval,
                rate_limiter,
                trusted_proxy_config,
                local_vault,
                redis,
                s3,
                s3_canary_config,
                pg_readiness_period,
                hot_payload_protector,
                archive_key,
                auth_audit_sink_permit,
                device_revocation_store_permit,
                distributed_cas_store_permit,
                service_token_replay_store_permit,
                dlx_lifecycle_repository_permit,
                dlx_archive_store_permit,
                dlx_archive_key_provider_permit,
            },
            dlx_preflight: PhaseADlxPreflightInputs {
                dlx_archiver_pg_config,
                dlx_verifier_pg_config,
                dlx_purger_pg_config,
                archive_store,
                hot_vault_provider,
                archive_vault_provider,
                hot_key,
                archive_key_for_preflight,
            },
        })
    }

    async fn build_identity_vault(
        config: crate::config::SnapshotConfig<'_>,
        token_profiles: &crate::config::TokenProfilesConfig,
        rss_jwks: Option<oidc::JwksReadinessHandle>,
        provider_build: &mut crate::provider_output::ProviderBuild,
        signer_permit: crate::provider_output::IdentitySignerPermit,
    ) -> anyhow::Result<Arc<vault::VaultSigner>> {
        let binding = token_profiles
            .rss_access()
            .context("active identity signer requires RSS access token profile")?
            .signing_binding()
            .clone();
        let signer = IdentityVaultRuntimeConfig::from_snapshot(config)
            .context("build identity-local vault config")?
            .into_signer(binding.clone())
            .context("setup identity-local vault signer")?;
        let module = crate::provider_output::identity_signer_module(
            Arc::clone(&signer),
            binding,
            rss_jwks.context("active identity signer requires RSS access-token JWKS")?,
        )
        .await?;
        provider_build
            .record(crate::provider_output::ProviderOutput::identity_vault(
                module,
                signer_permit,
            ))
            .context("record identity-local vault provider output")?;
        Ok(signer)
    }

    async fn build_settings_vault(
        config: crate::config::SnapshotConfig<'_>,
        domain_modules: &crate::modules_gen::PreparedLocalDomainInputs,
        provider_build: &mut crate::provider_output::ProviderBuild,
        key_provider_permit: crate::provider_output::SettingsKeyProviderPermit,
        secret_resolver_permit: crate::provider_output::SettingsSecretResolverPermit,
    ) -> anyhow::Result<(
        vault::VaultRuntimeDeps,
        diport::KeyName,
        settings_composition::SettingsProviderReadinessAwaitingPostgres,
    )> {
        let (vault, key_name) = SettingsVaultRuntimeConfig::from_snapshot(config)
            .context("build settings-local vault config")?
            .into_settings()
            .context("setup settings-local vault providers")?;
        let readiness = settings_composition::SettingsProviderReadiness::new(
            &vault.for_domain::<vault::caps::Settings>(),
            key_name.clone(),
            domain_modules.settings_readiness_interval()?,
        )
        .await
        .context("build settings provider readiness")?;
        let (readiness, key_output, resolver_output) = readiness.into_vault_parts();
        let mut resources = vault.runtime_resources().into_iter();
        let resolver_resource = resources
            .next()
            .context("vault omitted settings secret-resolver resource")?;
        let key_resource = resources
            .next()
            .context("vault omitted settings key-provider resource")?;
        anyhow::ensure!(
            resources.next().is_none(),
            "vault exposed an undeclared settings provider resource"
        );
        let mut key_module = key_output.into_output();
        key_module.resources.push(key_resource);
        let mut resolver_module = resolver_output.into_output();
        resolver_module.resources.push(resolver_resource);
        provider_build
            .record(crate::provider_output::ProviderOutput::settings_vault(
                key_module,
                resolver_module,
                key_provider_permit,
                secret_resolver_permit,
            ))
            .context("record settings-local vault provider outputs")?;
        Ok((vault, key_name, readiness))
    }

    async fn phase_a_run_dlx_preflight(
        inputs: PhaseADlxPreflightInputs,
    ) -> anyhow::Result<PhaseADlxVerified> {
        let PhaseADlxPreflightInputs {
            dlx_archiver_pg_config,
            dlx_verifier_pg_config,
            dlx_purger_pg_config,
            archive_store,
            hot_vault_provider,
            archive_vault_provider,
            hot_key,
            archive_key_for_preflight,
        } = inputs;
        PgDlxLifecycleRuntime::preflight_identities(
            &dlx_archiver_pg_config,
            &dlx_verifier_pg_config,
            &dlx_purger_pg_config,
        )
        .await
        .context("preflight independent DLX postgres identities")?;
        let archive_store = archive_store
            .verify()
            .await
            .context("verify DLX archive S3 WORM capability")?;
        crate::event_transport::verify_dlx_vault_key_capability(
            &hot_vault_provider,
            hot_key.as_key_name(),
            "dlx-hot-startup",
        )
        .await
        .context("verify DLX hot Vault capability")?;
        crate::event_transport::verify_dlx_vault_key_capability(
            &archive_vault_provider,
            archive_key_for_preflight.as_key_name(),
            "dlx-archive-startup",
        )
        .await
        .context("verify DLX archive Vault capability")?;
        Ok(PhaseADlxVerified {
            dlx_archiver_pg_config,
            dlx_verifier_pg_config,
            dlx_purger_pg_config,
            archive_store,
            archive_vault_provider,
        })
    }

    async fn phase_b_setup_postgres(
        inputs: PhaseBSetupInputs,
        projection_capture: eventexec::ProjectionCaptureView<'_>,
    ) -> anyhow::Result<PgRuntimeDeps> {
        // Serving startup is non-destructive and accepts no migration capability.
        let PhaseBSetupInputs {
            app_pg_config,
            tenant_read_pg_config,
            audit_admin_config,
        } = inputs;
        PgRuntimeDeps::connect_serving(
            &app_pg_config,
            &tenant_read_pg_config,
            audit_admin_config.as_ref(),
            projection_capture,
        )
        .await
        .context("connect postgres serving deps after DLX capability preflight")
    }

    async fn phase_b_setup_postgres_after_preflight(
        inputs: PhaseBSetupInputs,
        verified: PhaseADlxVerified,
        projection_capture: eventexec::ProjectionCaptureView<'_>,
    ) -> anyhow::Result<(PgRuntimeDeps, PhaseADlxVerified)> {
        let pg = Self::phase_b_setup_postgres(inputs, projection_capture).await?;
        Ok((pg, verified))
    }
}
