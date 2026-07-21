use super::{
    InfraBuilt, PG_MODULE_COMMITTED_ONCE, ProvidersBuilt, RuntimePhaseState, UncommittedModule,
    phase_result,
};
use crate::config::RuntimeServingConfigParts;
use crate::infra::pg::{PgRuntimeConfig, PgRuntimeConfigParts};
use crate::infra::redis::{RedisRuntimeConfig, build_redis_runtime_deps};
use crate::infra::s3::{S3RuntimeConfig, S3RuntimeConfigParts, build_s3_runtime_deps};
use crate::infra::vault::VaultRuntimeConfig;
use crate::{
    DlxLifecycleBootstrapConfig, SharedRuntimeDeps, SystemClock,
    build_command_idempotency_keyring_from, build_dlx_lifecycle_bootstrap_config_from,
    topology_label, verify_dlx_vault_key_capability, wire_domain_transport,
    wire_service_token_replay_sweeper,
};
use anyhow::Context as _;
use bootstrap::DomainModuleResult;
use postgres::{PgDlxLifecycleRuntime, PgRuntimeDeps};
use std::sync::Arc;
use std::time::Duration;

pub(super) struct RuntimeWiringInputs {
    pub(super) event_transport: crate::event_transport::EventTransportConfig,
    pub(super) event_worker: crate::event_transport::EventWorkerConfig,
    pub(super) distributed_worker: crate::distributed_runtime::DistributedWorkerConfig,
    pub(super) domain_modules: crate::domains::DomainModuleInputs,
    pub(super) audit_consumer_key: primitives::MacKey,
    pub(super) auth_grant_sweep_interval: Duration,
}

struct BuiltInfra {
    deps: SharedRuntimeDeps,
    s3_canary_config: crate::infra::s3::S3CanaryConfig,
    wiring_inputs: RuntimeWiringInputs,
    domain_transport: crate::DomainTransportRuntime<httpd::SharedDomainHttpTransport>,
    metrics_exporter: Arc<dyn diport::MetricsExporter>,
    redis_readiness_period: Duration,
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
    migrator_config: postgres::PgConfig,
    app_pg_config: postgres::PgConfig,
    tenant_read_pg_config: postgres::PgTenantReadConfig,
    audit_admin_config: Option<postgres::PgConfig>,
    plaintext_policy: postgres::LegacyConfigPlaintextPolicy,
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
    password_blocklist: Arc<secure::DigestPasswordBlocklist>,
    token_profiles: crate::config::TokenProfilesConfig,
    event_transport: crate::event_transport::EventTransportConfig,
    event_worker: crate::event_transport::EventWorkerConfig,
    dlx_worker: crate::event_transport::DlxWorkerConfig,
    distributed_worker: crate::distributed_runtime::DistributedWorkerConfig,
    domain_modules: crate::domains::DomainModuleInputs,
    audit_consumer_key: primitives::MacKey,
    auth_grant_sweep_interval: Duration,
    domain_transport_config: crate::DomainTransportConfig,
    vault: vault::VaultRuntimeDeps,
    identity_signer: Arc<vault::VaultSigner>,
    settings_config_value_key_name: diport::KeyName,
    redis: redis::RedisRuntimeDeps,
    redis_readiness_period: Duration,
    s3: s3::S3RuntimeDeps,
    s3_canary_config: crate::infra::s3::S3CanaryConfig,
    pg_readiness_period: Duration,
    hot_payload_protector: postgres::DlxPayloadProtector,
    archive_key: eventexec::DlxArchiveKeyName,
    auth_audit_sink_permit: crate::provider_output::AuthAuditSinkPermit,
    distributed_cas_store_permit: crate::provider_output::DistributedCasStorePermit,
    service_token_replay_store_permit: crate::provider_output::ServiceTokenReplayStorePermit,
    dlx_lifecycle_repository_permit: crate::provider_output::DlxLifecycleRepositoryPermit,
    dlx_archive_store_permit: crate::provider_output::DlxArchiveStorePermit,
    dlx_archive_key_provider_permit: crate::provider_output::DlxArchiveKeyProviderPermit,
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
            rate_limiter,
            serving_config,
            runtime_rss_access,
            runtime_federated_access,
        } = self;
        let mut uncommitted_provider_module = UncommittedModule::new(PG_MODULE_COMMITTED_ONCE);
        let result = async {
            let config = context.config();
            let PhaseAPrepared {
                pg_setup,
                carried,
                dlx_preflight,
            } = Self::phase_a_prove_external_capabilities(
                config,
                Arc::clone(context.password_blocklist()),
                serving_config,
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
                |verified| Self::phase_b_setup_postgres_after_preflight(pg_setup, verified),
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
                password_blocklist,
                token_profiles,
                event_transport,
                event_worker,
                dlx_worker,
                distributed_worker,
                domain_modules,
                audit_consumer_key,
                auth_grant_sweep_interval,
                domain_transport_config,
                vault,
                identity_signer,
                settings_config_value_key_name,
                redis,
                redis_readiness_period,
                s3,
                s3_canary_config,
                pg_readiness_period,
                hot_payload_protector,
                archive_key,
                auth_audit_sink_permit,
                distributed_cas_store_permit,
                service_token_replay_store_permit,
                dlx_lifecycle_repository_permit,
                dlx_archive_store_permit,
                dlx_archive_key_provider_permit,
            } = carried;
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
                        crate::SERVICE_TOKEN_REPLAY_STORE_TIMEOUT,
                    )
                    .context("build service-token verifier with durable replay")
                })
                .transpose();
            let pg = pg_owner.handle();
            let pg_provider_module =
                crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period);
            *uncommitted_provider_module.get_mut() = pg_provider_module;
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
            let replay_sweeper_module = wire_service_token_replay_sweeper(&pg)
                .context("wire service-token replay sweeper")?;
            uncommitted_provider_module
                .get_mut()
                .merge(replay_sweeper_module);
            let pg_provider_module = uncommitted_provider_module.take();
            provider_build
                .record(crate::provider_output::ProviderOutput::postgres(
                    pg_provider_module,
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
            let dlx_module =
                match crate::event_transport::wire_dlx_lifecycle(dlx_lifecycle, dlx_worker) {
                    Ok(module) => module,
                    Err(failure) => {
                        let (module, error) = failure.into_rollback();
                        uncommitted_provider_module.restore(module);
                        return Err(error.context("wire DLX lifecycle"));
                    }
                };
            provider_build
                .record(crate::provider_output::ProviderOutput::dlx(
                    dlx_module,
                    dlx_lifecycle_repository_permit,
                    dlx_archive_store_permit,
                    dlx_archive_key_provider_permit,
                ))
                .context("record DLX provider output")?;
            let domain_transport = wire_domain_transport(domain_transport_config)
                .await
                .context("wire outbound domain transport")?;
            provider_build.record_domain(domain_transport.module_result());
            let command_idempotency_keyring = build_command_idempotency_keyring_from(config_value)
                .context("build command idempotency keyring")?;

            let deps = SharedRuntimeDeps {
                password_blocklist,
                pg,
                redis,
                s3,
                vault,
                identity_signer,
                settings_config_value_key_name,
                domain_transport: domain_transport.dispatch_handle(),
            };

            // Pull metrics have no shutdown lifecycle and therefore never enter ShutdownStack.
            let metrics_exporter: Arc<dyn diport::MetricsExporter> = Arc::new(
                prometheus::PromExporter::install().context("install prometheus recorder")?,
            );
            let wiring_inputs = RuntimeWiringInputs {
                event_transport,
                event_worker,
                distributed_worker,
                domain_modules,
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
                deps,
                s3_canary_config,
                wiring_inputs,
                domain_transport,
                metrics_exporter,
                redis_readiness_period,
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
                rate_limiter,
                deps: built.deps,
                s3_canary_config: built.s3_canary_config,
                wiring_inputs: built.wiring_inputs,
                domain_transport: built.domain_transport,
                metrics_exporter: built.metrics_exporter,
                redis_readiness_period: built.redis_readiness_period,
                command_idempotency_keyring: built.command_idempotency_keyring,
                signing_rotation_probe: built.signing_rotation_probe,
                runtime_rss_access,
                runtime_federated_access,
                runtime_service_token: built.runtime_service_token,
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
        password_blocklist: Arc<secure::DigestPasswordBlocklist>,
        serving_config: RuntimeServingConfigParts,
        provider_build: &mut crate::provider_output::ProviderBuild,
        provider_factories: &mut crate::provider_output::ProviderFactoryDispatch,
    ) -> anyhow::Result<PhaseAPrepared> {
        let RuntimeServingConfigParts {
            token_profiles,
            event_transport,
            event_worker,
            dlx_worker,
            distributed_worker,
            domain_transport: domain_transport_config,
            domain_modules,
            audit_consumer_key,
            auth_grant_sweep_interval,
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
            migrator: migrator_config,
            audit_admin: audit_admin_config,
            dlx_archiver: dlx_archiver_pg_config,
            dlx_verifier: dlx_verifier_pg_config,
            dlx_purger: dlx_purger_pg_config,
            legacy_policy: plaintext_policy,
            readiness_period: pg_readiness_period,
        } = pg_config.into_parts();
        let S3RuntimeConfigParts {
            general: s3_general_config,
            canary: s3_canary_config,
            dlx_archive: s3_dlx_archive_config,
        } = s3_config.into_parts();
        let config_value = |name: &str| config.value(name).map(str::to_owned);

        // Phase A parses every configuration and prepares DLX materials before capability proofs
        // and the forward-only 0062 migration can commit.
        let vault_config = VaultRuntimeConfig::from_snapshot(config)
            .context("build snapshot-backed vault config")?;

        let identity_signer_permit = provider_factories.identity_signer()?;
        let settings_key_provider_permit = provider_factories.settings_key_provider()?;
        let (vault, identity_signer, settings_config_value_key_name) =
            vault_config.into_runtime().context("setup vault deps")?;
        let mut vault_module = DomainModuleResult {
            resources: vault.runtime_resources(),
            ..DomainModuleResult::default()
        };
        vault_module
            .resources
            .push(crate::provider_output::identity_signer_resource(
                Arc::clone(&identity_signer),
            ));
        provider_build
            .record(crate::provider_output::ProviderOutput::vault(
                vault_module,
                identity_signer_permit,
                settings_key_provider_permit,
            ))
            .context("record vault provider output")?;

        let distributed_lock_store_permit = provider_factories.distributed_lock_store()?;
        let (redis, redis_readiness_period) = build_redis_runtime_deps(redis_config)
            .await
            .context("setup redis deps")?;
        provider_build
            .record(crate::provider_output::ProviderOutput::redis(
                DomainModuleResult {
                    resources: redis.runtime_resources(),
                    ..DomainModuleResult::default()
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
        let distributed_cas_store_permit = provider_factories.distributed_cas_store()?;
        let service_token_replay_store_permit = provider_factories.service_token_replay_store()?;
        let dlx_lifecycle_repository_permit = provider_factories.dlx_lifecycle_repository()?;
        let dlx_archive_store_permit = provider_factories.dlx_archive_store()?;
        let dlx_archive_key_provider_permit = provider_factories.dlx_archive_key_provider()?;

        Ok(PhaseAPrepared {
            pg_setup: PhaseBSetupInputs {
                migrator_config,
                app_pg_config,
                tenant_read_pg_config,
                audit_admin_config,
                plaintext_policy,
            },
            carried: PhaseACarried {
                password_blocklist,
                token_profiles,
                event_transport,
                event_worker,
                dlx_worker,
                distributed_worker,
                domain_modules,
                audit_consumer_key,
                auth_grant_sweep_interval,
                domain_transport_config,
                vault,
                identity_signer,
                settings_config_value_key_name,
                redis,
                redis_readiness_period,
                s3,
                s3_canary_config,
                pg_readiness_period,
                hot_payload_protector,
                archive_key,
                auth_audit_sink_permit,
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
        verify_dlx_vault_key_capability(
            &hot_vault_provider,
            hot_key.as_key_name(),
            "dlx-hot-startup",
        )
        .await
        .context("verify DLX hot Vault capability")?;
        verify_dlx_vault_key_capability(
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

    async fn phase_b_setup_postgres(inputs: PhaseBSetupInputs) -> anyhow::Result<PgRuntimeDeps> {
        // Phase B is the only destructive step. Exact function/table ACL checks run
        // only after the migration has installed the closed surface.
        let PhaseBSetupInputs {
            migrator_config,
            app_pg_config,
            tenant_read_pg_config,
            audit_admin_config,
            plaintext_policy,
        } = inputs;
        PgRuntimeDeps::setup_with_audit_admin_config(
            &migrator_config,
            &app_pg_config,
            &tenant_read_pg_config,
            audit_admin_config.as_ref(),
            plaintext_policy,
            generated::event::PROJECTION_INPUT_GENERATION,
            generated::event::PROJECTION_INPUTS,
        )
        .await
        .context("setup postgres deps after DLX capability preflight")
    }

    async fn phase_b_setup_postgres_after_preflight(
        inputs: PhaseBSetupInputs,
        verified: PhaseADlxVerified,
    ) -> anyhow::Result<(PgRuntimeDeps, PhaseADlxVerified)> {
        let pg = Self::phase_b_setup_postgres(inputs).await?;
        Ok((pg, verified))
    }
}
