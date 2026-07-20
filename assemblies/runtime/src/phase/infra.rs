use super::{InfraBuilt, ProvidersBuilt, RuntimePhaseState, phase_result};
use crate::config::RuntimeServingConfigParts;
use crate::infra::pg::{PgRuntimeConfig, PgRuntimeConfigParts};
use crate::infra::redis::{RedisRuntimeConfig, build_redis_runtime_deps};
use crate::infra::s3::{S3RuntimeConfig, S3RuntimeConfigParts, build_s3_runtime_deps};
use crate::infra::vault::VaultRuntimeConfig;
use crate::{
    DlxLifecycleBootstrapConfig, SharedRuntimeDeps, SystemClock,
    build_command_idempotency_keyring_from, build_dlx_lifecycle_bootstrap_config_from,
    topology_label, verify_dlx_vault_key_capability, wire_domain_transport,
};
use anyhow::Context as _;
use postgres::{PgDlxLifecycleRuntime, PgRuntimeDeps};
use std::sync::Arc;
use std::time::Duration;

pub(super) struct RuntimeWiringInputs {
    pub(super) event_transport: crate::event_transport::EventTransportConfig,
    pub(super) event_worker: crate::event_transport::EventWorkerConfig,
    pub(super) dlx_worker: crate::event_transport::DlxWorkerConfig,
    pub(super) distributed_worker: crate::distributed_runtime::DistributedWorkerConfig,
    pub(super) domain_modules: crate::domains::DomainModuleInputs,
    pub(super) audit_consumer_key: primitives::MacKey,
    pub(super) auth_grant_sweep_interval: Duration,
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

impl<'a> ProvidersBuilt<'a> {
    pub(super) async fn build_infra(self) -> anyhow::Result<<Self as RuntimePhaseState>::Next> {
        let ProvidersBuilt {
            context,
            listener_execution_plan,
            serving_config,
            runtime_rss_access,
            runtime_federated_access,
        } = self;
        let result = async move {
            let config = context.config();
            let password_blocklist = Arc::clone(context.password_blocklist());
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
            let s3_config = S3RuntimeConfig::from_snapshot(config)
                .context("build snapshot-backed s3 config")?;
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

            // Phase A parses every configuration and proves all external DLX capabilities before
            // the forward-only 0062 migration can commit.
            let vault_config = VaultRuntimeConfig::from_snapshot(config)
                .context("build snapshot-backed vault config")?;
            let (vault, settings_config_value_key_name) =
                vault_config.into_runtime().context("setup vault deps")?;
            let (redis, redis_readiness_period) = build_redis_runtime_deps(redis_config)
                .await
                .context("setup redis deps")?;
            let s3 = build_s3_runtime_deps(s3_general_config).context("setup s3 deps")?;
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

            let (pg_owner, dlx_pg_owner, archive_store, archive_vault_provider) =
                after_required_preflight(
                    async move {
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
                        Ok((
                            dlx_archiver_pg_config,
                            dlx_verifier_pg_config,
                            dlx_purger_pg_config,
                            archive_store,
                            archive_vault_provider,
                        ))
                    },
                    |(
                        dlx_archiver_pg_config,
                        dlx_verifier_pg_config,
                        dlx_purger_pg_config,
                        archive_store,
                        archive_vault_provider,
                    )| async move {
                        // Phase B is the only destructive step. Exact function/table ACL checks run
                        // only after the migration has installed the closed surface.
                        let pg_owner = PgRuntimeDeps::setup_with_audit_admin_config(
                            &migrator_config,
                            &app_pg_config,
                            &tenant_read_pg_config,
                            audit_admin_config.as_ref(),
                            plaintext_policy,
                            generated::event::PROJECTION_INPUT_GENERATION,
                            generated::event::PROJECTION_INPUTS,
                        )
                        .await
                        .context("setup postgres deps after DLX capability preflight")?;
                        let dlx_pg_owner = PgDlxLifecycleRuntime::setup(
                            &dlx_archiver_pg_config,
                            &dlx_verifier_pg_config,
                            &dlx_purger_pg_config,
                            hot_payload_protector,
                        )
                        .await
                        .context("verify exact DLX lifecycle postgres ACLs")?;
                        Ok((
                            pg_owner,
                            dlx_pg_owner,
                            archive_store,
                            archive_vault_provider,
                        ))
                    },
                )
                .await?;
            let pg = pg_owner.handle();
            let dlx_lifecycle = crate::event_transport::DlxLifecycleRuntimeDeps::new(
                dlx_pg_owner,
                archive_store,
                archive_vault_provider,
                archive_key,
            );
            let domain_transport = wire_domain_transport(domain_transport_config)
                .await
                .context("wire outbound domain transport")?;
            let command_idempotency_keyring = build_command_idempotency_keyring_from(config_value)
                .context("build command idempotency keyring")?;

            let deps = SharedRuntimeDeps {
                password_blocklist,
                pg,
                redis,
                s3,
                vault,
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
                dlx_worker,
                distributed_worker,
                domain_modules,
                audit_consumer_key,
                auth_grant_sweep_interval,
            };

            let runtime_service_token = token_profiles
                .service_token()
                .map(|config| {
                    crate::infra::oidc::build_service_token_provider(
                        config,
                        &pg_owner,
                        crate::SERVICE_TOKEN_REPLAY_STORE_TIMEOUT,
                    )
                    .context("build service-token verifier with durable replay")
                })
                .transpose()?;

            Ok(InfraBuilt {
                context,
                listener_execution_plan,
                pg_owner,
                deps,
                s3_canary_config,
                wiring_inputs,
                dlx_lifecycle,
                domain_transport,
                metrics_exporter,
                pg_readiness_period,
                redis_readiness_period,
                command_idempotency_keyring,
                runtime_rss_access,
                runtime_federated_access,
                runtime_service_token,
            })
        }
        .await;

        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
