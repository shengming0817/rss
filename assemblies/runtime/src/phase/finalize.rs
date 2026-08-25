use super::{DomainsWired, Finalized, RuntimePhaseState, phase_result};
use crate::routes::{FinalizeListenerPlanInputs, finalize_listener_plan};
use crate::support::SystemClock;
use anyhow::Context as _;
use postgres::caps;
use std::sync::Arc;

impl<'a> DomainsWired<'a> {
    pub(super) async fn finalize(self) -> anyhow::Result<<Self as RuntimePhaseState>::Next> {
        let DomainsWired {
            context,
            listener_execution_plan,
            rate_limiter,
            trusted_proxy_config,
            deps,
            runtime_rss_access,
            runtime_federated_access,
            runtime_service_token,
            domain_transport,
            command_idempotency_keyring,
            metrics_exporter,
            security_root_registry,
            mut provider_build,
            placement_execution_plan,
        } = self;
        let mut registry = security_root_registry.into_registry();
        let result = (|| {
            // Auth decision audit is a flat durable sink, not the audit ledger hash-chain actor
            // model. Provider ownership remains in this state while routers receive a capability.
            let auth_audit_sink = httpserve::AuditSinkHandle::new(
                deps.pg.for_domain::<caps::Audit>().auth_audit_sink(),
            );
            let auth_audit_clock: Arc<dyn diport::Clock> = Arc::new(SystemClock);
            let grant_validation_clock: Arc<dyn diport::Clock> = Arc::new(SystemClock);
            let rss_access_grants = runtime_rss_access.as_ref().map(|_| {
                identity_composition::access_grant_validation_service(
                    &deps.pg.for_domain::<caps::Identity>(),
                    &grant_validation_clock,
                )
            });
            let token_provider_bindings = crate::routes::TokenProviderBindings::new(
                runtime_rss_access
                    .as_ref()
                    .map(|provider| provider.provider()),
                rss_access_grants,
                runtime_federated_access
                    .as_ref()
                    .map(|provider| provider.provider()),
                runtime_service_token
                    .as_ref()
                    .map(|provider| provider.provider()),
            );
            let mut seed = runtimeexec::inventory::RuntimeInventorySeed::from_runtime_plan(
                context.runtime_plan.as_typed(),
                context
                    .runtime_plan
                    .workflow_runtime()
                    .activated_workflows(),
                provider_build
                    .take_inventory_receipt()
                    .context("consume provider inventory completion receipt")?,
                placement_execution_plan
                    .inventory_observations()
                    .context("project runtime placement inventory")?,
            )
            .context("seal runtime inventory seed")?;
            if let Some(profile) = context.runtime_plan.official_inventory_profile() {
                seed = seed.with_official_profile(profile.clone());
            }
            let seed = match crate::config::build_metadata(context.config())
                .context("capture launch-supplied build metadata")?
            {
                Some(metadata) => seed.with_build_metadata(metadata),
                None => seed,
            };
            let (
                inventory_publisher,
                inventory_reader,
                inventory_health_publisher,
                inventory_placement_publisher,
            ) = runtimeexec::inventory::deferred_inventory_channel(seed);
            let platform_host = runtimeexec::RuntimeHostView::starting(inventory_reader.clone());
            let inventory_routes = crate::runtime_inventory::RuntimeInventoryRoutes::new(
                inventory_reader,
                platform_host.clone(),
            )
            .context("compose Platform runtime inventory dispatcher")?;
            if let Some(domain_transport) = domain_transport.as_ref() {
                inventory_placement_publisher
                    .publish(domain_transport.readiness_sampler())
                    .context("publish runtime inventory placement readiness sampler")?;
            }
            let finalized_listeners = finalize_listener_plan(FinalizeListenerPlanInputs {
                execution_plan: listener_execution_plan,
                config: context.config(),
                registry: &mut registry,
                providers: &token_provider_bindings,
                audit_sink: auth_audit_sink,
                audit_clock: auth_audit_clock,
                rate_limiter,
                trusted_proxy_config,
                metrics: metrics_exporter,
                framework_routes: inventory_routes,
            })
            .context("finalize RuntimePlan listeners")?;
            let (listeners, probe_receipt, health_reporter) = finalized_listeners.into_parts();
            inventory_health_publisher
                .publish(health_reporter)
                .context("publish runtime inventory health reporter")?;

            Ok((
                (listeners, probe_receipt),
                inventory_publisher,
                platform_host,
            ))
        })();
        let result = match result {
            Ok(((listeners, probe_receipt), inventory_publisher, platform_host)) => Ok(Finalized {
                context,
                provider_build,
                deps,
                runtime_rss_access,
                runtime_federated_access,
                runtime_service_token,
                domain_transport,
                command_idempotency_keyring,
                listeners,
                probe_receipt,
                inventory_publisher,
                platform_host,
            }),
            Err(error) => Err(provider_build.abort(error).await),
        };

        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
