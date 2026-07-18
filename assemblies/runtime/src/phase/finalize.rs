use super::{DomainsWired, Finalized, RuntimePhaseState, phase_result};
use crate::SystemClock;
use crate::listeners::health_listener;
use crate::routes::{AssembledListener, assemble_authed_routers};
use anyhow::Context as _;
use postgres::caps;
use std::sync::Arc;

impl<'a> DomainsWired<'a> {
    pub(super) async fn finalize(self) -> anyhow::Result<<Self as RuntimePhaseState>::Next> {
        let DomainsWired {
            context,
            pg_owner,
            deps,
            token_profiles,
            runtime_rss_access,
            runtime_federated_access,
            runtime_service_token,
            domain_transport,
            command_idempotency_keyring,
            metrics_exporter,
            pg_readiness_period,
            mut registry,
            domain_module,
        } = self;
        let result = (|| {
            // Auth decision audit is a flat durable sink, not the audit ledger hash-chain actor
            // model. Provider ownership remains in this state while routers receive a capability.
            let auth_audit_sink = httpserve::AuditSinkHandle::new(
                deps.pg.for_domain::<caps::Audit>().auth_audit_sink(),
            );
            let auth_audit_clock: Arc<dyn diport::Clock> = Arc::new(SystemClock);
            let token_provider_bindings = crate::routes::TokenProviderBindings::new(
                runtime_rss_access
                    .as_ref()
                    .map(|provider| provider.provider()),
                runtime_federated_access
                    .as_ref()
                    .map(|provider| provider.provider()),
                runtime_service_token
                    .as_ref()
                    .map(|provider| provider.provider()),
            );
            let mut listeners = assemble_authed_routers(
                context.config(),
                &token_profiles,
                &mut registry,
                &token_provider_bindings,
                auth_audit_sink,
                auth_audit_clock,
            )
            .context("assemble authed routers")?;

            // Route groups are drained before the reporter is taken, so readyz owns every domain
            // and runtime probe registered by WireDomains.
            let reporter = Arc::new(registry.take_health_reporter());
            let (listener, routes) =
                health_listener(reporter, metrics_exporter).context("build health listener")?;
            listeners.push(AssembledListener::plain(listener, routes));

            Ok(Finalized {
                context,
                pg_owner,
                deps,
                token_profiles,
                runtime_rss_access,
                runtime_federated_access,
                runtime_service_token,
                domain_transport,
                command_idempotency_keyring,
                pg_readiness_period,
                domain_module,
                listeners,
            })
        })();

        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
