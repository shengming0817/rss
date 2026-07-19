use super::{DomainsWired, Finalized, RuntimePhaseState, phase_result};
use crate::SystemClock;
use crate::routes::finalize_listener_plan;
use anyhow::Context as _;
use postgres::caps;
use std::sync::Arc;

impl<'a> DomainsWired<'a> {
    pub(super) async fn finalize(self) -> anyhow::Result<<Self as RuntimePhaseState>::Next> {
        let DomainsWired {
            context,
            listener_execution_plan,
            pg_owner,
            deps,
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
            let listeners = finalize_listener_plan(
                listener_execution_plan,
                context.config(),
                &mut registry,
                &token_provider_bindings,
                auth_audit_sink,
                auth_audit_clock,
                metrics_exporter,
            )
            .context("finalize RuntimePlan listeners")?;

            Ok(Finalized {
                context,
                pg_owner,
                deps,
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
