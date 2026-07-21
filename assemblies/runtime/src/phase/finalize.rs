use super::{DomainsWired, Finalized, RuntimePhaseState, phase_result};
use crate::SystemClock;
use crate::routes::{FinalizeListenerPlanInputs, finalize_listener_plan};
use anyhow::Context as _;
use postgres::caps;
use std::sync::Arc;

impl<'a> DomainsWired<'a> {
    pub(super) async fn finalize(self) -> anyhow::Result<<Self as RuntimePhaseState>::Next> {
        let DomainsWired {
            context,
            listener_execution_plan,
            rate_limiter,
            deps,
            runtime_rss_access,
            runtime_federated_access,
            runtime_service_token,
            domain_transport,
            command_idempotency_keyring,
            metrics_exporter,
            mut registry,
            provider_build,
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
            let listeners = finalize_listener_plan(FinalizeListenerPlanInputs {
                execution_plan: listener_execution_plan,
                config: context.config(),
                registry: &mut registry,
                providers: &token_provider_bindings,
                audit_sink: auth_audit_sink,
                audit_clock: auth_audit_clock,
                rate_limiter,
                metrics: metrics_exporter,
            })
            .context("finalize RuntimePlan listeners")?;

            Ok(listeners)
        })();
        let result = match result {
            Ok(listeners) => Ok(Finalized {
                context,
                provider_build,
                deps,
                runtime_rss_access,
                runtime_federated_access,
                runtime_service_token,
                domain_transport,
                command_idempotency_keyring,
                listeners,
            }),
            Err(error) => Err(provider_build.abort(error).await),
        };

        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
