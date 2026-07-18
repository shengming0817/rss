use super::{Finalized, RuntimeOutputs, RuntimePhaseState, phase_result};
use anyhow::Context as _;
use diport::DynManagedResource;

impl Finalized<'_> {
    pub(super) async fn launch(self) -> anyhow::Result<<Self as RuntimePhaseState>::Next> {
        let Finalized {
            mut context,
            pg_owner,
            deps: _deps,
            token_profiles: _token_profiles,
            runtime_rss_access: _runtime_rss_access,
            runtime_federated_access: _runtime_federated_access,
            runtime_service_token: _runtime_service_token,
            domain_transport: _domain_transport,
            command_idempotency_keyring: _command_idempotency_keyring,
            pg_readiness_period,
            domain_module,
            listeners,
        } = self;

        let result = async move {
            // Validate every fallible launch input while the outer lifecycle owner still owns
            // trace. Only a launchable state may hand resources to the unique ShutdownStack.
            let request_budget = crate::launch::server_request_budget(context.config())
                .context("resolve HTTP server request budget")?;

            // This is the only Finalized consumer and the only phase allowed to construct
            // LaunchPlan. The top-level launch executor remains the sole ShutdownStack owner.
            let trace_exporter = context.take_trace_export().map(DynManagedResource::new_box);
            let pg_runtime_module =
                crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period);
            let launch_plan = crate::launch::LaunchPlan::new(crate::launch::LaunchPlanParts {
                listeners,
                trace_exporter,
                pg_runtime_module,
                domain_module,
            });
            crate::launch::launch(context.config(), request_budget, launch_plan)
                .await
                .map(|()| RuntimeOutputs::completed())
        }
        .await;

        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
