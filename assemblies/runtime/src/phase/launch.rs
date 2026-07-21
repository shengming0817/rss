use super::{Finalized, RuntimeOutputs, RuntimePhaseState, phase_result};
use anyhow::Context as _;
use diport::DynManagedResource;

impl Finalized<'_> {
    pub(super) async fn launch(self) -> anyhow::Result<<Self as RuntimePhaseState>::Next> {
        let Finalized {
            mut context,
            provider_build,
            deps: _deps,
            runtime_rss_access: _runtime_rss_access,
            runtime_federated_access: _runtime_federated_access,
            runtime_service_token: _runtime_service_token,
            domain_transport: _domain_transport,
            command_idempotency_keyring: _command_idempotency_keyring,
            listeners,
        } = self;

        // Validate every fallible launch input while the completed provider transaction still owns
        // its resources. Only a launchable state may hand them to the unique ShutdownStack.
        let result = match crate::launch::server_request_budget(context.config())
            .context("resolve HTTP server request budget")
        {
            Err(error) => Err(provider_build.abort(error).await),
            Ok(request_budget) => {
                // This is the only Finalized consumer and the only phase allowed to construct
                // LaunchPlan. The top-level launch executor remains the sole ShutdownStack owner.
                let trace_exporter = context.take_trace_export().map(DynManagedResource::new_box);
                let (provider_module, domain_module) = provider_build.into_modules();
                let launch_plan = crate::launch::LaunchPlan::new(crate::launch::LaunchPlanParts {
                    listeners,
                    trace_exporter,
                    provider_module,
                    domain_module,
                });
                crate::launch::launch(context.config(), request_budget, launch_plan)
                    .await
                    .map(|()| RuntimeOutputs::completed())
            }
        };

        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
