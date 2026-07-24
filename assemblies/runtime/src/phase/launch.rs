use super::{Finalized, RuntimePhaseState, phase_result};
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
            probe_receipt,
        } = self;

        // Validate every fallible launch input while the completed provider transaction still owns
        // its resources. Only a launchable state may hand them to the unique ShutdownStack.
        let result = match crate::launch::server_request_budget(context.config())
            .context("resolve HTTP server request budget")
        {
            Err(error) => Err(provider_build.abort(error).await),
            Ok(request_budget) => {
                // This is the only Finalized consumer and the only phase allowed to construct the
                // shared kernel's single-use launch plan.
                let trace_exporter = context.take_trace_export().map(DynManagedResource::new_box);
                let lifecycle_batches = provider_build.into_launch_batches();
                let config = context.config();
                let adapter = crate::launch::RuntimeLaunchAdapter::new(
                    listeners,
                    request_budget,
                    move |listener, scheme| {
                        crate::listeners::listener_addr_for_scheme(config, listener, scheme)
                    },
                );
                let launch_plan = runtimeexec::LaunchPlan::new(
                    adapter,
                    probe_receipt,
                    |inventory| async move { crate::launch::log_ready(inventory) },
                    trace_exporter,
                    lifecycle_batches,
                    crate::launch::total_drain_budget()?,
                );
                runtimeexec::launch(launch_plan).await
            }
        };

        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
