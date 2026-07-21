use super::{
    PhaseContext, Planned, ProvidersBuilt, RuntimePhaseState, TOKEN_MODULE_COMMITTED_ONCE,
    UncommittedModule, phase_result,
};
use crate::config::RuntimeServingConfig;
use crate::infra::oidc::{build_federated_access_provider, build_rss_access_provider};
use anyhow::Context as _;
use tokio_util::sync::CancellationToken;

impl<'a> Planned<'a> {
    pub(super) async fn build_providers(self) -> anyhow::Result<<Self as RuntimePhaseState>::Next> {
        let runtime_plan = crate::plan::RuntimePlan::bundled(self.runtime_inputs.config())
            .context("build RuntimePlan")?;
        let listener_execution_plan = runtime_plan.listener_execution_plan();
        let context = PhaseContext::new(self.runtime_inputs, runtime_plan);
        let typed_runtime_plan = context.runtime_plan.as_typed();
        tracing::info!(
            assembly.fingerprint = typed_runtime_plan.assembly_fingerprint().as_str(),
            runtime_plan.fingerprint = typed_runtime_plan.runtime_plan_fingerprint().as_str(),
            runtime_plan.providers = typed_runtime_plan.provider_plans().len(),
            runtime_plan.listeners = typed_runtime_plan.listener_plans().len(),
            runtime_plan.domains = typed_runtime_plan.domain_plans().len(),
            runtime_plan.placements = typed_runtime_plan.placement_plans().len(),
            "typed RuntimePlan loaded"
        );
        let mut provider_build = crate::provider_output::ProviderBuild::from_plan(
            typed_runtime_plan.provider_plans(),
            crate::providers_gen::PROVIDER_CATALOG,
        )
        .context("join RuntimePlan with generated active provider catalog")?;
        let mut provider_factories = crate::provider_output::ProviderFactoryDispatch::from_catalog(
            &mut provider_build,
            crate::providers_gen::PROVIDER_CATALOG,
        )
        .context("dispatch generated active provider catalog")?;
        let mut uncommitted_token_module = UncommittedModule::new(TOKEN_MODULE_COMMITTED_ONCE);
        let result = async {
            let rate_limiter_permit = provider_factories.listener_rate_limiter()?;
            let rate_limiter = crate::routes::build_runtime_rate_limiter();
            provider_build
                .record(
                    crate::provider_output::ProviderOutput::listener_rate_limiter(
                        rate_limiter_permit,
                    ),
                )
                .context("record listener rate-limiter provider output")?;
            let listener_pdp_permit = provider_factories.listener_pdp()?;

            let config = context.config();
            let serving_config = RuntimeServingConfig::from_snapshot(config)
                .context("build snapshot-backed serving config")?
                .into_parts();
            let token_profiles = &serving_config.token_profiles;
            let (rss_key_isolation, federated_key_isolation) =
                if token_profiles.rss_access().is_some()
                    && token_profiles.federated_access().is_some()
                {
                    let generation = oidc::AccessJwksKeyIsolationGeneration::new();
                    let (rss, federated) = generation.into_bindings();
                    (Some(rss), Some(federated))
                } else {
                    (None, None)
                };
            let runtime_rss_access = token_profiles
                .rss_access()
                .map(|config| {
                    build_rss_access_provider(config, CancellationToken::new(), rss_key_isolation)
                        .context("build RSS access-token verifier")
                })
                .transpose()?;
            if let Some(provider) = runtime_rss_access.as_ref() {
                uncommitted_token_module
                    .get_mut()
                    .resources
                    .push(provider.managed_resource());
            }
            let runtime_federated_access = token_profiles
                .federated_access()
                .map(|config| {
                    build_federated_access_provider(
                        config,
                        CancellationToken::new(),
                        federated_key_isolation,
                    )
                    .context("build federated access-token verifier")
                })
                .transpose()?;
            let token_provider_module = uncommitted_token_module.get_mut();
            if let Some(provider) = runtime_federated_access.as_ref() {
                token_provider_module
                    .resources
                    .push(provider.managed_resource());
            }
            let token_provider_module = uncommitted_token_module.take();
            provider_build
                .record(crate::provider_output::ProviderOutput::listener_pdp(
                    token_provider_module,
                    listener_pdp_permit,
                ))
                .context("record listener PDP provider output")?;

            Ok((
                rate_limiter,
                serving_config,
                runtime_rss_access,
                runtime_federated_access,
            ))
        }
        .await;

        let result = match result {
            Ok((rate_limiter, serving_config, runtime_rss_access, runtime_federated_access)) => {
                Ok(ProvidersBuilt {
                    context,
                    provider_build,
                    provider_factories,
                    listener_execution_plan,
                    rate_limiter,
                    serving_config,
                    runtime_rss_access,
                    runtime_federated_access,
                })
            }
            Err(error) => {
                let module = uncommitted_token_module.take_or_default();
                Err(provider_build.abort_with(module, error).await)
            }
        };
        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
