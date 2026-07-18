use super::{PhaseContext, Planned, ProvidersBuilt, RuntimePhaseState, phase_result};
use crate::config::RuntimeServingConfig;
use crate::infra::oidc::{build_federated_access_provider, build_rss_access_provider};
use anyhow::Context as _;
use tokio_util::sync::CancellationToken;

impl<'a> Planned<'a> {
    pub(super) async fn build_providers(self) -> anyhow::Result<<Self as RuntimePhaseState>::Next> {
        let result = async move {
            let runtime_plan = crate::plan::RuntimePlan::bundled(self.runtime_inputs.config())
                .context("build RuntimePlan")?;
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

            Ok(ProvidersBuilt {
                context,
                serving_config,
                runtime_rss_access,
                runtime_federated_access,
            })
        }
        .await;

        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
