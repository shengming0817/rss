use super::{
    DomainPhaseContext, Planned, ProvidersBuilt, RuntimePhaseState, TOKEN_MODULE_COMMITTED_ONCE,
    phase_result,
};
use crate::config::RuntimeServingConfig;
use crate::infra::oidc::{build_federated_access_provider, build_rss_access_provider};
use crate::providers_gen::ListenerPdpJwksLifecycle;
use anyhow::Context as _;
use tokio_util::sync::CancellationToken;

fn emit_typed_runtime_plan_loaded(
    assembly_fingerprint: &str,
    runtime_plan_fingerprint: &str,
    providers: usize,
    listeners: usize,
    domains: usize,
    placements: usize,
) {
    tracing::info!(
        assembly.fingerprint = assembly_fingerprint,
        runtime_plan.fingerprint = runtime_plan_fingerprint,
        runtime_plan.providers = providers,
        runtime_plan.listeners = listeners,
        runtime_plan.domains = domains,
        runtime_plan.placements = placements,
        "typed RuntimePlan loaded"
    );
}

struct UncommittedListenerPdpLifecycle {
    lifecycle: Option<ListenerPdpJwksLifecycle>,
    committed: bool,
}

impl UncommittedListenerPdpLifecycle {
    fn new() -> Self {
        Self {
            lifecycle: None,
            committed: false,
        }
    }

    fn add(&mut self, lifecycle: ListenerPdpJwksLifecycle) {
        if self.committed {
            unreachable!("{}", TOKEN_MODULE_COMMITTED_ONCE);
        }
        self.lifecycle = Some(match self.lifecycle.take() {
            Some(current) => current.merge(lifecycle),
            None => lifecycle,
        });
    }

    fn take(&mut self) -> Option<ListenerPdpJwksLifecycle> {
        if std::mem::replace(&mut self.committed, true) {
            unreachable!("{}", TOKEN_MODULE_COMMITTED_ONCE);
        }
        self.lifecycle.take()
    }

    fn take_or_default_module(&mut self) -> bootstrap::DomainModuleResult {
        if self.committed {
            bootstrap::DomainModuleResult::default()
        } else {
            self.committed = true;
            self.lifecycle
                .take()
                .map(ListenerPdpJwksLifecycle::into_output)
                .unwrap_or_default()
        }
    }
}

impl<'a> Planned<'a> {
    pub(super) async fn build_providers(self) -> anyhow::Result<<Self as RuntimePhaseState>::Next> {
        let runtime_plan = self.runtime_inputs.take_runtime_plan();
        let listener_execution_plan = runtime_plan.listener_execution_plan();
        let placement_execution_plan =
            runtime_plan.placement_execution_plan(self.runtime_inputs.config());
        placement_execution_plan
            .reject_remote_on_local_listeners(&listener_execution_plan)
            .context("validate placement against local listeners")?;
        let domain_execution_plan = runtime_plan.domain_execution_plan(&placement_execution_plan);
        let context =
            DomainPhaseContext::new(self.runtime_inputs, runtime_plan, domain_execution_plan);
        let typed_runtime_plan = context.runtime_plan.as_typed();
        let mut provider_build = crate::provider_output::ProviderBuild::from_plan(
            typed_runtime_plan.provider_plans(),
            crate::providers_gen::PROVIDER_CATALOG,
        )
        .context("join RuntimePlan with generated active provider catalog")?;
        self::emit_typed_runtime_plan_loaded(
            typed_runtime_plan.assembly_fingerprint().as_str(),
            typed_runtime_plan.runtime_plan_fingerprint().as_str(),
            typed_runtime_plan.provider_plans().len(),
            typed_runtime_plan.listener_plans().len(),
            typed_runtime_plan.domain_plans().len(),
            typed_runtime_plan.placement_plans().len(),
        );
        let mut provider_factories = crate::provider_output::ProviderFactoryDispatch::from_catalog(
            &mut provider_build,
            crate::providers_gen::PROVIDER_CATALOG,
        )
        .context("dispatch generated active provider catalog")?;
        let mut uncommitted_token_lifecycle = self::UncommittedListenerPdpLifecycle::new();
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
            let listener_pdp_constructor = provider_factories.listener_pdp()?;

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
                uncommitted_token_lifecycle.add(
                    crate::infra::oidc::build_rss_listener_pdp_jwks_lifecycle(provider),
                );
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
            if let Some(provider) = runtime_federated_access.as_ref() {
                uncommitted_token_lifecycle
                    .add(crate::infra::oidc::build_federated_listener_pdp_jwks_lifecycle(provider));
            }
            let Some(token_lifecycle) = uncommitted_token_lifecycle.take() else {
                anyhow::bail!("listener PDP requires an active profile-specific JWKS lifecycle");
            };
            provider_build
                .record(crate::provider_output::commit_listener_pdp_jwks_lifecycle(
                    listener_pdp_constructor,
                    token_lifecycle,
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
                    placement_execution_plan,
                    rate_limiter,
                    serving_config,
                    runtime_rss_access,
                    runtime_federated_access,
                })
            }
            Err(error) => {
                let module = uncommitted_token_lifecycle.take_or_default_module();
                Err(provider_build.abort_with(module, error).await)
            }
        };
        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
