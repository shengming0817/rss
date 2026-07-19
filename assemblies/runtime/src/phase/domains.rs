use super::{DomainsWired, InfraBuilt, RuntimePhaseState, phase_result};
use crate::infra::oidc::{
    AccessTokenJwksReadyProbe, FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME,
    RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME,
};
use crate::infra::redis::{REDIS_READY_PROBE_NAME, RedisReadyProbe, spawn_redis_readiness_sampler};
use crate::infra::s3::wire_s3_canary;
use crate::{
    RLS_READY_PROBE_NAME, RlsReadyProbe, wire_service_token_replay_sweeper, wire_session_sweeper,
};
use anyhow::{Context as _, Result};
use bootstrap::DomainModuleResult;
use diport::DynManagedResource;
use primitives::ProbeName;
use std::sync::Arc;

pub(crate) struct RuntimeModuleAssemblyInputs {
    pub(crate) domains_module: DomainModuleResult,
    pub(crate) session_sweeper_module: DomainModuleResult,
    pub(crate) service_token_replay_sweeper_module: DomainModuleResult,
    pub(crate) s3_canary_module: DomainModuleResult,
    pub(crate) provider_module: DomainModuleResult,
    pub(crate) token_verifier_resources: Vec<Box<DynManagedResource<'static>>>,
    pub(crate) domain_transport_module: DomainModuleResult,
    pub(crate) event_module: DomainModuleResult,
    pub(crate) dlx_lifecycle_module: DomainModuleResult,
    pub(crate) redis_readiness_worker: bootstrap::WorkerSpec,
}

pub(crate) fn assemble_runtime_module_outputs(
    inputs: RuntimeModuleAssemblyInputs,
) -> DomainModuleResult {
    let mut module = DomainModuleResult::default();
    module.merge(inputs.domains_module);
    module.merge(inputs.session_sweeper_module);
    module.merge(inputs.service_token_replay_sweeper_module);
    module.merge(inputs.s3_canary_module);
    module.merge(inputs.provider_module);
    module.resources.extend(inputs.token_verifier_resources);
    module.merge(inputs.domain_transport_module);
    module.merge(inputs.event_module);
    module.merge(inputs.dlx_lifecycle_module);
    module.workers.push(inputs.redis_readiness_worker);
    module
}

pub(crate) fn validate_domain_listener_evidence(
    plan: &crate::plan::ListenerExecutionPlan,
    actual: &[bootstrap::DomainListenerBinding],
) -> anyhow::Result<()> {
    validate_binding_projection(
        plan,
        crate::modules_gen::DOMAIN_LISTENER_BINDINGS,
        "generated",
    )?;
    validate_binding_projection(plan, actual, "live")?;
    Ok(())
}

fn validate_binding_projection(
    plan: &crate::plan::ListenerExecutionPlan,
    bindings: &[bootstrap::DomainListenerBinding],
    source: &'static str,
) -> anyhow::Result<()> {
    let expected_count = plan
        .listeners()
        .iter()
        .map(|listener| listener.domains().len())
        .sum::<usize>();
    anyhow::ensure!(
        bindings.len() == expected_count,
        "{source} domain-listener binding count drifts from RuntimePlan: plan {expected_count}, {source} {}",
        bindings.len()
    );
    for listener in plan.listeners() {
        let actual_domains = bindings
            .iter()
            .filter(|binding| binding.listener == listener.kind())
            .map(|binding| binding.domain)
            .collect::<Vec<_>>();
        let expected_domains = listener
            .domains()
            .iter()
            .map(assembly_schema::AssemblyDomain::as_str)
            .collect::<Vec<_>>();
        anyhow::ensure!(
            actual_domains == expected_domains,
            "{source} domain order or placement drifts from RuntimePlan for listener {:?}",
            listener.kind()
        );
    }
    Ok(())
}

pub(crate) fn validate_provider_output_evidence() -> anyhow::Result<()> {
    let mut actual = crate::provider_output::provider_output_bindings();
    actual.extend_from_slice(crate::event_transport::PROVIDER_OUTPUT_BINDINGS);
    validate_provider_output_bindings(&actual)
}

pub(crate) fn validate_provider_output_bindings(
    actual: &[bootstrap::ProviderOutputBinding],
) -> anyhow::Result<()> {
    let mut actual = actual.to_vec();
    actual.sort_by_key(|binding| (binding.port, binding.provider, binding.consumer));
    let mut expected: Vec<_> = crate::modules_gen::PROVIDER_OUTPUT_BINDINGS
        .iter()
        .copied()
        .filter(|binding| !binding.channels.is_empty())
        .collect();
    expected.sort_by_key(|binding| (binding.port, binding.provider, binding.consumer));
    anyhow::ensure!(
        actual == expected,
        "runtime provider-output evidence drift: expected {}, observed {}",
        expected.len(),
        actual.len()
    );
    Ok(())
}

impl<'a> InfraBuilt<'a> {
    pub(super) async fn wire_domains(self) -> anyhow::Result<<Self as RuntimePhaseState>::Next> {
        let InfraBuilt {
            context,
            listener_execution_plan,
            pg_owner,
            deps,
            s3_canary_config,
            wiring_inputs,
            dlx_lifecycle,
            domain_transport,
            metrics_exporter,
            pg_readiness_period,
            redis_readiness_period,
            command_idempotency_keyring,
            runtime_rss_access,
            runtime_federated_access,
            runtime_service_token,
        } = self;
        let result = async move {
            let super::infra::RuntimeWiringInputs {
                event_transport,
                event_worker,
                dlx_worker,
                distributed_worker,
                domain_modules,
                audit_consumer_key,
                session_sweep_interval,
            } = wiring_inputs;

            // assembly.toml ordering becomes the live source through generated glue. Typed route
            // and subscriber handles enter Registry, never SharedRuntimeDeps or a service bag.
            // bootstrap 启动 tail-verify（跨租户全量巡检）defer 到 Part B；本 phase 仍只收窄
            // request/subscriber capability。
            let mut domain_bindings = crate::modules_gen::wire_domains(&deps, domain_modules)
                .await
                .context("wire generated domains")?;
            let (mut registry, domains_module) = bootstrap::compose_bindings(&mut domain_bindings)
                .context("compose generated domains")?;
            validate_domain_listener_evidence(
                &listener_execution_plan,
                &registry.domain_listener_bindings(),
            )
            .context("validate runtime domain-listener evidence")?;

            let session_sweeper_module = wire_session_sweeper(&deps.pg, session_sweep_interval)
                .context("wire session sweeper")?;
            let service_token_replay_sweeper_module =
                wire_service_token_replay_sweeper(&deps.pg)
                    .context("wire service-token replay sweeper")?;
            let s3_canary_module =
                wire_s3_canary(&deps, s3_canary_config).context("wire s3 canary")?;
            let provider_module = crate::provider_output::build_provider_module(&deps);
            validate_provider_output_evidence()
                .context("validate runtime provider-output evidence")?;
            let mut token_verifier_resources = Vec::new();
            if let Some(provider) = runtime_rss_access.as_ref() {
                token_verifier_resources.push(provider.managed_resource());
            }
            if let Some(provider) = runtime_federated_access.as_ref() {
                token_verifier_resources.push(provider.managed_resource());
            }
            if let Some(provider) = runtime_service_token.as_ref() {
                token_verifier_resources.push(provider.managed_resource());
            }

            let rls_probe_name =
                ProbeName::parse(RLS_READY_PROBE_NAME).context("parse rls_ready probe name")?;
            registry
                .probe(
                    rls_probe_name,
                    Box::new(RlsReadyProbe::new(deps.pg.rls_ready_handle())),
                )
                .context("register rls_ready probe")?;
            let redis_ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let redis_probe_name =
                ProbeName::parse(REDIS_READY_PROBE_NAME).context("parse redis_ready probe name")?;
            registry
                .probe(
                    redis_probe_name,
                    Box::new(RedisReadyProbe::new(Arc::clone(&redis_ready))),
                )
                .context("register redis_ready probe")?;
            if let Some(provider) = runtime_rss_access.as_ref() {
                let name = ProbeName::parse(RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME)
                    .context("parse RSS access-token JWKS probe name")?;
                registry
                    .probe(
                        name,
                        Box::new(AccessTokenJwksReadyProbe::rss_access(
                            provider.jwks_readiness(),
                        )),
                    )
                    .context("register RSS access-token JWKS readiness probe")?;
            }
            if let Some(provider) = runtime_federated_access.as_ref() {
                let name = ProbeName::parse(FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME)
                    .context("parse federated access-token JWKS probe name")?;
                registry
                    .probe(
                        name,
                        Box::new(AccessTokenJwksReadyProbe::federated_access(
                            provider.jwks_readiness(),
                        )),
                    )
                    .context("register federated access-token JWKS readiness probe")?;
            }

            let domain_transport_module = domain_transport
                .module_result()
                .context("wire outbound domain transport module")?;
            let distributed =
                crate::distributed_runtime::wire_distributed(&deps, distributed_worker)
                    .context("wire distributed")?;
            let event_subscribers = crate::event_transport::bridge_generated_subscriptions(
                registry.drain_subscribers(),
            )
            .context("bridge generated event subscriptions")?;
            let event_module = crate::event_transport::wire_event_transport(
                &deps.pg,
                distributed,
                event_subscribers,
                event_transport,
                event_worker,
                audit_consumer_key,
            )
            .await
            .context("wire event transport")?;
            let dlx_lifecycle_module =
                crate::event_transport::wire_dlx_lifecycle(dlx_lifecycle, dlx_worker)
                    .context("wire DLX lifecycle")?;

            let redis_for_sampler = deps.redis.clone();
            let redis_readiness_worker: bootstrap::WorkerSpec = Box::new(move |token| {
                DynManagedResource::new_box(spawn_redis_readiness_sampler(
                    redis_for_sampler.clone(),
                    redis_readiness_period,
                    token,
                    Arc::clone(&redis_ready),
                ))
            });
            let mut module = assemble_runtime_module_outputs(RuntimeModuleAssemblyInputs {
                domains_module,
                session_sweeper_module,
                service_token_replay_sweeper_module,
                s3_canary_module,
                provider_module,
                token_verifier_resources,
                domain_transport_module,
                event_module,
                dlx_lifecycle_module,
                redis_readiness_worker,
            });

            // Module probes must enter Registry before Finalize takes the health reporter.
            for (name, probe) in std::mem::take(&mut module.probes) {
                let probe_label = name.as_str().to_owned();
                registry
                    .probe(name, probe)
                    .with_context(|| format!("register module probe '{probe_label}'"))?;
            }

            tracing::info!(
                sample_interval_secs = pg_readiness_period.as_secs(),
                "pg readiness sampler interval configured"
            );
            tracing::info!(
                sample_interval_secs = redis_readiness_period.as_secs(),
                "redis readiness sampler interval configured"
            );

            Result::<_, anyhow::Error>::Ok(DomainsWired {
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
                registry,
                domain_module: module,
            })
        }
        .await;

        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}

#[cfg(test)]
mod listener_plan_tests {
    use super::validate_domain_listener_evidence;

    #[allow(clippy::expect_used)]
    fn plan() -> crate::plan::ListenerExecutionPlan {
        let snapshot = crate::config::test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ])
        .expect("listener plan snapshot");
        crate::plan::RuntimePlan::bundled(snapshot.view())
            .expect("bundled RuntimePlan")
            .listener_execution_plan()
    }

    #[test]
    fn listener_plan_rejects_missing_extra_wrong_duplicate_and_reordered_live_domains() {
        let plan = plan();
        let expected = crate::modules_gen::DOMAIN_LISTENER_BINDINGS;
        assert!(validate_domain_listener_evidence(&plan, expected).is_ok());

        let missing = &expected[1..];
        assert!(validate_domain_listener_evidence(&plan, missing).is_err());

        let mut duplicate = expected.to_vec();
        duplicate.push(expected[0]);
        assert!(validate_domain_listener_evidence(&plan, &duplicate).is_err());

        let mut wrong_listener = expected.to_vec();
        wrong_listener[0].listener = primitives::ListenerKind::Admin;
        assert!(validate_domain_listener_evidence(&plan, &wrong_listener).is_err());

        let mut wrong_domain = expected.to_vec();
        wrong_domain[0].domain = "audit";
        assert!(validate_domain_listener_evidence(&plan, &wrong_domain).is_err());

        let mut reordered = expected.to_vec();
        reordered.reverse();
        assert!(validate_domain_listener_evidence(&plan, &reordered).is_err());
    }
}
