use super::{DomainsWired, InfraBuilt, RuntimePhaseState, phase_result};
use crate::infra::oidc::{
    AccessTokenJwksReadyProbe, FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME,
    RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME,
};
use crate::infra::redis::{REDIS_READY_PROBE_NAME, RedisReadyProbe, spawn_redis_readiness_sampler};
use crate::infra::s3::wire_s3_canary;
use crate::infra::signing_rotation::RSS_ACCESS_TOKEN_SIGNING_ROTATION_PROBE_NAME;
use crate::{RLS_READY_PROBE_NAME, RlsReadyProbe, wire_auth_grant_sweeper};
use anyhow::{Context as _, Result};
use bootstrap::DomainModuleResult;
use diport::DynManagedResource;
use primitives::ProbeName;
use std::sync::Arc;

struct WiredDomains {
    registry: bootstrap::Registry,
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

impl<'a> InfraBuilt<'a> {
    pub(super) async fn wire_domains(self) -> anyhow::Result<<Self as RuntimePhaseState>::Next> {
        let InfraBuilt {
            context,
            mut provider_build,
            mut provider_factories,
            listener_execution_plan,
            rate_limiter,
            deps,
            s3_canary_config,
            wiring_inputs,
            domain_transport,
            metrics_exporter,
            redis_readiness_period,
            command_idempotency_keyring,
            signing_rotation_probe,
            runtime_rss_access,
            runtime_federated_access,
            runtime_service_token,
        } = self;
        let result = async {
            let super::infra::RuntimeWiringInputs {
                event_transport,
                event_worker,
                distributed_worker,
                domain_modules,
                audit_consumer_key,
                auth_grant_sweep_interval,
            } = wiring_inputs;

            // assembly.toml ordering becomes the live source through generated glue. Typed route
            // and subscriber handles enter Registry, never SharedRuntimeDeps or a service bag.
            // bootstrap 启动 tail-verify（跨租户全量巡检）defer 到 Part B；本 phase 仍只收窄
            // request/subscriber capability。
            let mut domain_bindings = match crate::modules_gen::wire_domains(&deps, domain_modules)
                .await
            {
                Ok(bindings) => bindings,
                Err(failure) => {
                    let (source, mut bindings) = failure.into_parts();
                    provider_build.record_domain(bootstrap::drain_binding_outputs(&mut bindings));
                    return Err(source).context("wire generated domains");
                }
            };
            let (mut registry, domains_module) =
                match bootstrap::compose_bindings(&mut domain_bindings) {
                    Ok(composed) => composed,
                    Err(source) => {
                        provider_build
                            .record_domain(bootstrap::drain_binding_outputs(&mut domain_bindings));
                        return Err(source).context("compose generated domains");
                    }
                };
            provider_build.record_domain(domains_module);
            validate_domain_listener_evidence(
                &listener_execution_plan,
                &registry.domain_listener_bindings(),
            )
            .context("validate runtime domain-listener evidence")?;

            let auth_grant_sweeper_module =
                wire_auth_grant_sweeper(&deps.pg, auth_grant_sweep_interval)
                    .context("wire AuthGrant sweeper")?;
            provider_build.record_domain(auth_grant_sweeper_module);
            let s3_canary_module =
                wire_s3_canary(&deps, s3_canary_config).context("wire s3 canary")?;
            provider_build.record_domain(s3_canary_module);
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
            if let Some(probe) = signing_rotation_probe {
                let name = ProbeName::parse(RSS_ACCESS_TOKEN_SIGNING_ROTATION_PROBE_NAME)
                    .context("parse RSS access signing rotation probe name")?;
                registry
                    .probe(name, Box::new(probe))
                    .context("register RSS access signing rotation probe")?;
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

            let distributed =
                crate::distributed_runtime::wire_distributed(&deps, distributed_worker)
                    .context("wire distributed")?;
            let event_subscribers = crate::event_transport::bridge_generated_subscriptions(
                registry.drain_subscribers(),
            )
            .context("bridge generated event subscriptions")?;
            let event_publisher_permit = provider_factories.event_publisher()?;
            let event_subscriber_permit = provider_factories.event_subscriber()?;
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
            provider_build
                .record(crate::provider_output::ProviderOutput::event(
                    event_module,
                    event_publisher_permit,
                    event_subscriber_permit,
                ))
                .context("record event provider output")?;

            let redis_for_sampler = deps.redis.clone();
            let redis_readiness_worker: bootstrap::WorkerSpec = Box::new(move |token| {
                DynManagedResource::new_box(spawn_redis_readiness_sampler(
                    redis_for_sampler.clone(),
                    redis_readiness_period,
                    token,
                    Arc::clone(&redis_ready),
                ))
            });
            provider_build.record_domain(DomainModuleResult {
                workers: vec![redis_readiness_worker],
                ..DomainModuleResult::default()
            });

            tracing::info!(
                sample_interval_secs = redis_readiness_period.as_secs(),
                "redis readiness sampler interval configured"
            );

            Result::<_, anyhow::Error>::Ok(WiredDomains { registry })
        }
        .await;

        let result = match result {
            Err(error) => Err(provider_build.abort(error).await),
            Ok(mut wired) => match provider_build.finish() {
                Err(failure) => Err(failure.abort().await),
                Ok(mut completed) => match completed.register_probes(&mut wired.registry) {
                    Err(error) => Err(completed.abort(error).await),
                    Ok(()) => Ok(DomainsWired {
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
                        registry: wired.registry,
                        provider_build: completed,
                    }),
                },
            },
        };

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
