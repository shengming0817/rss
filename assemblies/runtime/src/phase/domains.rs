use super::maintenance::{RLS_READY_PROBE_NAME, RlsReadyProbe, wire_auth_grant_sweeper};
use super::{DomainsWired, InfraBuilt, RuntimePhaseState, phase_result};
use crate::infra::oidc::{
    AccessTokenJwksReadyProbe, FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME,
    RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME,
};
use crate::infra::s3::wire_s3_canary;
use crate::infra::signing_rotation::RSS_ACCESS_TOKEN_SIGNING_ROTATION_PROBE_NAME;
use anyhow::{Context as _, Result};
use primitives::ProbeName;

struct WiredDomains {
    registry: bootstrap::Registry,
}

/// How domain-listener evidence is projected against RuntimePlan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingEvidenceMode {
    /// Generated manifest must list every plan domain on its listener (including remote-placed).
    GeneratedManifest,
    /// Live registry omits remote-placed domains (they are not composed locally).
    LiveOmitRemote,
}

pub(crate) fn validate_domain_listener_evidence(
    plan: &crate::plan::ListenerExecutionPlan,
    placement: &crate::plan::PlacementExecutionPlan,
    actual: &[bootstrap::DomainListenerBinding],
) -> anyhow::Result<()> {
    validate_binding_projection(
        plan,
        placement,
        crate::modules_gen::DOMAIN_LISTENER_BINDINGS,
        "generated",
        BindingEvidenceMode::GeneratedManifest,
    )?;
    validate_binding_projection(
        plan,
        placement,
        actual,
        "live",
        BindingEvidenceMode::LiveOmitRemote,
    )?;
    Ok(())
}

fn validate_binding_projection(
    plan: &crate::plan::ListenerExecutionPlan,
    placement: &crate::plan::PlacementExecutionPlan,
    bindings: &[bootstrap::DomainListenerBinding],
    source: &'static str,
    mode: BindingEvidenceMode,
) -> anyhow::Result<()> {
    let mut expected = plan
        .listeners()
        .iter()
        .flat_map(|listener| {
            listener.domains().iter().filter_map(|domain| {
                if matches!(mode, BindingEvidenceMode::LiveOmitRemote)
                    && !placement.is_local(*domain)
                {
                    return None;
                }
                Some((listener.kind(), domain.as_str()))
            })
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        bindings.len() == expected.len(),
        "{source} domain-listener binding count drifts from RuntimePlan: plan {}, {source} {}",
        expected.len(),
        bindings.len()
    );
    // Bijection is order-independent: RuntimePlan sorts listeners by kind, while generated /
    // live glue may retain assembly.toml composition order.
    for binding in bindings {
        let Some(pos) = expected.iter().position(|(listener_kind, domain)| {
            binding.listener == *listener_kind && binding.domain == *domain
        }) else {
            anyhow::bail!(
                "{source} domain-listener binding drifts from RuntimePlan: listener={:?} domain={}",
                binding.listener,
                binding.domain
            );
        };
        expected.swap_remove(pos);
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
            placement_execution_plan,
            rate_limiter,
            deps,
            s3_canary_config,
            wiring_inputs,
            domain_transport,
            metrics_exporter,
            command_idempotency_keyring,
            signing_rotation_probe,
            runtime_rss_access,
            runtime_federated_access,
            runtime_service_token,
        } = self;
        let (context, domain_execution_plan) = context.into_parts();
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
            let domain_bindings = match crate::modules_gen::wire_domains(
                &deps,
                domain_modules,
                &placement_execution_plan,
            )
            .await
            {
                Ok(bindings) => bindings,
                Err(failure) => {
                    let (source, mut bindings) = failure.into_parts();
                    provider_build.record_domain(bootstrap::drain_binding_outputs(&mut bindings));
                    return Err(source).context("wire generated domains");
                }
            };
            let validated_domain_bindings = match domain_execution_plan.validate(domain_bindings) {
                Ok(bindings) => bindings,
                Err(failure) => {
                    let (source, mut bindings) = failure.into_parts();
                    provider_build.record_domain(bootstrap::drain_binding_outputs(&mut bindings));
                    return Err(source).context("validate generated domains against RuntimePlan");
                }
            };
            let (mut registry, domains_module) = match validated_domain_bindings.compose() {
                Ok(composed) => composed,
                Err(failure) => {
                    let (source, mut bindings) = failure.into_parts();
                    provider_build.record_domain(bootstrap::drain_binding_outputs(&mut bindings));
                    return Err(source).context("compose generated domains");
                }
            };
            provider_build.record_domain(domains_module);
            validate_domain_listener_evidence(
                &listener_execution_plan,
                &placement_execution_plan,
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
                        placement_execution_plan,
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
    use crate::config::test_snapshot;
    use crate::plan::RuntimePlan;

    #[allow(clippy::expect_used)]
    fn plan() -> (
        crate::plan::ListenerExecutionPlan,
        crate::plan::PlacementExecutionPlan,
    ) {
        let snapshot = test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ])
        .expect("listener plan snapshot");
        let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled RuntimePlan");
        (
            runtime_plan.listener_execution_plan(),
            runtime_plan.placement_execution_plan(snapshot.view()),
        )
    }

    #[allow(clippy::expect_used)]
    fn plan_with_remote_identity() -> (
        crate::plan::ListenerExecutionPlan,
        crate::plan::PlacementExecutionPlan,
    ) {
        let merged = [
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
            ("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD", "peer-cell"),
        ];
        let snapshot = test_snapshot(&merged).expect("remote identity snapshot");
        let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled RuntimePlan");
        (
            runtime_plan.listener_execution_plan(),
            runtime_plan.placement_execution_plan(snapshot.view()),
        )
    }

    #[test]
    fn listener_plan_rejects_missing_extra_wrong_duplicate_live_domains() {
        let (plan, placement) = plan();
        let expected = crate::modules_gen::DOMAIN_LISTENER_BINDINGS;
        assert!(validate_domain_listener_evidence(&plan, &placement, expected).is_ok());

        let missing = &expected[1..];
        assert!(validate_domain_listener_evidence(&plan, &placement, missing).is_err());

        let mut duplicate = expected.to_vec();
        duplicate.push(expected[0]);
        assert!(validate_domain_listener_evidence(&plan, &placement, &duplicate).is_err());

        let mut wrong_listener = expected.to_vec();
        wrong_listener[0].listener = primitives::ListenerKind::Admin;
        assert!(validate_domain_listener_evidence(&plan, &placement, &wrong_listener).is_err());

        let mut wrong_domain = expected.to_vec();
        wrong_domain[0].domain = "audit";
        assert!(validate_domain_listener_evidence(&plan, &placement, &wrong_domain).is_err());

        let mut reordered = expected.to_vec();
        reordered.reverse();
        // Order may differ between RuntimePlan kind-sort and assembly composition order.
        assert!(validate_domain_listener_evidence(&plan, &placement, &reordered).is_ok());
    }

    #[test]
    fn listener_plan_live_omits_remote_domains_ok_full_bindings_err() {
        let (plan, placement) = plan_with_remote_identity();
        let generated = crate::modules_gen::DOMAIN_LISTENER_BINDINGS;
        let live_omitted: Vec<_> = generated
            .iter()
            .copied()
            .filter(|binding| binding.domain != "identity")
            .collect();
        assert!(
            validate_domain_listener_evidence(&plan, &placement, &live_omitted).is_ok(),
            "live evidence must omit remote-placed identity"
        );
        assert!(
            validate_domain_listener_evidence(&plan, &placement, generated).is_err(),
            "live evidence still listing remote identity must fail"
        );
    }
}
