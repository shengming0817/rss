use super::maintenance::{
    RLS_READY_PROBE_NAME, RlsReadyProbe, wire_auth_grant_sweeper, wire_saga_terminal_sweeper,
};
use super::{DomainsWired, InfraBuilt, RuntimePhaseState, phase_result};
use crate::infra::s3::wire_s3_canary;
use crate::infra::signing_rotation::RSS_ACCESS_TOKEN_SIGNING_ROTATION_PROBE_NAME;
use anyhow::{Context as _, Result};
use primitives::ProbeName;
use std::sync::Arc;

fn register_runtime_security_root(
    registry: &mut bootstrap::Registry,
    authorizer: Arc<dyn httpserve::RouteAuthorizer>,
) -> anyhow::Result<()> {
    registry
        .register_primary_authorizer(authorizer)
        .context("register runtime security-root contract authorizer")
}

fn wire_runtime_security_root(
    _execution: crate::plan::RuntimeSecurityExecutionPlan,
    registry: &mut bootstrap::Registry,
    pg: &postgres::PgRuntimeHandle,
    clock: Arc<dyn diport::Clock>,
    auth_grant_sweep_interval: std::time::Duration,
    write_admission: &primitives::WriteAdmission,
) -> anyhow::Result<bootstrap::DomainModuleResult> {
    let identity_pg = pg.for_domain::<postgres::caps::Identity>();
    register_runtime_security_root(
        registry,
        identity_composition::root_contract_authorizer(&identity_pg, clock),
    )?;
    wire_auth_grant_sweeper(pg, auth_grant_sweep_interval, write_admission)
        .context("wire process-owned AuthGrant security maintenance")
}

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
    actual: &[bootstrap::DomainListenerBinding],
) -> anyhow::Result<()> {
    validate_binding_projection(
        plan,
        crate::modules_gen::DOMAIN_LISTENER_BINDINGS,
        "generated",
        BindingEvidenceMode::GeneratedManifest,
    )?;
    validate_binding_projection(plan, actual, "live", BindingEvidenceMode::LiveOmitRemote)?;
    Ok(())
}

fn validate_binding_projection(
    plan: &crate::plan::ListenerExecutionPlan,
    bindings: &[bootstrap::DomainListenerBinding],
    source: &'static str,
    mode: BindingEvidenceMode,
) -> anyhow::Result<()> {
    let listeners = match mode {
        BindingEvidenceMode::GeneratedManifest => plan.declared_listeners(),
        BindingEvidenceMode::LiveOmitRemote => plan.listeners(),
    };
    let mut expected = listeners
        .iter()
        .flat_map(|listener| {
            listener
                .domains()
                .iter()
                .map(|domain| (listener.kind(), domain.as_str()))
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
            local_event_execution_plan,
            placement_execution_plan,
            rate_limiter,
            trusted_proxy_config,
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
            admission_identity,
            admission_control,
            relay_admission,
            consumer_admission,
            write_admission,
        } = self;
        let (mut context, domain_execution_plan, security_execution_plan) = context.into_parts();
        let result = async {
            let super::infra::RuntimeWiringInputs {
                event_transport,
                event_worker,
                distributed_worker,
                domain_modules,
                local_domain_providers,
                audit_consumer_key,
                auth_grant_sweep_interval,
            } = wiring_inputs;

            // assembly.toml ordering becomes the live source through generated glue. Typed route
            // and subscriber handles enter Registry, never SharedRuntimeDeps or a service bag.
            // bootstrap 启动 tail-verify（跨租户全量巡检）defer 到 Part B；本 phase 仍只收窄
            // request/subscriber capability。
            let domain_bindings = match crate::modules_gen::wire_domains(
                &deps,
                local_domain_providers,
                domain_modules,
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
            registry
                .install_write_admission(write_admission.clone())
                .context("install runtime process write admission")?;
            provider_build.record_domain(domains_module);
            let security_root_module = wire_runtime_security_root(
                security_execution_plan,
                &mut registry,
                &deps.pg,
                Arc::new(crate::support::SystemClock),
                auth_grant_sweep_interval,
                &write_admission,
            )?;
            provider_build.record_domain(security_root_module);
            validate_domain_listener_evidence(
                &listener_execution_plan,
                &registry.domain_listener_bindings(),
            )
            .context("validate runtime domain-listener evidence")?;

            let s3_canary_module =
                wire_s3_canary(&deps, s3_canary_config).context("wire s3 canary")?;
            provider_build.record_domain(s3_canary_module);
            let (saga_module, active_saga_count) =
                crate::saga_runtime::bind_and_wire_selected_sagas(
                    &mut context.runtime_plan,
                    &write_admission,
                )
                .context("bind and wire plan-selected Saga providers")?;
            provider_build.record_domain(saga_module);
            let saga_retention_module =
                wire_saga_terminal_sweeper(&deps.pg, active_saga_count, &write_admission)
                    .context("wire terminal Saga retention")?;
            provider_build.record_domain(saga_retention_module);
            let rls_probe_name =
                ProbeName::parse(RLS_READY_PROBE_NAME).context("parse rls_ready probe name")?;
            registry
                .probe(
                    rls_probe_name,
                    Box::new(RlsReadyProbe::new(deps.pg.rls_ready_handle())),
                )
                .context("register rls_ready probe")?;
            if let Some(probe) = signing_rotation_probe {
                let name = ProbeName::parse(RSS_ACCESS_TOKEN_SIGNING_ROTATION_PROBE_NAME)
                    .context("parse RSS access signing rotation probe name")?;
                registry
                    .probe(name, Box::new(probe))
                    .context("register RSS access signing rotation probe")?;
            }
            let event_provider_permits =
                provider_factories.take_event_permits(&local_event_execution_plan)?;
            if let crate::provider_output::EventProviderPermits::Active {
                publisher,
                subscriber,
            } = event_provider_permits
            {
                let distributed =
                    crate::distributed_runtime::wire_distributed(&deps, distributed_worker)
                        .context("wire distributed")?;
                let event_subscribers =
                    crate::event_transport::bridge_generated_subscriptions_for_execution(
                        registry.drain_subscribers(),
                        &local_event_execution_plan,
                    )
                    .context("bridge generated event subscriptions")?;
                let event_module = crate::event_transport::wire_event_transport(
                    &deps.pg,
                    distributed,
                    event_subscribers,
                    event_transport,
                    event_worker.context("active local event execution lacks worker config")?,
                    audit_consumer_key,
                    relay_admission.clone(),
                    consumer_admission.clone(),
                    write_admission.clone(),
                )
                .await
                .context("wire event transport")?;
                provider_build
                    .record(crate::provider_output::ProviderOutput::event(
                        event_module,
                        publisher,
                        subscriber,
                    ))
                    .context("record event provider output")?;
            } else {
                anyhow::ensure!(
                    !local_event_execution_plan.is_active(),
                    "active local event execution omitted provider permits"
                );
                anyhow::ensure!(
                    registry.drain_subscribers().is_empty(),
                    "inactive local event execution retained subscriber bindings"
                );
            }
            let mut admission_module = bootstrap::DomainModuleResult::default();
            crate::event_transport::retain_admission_authority(
                deps.pg.clone(),
                admission_control,
                admission_identity,
                &mut admission_module,
            )?;
            provider_build.record_domain(admission_module);

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
                        trusted_proxy_config,
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
    use super::{validate_domain_listener_evidence, wire_runtime_security_root};
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
        let placement = runtime_plan
            .placement_execution_plan(bootstrap::Topology::Demo, snapshot.view())
            .expect("local placement plan");
        let listeners = runtime_plan.listener_execution_plan_for_placement(&placement);
        (listeners, placement)
    }

    #[allow(clippy::expect_used)]
    fn plan_with_remote_identity() -> (
        crate::plan::ListenerExecutionPlan,
        crate::plan::PlacementExecutionPlan,
        crate::plan::RuntimeSecurityExecutionPlan,
    ) {
        let merged = [
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
            ("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD", "peer-cell"),
            ("RSS_TOPOLOGY", "durable-shared"),
            (
                "RSS_IDENTITY_DOMAIN_TRANSPORT_URL",
                "https://identity.internal/rpc",
            ),
        ];
        let snapshot = test_snapshot(&merged).expect("remote identity snapshot");
        let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled RuntimePlan");
        let parts = runtime_plan
            .place(bootstrap::Topology::DurableShared, snapshot.view())
            .expect("remote placed runtime")
            .into_parts();
        (parts.listeners, parts.placement, parts.security)
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn identity_remote_keeps_the_runtime_security_root_fail_closed() {
        let (_listeners, placement, security) = plan_with_remote_identity();
        assert!(!placement.is_local(assembly_schema::AssemblyDomain::Identity));
        let mut registry = bootstrap::Registry::new();
        let pg = postgres::PgRuntimeHandle::for_module_test();
        let security_module = wire_runtime_security_root(
            security,
            &mut registry,
            &pg,
            std::sync::Arc::new(identity_composition::test_support::TestClock),
            std::time::Duration::from_secs(60),
            &primitives::prepare_dr_admission_controls().into_parts().3,
        )
        .expect("production-shaped process security root");
        let authorizer = registry
            .take_primary_authorizer()
            .expect("registered security root");
        let decision = authorizer
            .authorize(httpserve::RouteAuthorizationRequest {
                contract_id: generated::http::audit_v1::list_entries::SPEC
                    .route
                    .contract_id(),
                permission: vocab::AUDIT_READ_PERMISSION,
                tenant_id: None,
                principal_kind: rss_request_context::PrincipalKind::Service,
                principal_id: "remote-identity-security-root-test".to_owned(),
                federated_permissions: None,
                resource: None,
            })
            .await;
        assert_eq!(decision, httpserve::RouteAuthorizationDecision::Deny);
        let _ = crate::provider_output::abort_uncommitted(
            security_module,
            anyhow::anyhow!("test cleanup"),
        )
        .await;
    }

    #[test]
    fn listener_plan_rejects_missing_extra_wrong_duplicate_live_domains() {
        let (plan, _placement) = plan();
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
        // Order may differ between RuntimePlan kind-sort and assembly composition order.
        assert!(validate_domain_listener_evidence(&plan, &reordered).is_ok());
    }

    #[test]
    fn listener_plan_live_omits_remote_domains_ok_full_bindings_err() {
        let (plan, _placement, _security) = plan_with_remote_identity();
        let generated = crate::modules_gen::DOMAIN_LISTENER_BINDINGS;
        let live_omitted: Vec<_> = generated
            .iter()
            .copied()
            .filter(|binding| binding.domain != "identity")
            .collect();
        assert!(
            validate_domain_listener_evidence(&plan, &live_omitted).is_ok(),
            "live evidence must omit remote-placed identity"
        );
        assert!(
            validate_domain_listener_evidence(&plan, generated).is_err(),
            "live evidence still listing remote identity must fail"
        );
    }
}
