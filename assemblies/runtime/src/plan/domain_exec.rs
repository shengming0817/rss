//! Plan-owned local domain composition capability.

use assembly_schema::AssemblyDomain;
use bootstrap::{DomainBinding, DomainModuleResult, Registry};

/// Exact declaration-ordered set of domains that this process may compose locally.
///
/// INVARIANT: RUNTIME-DOMAIN-PLAN-EXECUTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private expected-domain fields, RuntimePlan-only mint, consuming DomainBinding validation, and private ValidatedDomainBindings compose handoff" } -- generated domain bindings cannot enter the canonical composition helper until their names exactly equal the RuntimePlan declaration filtered by the plan-owned local placement projection.
pub(crate) struct DomainExecutionPlan {
    local_domains: Vec<AssemblyDomain>,
}

/// Domain bindings whose live names exactly match the plan-owned local projection.
pub(crate) struct ValidatedDomainBindings {
    bindings: Vec<DomainBinding>,
}

/// Validation or composition failure that retains every constructed binding for rollback.
pub(crate) struct DomainBindingFailure {
    source: anyhow::Error,
    bindings: Vec<DomainBinding>,
}

impl DomainExecutionPlan {
    /// Consume generated bindings and close their live membership against plan declarations.
    pub(crate) fn validate(
        self,
        bindings: Vec<DomainBinding>,
    ) -> Result<ValidatedDomainBindings, DomainBindingFailure> {
        let expected = self
            .local_domains
            .iter()
            .map(AssemblyDomain::as_str)
            .collect::<Vec<_>>();
        let actual = bindings.iter().map(DomainBinding::name).collect::<Vec<_>>();
        if actual != expected {
            return Err(DomainBindingFailure {
                source: anyhow::anyhow!(
                    "domain bindings drift from RuntimePlan local projection: expected {expected:?}, actual {actual:?}"
                ),
                bindings,
            });
        }
        Ok(ValidatedDomainBindings { bindings })
    }

    #[cfg(test)]
    pub(crate) fn local_domains(&self) -> &[AssemblyDomain] {
        &self.local_domains
    }
}

impl ValidatedDomainBindings {
    /// The sole runtime handoff into bootstrap's canonical binding composition helper.
    pub(crate) fn compose(
        mut self,
    ) -> Result<(Registry, DomainModuleResult), DomainBindingFailure> {
        match bootstrap::compose_bindings(&mut self.bindings) {
            Ok(composed) => Ok(composed),
            Err(source) => Err(DomainBindingFailure {
                source: source.into(),
                bindings: self.bindings,
            }),
        }
    }
}

impl DomainBindingFailure {
    pub(crate) fn into_parts(self) -> (anyhow::Error, Vec<DomainBinding>) {
        (self.source, self.bindings)
    }
}

impl std::fmt::Debug for DomainBindingFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DomainBindingFailure")
            .field("source", &self.source)
            .field(
                "bindings",
                &self
                    .bindings
                    .iter()
                    .map(DomainBinding::name)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

pub(super) fn mint(
    plan: &assembly_schema::RuntimePlan,
    placement: &super::PlacementExecutionPlan,
) -> DomainExecutionPlan {
    let local_domains = plan
        .domain_plans()
        .iter()
        .map(assembly_schema::DomainPlan::id)
        .filter(|domain| placement.is_local(*domain))
        .collect();
    DomainExecutionPlan { local_domains }
}

#[cfg(test)]
pub(crate) fn render_live_inventory_for_test(
    runtime_plan: &super::RuntimePlan,
    local_domains: &[AssemblyDomain],
    placement: &super::PlacementExecutionPlan,
    live_domain_names: &[&str],
    live_listener_bindings: &[bootstrap::DomainListenerBinding],
) -> anyhow::Result<String> {
    use assembly_schema::ListenerAuth;

    fn auth_label(auth: ListenerAuth) -> &'static str {
        match auth {
            ListenerAuth::NoAuth => "no-auth",
            ListenerAuth::RssAccessToken => "rss-access-token",
            ListenerAuth::FederatedAccessToken => "federated-access-token",
            ListenerAuth::Mtls => "mtls",
            ListenerAuth::ServiceToken => "service-token",
        }
    }

    fn listener_label(listener: primitives::ListenerKind) -> anyhow::Result<&'static str> {
        match listener {
            primitives::ListenerKind::Primary => Ok("primary"),
            primitives::ListenerKind::Internal => Ok("internal"),
            primitives::ListenerKind::Health => Ok("health"),
            primitives::ListenerKind::Admin => Ok("admin"),
            _ => anyhow::bail!("unknown ListenerKind cannot enter live inventory"),
        }
    }

    fn write_set(output: &mut String, label: &str, values: Vec<String>) {
        output.push_str(label);
        output.push_str("=[");
        output.push_str(&values.join(","));
        output.push_str("]\n");
    }

    let typed = runtime_plan.as_typed();
    let mut output = String::from("runtime-plan-live-inventory-v1\n");
    write_set(
        &mut output,
        "provider.declared",
        typed
            .provider_plans()
            .iter()
            .map(|provider| provider.id().to_owned())
            .collect(),
    );
    write_set(
        &mut output,
        "provider.active",
        crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .map(|entry| entry.role().as_str().to_owned())
            .collect(),
    );
    write_set(
        &mut output,
        "provider.live-consumers",
        crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .map(|entry| {
                let evidence = entry.evidence();
                let channels = evidence
                    .outputs()
                    .iter()
                    .map(|channel| channel.as_str())
                    .collect::<Vec<_>>()
                    .join("+");
                format!(
                    "{}=>{}{{{channels}}}",
                    entry.role().as_str(),
                    entry.factory().as_str(),
                )
            })
            .collect(),
    );
    write_set(
        &mut output,
        "listener.plan",
        typed
            .listener_plans()
            .iter()
            .map(|listener| {
                let domains = listener
                    .domains()
                    .iter()
                    .map(|domain| domain.as_str())
                    .collect::<Vec<_>>()
                    .join("+");
                format!(
                    "{}:{}:{}{{{domains}}}",
                    listener.id(),
                    listener.kind().as_str(),
                    auth_label(listener.auth())
                )
            })
            .collect(),
    );
    write_set(
        &mut output,
        "listener.generated",
        crate::modules_gen::DOMAIN_LISTENER_BINDINGS
            .iter()
            .map(|binding| {
                Ok(format!(
                    "{}:{}",
                    listener_label(binding.listener)?,
                    binding.domain
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
    );
    write_set(
        &mut output,
        "listener.live",
        live_listener_bindings
            .iter()
            .map(|binding| {
                Ok(format!(
                    "{}:{}",
                    listener_label(binding.listener)?,
                    binding.domain
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
    );
    write_set(
        &mut output,
        "domain.declared",
        typed
            .domain_plans()
            .iter()
            .map(|domain| domain.id().as_str().to_owned())
            .collect(),
    );
    write_set(
        &mut output,
        "domain.local",
        local_domains
            .iter()
            .map(|domain| domain.as_str().to_owned())
            .collect(),
    );
    write_set(
        &mut output,
        "domain.live",
        live_domain_names
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
    );
    write_set(
        &mut output,
        "placement.declared",
        typed
            .placement_plans()
            .iter()
            .map(|placement| format!("{}@{}", placement.domain().as_str(), placement.workload()))
            .collect(),
    );
    write_set(
        &mut output,
        "placement.local",
        placement
            .placements()
            .iter()
            .filter(|spec| spec.is_local())
            .map(|spec| spec.domain().as_str().to_owned())
            .collect(),
    );
    write_set(
        &mut output,
        "placement.remote",
        placement
            .remote_domains()
            .map(|domain| domain.as_str().to_owned())
            .collect(),
    );
    Ok(output)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use crate::config::test_snapshot;
    use crate::plan::RuntimePlan;
    use bootstrap::{Domain, DomainBinding, DomainModuleResult, KernelError, Registry};
    use diport::{DynManagedResource, ManagedResource, ShutdownError};

    struct NoopDomain;

    struct FailingDomain;

    struct RollbackResource;

    impl Domain for NoopDomain {
        fn init(&self, _registry: &mut Registry) -> Result<(), KernelError> {
            Ok(())
        }
    }

    impl Domain for FailingDomain {
        fn init(&self, _registry: &mut Registry) -> Result<(), KernelError> {
            Err(KernelError::Invariant)
        }
    }

    impl ManagedResource for RollbackResource {
        fn name(&self) -> &str {
            "domain-validation-rollback"
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            Ok(())
        }
    }

    fn binding(name: &'static str) -> DomainBinding {
        DomainBinding::new(name, Box::new(NoopDomain), DomainModuleResult::default())
    }

    fn rollback_binding(name: &'static str) -> DomainBinding {
        DomainBinding::new(
            name,
            Box::new(NoopDomain),
            DomainModuleResult {
                resources: vec![DynManagedResource::new_box(RollbackResource)],
                ..DomainModuleResult::default()
            },
        )
    }

    fn failing_rollback_binding(name: &'static str) -> DomainBinding {
        DomainBinding::new(
            name,
            Box::new(FailingDomain),
            DomainModuleResult {
                resources: vec![DynManagedResource::new_box(RollbackResource)],
                ..DomainModuleResult::default()
            },
        )
    }

    fn execution(remote_identity: bool) -> super::DomainExecutionPlan {
        let mut entries = vec![
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ];
        if remote_identity {
            entries.push(("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD", "peer-cell"));
        }
        let snapshot = test_snapshot(&entries).expect("domain execution snapshot");
        let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled RuntimePlan");
        let placement = runtime_plan.placement_execution_plan(snapshot.view());
        runtime_plan.domain_execution_plan(&placement)
    }

    #[test]
    fn domain_execution_plan_accepts_only_exact_local_declaration_order() {
        let validated = execution(false)
            .validate(vec![
                binding("settings"),
                binding("identity"),
                binding("audit"),
            ])
            .expect("exact domain bindings validate");
        let (_registry, output) = validated.compose().expect("validated domains compose");
        assert!(output.probes.is_empty());
        assert!(output.resources.is_empty());
        assert!(output.workers.is_empty());
    }

    #[test]
    fn domain_execution_plan_rejects_missing_extra_duplicate_and_reorder() {
        let cases = [
            vec![binding("settings"), binding("identity")],
            vec![
                binding("settings"),
                binding("identity"),
                binding("audit"),
                binding("other"),
            ],
            vec![
                binding("settings"),
                binding("settings"),
                binding("identity"),
                binding("audit"),
            ],
            vec![binding("identity"), binding("settings"), binding("audit")],
        ];

        for bindings in cases {
            let failure = execution(false)
                .validate(bindings)
                .err()
                .expect("drifted domain bindings must fail");
            let (error, bindings) = failure.into_parts();
            assert!(
                error
                    .to_string()
                    .contains("domain bindings drift from RuntimePlan")
            );
            assert!(!bindings.is_empty(), "failure must return owned bindings");
        }
    }

    #[test]
    fn domain_execution_plan_omits_remote_and_rejects_remote_live_binding() {
        let validated = execution(true)
            .validate(vec![binding("settings"), binding("audit")])
            .expect("remote identity is omitted from local composition");
        validated.compose().expect("local domains compose");

        let failure = execution(true)
            .validate(vec![
                binding("settings"),
                binding("identity"),
                binding("audit"),
            ])
            .err()
            .expect("remote domain must not enter local composition");
        let (_, bindings) = failure.into_parts();
        assert_eq!(
            bindings.iter().map(DomainBinding::name).collect::<Vec<_>>(),
            ["settings", "identity", "audit"]
        );
    }

    #[test]
    fn domain_execution_plan_failure_returns_lifecycle_outputs_for_async_rollback() {
        let failure = execution(false)
            .validate(vec![rollback_binding("unexpected")])
            .err()
            .expect("mismatched binding must fail");
        let (_, mut bindings) = failure.into_parts();
        let output = bootstrap::drain_binding_outputs(&mut bindings);
        assert!(bindings.is_empty());
        assert_eq!(output.resources.len(), 1);
        assert_eq!(output.resources[0].name(), "domain-validation-rollback");
    }

    #[test]
    fn validated_domain_compose_failure_returns_all_bindings_for_async_rollback() {
        let validated = execution(false)
            .validate(vec![
                binding("settings"),
                failing_rollback_binding("identity"),
                binding("audit"),
            ])
            .expect("exact binding names validate before composition");
        let failure = validated
            .compose()
            .err()
            .expect("domain init failure must retain bindings");
        let (error, mut bindings) = failure.into_parts();
        assert!(error.to_string().contains("bootstrap invariant violated"));
        assert_eq!(bindings.len(), 3);
        let output = bootstrap::drain_binding_outputs(&mut bindings);
        assert!(bindings.is_empty());
        assert_eq!(output.resources.len(), 1);
        assert_eq!(output.resources[0].name(), "domain-validation-rollback");
    }

    #[tokio::test]
    async fn runtime_plan_live_inventory_freezes_complete_plan_to_live_closure() {
        let snapshot = test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ])
        .expect("live inventory snapshot");
        let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled RuntimePlan");
        let placement = runtime_plan.placement_execution_plan(snapshot.view());
        let domain_execution_plan = runtime_plan.domain_execution_plan(&placement);
        let local_domains = domain_execution_plan.local_domains().to_vec();
        let live_bindings = crate::modules_gen::wire_test_domains()
            .await
            .expect("generated live inventory domains build");
        let live_domain_names = live_bindings
            .iter()
            .map(DomainBinding::name)
            .collect::<Vec<_>>();
        let validated = domain_execution_plan
            .validate(live_bindings)
            .expect("exact live domain bindings validate");
        let (registry, _) = validated.compose().expect("live domains compose");
        let actual = super::render_live_inventory_for_test(
            &runtime_plan,
            &local_domains,
            &placement,
            &live_domain_names,
            &registry.domain_listener_bindings(),
        )
        .expect("render live inventory");
        assert_eq!(
            actual,
            include_str!("../../tests/fixtures/runtime-plan-live-inventory-v1.txt")
        );
    }
}
