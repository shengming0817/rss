//! Plan-owned local domain composition capability.
//!
//! INVARIANT: RUNTIME-PLAN-LIVE-CLOSURE-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "tests::domain_execution_plan_rejects_missing_extra_duplicate_and_reorder + tests::exact_relation_rejects_missing_extra_wrong_id_and_duplicates + tests::runtime_plan_live_relations_reject_each_typed_mapping_drift", anti_vacuity = "tests::runtime_plan_live_closure_matches_typed_relations" } -- the real generated wire → validate → compose path compares provider, placement, domain, and listener relations as exact typed sets. Cross-file handwritten factories, raw generated catalogs, and alternate activation owners remain forbidden by `RUNTIME-PLAN-BINDING-BYPASS-01`.

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
mod tests {
    #![allow(clippy::expect_used)]

    use crate::config::test_snapshot;
    use crate::plan::RuntimePlan;
    use bootstrap::{Domain, DomainBinding, DomainModuleResult, KernelError, Registry};
    use diport::{DynManagedResource, ManagedResource, ShutdownError};
    use std::collections::BTreeSet;

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

    fn exact_relation(
        label: &str,
        expected: impl IntoIterator<Item = String>,
        actual: impl IntoIterator<Item = String>,
    ) -> anyhow::Result<()> {
        let expected = expected.into_iter().collect::<Vec<_>>();
        let actual = actual.into_iter().collect::<Vec<_>>();
        let expected_set = expected.iter().cloned().collect::<BTreeSet<_>>();
        let actual_set = actual.iter().cloned().collect::<BTreeSet<_>>();
        anyhow::ensure!(
            expected.len() == expected_set.len(),
            "{label} expected relation contains duplicate IDs"
        );
        anyhow::ensure!(
            actual.len() == actual_set.len(),
            "{label} live relation contains duplicate IDs"
        );
        anyhow::ensure!(
            expected_set == actual_set,
            "{label} relation drift: missing={:?}, extra={:?}",
            expected_set.difference(&actual_set).collect::<Vec<_>>(),
            actual_set.difference(&expected_set).collect::<Vec<_>>()
        );
        Ok(())
    }

    fn listener_label(listener: primitives::ListenerKind) -> &'static str {
        match listener {
            primitives::ListenerKind::Primary => "primary",
            primitives::ListenerKind::Internal => "internal",
            primitives::ListenerKind::Health => "health",
            primitives::ListenerKind::Admin => "admin",
            _ => "unknown",
        }
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

    #[test]
    fn exact_relation_rejects_missing_extra_wrong_id_and_duplicates() {
        for actual in [
            vec!["settings".to_owned()],
            vec![
                "settings".to_owned(),
                "audit".to_owned(),
                "extra".to_owned(),
            ],
            vec!["settings".to_owned(), "wrong-id".to_owned()],
            vec!["settings".to_owned(), "settings".to_owned()],
        ] {
            assert!(
                exact_relation(
                    "synthetic",
                    ["settings".to_owned(), "audit".to_owned()],
                    actual,
                )
                .is_err()
            );
        }
    }

    fn assert_relation_mutations(label: &str, expected: Vec<String>, actual: Vec<String>) {
        exact_relation(label, expected.clone(), actual.clone()).expect("real relation must close");

        let mut missing = actual.clone();
        missing
            .pop()
            .expect("anti-vacuity: relation must be non-empty");
        assert!(exact_relation(label, expected.clone(), missing).is_err());

        let mut extra = actual.clone();
        extra.push(format!("{label}-synthetic-extra"));
        assert!(exact_relation(label, expected.clone(), extra).is_err());

        let mut wrong_id = actual;
        wrong_id[0] = format!("{label}-synthetic-wrong-id");
        assert!(exact_relation(label, expected, wrong_id).is_err());
    }

    #[tokio::test]
    async fn runtime_plan_live_relations_reject_each_typed_mapping_drift() {
        let snapshot = test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ])
        .expect("live relation snapshot");
        let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled RuntimePlan");
        let typed = runtime_plan.as_typed();
        let placement = runtime_plan.placement_execution_plan(snapshot.view());

        assert_relation_mutations(
            "placement",
            typed
                .placement_plans()
                .iter()
                .map(|spec| format!("{}@{}", spec.domain().as_str(), spec.workload()))
                .collect(),
            placement
                .placements()
                .iter()
                .map(|spec| format!("{}@{}", spec.domain().as_str(), spec.workload()))
                .collect(),
        );

        let domain_execution_plan = runtime_plan.domain_execution_plan(&placement);
        let live_bindings = crate::modules_gen::wire_test_domains()
            .await
            .expect("generated live domains build");
        assert_relation_mutations(
            "domain",
            domain_execution_plan
                .local_domains()
                .iter()
                .map(|domain| domain.as_str().to_owned())
                .collect(),
            live_bindings
                .iter()
                .map(|binding| binding.name().to_owned())
                .collect(),
        );

        assert_relation_mutations(
            "listener",
            typed
                .listener_plans()
                .iter()
                .flat_map(|listener| {
                    listener.domains().iter().map(move |domain| {
                        format!("{}:{}", listener.kind().as_str(), domain.as_str())
                    })
                })
                .collect(),
            crate::modules_gen::DOMAIN_LISTENER_BINDINGS
                .iter()
                .map(|binding| format!("{}:{}", listener_label(binding.listener), binding.domain))
                .collect(),
        );
    }

    #[tokio::test]
    async fn runtime_plan_live_closure_matches_typed_relations() {
        let snapshot = test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ])
        .expect("live closure snapshot");
        let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled RuntimePlan");
        let typed = runtime_plan.as_typed();
        let placement = runtime_plan.placement_execution_plan(snapshot.view());
        exact_relation(
            "provider",
            typed
                .provider_plans()
                .iter()
                .map(|provider| provider.id().to_owned()),
            crate::providers_gen::PROVIDER_CATALOG
                .iter()
                .map(|provider| provider.role().as_str().to_owned()),
        )
        .expect("provider declaration/catalog closure");
        exact_relation(
            "placement",
            typed
                .placement_plans()
                .iter()
                .map(|spec| format!("{}@{}", spec.domain().as_str(), spec.workload())),
            placement
                .placements()
                .iter()
                .map(|spec| format!("{}@{}", spec.domain().as_str(), spec.workload())),
        )
        .expect("placement declaration/execution closure");
        let domain_execution_plan = runtime_plan.domain_execution_plan(&placement);
        let local_domains = domain_execution_plan
            .local_domains()
            .iter()
            .map(|domain| domain.as_str().to_owned())
            .collect::<Vec<_>>();
        let live_bindings = crate::modules_gen::wire_test_domains()
            .await
            .expect("generated live domains build");
        let live_domain_names = live_bindings
            .iter()
            .map(|binding| binding.name().to_owned())
            .collect::<Vec<_>>();
        exact_relation("domain", local_domains, live_domain_names)
            .expect("domain local/live closure");
        let validated = domain_execution_plan
            .validate(live_bindings)
            .expect("exact live domain bindings validate");
        let (registry, _) = validated.compose().expect("live domains compose");
        let expected_listeners = typed.listener_plans().iter().flat_map(|listener| {
            listener
                .domains()
                .iter()
                .map(move |domain| format!("{}:{}", listener.kind().as_str(), domain.as_str()))
        });
        exact_relation(
            "generated listener",
            expected_listeners,
            crate::modules_gen::DOMAIN_LISTENER_BINDINGS
                .iter()
                .map(|binding| format!("{}:{}", listener_label(binding.listener), binding.domain)),
        )
        .expect("listener plan/generated closure");
        let listener_plan = runtime_plan.listener_execution_plan();
        let live_listeners = registry.domain_listener_bindings();
        crate::validate_domain_listener_evidence(&listener_plan, &placement, &live_listeners)
            .expect("listener generated/live closure");
    }
}
