//! Runtime-owned domain wiring modules.
//!
//! Each module exposes one async Phase 4 ownership funnel returning
//! `anyhow::Result<DomainBinding>`. Production passes `SharedRuntimeDeps`; identity, audit, and
//! settings delegate to their typed composition entrypoints, and generated tests reuse those same
//! entrypoints hermetically without introducing a generic service bag. The live runtime consumes
//! the manifest-derived binding list.

pub mod audit;
pub mod identity;
pub mod settings;

use bootstrap::DomainBinding;

/// Partial domain wiring failure that retains earlier successful bindings for async rollback.
pub struct DomainWiringFailure {
    pub(crate) source: anyhow::Error,
    pub(crate) bindings: Vec<DomainBinding>,
}

impl DomainWiringFailure {
    pub(crate) fn into_parts(self) -> (anyhow::Error, Vec<DomainBinding>) {
        (self.source, self.bindings)
    }
}

#[cfg(test)]
mod tests {
    use bootstrap::compose_bindings;
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn generated_modules_compose_in_manifest_order_with_stable_outputs() {
        let snapshot = crate::config::test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ])
        .expect("all-local snapshot");
        let runtime_plan =
            crate::plan::RuntimePlan::bundled(snapshot.view()).expect("bundled RuntimePlan");
        let placement = runtime_plan
            .placement_execution_plan(bootstrap::Topology::Demo, snapshot.view())
            .expect("all-local placement");
        let execution = runtime_plan.domain_execution_plan(&placement);
        let mut bindings = crate::modules_gen::wire_test_domains(&execution)
            .await
            .expect("generated test domains build");
        assert_eq!(
            bindings
                .iter()
                .map(bootstrap::DomainBinding::name)
                .collect::<Vec<_>>(),
            ["settings", "identity", "audit"]
        );

        let (_, output) = compose_bindings(&mut bindings).expect("domain modules compose");
        assert!(bindings.is_empty());
        assert!(output.probes.is_empty());
        assert!(output.resources.is_empty());
        assert!(output.workers.is_empty());
    }
}
