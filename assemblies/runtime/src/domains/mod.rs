//! Runtime-owned domain wiring modules.
//!
//! Each module keeps its typed `wire_*` entrypoint and exposes one async Phase 4 ownership funnel
//! that returns `anyhow::Result<DomainBinding>`. Production passes `SharedRuntimeDeps`; sealed,
//! per-domain provider traits let generated tests execute the same entrypoints hermetically without
//! introducing a generic service bag. The live runtime consumes the manifest-derived binding list.

pub mod audit;
pub mod identity;
pub mod settings;

#[cfg(test)]
mod tests {
    use bootstrap::compose_bindings;
    use diport::ManagedResource as _;
    use tokio_util::sync::CancellationToken;

    use super::settings;

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn generated_modules_compose_in_manifest_order_with_stable_outputs() {
        let mut bindings = crate::modules_gen::wire_test_domains()
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
        assert_eq!(output.probes.len(), 2);
        assert_eq!(
            output.probes[0].0.as_str(),
            settings::CONFIGS_READY_PROBE_NAME
        );
        assert_eq!(
            output.probes[1].0.as_str(),
            settings_composition::KEYPROVIDER_READY_PROBE_NAME
        );
        let resource_names = output
            .resources
            .iter()
            .map(|resource| resource.name().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(resource_names, Vec::<String>::new());
        let worker_names = output
            .workers
            .into_iter()
            .map(|worker| worker(CancellationToken::new()).name().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(worker_names, ["settings-test-worker"]);
    }
}
