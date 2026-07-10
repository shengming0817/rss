//! Runtime-owned domain wiring modules.
//!
//! Each module keeps its typed `wire_*` entrypoint and exposes one async Phase 4 ownership funnel
//! that returns `anyhow::Result<DomainBinding>`. Production passes `SharedRuntimeDeps`; sealed,
//! per-domain provider traits let default tests execute the same public entrypoints hermetically
//! without introducing a generic service bag. The live runtime still uses the typed entrypoints
//! until #1672 completes typed-handle handoff and generated binding composition.

pub mod audit;
pub mod identity;
pub mod settings;

#[cfg(test)]
mod tests {
    use bootstrap::compose_bindings;

    use super::{audit, identity, settings};

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn hermetic_modules_compose_in_manifest_order_with_stable_outputs() {
        let mut bindings = vec![
            identity::tests::test_binding()
                .await
                .expect("identity module builds"),
            settings::tests::test_binding()
                .await
                .expect("settings module builds"),
            audit::tests::test_binding()
                .await
                .expect("audit module builds"),
        ];
        assert_eq!(
            bindings
                .iter()
                .map(bootstrap::DomainBinding::name)
                .collect::<Vec<_>>(),
            ["identity", "settings", "audit"]
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
            crate::infra::vault::KEYPROVIDER_READY_PROBE_NAME
        );
        assert!(output.resources.is_empty());
        assert_eq!(output.workers.len(), 1);
    }
}
