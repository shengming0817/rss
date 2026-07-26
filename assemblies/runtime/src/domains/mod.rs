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

use crate::config::ServingConfigMapper;
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

pub(crate) struct DomainModuleInputs {
    pub(crate) settings: settings::SettingsModuleInput,
    pub(crate) identity: identity::IdentityModuleInput,
    pub(crate) audit: audit::AuditModuleInput,
}

impl DomainModuleInputs {
    pub(crate) fn from_snapshot(
        mapper: &ServingConfigMapper<'_>,
        keyprovider_readiness_interval: settings_composition::KeyProviderReadinessInterval,
        identity_token_profile: identity::IdentityTokenProfileInput,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            settings: settings::SettingsModuleInput::new(keyprovider_readiness_interval),
            identity: identity::IdentityModuleInput::from_mapper(mapper, identity_token_profile)?,
            audit: audit::AuditModuleInput::from_mapper(mapper)?,
        })
    }

    #[must_use]
    pub(crate) fn audit_consumer_key(&self) -> primitives::MacKey {
        self.audit.consumer_key()
    }
}

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
        assert_eq!(output.probes.len(), 3);
        assert_eq!(
            output.probes[0].0.as_str(),
            settings::CONFIGS_READY_PROBE_NAME
        );
        assert_eq!(
            output.probes[1].0.as_str(),
            settings_composition::KEYPROVIDER_READY_PROBE_NAME
        );
        assert_eq!(
            output.probes[2].0.as_str(),
            settings_composition::SECRET_RESOLVER_READY_PROBE_NAME
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
        assert_eq!(
            worker_names,
            ["settings-test-worker", "settings-test-worker"]
        );
    }
}
