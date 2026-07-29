//! Runtime adapter for the reusable settings composition.

use bootstrap::DomainBinding;
use settings_composition::{KeyProviderReadinessInterval, SettingsModuleDeps};
use vault::caps as vault_caps;

use crate::SharedRuntimeDeps;
use crate::support::SystemClock;

pub use settings_composition::{CONFIGS_READY_PROBE_NAME, ConfigsReadyProbe};

pub(crate) struct SettingsModuleInput {
    keyprovider_readiness_interval: KeyProviderReadinessInterval,
}

impl SettingsModuleInput {
    #[must_use]
    pub(crate) fn new(keyprovider_readiness_interval: KeyProviderReadinessInterval) -> Self {
        Self {
            keyprovider_readiness_interval,
        }
    }

    pub(crate) fn readiness_interval(&self) -> KeyProviderReadinessInterval {
        self.keyprovider_readiness_interval
    }
}

/// Build the settings domain from runtime-owned Postgres and Vault bundles.
///
/// # Errors
///
/// Returns an error when the settings composition fails its startup self-check.
pub async fn module(
    deps: &SharedRuntimeDeps,
    input: SettingsModuleInput,
) -> anyhow::Result<DomainBinding> {
    wire_from_runtime(deps, input).await
}

/// Integration-only entry that exercises the same typed wiring without naming the generated live
/// module factory outside its generated owner.
#[cfg(feature = "integration")]
pub(crate) async fn integration_binding(
    deps: &SharedRuntimeDeps,
    input: SettingsModuleInput,
) -> anyhow::Result<DomainBinding> {
    wire_from_runtime(deps, input).await
}

async fn wire_from_runtime(
    deps: &SharedRuntimeDeps,
    _input: SettingsModuleInput,
) -> anyhow::Result<DomainBinding> {
    settings_composition::wire(SettingsModuleDeps::new(
        deps.pg.for_domain(),
        deps.vault.for_domain::<vault_caps::Settings>(),
        deps.settings_config_value_key_name.clone(),
        std::sync::Arc::new(SystemClock),
        deps.settings_readiness.clone(),
    ))
    .await
}

#[cfg(test)]
pub(crate) mod tests {
    use bootstrap::DomainBinding;

    pub(crate) fn test_input() -> anyhow::Result<super::SettingsModuleInput> {
        Ok(super::SettingsModuleInput::new(
            settings_composition::KeyProviderReadinessInterval::default(),
        ))
    }

    pub(crate) async fn test_binding(
        _input: super::SettingsModuleInput,
    ) -> anyhow::Result<DomainBinding> {
        settings_composition::test_support::binding().await
    }
}
