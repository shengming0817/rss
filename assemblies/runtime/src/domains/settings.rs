//! Runtime adapter for the reusable settings composition.

use bootstrap::DomainBinding;
use settings_composition::SettingsModuleDeps;
use vault::caps as vault_caps;

use crate::{SharedRuntimeDeps, SystemClock};

pub use settings_composition::{CONFIGS_READY_PROBE_NAME, ConfigsReadyProbe};

/// Build the settings domain from runtime-owned Postgres and Vault bundles.
///
/// # Errors
///
/// Returns an error when the settings composition fails its startup self-check.
pub async fn module(deps: &SharedRuntimeDeps) -> anyhow::Result<DomainBinding> {
    wire_from_runtime(deps).await
}

/// Integration-only entry that exercises the same typed wiring without naming the generated live
/// module factory outside its generated owner.
#[cfg(feature = "integration")]
pub(crate) async fn integration_binding(deps: &SharedRuntimeDeps) -> anyhow::Result<DomainBinding> {
    wire_from_runtime(deps).await
}

async fn wire_from_runtime(deps: &SharedRuntimeDeps) -> anyhow::Result<DomainBinding> {
    settings_composition::wire(SettingsModuleDeps::new(
        deps.pg.for_domain(),
        deps.pg.readiness_handle(),
        deps.vault.for_domain::<vault_caps::Settings>(),
        deps.settings_config_value_key_name.clone(),
        std::sync::Arc::new(SystemClock),
    ))
    .await
}

#[cfg(test)]
pub(crate) mod tests {
    use bootstrap::DomainBinding;

    pub(crate) async fn test_binding() -> anyhow::Result<DomainBinding> {
        settings_composition::test_support::binding().await
    }
}
