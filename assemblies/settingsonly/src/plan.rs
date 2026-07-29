//! Bundled, sealed RuntimePlan compiler for the settings-only assembly.

use anyhow::Context as _;
use assembly_schema::{
    AssemblyDomain, AssemblyIdentity, AssemblyListenerKind, AssemblyManifest, AssemblyProfile,
    AssemblyTopology, CanonicalAssemblyManifestV2, DomainLifecyclePhase, ExecutableAssemblyLock,
    ListenerAuth, ParsedAssemblyLock, RuntimePlan as TypedRuntimePlan, RuntimePlanV2Input,
};

const BUNDLED_ASSEMBLY_TOML: &str = include_str!("../assembly.toml");
const BUNDLED_ASSEMBLY_LOCK: &[u8] = include_bytes!("../assembly.lock.json");
const ASSEMBLY_NAME: &str = "settingsonly";
const SETTINGS_WORKLOAD: &str = "settingsonly";
const INVENTORY_CONTRACT: &str = "runtime.inventory";

/// Capability proving that the bundled settings-only deployment closure compiled successfully.
///
/// The field is private so no caller can construct or substitute a partially validated plan.
pub(crate) struct SettingsOnlyPlan {
    typed: TypedRuntimePlan,
}

impl SettingsOnlyPlan {
    pub(crate) fn bundled() -> anyhow::Result<Self> {
        let manifest = AssemblyManifest::from_toml_str(BUNDLED_ASSEMBLY_TOML)
            .context("parse bundled settingsonly assembly manifest")?
            .canonicalize_v2()
            .context("canonicalize bundled settingsonly assembly manifest")?;
        let lock = ExecutableAssemblyLock::from_build_attested(
            ParsedAssemblyLock::from_json_slice(BUNDLED_ASSEMBLY_LOCK)
                .context("parse bundled settingsonly AssemblyLock")?,
        );

        validate_manifest_closure(&manifest, lock.identity())?;
        let input = compiler_input(&manifest)?;
        let typed = TypedRuntimePlan::compile_v2(&manifest, &lock, input)
            .context("compile bundled settingsonly RuntimePlan")?;
        validate_typed_closure(&typed)?;
        Ok(Self { typed })
    }

    #[cfg(test)]
    pub(crate) const fn as_typed(&self) -> &TypedRuntimePlan {
        &self.typed
    }

    pub(crate) fn provider_build(
        &self,
    ) -> anyhow::Result<crate::providers_gen::ProviderRoleBatches> {
        crate::providers_gen::ProviderRoleBatches::exact_join(self.typed.provider_plans())
    }

    pub(crate) fn into_inventory_seed(
        self,
        completed_roles: crate::providers_gen::CompletedProviderRoles,
    ) -> anyhow::Result<runtimeexec::inventory::RuntimeInventorySeed> {
        self.inventory_seed_with_bindings(completed_roles.into_probe_bindings())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn into_inventory_seed_fixture(
        self,
        provider_bindings: Vec<runtimeexec::inventory::ProviderProbeBinding>,
    ) -> anyhow::Result<runtimeexec::inventory::RuntimeInventorySeed> {
        Ok(self
            .inventory_seed_with_bindings(provider_bindings)?
            .with_build_metadata(runtimeexec::inventory::BuildMetadata::parse(
                &"a".repeat(40),
                &format!("sha256:{}", "b".repeat(64)),
            )?))
    }

    fn inventory_seed_with_bindings(
        self,
        provider_bindings: Vec<runtimeexec::inventory::ProviderProbeBinding>,
    ) -> anyhow::Result<runtimeexec::inventory::RuntimeInventorySeed> {
        let placements = self
            .typed
            .placement_plans()
            .iter()
            .map(|placement| {
                runtimeexec::inventory::PlacementObservation::local(
                    placement.domain(),
                    placement.workload(),
                )
            })
            .collect();
        runtimeexec::inventory::RuntimeInventorySeed::from_runtime_plan(
            &self.typed,
            provider_bindings,
            placements,
        )
        .context("seal settingsonly runtime inventory seed")
    }
}

fn validate_manifest_closure(
    manifest: &CanonicalAssemblyManifestV2,
    lock_identity: &AssemblyIdentity,
) -> anyhow::Result<()> {
    anyhow::ensure!(manifest.name() == ASSEMBLY_NAME, "unexpected assembly name");
    anyhow::ensure!(
        manifest.profile() == AssemblyProfile::Production
            && manifest.topology() == AssemblyTopology::DurableIsolated,
        "settingsonly requires production + durable-isolated"
    );
    anyhow::ensure!(
        manifest.framework_contracts().len() == 1
            && manifest.framework_contracts()[0].id == INVENTORY_CONTRACT
            && manifest.framework_contracts()[0].listener == AssemblyListenerKind::Admin,
        "settingsonly requires exactly the Admin runtime.inventory framework contract"
    );
    anyhow::ensure!(
        lock_identity.name() == ASSEMBLY_NAME
            && lock_identity.profile() == AssemblyProfile::Production,
        "settingsonly AssemblyLock identity does not match the closed assembly"
    );
    anyhow::ensure!(
        manifest.domains() == [AssemblyDomain::Settings],
        "settingsonly requires exactly the Settings domain"
    );
    validate_manifest_listeners(manifest)?;
    Ok(())
}

fn validate_manifest_listeners(manifest: &CanonicalAssemblyManifestV2) -> anyhow::Result<()> {
    anyhow::ensure!(
        manifest.listeners().len() == 3,
        "settingsonly requires exactly Primary, Admin and Health listeners"
    );
    let primary = manifest
        .listeners()
        .iter()
        .find(|listener| listener.kind == AssemblyListenerKind::Primary)
        .context("settingsonly manifest is missing the Primary listener")?;
    anyhow::ensure!(
        primary.domains == [AssemblyDomain::Settings],
        "settingsonly Primary listener must contain only Settings"
    );
    let health = manifest
        .listeners()
        .iter()
        .find(|listener| listener.kind == AssemblyListenerKind::Health)
        .context("settingsonly manifest is missing the Health listener")?;
    anyhow::ensure!(
        health.domains.is_empty(),
        "settingsonly Health listener must be domain-free"
    );
    let admin = manifest
        .listeners()
        .iter()
        .find(|listener| listener.kind == AssemblyListenerKind::Admin)
        .context("settingsonly manifest is missing the Admin listener")?;
    anyhow::ensure!(
        admin.domains.is_empty(),
        "settingsonly Admin listener must be domain-free"
    );
    Ok(())
}

fn compiler_input(manifest: &CanonicalAssemblyManifestV2) -> anyhow::Result<RuntimePlanV2Input> {
    let mut input = RuntimePlanV2Input::from_manifest(manifest);

    let mut listeners = manifest.listeners().iter().collect::<Vec<_>>();
    listeners.sort_by_key(|listener| listener.kind.as_str());
    for listener in listeners {
        let auth = match listener.kind {
            AssemblyListenerKind::Primary | AssemblyListenerKind::Admin => {
                ListenerAuth::FederatedAccessToken
            }
            AssemblyListenerKind::Health => ListenerAuth::NoAuth,
            AssemblyListenerKind::Internal => {
                anyhow::bail!("settingsonly manifest contains an unsupported listener kind")
            }
        };
        input.listener(listener.kind, auth, listener.domains.clone());
    }

    for domain in manifest.domains() {
        input.domain(*domain);
    }
    input.placement(AssemblyDomain::Settings, SETTINGS_WORKLOAD);
    Ok(input)
}

fn validate_typed_closure(plan: &TypedRuntimePlan) -> anyhow::Result<()> {
    anyhow::ensure!(
        plan.schema_version() == 2,
        "settingsonly requires RuntimePlan schema version 1"
    );
    let listeners = plan.listener_plans();
    anyhow::ensure!(
        listeners.len() == 3
            && listeners[0].id() == "admin-main"
            && listeners[0].kind() == AssemblyListenerKind::Admin
            && listeners[0].auth() == ListenerAuth::FederatedAccessToken
            && listeners[0].domains().is_empty()
            && listeners[1].id() == "health-main"
            && listeners[1].kind() == AssemblyListenerKind::Health
            && listeners[1].auth() == ListenerAuth::NoAuth
            && listeners[1].domains().is_empty()
            && listeners[2].id() == "primary-main"
            && listeners[2].kind() == AssemblyListenerKind::Primary
            && listeners[2].auth() == ListenerAuth::FederatedAccessToken
            && listeners[2].domains() == [AssemblyDomain::Settings],
        "compiled settingsonly plan has an unexpected listener closure"
    );
    let domains = plan.domain_plans();
    anyhow::ensure!(
        domains.len() == 1
            && domains[0].id() == AssemblyDomain::Settings
            && domains[0].lifecycle()
                == [
                    DomainLifecyclePhase::Construct,
                    DomainLifecyclePhase::Ready,
                    DomainLifecyclePhase::Shutdown,
                ],
        "compiled settingsonly plan has an unexpected domain closure"
    );
    let placements = plan.placement_plans();
    anyhow::ensure!(
        placements.len() == 1
            && placements[0].domain() == AssemblyDomain::Settings
            && placements[0].workload() == SETTINGS_WORKLOAD,
        "compiled settingsonly plan has an unexpected placement closure"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    // reason: bundled artifact contract tests should stop at the exact failed invariant.

    use super::*;

    #[test]
    fn bundled_manifest_has_the_closed_production_profile() {
        let manifest = AssemblyManifest::from_toml_str(BUNDLED_ASSEMBLY_TOML)
            .expect("bundled manifest")
            .canonicalize_v2()
            .expect("canonical bundled manifest");
        let lock = ParsedAssemblyLock::from_json_slice(BUNDLED_ASSEMBLY_LOCK)
            .expect("bundled AssemblyLock");

        validate_manifest_closure(&manifest, lock.identity())
            .expect("closed settingsonly manifest");
        assert_eq!(manifest.name(), ASSEMBLY_NAME);
        assert_eq!(manifest.profile(), AssemblyProfile::Production);
        assert_eq!(manifest.topology(), AssemblyTopology::DurableIsolated);
    }

    #[test]
    fn bundled_plan_seals_listener_auth_and_domain_placement() {
        let plan = SettingsOnlyPlan::bundled().expect("bundled settingsonly plan");
        let typed = plan.as_typed();

        assert_eq!(
            typed
                .listener_plans()
                .iter()
                .map(|listener| (listener.kind(), listener.auth(), listener.domains()))
                .collect::<Vec<_>>(),
            [
                (
                    AssemblyListenerKind::Admin,
                    ListenerAuth::FederatedAccessToken,
                    &[][..],
                ),
                (AssemblyListenerKind::Health, ListenerAuth::NoAuth, &[][..]),
                (
                    AssemblyListenerKind::Primary,
                    ListenerAuth::FederatedAccessToken,
                    &[AssemblyDomain::Settings][..],
                ),
            ]
        );
        assert_eq!(typed.domain_plans().len(), 1);
        assert_eq!(typed.domain_plans()[0].id(), AssemblyDomain::Settings);
        assert_eq!(typed.placement_plans().len(), 1);
        assert_eq!(typed.placement_plans()[0].workload(), SETTINGS_WORKLOAD);
    }

    #[test]
    fn bundled_plan_contains_only_the_expected_provider_closure() {
        let plan = SettingsOnlyPlan::bundled().expect("bundled settingsonly plan");
        assert_eq!(
            plan.as_typed()
                .provider_plans()
                .iter()
                .map(|provider| (provider.id(), provider.constructor(), provider.outputs()))
                .collect::<Vec<_>>(),
            crate::providers_gen::PROVIDER_CATALOG
                .iter()
                .map(|provider| (
                    provider.role().as_str(),
                    provider.evidence().constructor(),
                    provider.evidence().outputs(),
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn bundled_plan_json_matches_committed_runtime_plan() {
        let plan = SettingsOnlyPlan::bundled().expect("bundled settingsonly plan");
        let mut actual = serde_json::to_string_pretty(plan.as_typed()).expect("RuntimePlan JSON");
        actual.push('\n');
        assert_eq!(
            actual.as_bytes(),
            include_bytes!("../runtime-plan.json"),
            "settingsonly RuntimePlan artifact drift"
        );
    }
}
