//! Bundled, sealed RuntimePlan compiler for the production identityaudit assembly.

use anyhow::Context as _;
use assembly_schema::{
    AssemblyDomain, AssemblyListenerKind, AssemblyManifest, AssemblyProfile, AssemblyTopology,
    CanonicalAssemblyManifestV1, DomainLifecyclePhase, ListenerAuth, ParsedAssemblyLock,
    RuntimePlan as TypedRuntimePlan, RuntimePlanV1Input,
};

const BUNDLED_ASSEMBLY_TOML: &str = include_str!("../assembly.toml");
const BUNDLED_ASSEMBLY_LOCK: &[u8] = include_bytes!("../assembly.lock.json");
const ASSEMBLY_NAME: &str = "identityaudit";
const WORKLOAD: &str = "identityaudit";

/// Proof that the bundled manifest, lock and generated provider catalog agree exactly.
pub(crate) struct IdentityAuditPlan {
    typed: TypedRuntimePlan,
}

impl IdentityAuditPlan {
    pub(crate) fn bundled() -> anyhow::Result<Self> {
        let manifest = AssemblyManifest::from_toml_str(BUNDLED_ASSEMBLY_TOML)
            .context("parse bundled identityaudit assembly manifest")?
            .canonicalize_v1()
            .context("canonicalize bundled identityaudit assembly manifest")?;
        let lock = ParsedAssemblyLock::from_json_slice(BUNDLED_ASSEMBLY_LOCK)
            .context("parse bundled identityaudit AssemblyLock")?;
        validate_manifest(&manifest, &lock)?;
        let typed = TypedRuntimePlan::compile_v1(&manifest, &lock, compiler_input(&manifest)?)
            .context("compile bundled identityaudit RuntimePlan")?;
        validate_typed(&typed)?;
        Ok(Self { typed })
    }

    pub(crate) fn provider_build(
        &self,
    ) -> anyhow::Result<crate::providers_gen::ProviderRoleBatches> {
        crate::providers_gen::ProviderRoleBatches::exact_join(self.typed.provider_plans())
    }

    pub(crate) fn inventory_seed(
        &self,
        completed_roles: crate::providers_gen::CompletedProviderRoles,
    ) -> anyhow::Result<runtimeexec::inventory::RuntimeInventorySeed> {
        self.inventory_seed_with_bindings(completed_roles.into_probe_bindings())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn inventory_seed_fixture(
        &self,
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
        &self,
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
        .context("seal identityaudit runtime inventory seed")
    }

    #[cfg(test)]
    pub(crate) const fn as_typed(&self) -> &TypedRuntimePlan {
        &self.typed
    }
}

fn validate_manifest(
    manifest: &CanonicalAssemblyManifestV1,
    lock: &ParsedAssemblyLock,
) -> anyhow::Result<()> {
    anyhow::ensure!(manifest.name() == ASSEMBLY_NAME, "unexpected assembly name");
    anyhow::ensure!(
        manifest.profile() == AssemblyProfile::Production
            && manifest.topology() == AssemblyTopology::DurableIsolated,
        "identityaudit requires production + durable-isolated"
    );
    anyhow::ensure!(
        lock.identity().name() == ASSEMBLY_NAME
            && lock.identity().profile() == AssemblyProfile::Production,
        "identityaudit AssemblyLock identity mismatch"
    );
    anyhow::ensure!(
        manifest.domains() == [AssemblyDomain::Identity, AssemblyDomain::Audit],
        "identityaudit requires exactly Identity and Audit"
    );
    let framework = manifest.framework_contracts();
    anyhow::ensure!(
        framework.len() == 1
            && framework[0].id == "runtime.inventory"
            && framework[0].listener == AssemblyListenerKind::Admin,
        "identityaudit requires exactly runtime.inventory on Admin"
    );
    let expected = [
        (
            AssemblyListenerKind::Primary,
            &[AssemblyDomain::Identity][..],
        ),
        (AssemblyListenerKind::Admin, &[AssemblyDomain::Audit][..]),
        (AssemblyListenerKind::Health, &[][..]),
    ];
    anyhow::ensure!(
        manifest.listeners().len() == expected.len(),
        "identityaudit requires exactly three listeners"
    );
    for (kind, domains) in expected {
        let listener = manifest
            .listeners()
            .iter()
            .find(|listener| listener.kind == kind)
            .with_context(|| format!("identityaudit manifest is missing {kind:?}"))?;
        anyhow::ensure!(
            listener.domains == domains,
            "identityaudit listener/domain mismatch"
        );
    }
    Ok(())
}

fn compiler_input(manifest: &CanonicalAssemblyManifestV1) -> anyhow::Result<RuntimePlanV1Input> {
    let mut input = RuntimePlanV1Input::from_manifest(manifest);
    let mut listeners = manifest.listeners().iter().collect::<Vec<_>>();
    listeners.sort_by_key(|listener| listener.kind.as_str());
    for listener in listeners {
        let auth = match listener.kind {
            AssemblyListenerKind::Primary | AssemblyListenerKind::Admin => {
                ListenerAuth::RssAccessToken
            }
            AssemblyListenerKind::Health => ListenerAuth::NoAuth,
            AssemblyListenerKind::Internal => {
                anyhow::bail!("identityaudit does not admit Internal")
            }
        };
        input.listener(listener.kind, auth, listener.domains.clone());
    }
    for domain in manifest.domains() {
        input.domain(*domain);
    }
    let mut placements = manifest.domains().to_vec();
    placements.sort_by_key(|domain| domain.as_str());
    for domain in placements {
        input.placement(domain, WORKLOAD);
    }
    Ok(input)
}

fn validate_typed(plan: &TypedRuntimePlan) -> anyhow::Result<()> {
    anyhow::ensure!(plan.schema_version() == 1, "unexpected RuntimePlan schema");
    let listeners = plan.listener_plans();
    anyhow::ensure!(
        listeners.len() == 3
            && listeners
                .iter()
                .any(|listener| listener.kind() == AssemblyListenerKind::Primary
                    && listener.auth() == ListenerAuth::RssAccessToken
                    && listener.domains() == [AssemblyDomain::Identity])
            && listeners
                .iter()
                .any(|listener| listener.kind() == AssemblyListenerKind::Admin
                    && listener.auth() == ListenerAuth::RssAccessToken
                    && listener.domains() == [AssemblyDomain::Audit])
            && listeners
                .iter()
                .any(|listener| listener.kind() == AssemblyListenerKind::Health
                    && listener.auth() == ListenerAuth::NoAuth
                    && listener.domains().is_empty()),
        "compiled identityaudit listener closure mismatch"
    );
    anyhow::ensure!(
        plan.domain_plans().len() == 2
            && plan.domain_plans().iter().all(|domain| domain.lifecycle()
                == [
                    DomainLifecyclePhase::Construct,
                    DomainLifecyclePhase::Ready,
                    DomainLifecyclePhase::Shutdown
                ]),
        "compiled identityaudit domain lifecycle mismatch"
    );
    anyhow::ensure!(
        plan.placement_plans().len() == 2
            && plan
                .placement_plans()
                .iter()
                .all(|placement| placement.workload() == WORKLOAD),
        "compiled identityaudit placement mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_plan_seals_production_listener_and_provider_closure() -> anyhow::Result<()> {
        let plan = IdentityAuditPlan::bundled()?;
        assert_eq!(plan.as_typed().listener_plans().len(), 3);
        assert_eq!(
            plan.as_typed().provider_plans().len(),
            crate::providers_gen::PROVIDER_CATALOG.len()
        );
        Ok(())
    }

    #[test]
    fn bundled_plan_json_matches_committed_runtime_plan() -> anyhow::Result<()> {
        let plan = IdentityAuditPlan::bundled()?;
        let mut actual = serde_json::to_string_pretty(plan.as_typed())?;
        actual.push('\n');
        assert_eq!(
            actual.as_bytes(),
            include_bytes!("../runtime-plan.json"),
            "identityaudit RuntimePlan artifact drift"
        );
        Ok(())
    }
}
