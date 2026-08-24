//! Bundled, sealed RuntimePlan compiler for the production deviceidentity candidate.

use anyhow::Context as _;
use assembly_schema::{
    AssemblyDomain, AssemblyIdentity, AssemblyListenerKind, AssemblyProfile, AssemblyTopology,
    CanonicalAssemblyManifestV2, ListenerAuth, RepositoryAssemblySnapshotV2,
    RuntimePlan as TypedRuntimePlan, RuntimePlanV3Input,
};

const BUNDLED_REPOSITORY_SNAPSHOT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/repository-assembly-v2.json"));
const ASSEMBLY_NAME: &str = "deviceidentity";

pub(crate) struct DeviceIdentityPlan {
    typed: TypedRuntimePlan,
    workflows: eventexec::WorkflowRuntimePlan,
}

impl DeviceIdentityPlan {
    pub(crate) fn bundled() -> anyhow::Result<Self> {
        let repository = RepositoryAssemblySnapshotV2::from_json_slice(BUNDLED_REPOSITORY_SNAPSHOT)
            .context("verify bundled deviceidentity repository snapshot")?;
        validate_manifest(repository.manifest(), repository.lock().identity())?;
        let typed = TypedRuntimePlan::compile_v3(
            repository.manifest(),
            repository.lock(),
            compiler_input(repository.manifest()),
        )
        .context("compile bundled deviceidentity RuntimePlan")?;
        anyhow::ensure!(typed.schema_version() == 3, "unexpected RuntimePlan schema");
        let workflows = eventexec::WorkflowActivationPlan::select(&typed)
            .and_then(|selection| selection.bind(std::iter::empty(), std::iter::empty()))
            .context("compile deviceidentity empty workflow plan")?;
        Ok(Self { typed, workflows })
    }

    pub(crate) fn provider_build(
        &self,
    ) -> anyhow::Result<crate::providers_gen::ProviderRoleBatches> {
        crate::providers_gen::ProviderRoleBatches::exact_join(self.typed.provider_plans())
    }

    pub(crate) const fn workflow_runtime(&self) -> &eventexec::WorkflowRuntimePlan {
        &self.workflows
    }

    pub(crate) fn inventory_seed(
        &self,
        completed: crate::providers_gen::CompletedProviderRoles,
    ) -> anyhow::Result<runtimeexec::inventory::RuntimeInventorySeed> {
        let provider_receipt = runtimeexec::inventory::ProviderExecutionReceipt::from_runtime_plan(
            &self.typed,
            completed.into_probe_bindings(),
        )?;
        runtimeexec::inventory::RuntimeInventorySeed::from_runtime_plan(
            &self.typed,
            self.workflows.activated_workflows(),
            provider_receipt,
            vec![runtimeexec::inventory::PlacementObservation::local(
                AssemblyDomain::Identity,
                ASSEMBLY_NAME,
            )],
        )
        .context("seal deviceidentity runtime inventory seed")
    }

    pub(crate) fn expected_workers(&self) -> anyhow::Result<bootstrap::ExpectedWorkerInventory> {
        use bootstrap::{WorkerAdmissionLane as Lane, WorkerDescriptor as Worker};
        bootstrap::ExpectedWorkerInventory::closed([
            Worker::expected(
                "assemblies.deviceidentity.src.providers.pg-monitor",
                Lane::Observational,
            ),
            Worker::expected(
                "assemblies.deviceidentity.src.providers.command-store",
                Lane::Observational,
            ),
            Worker::expected(
                "assemblies.deviceidentity.src.providers.revocation-store",
                Lane::Observational,
            ),
            Worker::expected("composition.identity.src.runtime.01", Lane::Observational),
        ])
        .map_err(Into::into)
    }
}

fn validate_manifest(
    manifest: &CanonicalAssemblyManifestV2,
    lock_identity: &AssemblyIdentity,
) -> anyhow::Result<()> {
    anyhow::ensure!(manifest.name() == ASSEMBLY_NAME, "unexpected assembly name");
    anyhow::ensure!(
        manifest.profile() == AssemblyProfile::Production
            && manifest.topology() == AssemblyTopology::DurableIsolated,
        "deviceidentity requires production + durable-isolated"
    );
    anyhow::ensure!(
        lock_identity.name() == ASSEMBLY_NAME
            && lock_identity.profile() == AssemblyProfile::Production,
        "deviceidentity AssemblyLock identity mismatch"
    );
    anyhow::ensure!(
        manifest.domains() == [AssemblyDomain::Identity],
        "deviceidentity requires exactly Identity"
    );
    Ok(())
}

fn compiler_input(manifest: &CanonicalAssemblyManifestV2) -> RuntimePlanV3Input {
    let mut input = RuntimePlanV3Input::from_manifest(manifest);
    let mut listeners = manifest.listeners().iter().collect::<Vec<_>>();
    listeners.sort_by_key(|listener| listener.kind.as_str());
    for listener in listeners {
        let auth = match listener.kind {
            AssemblyListenerKind::Primary => ListenerAuth::FederatedAccessToken,
            AssemblyListenerKind::Internal => ListenerAuth::Mtls,
            AssemblyListenerKind::Health => ListenerAuth::NoAuth,
            AssemblyListenerKind::Admin => unreachable!("manifest validation excludes Admin"),
        };
        input.listener(listener.kind, auth, listener.domains.clone());
    }
    input.domain(AssemblyDomain::Identity);
    input.placement(AssemblyDomain::Identity, ASSEMBLY_NAME);
    input
}
