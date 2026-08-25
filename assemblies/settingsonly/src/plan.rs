//! Bundled, sealed RuntimePlan compiler for the settings-only assembly.

use anyhow::Context as _;
use assembly_schema::{
    AssemblyDomain, AssemblyIdentity, AssemblyListenerKind, AssemblyProfile, AssemblyTopology,
    CanonicalAssemblyManifestV2, DomainLifecyclePhase, ListenerAuth, RepositoryAssemblySnapshotV2,
    RuntimePlan as TypedRuntimePlan, RuntimePlanV4Input,
};

#[cfg(test)]
use assembly_schema::{AssemblyManifest, ParsedAssemblyLock};
#[cfg(test)]
const BUNDLED_ASSEMBLY_TOML: &str = include_str!("../assembly.toml");
#[cfg(test)]
const BUNDLED_ASSEMBLY_LOCK: &[u8] = include_bytes!("../assembly.lock.json");
const BUNDLED_REPOSITORY_SNAPSHOT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/repository-assembly-v2.json"));
const ASSEMBLY_NAME: &str = "settingsonly";
const SETTINGS_WORKLOAD: &str = "settingsonly";
const INVENTORY_CONTRACT: &str = "runtime.inventory";

/// Capability proving that the bundled settings-only deployment closure compiled successfully.
///
/// The field is private so no caller can construct or substitute a partially validated plan.
pub(crate) struct SettingsOnlyPlan {
    typed: TypedRuntimePlan,
    workflow_activation: eventexec::WorkflowActivationPlan,
}

/// Move-only proof that every selected workflow capability was bound to the bundled plan.
pub(crate) struct BoundSettingsOnlyPlan {
    typed: TypedRuntimePlan,
    workflow_runtime: eventexec::WorkflowRuntimePlan,
    settings_v3_serving: SettingsV3ServingHandoff,
}

enum SettingsV3ServingHandoff {
    #[cfg(any(test, feature = "test-support"))]
    Disabled,
    Production(Option<std::sync::Arc<settings::SettingsProjectionQueryService>>),
    #[cfg(any(test, feature = "test-support"))]
    Fixture,
}

/// Offline Settings v3 maintenance target selected by the bundled SettingsOnly manifest.
///
/// Construction consumes a fresh plan-issued active permit. Binding it produces a target registry
/// but never starts serving or a background worker.
pub struct SettingsProjectionMaintenancePlan {
    permit: eventexec::ProjectionActivationPermit,
}

impl SettingsOnlyPlan {
    pub(crate) fn bundled() -> anyhow::Result<Self> {
        let repository = RepositoryAssemblySnapshotV2::from_json_slice(BUNDLED_REPOSITORY_SNAPSHOT)
            .context("verify bundled settingsonly repository snapshot")?;
        let manifest = repository.manifest();
        let lock = repository.lock();

        validate_manifest_closure(manifest, lock.identity())?;
        let input = compiler_input(manifest)?;
        let typed = TypedRuntimePlan::compile_v4(manifest, lock, input)
            .context("compile bundled settingsonly RuntimePlan")?;
        validate_typed_closure(&typed)?;
        let workflow_activation = eventexec::WorkflowActivationPlan::select(&typed)
            .context("select bundled settingsonly workflow activation plan")?;
        Ok(Self {
            typed,
            workflow_activation,
        })
    }

    pub(crate) fn expected_workers(&self) -> anyhow::Result<bootstrap::ExpectedWorkerInventory> {
        expected_workers()
    }

    #[cfg(test)]
    pub(crate) const fn as_typed(&self) -> &TypedRuntimePlan {
        &self.typed
    }

    pub(crate) fn projection_capture(&self) -> eventexec::ProjectionCaptureView<'_> {
        self.workflow_activation.projection_capture()
    }

    pub(crate) fn projection_is_active(&self) -> bool {
        self.typed.workflow_plans().iter().any(|workflow| {
            matches!(
                workflow.activation(),
                assembly_schema::WorkflowActivation::Projection {
                    id,
                    activation: assembly_schema::ProjectionActivation::Active,
                    ..
                } if id == generated::projection::settings_v3::CONTRACT_ID
            )
        })
    }

    pub(crate) fn bind_projection<B>(
        self,
        build: B,
        serving: std::sync::Arc<settings::SettingsProjectionQueryService>,
    ) -> anyhow::Result<BoundSettingsOnlyPlan>
    where
        B: FnOnce(
            eventexec::ProjectionRuntimeBinding,
        ) -> Result<eventexec::ProjectionRuntime, eventexec::WorkflowRuntimeError>,
    {
        let serving_evidence: std::sync::Arc<dyn eventexec::ProjectionServingEvidence> =
            serving.clone();
        self.bind_projection_with_evidence(
            build,
            serving_evidence,
            SettingsV3ServingHandoff::Production(Some(serving)),
        )
    }

    fn bind_projection_with_evidence<B>(
        mut self,
        build: B,
        serving_evidence: std::sync::Arc<dyn eventexec::ProjectionServingEvidence>,
        settings_v3_serving: SettingsV3ServingHandoff,
    ) -> anyhow::Result<BoundSettingsOnlyPlan>
    where
        B: FnOnce(
            eventexec::ProjectionRuntimeBinding,
        ) -> Result<eventexec::ProjectionRuntime, eventexec::WorkflowRuntimeError>,
    {
        let permit = self
            .workflow_activation
            .take_projection_permit(generated::projection::settings_v3::CONTRACT_ID)
            .context("take settings projection activation permit")?;
        let capability =
            eventexec::ProjectionRuntimeCapability::bind_active(permit, build, serving_evidence)
                .context("bind settings active projection runtime")?;
        let workflow_runtime = self
            .workflow_activation
            .bind([capability], std::iter::empty())
            .context("seal bundled settingsonly workflow runtime plan")?;
        Ok(BoundSettingsOnlyPlan {
            typed: self.typed,
            workflow_runtime,
            settings_v3_serving,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn bind_disabled(self) -> anyhow::Result<BoundSettingsOnlyPlan> {
        anyhow::ensure!(
            self.typed.workflow_plans().iter().all(|workflow| matches!(
                workflow.activation(),
                assembly_schema::WorkflowActivation::Projection {
                    activation: assembly_schema::ProjectionActivation::Disabled,
                    ..
                } | assembly_schema::WorkflowActivation::Saga {
                    activation: assembly_schema::SagaActivation::Disabled,
                    ..
                }
            )),
            "disabled workflow bind cannot consume an activated settingsonly plan"
        );
        let workflow_runtime = self
            .workflow_activation
            .bind(std::iter::empty(), std::iter::empty())
            .context("seal disabled settingsonly workflow runtime plan")?;
        Ok(BoundSettingsOnlyPlan {
            typed: self.typed,
            workflow_runtime,
            settings_v3_serving: SettingsV3ServingHandoff::Disabled,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn bind_fixture_projection(self) -> anyhow::Result<BoundSettingsOnlyPlan> {
        self.bind_projection_with_evidence(
            fixture_projection_factory,
            std::sync::Arc::new(FixtureProjectionServing),
            SettingsV3ServingHandoff::Fixture,
        )
    }

    #[cfg(feature = "test-support")]
    fn bind_fixture_projection_with_observation(
        self,
        publisher: std::sync::Arc<
            std::sync::Mutex<Option<eventexec::ProjectionObservationPublisher>>,
        >,
    ) -> anyhow::Result<BoundSettingsOnlyPlan> {
        self.bind_projection_with_evidence(
            move |binding| fixture_projection_runtime(binding, Some(publisher)),
            std::sync::Arc::new(FixtureProjectionServing),
            SettingsV3ServingHandoff::Fixture,
        )
    }

    pub(crate) fn provider_build(
        &self,
    ) -> anyhow::Result<crate::providers_gen::ProviderRoleBatches> {
        crate::providers_gen::ProviderRoleBatches::exact_join(self.typed.provider_plans())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn into_inventory_seed_fixture(
        self,
        provider_bindings: Vec<runtimeexec::inventory::ProviderProbeBinding>,
    ) -> anyhow::Result<runtimeexec::inventory::RuntimeInventorySeed> {
        let activated = self.typed.workflow_plans().iter().any(|workflow| {
            matches!(
                workflow.activation(),
                assembly_schema::WorkflowActivation::Projection {
                    activation: assembly_schema::ProjectionActivation::Active,
                    ..
                }
            )
        });
        let bound = if activated {
            self.bind_fixture_projection()?
        } else {
            self.bind_disabled()?
        };
        Ok(bound
            .inventory_seed_with_bindings(provider_bindings)?
            .with_build_metadata(runtimeexec::inventory::BuildMetadata::parse(
                &"a".repeat(40),
                &format!("sha256:{}", "b".repeat(64)),
            )?))
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn into_live_inventory_fixture(
        self,
        provider_bindings: Vec<runtimeexec::inventory::ProviderProbeBinding>,
    ) -> anyhow::Result<LiveInventoryFixture> {
        let observation = std::sync::Arc::new(std::sync::Mutex::new(None));
        let bound =
            self.bind_fixture_projection_with_observation(std::sync::Arc::clone(&observation))?;
        let (_control, _relay, _consumer, write_admission) =
            primitives::prepare_dr_admission_controls().into_parts();
        let lifecycle = crate::projection::ProjectionLifecycleBatch::from_runtime_plan(
            bound.workflow_runtime(),
            &write_admission,
        )?
        .into_output();
        let seed = bound
            .inventory_seed_with_bindings(provider_bindings)?
            .with_build_metadata(runtimeexec::inventory::BuildMetadata::parse(
                &"a".repeat(40),
                &format!("sha256:{}", "b".repeat(64)),
            )?);
        Ok(LiveInventoryFixture {
            seed,
            lifecycle,
            observation,
        })
    }
}

#[cfg(feature = "test-support")]
pub(crate) struct LiveInventoryFixture {
    seed: runtimeexec::inventory::RuntimeInventorySeed,
    lifecycle: bootstrap::DomainModuleResult,
    observation:
        std::sync::Arc<std::sync::Mutex<Option<eventexec::ProjectionObservationPublisher>>>,
}

#[cfg(feature = "test-support")]
impl LiveInventoryFixture {
    pub(crate) fn into_parts(
        self,
    ) -> (
        runtimeexec::inventory::RuntimeInventorySeed,
        bootstrap::DomainModuleResult,
        std::sync::Arc<std::sync::Mutex<Option<eventexec::ProjectionObservationPublisher>>>,
    ) {
        (self.seed, self.lifecycle, self.observation)
    }
}

impl SettingsProjectionMaintenancePlan {
    /// Compile the bundled SettingsOnly manifest and consume its exact Settings v3 active permit.
    pub fn bundled() -> anyhow::Result<Self> {
        let mut plan = SettingsOnlyPlan::bundled()?;
        let permit = plan
            .workflow_activation
            .take_projection_permit(generated::projection::settings_v3::CONTRACT_ID)
            .context("take SettingsOnly maintenance projection permit")?;
        Ok(Self { permit })
    }

    /// Bind the plan-issued identity to an operator-owned target without activating runtime work.
    pub fn bind_target<B>(self, build: B) -> anyhow::Result<eventexec::ProjectionTargetRegistry>
    where
        B: FnOnce(
            eventexec::ProjectionMaintenanceBinding,
        ) -> Result<
            std::sync::Arc<dyn eventexec::ProjectionTarget>,
            eventexec::WorkflowRuntimeError,
        >,
    {
        let capability = eventexec::ProjectionMaintenanceCapability::bind(self.permit, build)
            .context("bind SettingsOnly maintenance projection target")?;
        let registry =
            eventexec::ProjectionTargetRegistry::from_maintenance_capabilities([capability])
                .context("build SettingsOnly maintenance projection registry")?;
        registry
            .validate_coverage()
            .context("validate SettingsOnly maintenance projection coverage")?;
        Ok(registry)
    }
}

#[cfg(any(test, feature = "test-support"))]
fn fixture_projection_factory(
    binding: eventexec::ProjectionRuntimeBinding,
) -> Result<eventexec::ProjectionRuntime, eventexec::WorkflowRuntimeError> {
    fixture_projection_runtime(binding, None)
}

#[cfg(any(test, feature = "test-support"))]
fn fixture_projection_runtime(
    binding: eventexec::ProjectionRuntimeBinding,
    observation: Option<
        std::sync::Arc<std::sync::Mutex<Option<eventexec::ProjectionObservationPublisher>>>,
    >,
) -> Result<eventexec::ProjectionRuntime, eventexec::WorkflowRuntimeError> {
    let workflow = binding.definition().contract_id().to_owned();
    let definition = eventexec::ProjectionTargetDefinition::new(
        binding.definition(),
        binding.input_generation(),
    )
    .map_err(
        |_| eventexec::WorkflowRuntimeError::CapabilityBindingRejected {
            workflow: workflow.clone(),
        },
    )?;
    let target = eventexec::ConformingProjectionTarget::new(
        definition,
        binding.inputs().to_vec(),
        std::sync::Arc::new(FixtureProjectionStore),
    )
    .map_err(|_| eventexec::WorkflowRuntimeError::CapabilityBindingRejected { workflow })?;
    binding.issue_runtime(
        std::sync::Arc::new(target),
        move |_target, _token, _health, _admission, publisher| {
            if let Some(observation) = &observation {
                *observation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(publisher);
            }
            diport::DynManagedResource::new_box(FixtureProjectionResource)
        },
    )
}

#[cfg(any(test, feature = "test-support"))]
struct FixtureProjectionServing;

#[cfg(any(test, feature = "test-support"))]
impl eventexec::ProjectionServingEvidence for FixtureProjectionServing {
    fn definition(&self) -> vocab::ContractBinding {
        generated::projection::settings_v3::CONTRACT
    }
}

#[cfg(any(test, feature = "test-support"))]
struct FixtureProjectionStore;

#[cfg(any(test, feature = "test-support"))]
impl eventexec::ProjectionTargetStore for FixtureProjectionStore {
    fn apply<'a>(
        &'a self,
        _input: &'a eventexec::ValidatedProjectionApply,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        eventexec::ProjectionTargetStoreOutcome,
                        eventexec::ProjectionTargetStoreError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Ok(eventexec::ProjectionTargetStoreOutcome::Applied) })
    }
}

#[cfg(any(test, feature = "test-support"))]
struct FixtureProjectionResource;

#[cfg(any(test, feature = "test-support"))]
impl diport::ManagedResource for FixtureProjectionResource {
    fn name(&self) -> &str {
        "settingsonly-fixture-projection-worker"
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        Ok(())
    }
}

impl BoundSettingsOnlyPlan {
    pub(crate) fn runtime_plan_fingerprint(&self) -> &str {
        self.typed.runtime_plan_fingerprint().as_str()
    }

    pub(crate) const fn workflow_runtime(&self) -> &eventexec::WorkflowRuntimePlan {
        &self.workflow_runtime
    }
}

fn expected_workers() -> anyhow::Result<bootstrap::ExpectedWorkerInventory> {
    use bootstrap::{WorkerAdmissionLane as Lane, WorkerDescriptor as Worker};

    bootstrap::ExpectedWorkerInventory::closed([
        Worker::expected("assemblies.settingsonly.src.projection.01", Lane::Writes),
        Worker::expected("assemblies.settingsonly.src.dlx.01", Lane::Writes),
        Worker::expected("assemblies.settingsonly.src.eventing.03", Lane::Relay),
        Worker::expected("assemblies.settingsonly.src.eventing.04", Lane::Writes),
        Worker::expected("assemblies.settingsonly.src.eventing.06", Lane::Writes),
        Worker::expected(
            format!(
                "event-consumer:settingsonly-event-consumer:settings:{}",
                generated::event::settings_v1::TOPIC
            ),
            Lane::Consumer,
        ),
    ])
    .map_err(Into::into)
}

impl BoundSettingsOnlyPlan {
    /// Consume the sole production handoff of the exact service whose identity entered active
    /// binding. Inventory sealing rejects an active plan until this handoff has been claimed.
    pub(crate) fn take_settings_v3_serving(
        &mut self,
    ) -> anyhow::Result<std::sync::Arc<settings::SettingsProjectionQueryService>> {
        match &mut self.settings_v3_serving {
            SettingsV3ServingHandoff::Production(serving) => serving
                .take()
                .context("Settings v3 serving capability was already consumed"),
            #[cfg(any(test, feature = "test-support"))]
            SettingsV3ServingHandoff::Disabled => {
                anyhow::bail!("disabled SettingsOnly plan has no v3 serving capability")
            }
            #[cfg(any(test, feature = "test-support"))]
            SettingsV3ServingHandoff::Fixture => {
                anyhow::bail!("fixture SettingsOnly plan has no production v3 serving capability")
            }
        }
    }

    pub(crate) fn into_inventory_seed(
        self,
        completed_roles: crate::providers_gen::CompletedProviderRoles,
    ) -> anyhow::Result<runtimeexec::inventory::RuntimeInventorySeed> {
        self.inventory_seed_with_bindings(completed_roles.into_probe_bindings())
    }

    fn inventory_seed_with_bindings(
        self,
        provider_bindings: Vec<runtimeexec::inventory::ProviderProbeBinding>,
    ) -> anyhow::Result<runtimeexec::inventory::RuntimeInventorySeed> {
        anyhow::ensure!(
            !matches!(
                &self.settings_v3_serving,
                SettingsV3ServingHandoff::Production(Some(_))
            ),
            "active Settings v3 serving was not consumed by Settings composition"
        );
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
        let provider_receipt = runtimeexec::inventory::ProviderExecutionReceipt::from_runtime_plan(
            &self.typed,
            provider_bindings,
        )?;
        runtimeexec::inventory::RuntimeInventorySeed::from_runtime_plan(
            &self.typed,
            self.workflow_runtime.activated_workflows(),
            provider_receipt,
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

fn compiler_input(manifest: &CanonicalAssemblyManifestV2) -> anyhow::Result<RuntimePlanV4Input> {
    let mut input = RuntimePlanV4Input::generic_from_manifest(manifest);

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
        plan.schema_version() == 4,
        "settingsonly requires RuntimePlan schema version 4"
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

    struct UninitializedResolver;

    impl settings::ports::ActiveProjectionResolver for UninitializedResolver {
        async fn resolve(
            &self,
            _scope: settings::ports::TenantRepoScope,
        ) -> Result<
            settings::ports::ActiveProjectionSelection,
            settings::ports::ActiveProjectionResolveError,
        > {
            Ok(settings::ports::ActiveProjectionSelection::Uninitialized)
        }
    }

    struct EmptyProjectionReadRepo;

    impl settings::ports::SettingsProjectionReadRepo for EmptyProjectionReadRepo {
        async fn find(
            &self,
            _scope: settings::ports::SettingsProjectionReadScope,
            _key: &settings::ports::SettingKey,
        ) -> Result<
            Option<settings::ports::SettingsConfigProjectionRow>,
            settings::ports::SettingsProjectionRepoError,
        > {
            Ok(None)
        }
    }

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
    fn bundled_plan_selects_exactly_the_settings_projection_as_active() {
        let plan = SettingsOnlyPlan::bundled().expect("bundled settingsonly plan");
        let workflows = plan.as_typed().workflow_plans();
        assert_eq!(workflows.len(), 1, "settingsonly workflow count");
        let workflow = workflows.first().expect("sole settingsonly workflow");
        assert!(
            matches!(
                workflow.activation(),
                assembly_schema::WorkflowActivation::Projection {
                    id,
                    activation: assembly_schema::ProjectionActivation::Active,
                    ..
                } if id == generated::projection::settings_v3::CONTRACT_ID
            ),
            "settings.config-projection must be the sole active workflow"
        );
    }

    #[test]
    fn bundled_maintenance_plan_issues_the_exact_settings_target_without_runtime() {
        let registry = SettingsProjectionMaintenancePlan::bundled()
            .expect("bundled maintenance plan")
            .bind_target(|binding| {
                let definition = eventexec::ProjectionTargetDefinition::new(
                    binding.definition(),
                    binding.input_generation(),
                )
                .map_err(|_| {
                    eventexec::WorkflowRuntimeError::CapabilityBindingRejected {
                        workflow: binding.definition().contract_id().to_owned(),
                    }
                })?;
                let target = eventexec::ConformingProjectionTarget::new(
                    definition,
                    binding.inputs().to_vec(),
                    std::sync::Arc::new(FixtureProjectionStore),
                )
                .map_err(|_| {
                    eventexec::WorkflowRuntimeError::CapabilityBindingRejected {
                        workflow: binding.definition().contract_id().to_owned(),
                    }
                })?;
                Ok(std::sync::Arc::new(target))
            })
            .expect("exact maintenance target");
        let projection =
            eventexec::ProjectionId::parse(generated::projection::settings_v3::CONTRACT_ID)
                .expect("generated Settings projection id");

        registry.validate_coverage().expect("covered registry");
        assert_eq!(
            registry
                .target(&projection)
                .expect("Settings maintenance target")
                .definition()
                .contract(),
            generated::projection::settings_v3::CONTRACT
        );
    }

    #[test]
    fn active_plan_hands_the_exact_serving_arc_to_settings_composition_once() {
        let serving = std::sync::Arc::new(settings::SettingsProjectionQueryService::new(
            settings::ports::DynActiveProjectionResolver::new_box(UninitializedResolver),
            settings::ports::DynSettingsProjectionReadRepo::new_box(EmptyProjectionReadRepo),
        ));
        let mut plan = SettingsOnlyPlan::bundled()
            .expect("bundled active plan")
            .bind_projection(fixture_projection_factory, std::sync::Arc::clone(&serving))
            .expect("bind exact serving capability");

        let claimed = plan
            .take_settings_v3_serving()
            .expect("single serving handoff");
        assert!(std::sync::Arc::ptr_eq(&serving, &claimed));
        assert!(plan.take_settings_v3_serving().is_err());
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
