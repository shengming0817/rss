//! Bundled RuntimePlan compiler.

mod domain;
mod domain_exec;
mod listener;
mod placement;
mod placement_exec;

use crate::config::SnapshotConfig;
use anyhow::Context as _;
use assembly_schema::{
    AssemblyDomain, AssemblyListenerKind, ListenerAuth, OfficialAssemblyProfile,
    ProviderActivation, ProviderCatalogEntry, RepositoryAssemblySnapshotV2,
    RuntimePlan as TypedRuntimePlan, RuntimePlanV4Input,
};
use primitives::{AuthScheme, ListenerKind};
use std::fmt;

const BUNDLED_REPOSITORY_SNAPSHOT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/repository-assembly-v2.json"));
#[cfg(test)]
const BUNDLED_ASSEMBLY_TOML: &str = include_str!("../assembly.toml");
#[cfg(test)]
const BUNDLED_ASSEMBLY_LOCK: &[u8] = include_bytes!("../assembly.lock.json");

pub(crate) use domain_exec::DomainExecutionPlan;
pub(crate) use placement_exec::PlacementExecutionPlan;
#[cfg(test)]
pub(crate) use placement_exec::PlacementExecutionSpec;

/// Close one manifest-derived official-profile identity set against the live composition.
///
/// The manifest canonicalizer owns the expected order. Live construction order is deliberately
/// irrelevant, but duplicate live identities are always a hard error rather than being hidden by
/// set normalization.
pub(crate) fn validate_official_profile_exact_ids(
    label: &str,
    expected: &[String],
    mut actual: Vec<String>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        expected.windows(2).all(|pair| pair[0] < pair[1]),
        "official profile {label} expectation is not a closed canonical set: {expected:?}"
    );
    actual.sort();
    anyhow::ensure!(
        actual.windows(2).all(|pair| pair[0] < pair[1]),
        "official profile composed duplicate {label}: {actual:?}"
    );
    anyhow::ensure!(
        actual == expected,
        "official profile {label} closure drift: expected={expected:?} actual={actual:?}"
    );
    Ok(())
}

/// Runtime-owned entrypoint around the shared, sealed protocol value.
pub struct RuntimePlan {
    plan: TypedRuntimePlan,
    workflow_activation: Option<eventexec::WorkflowActivationPlan>,
    workflow_runtime: Option<eventexec::WorkflowRuntimePlan>,
    pending_worker_descriptors: Option<Vec<bootstrap::WorkerDescriptor>>,
    official_inventory_profile:
        Option<assembly_schema::runtime_inventory::RuntimeInventoryOfficialProfile>,
    assembly_identity: String,
    telemetry_resource: observ::TelemetryResource,
}

/// The sole placement-first runtime execution capability.
///
/// Construction consumes the unplaced plan, so domain-local configuration and provider factories
/// cannot be reached through a surviving raw plan value.
pub(crate) struct PlacedRuntimePlan {
    runtime_plan: RuntimePlan,
    domain: DomainExecutionPlan,
    listeners: ListenerExecutionPlan,
    providers: ProviderExecutionPlan,
    events: LocalEventExecutionPlan,
    security: RuntimeSecurityExecutionPlan,
    placement: PlacementExecutionPlan,
}

/// Process-owned listener security capability minted only by placement.
///
/// This is deliberately independent from Identity domain locality: protected local/framework
/// routes must remain fail-closed when Identity executes remotely.
pub(crate) struct RuntimeSecurityExecutionPlan {
    _private: (),
}

pub(crate) struct ProviderExecutionPlan {
    source_runtime_plan_fingerprint: String,
    plans: Vec<ProviderExecutionSpec>,
    catalog: Vec<&'static ProviderCatalogEntry>,
}

pub(crate) struct ProviderExecutionSpec {
    id: String,
    constructor: assembly_schema::ProviderConstructor,
    activation: ProviderActivation,
    outputs: Vec<assembly_schema::LifecycleChannel>,
}

pub(crate) struct LocalEventExecutionPlan {
    active: bool,
    local_producers: Vec<generated::event::ProducerDomain>,
    local_subscriptions: Vec<generated::event::SubscriptionDispatchKey>,
    requires_audit_consumer_key: bool,
    required_amqp_domains: Vec<String>,
}

impl ProviderExecutionPlan {
    pub(crate) fn into_parts(
        self,
    ) -> (
        String,
        Vec<ProviderExecutionSpec>,
        Vec<&'static ProviderCatalogEntry>,
    ) {
        (
            self.source_runtime_plan_fingerprint,
            self.plans,
            self.catalog,
        )
    }
}

impl ProviderExecutionSpec {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) const fn constructor(&self) -> assembly_schema::ProviderConstructor {
        self.constructor
    }
    pub(crate) const fn activation(&self) -> ProviderActivation {
        self.activation
    }
    pub(crate) fn outputs(&self) -> &[assembly_schema::LifecycleChannel] {
        &self.outputs
    }

    #[cfg(test)]
    pub(crate) fn from_typed(plan: &assembly_schema::ProviderPlan) -> Self {
        Self {
            id: plan.id().to_owned(),
            constructor: plan.constructor(),
            activation: plan.activation(),
            outputs: plan.outputs().to_vec(),
        }
    }
}

impl LocalEventExecutionPlan {
    pub(crate) const fn is_active(&self) -> bool {
        self.active
    }

    pub(crate) const fn requires_audit_consumer_key(&self) -> bool {
        self.requires_audit_consumer_key
    }

    pub(crate) fn required_amqp_domains(&self) -> &[String] {
        &self.required_amqp_domains
    }

    pub(crate) fn local_producers(&self) -> &[generated::event::ProducerDomain] {
        &self.local_producers
    }

    pub(crate) fn local_subscriptions(&self) -> &[generated::event::SubscriptionDispatchKey] {
        &self.local_subscriptions
    }
}

pub(crate) struct PlacedRuntimeParts {
    pub(crate) runtime_plan: RuntimePlan,
    pub(crate) domain: DomainExecutionPlan,
    pub(crate) listeners: ListenerExecutionPlan,
    pub(crate) providers: ProviderExecutionPlan,
    pub(crate) events: LocalEventExecutionPlan,
    pub(crate) security: RuntimeSecurityExecutionPlan,
    pub(crate) placement: PlacementExecutionPlan,
}

impl PlacedRuntimePlan {
    pub(crate) fn into_parts(self) -> PlacedRuntimeParts {
        PlacedRuntimeParts {
            runtime_plan: self.runtime_plan,
            domain: self.domain,
            listeners: self.listeners,
            providers: self.providers,
            events: self.events,
            security: self.security,
            placement: self.placement,
        }
    }
}

/// A validated listener projection that can only be minted from [`RuntimePlan`].
///
/// INVARIANT: RUNTIME-LISTENER-PLAN-EXECUTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private execution fields plus RuntimePlan-only mint and consuming FinalizedListenerSet handoff" } -- runtime listener identity, domain placement, authentication and launch membership cross the composition root only through this plan-derived capability.
pub(crate) struct ListenerExecutionPlan {
    declared: Vec<ListenerExecutionSpec>,
    listeners: Vec<ListenerExecutionSpec>,
    official_routes: Option<Vec<String>>,
}

pub(crate) struct ListenerExecutionSpec {
    id: String,
    kind: ListenerKind,
    auth_scheme: AuthScheme,
    domains: Vec<AssemblyDomain>,
}

impl ListenerExecutionPlan {
    pub(crate) fn listeners(&self) -> &[ListenerExecutionSpec] {
        &self.listeners
    }

    pub(crate) fn declared_listeners(&self) -> &[ListenerExecutionSpec] {
        &self.declared
    }

    pub(crate) fn into_listeners(self) -> Vec<ListenerExecutionSpec> {
        self.listeners
    }

    pub(crate) fn official_routes(&self) -> Option<&[String]> {
        self.official_routes.as_deref()
    }
}

impl ListenerExecutionSpec {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) const fn kind(&self) -> ListenerKind {
        self.kind
    }

    pub(crate) const fn auth_scheme(&self) -> AuthScheme {
        self.auth_scheme
    }

    pub(crate) fn domains(&self) -> &[AssemblyDomain] {
        &self.domains
    }

    /// Project a fingerprint-verified access-listener fixture onto the closed Federated profile.
    ///
    /// This exists only for integration tests that exercise non-User principals. It accepts no
    /// raw scheme and preserves the fixture's listener identity and domain membership.
    #[cfg(feature = "integration")]
    pub(crate) fn into_federated_access_fixture(mut self) -> anyhow::Result<Self> {
        anyhow::ensure!(
            matches!(self.kind, ListenerKind::Primary | ListenerKind::Admin)
                && self.auth_scheme == AuthScheme::RssAccessToken,
            "Federated integration fixture requires a plan-declared access listener"
        );
        self.auth_scheme = AuthScheme::FederatedAccessToken;
        Ok(self)
    }

    #[cfg(test)]
    pub(crate) fn health_for_test() -> Self {
        Self {
            id: "health-main".to_owned(),
            kind: ListenerKind::Health,
            auth_scheme: AuthScheme::NoAuth,
            domains: Vec::new(),
        }
    }
}

impl RuntimePlan {
    /// Build the exact bundled plan from the committed manifest, lock and captured configuration.
    pub(crate) fn bundled(config: SnapshotConfig<'_>) -> Result<Self, RuntimePlanError> {
        Self::from_bundled_snapshot(BUNDLED_REPOSITORY_SNAPSHOT, config)
    }

    fn from_bundled_snapshot(
        repository_snapshot: &[u8],
        config: SnapshotConfig<'_>,
    ) -> Result<Self, RuntimePlanError> {
        let repository = RepositoryAssemblySnapshotV2::from_json_slice(repository_snapshot)
            .map_err(RuntimePlanError::RepositorySnapshot)?;
        let manifest = repository.manifest();
        let lock = repository.lock();

        let mut input = match config.value(crate::config::RUNTIME_PLAN_KIND_ENV) {
            Some("generic") => RuntimePlanV4Input::generic_from_manifest(manifest),
            Some("core") => {
                if let Some(env) = config.core_forbidden_key() {
                    return Err(RuntimePlanError::CoreExtraConfig {
                        env: env.to_owned(),
                    });
                }
                RuntimePlanV4Input::official_from_manifest(manifest, OfficialAssemblyProfile::Core)
                    .map_err(RuntimePlanError::Protocol)?
            }
            _ => return Err(RuntimePlanError::PlanKind),
        };
        listener::append(manifest, config, &mut input)?;
        domain::append(manifest, &mut input);
        placement::append(manifest, lock, config, &mut input)?;

        let plan = TypedRuntimePlan::compile_v4(manifest, lock, input)
            .map_err(RuntimePlanError::Protocol)?;
        let official_inventory_profile = plan.plan_kind().official_profile().map(|_| {
            assembly_schema::runtime_inventory::RuntimeInventoryOfficialProfile::from_manifest_and_plan(
                manifest, &plan,
            )
            .unwrap_or_else(|_| unreachable!("compiled official plan is manifest-bound"))
        });
        let workflow_activation = eventexec::WorkflowActivationPlan::select(&plan)
            .map_err(RuntimePlanError::WorkflowRuntime)?;
        let assembly_identity = lock.identity().name().to_owned();
        let telemetry_resource = observ::TelemetryResource::try_new(
            assembly_identity.as_str(),
            plan.assembly_fingerprint().as_str(),
            plan.runtime_plan_fingerprint().as_str(),
        )
        .map_err(RuntimePlanError::TelemetryResource)?;
        Ok(Self {
            plan,
            workflow_activation: Some(workflow_activation),
            workflow_runtime: None,
            pending_worker_descriptors: None,
            official_inventory_profile,
            assembly_identity,
            telemetry_resource,
        })
    }

    pub const fn as_typed(&self) -> &TypedRuntimePlan {
        &self.plan
    }

    /// Project the single application telemetry resource from the verified plan identity.
    pub(crate) const fn telemetry_resource(&self) -> &observ::TelemetryResource {
        &self.telemetry_resource
    }

    pub(crate) fn projection_capture(&self) -> eventexec::ProjectionCaptureView<'_> {
        match self.workflow_runtime.as_ref() {
            Some(runtime) => runtime.projection_capture(),
            None => self
                .workflow_activation
                .as_ref()
                .unwrap_or_else(|| unreachable!("workflow activation is consumed exactly once"))
                .projection_capture(),
        }
    }

    pub(crate) fn bind_workflow_runtime(
        &mut self,
        sagas: impl IntoIterator<Item = eventexec::SagaRuntimeCapability>,
    ) -> Result<(), RuntimePlanError> {
        let activation = self
            .workflow_activation
            .take()
            .ok_or(RuntimePlanError::WorkflowRuntimeAlreadyBound)?;
        self.workflow_runtime = Some(
            activation
                .bind(std::iter::empty(), sagas)
                .map_err(RuntimePlanError::WorkflowRuntime)?,
        );
        Ok(())
    }

    #[cfg(feature = "integration")]
    pub(crate) fn take_saga_conformance_permit(
        &mut self,
    ) -> Result<eventexec::SagaActivationPermit, RuntimePlanError> {
        self.workflow_activation
            .as_mut()
            .ok_or(RuntimePlanError::WorkflowRuntimeAlreadyBound)?
            .take_saga_permit(generated::saga::test_support::test_v1::primary::CONTRACT_ID)
            .map_err(RuntimePlanError::WorkflowRuntime)
    }

    #[cfg(feature = "integration")]
    pub(crate) fn from_saga_conformance_typed(
        plan: TypedRuntimePlan,
        assembly_identity: impl Into<String>,
    ) -> Result<Self, RuntimePlanError> {
        let workflow_activation =
            eventexec::WorkflowActivationPlan::select_saga_conformance_for_test(&plan)
                .map_err(RuntimePlanError::WorkflowRuntime)?;
        let assembly_identity = assembly_identity.into();
        let telemetry_resource = observ::TelemetryResource::try_new(
            assembly_identity.as_str(),
            plan.assembly_fingerprint().as_str(),
            plan.runtime_plan_fingerprint().as_str(),
        )
        .map_err(RuntimePlanError::TelemetryResource)?;
        Ok(Self {
            plan,
            workflow_activation: Some(workflow_activation),
            workflow_runtime: None,
            pending_worker_descriptors: None,
            official_inventory_profile: None,
            assembly_identity,
            telemetry_resource,
        })
    }

    pub(crate) fn workflow_runtime(&self) -> &eventexec::WorkflowRuntimePlan {
        self.workflow_runtime
            .as_ref()
            .unwrap_or_else(|| unreachable!("workflow runtime must be bound before consumption"))
    }

    pub(crate) fn official_inventory_profile(
        &self,
    ) -> Option<&assembly_schema::runtime_inventory::RuntimeInventoryOfficialProfile> {
        self.official_inventory_profile.as_ref()
    }

    /// Decide construction from the manifest-owned official probe closure. Generic plans retain
    /// the complete assembly behavior; official plans can construct only explicitly required
    /// probes, before any probe-specific configuration or runtime object is read or built.
    pub(crate) fn constructs_probe(&self, probe: &str) -> bool {
        self.official_inventory_profile
            .as_ref()
            .is_none_or(|profile| profile.probes().iter().any(|required| required == probe))
    }

    pub(crate) fn take_expected_workers(
        &mut self,
    ) -> anyhow::Result<bootstrap::ExpectedWorkerInventory> {
        use bootstrap::{WorkerAdmissionLane as Lane, WorkerDescriptor as Worker};

        let mut expected = match self.official_inventory_profile.as_ref() {
            Some(profile) => {
                let generated = crate::modules_gen::OFFICIAL_CORE_WORKERS
                    .iter()
                    .map(|(identity, _)| (*identity).to_owned())
                    .collect::<Vec<_>>();
                validate_official_profile_exact_ids(
                    "worker-codegen",
                    profile.workers(),
                    generated,
                )?;
                crate::modules_gen::OFFICIAL_CORE_WORKERS
                    .iter()
                    .map(|(identity, lane)| Worker::expected(*identity, *lane))
                    .collect()
            }
            None => self
                .pending_worker_descriptors
                .take()
                .context("runtime worker descriptors were not prepared during placement")?,
        };
        let sagas = self.workflow_runtime().sagas();
        if !sagas.is_empty() {
            expected.push(Worker::expected(
                "assemblies.runtime.src.phase.maintenance.04",
                Lane::Writes,
            ));
        }
        for spec in sagas.specs() {
            expected.push(Worker::expected(
                format!("saga:{}:{}", spec.domain(), spec.contract_id()),
                Lane::Writes,
            ));
        }
        bootstrap::ExpectedWorkerInventory::closed(expected).map_err(Into::into)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    // reason: assembly identity accessor for placement matrix / inventory tests.
    pub(crate) fn assembly_identity(&self) -> &str {
        &self.assembly_identity
    }

    /// Consume this plan into the exclusive Local / Remote execution projection.
    ///
    /// INVARIANT: RUNTIME-PLACEMENT-PLAN-EXECUTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private closed placement state with mandatory secure::DomainHttpEndpoint plus RuntimePlan-only fallible mint from typed topology" } -- this is the sole mint for [`PlacementExecutionPlan`].
    pub(crate) fn place(
        mut self,
        topology: bootstrap::Topology,
        config: SnapshotConfig<'_>,
    ) -> anyhow::Result<PlacedRuntimePlan> {
        let placement =
            placement_exec::mint(&self.plan, &self.assembly_identity, topology, config)?;
        let domain = domain_exec::mint(&self.plan, &placement);
        let official_routes = self
            .official_inventory_profile
            .as_ref()
            .map(|profile| profile.routes().to_vec());
        let listeners =
            listener_execution_plan_from_typed(&self.plan, Some(&placement), official_routes);
        let local_domains = domain.local_domains().to_vec();
        let event_transport_selected = self
            .plan
            .provider_plans()
            .iter()
            .any(|provider| provider.activation() == ProviderActivation::LocalEventExecution);
        let local_producers = if event_transport_selected {
            generated::event::PRODUCER_DOMAINS
                .iter()
                .copied()
                .filter(|producer| {
                    local_domains
                        .iter()
                        .any(|domain| domain.as_str() == producer.as_str())
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mut local_subscriptions = Vec::new();
        let mut requires_audit_consumer_key = false;
        let mut required_amqp_domains = local_producers
            .iter()
            .map(|producer| producer.as_str().to_owned())
            .collect::<Vec<_>>();
        for event in generated::event::EVENTS
            .iter()
            .filter(|_| event_transport_selected)
        {
            requires_audit_consumer_key |= event.subscriptions().iter().any(|subscription| {
                subscription.consumer() == AssemblyDomain::Audit.as_str()
                    && local_domains.contains(&AssemblyDomain::Audit)
            });
            if event.subscriptions().iter().any(|subscription| {
                local_domains
                    .iter()
                    .any(|domain| domain.as_str() == subscription.consumer())
            }) {
                required_amqp_domains.push(
                    event
                        .topic()
                        .split('.')
                        .next()
                        .unwrap_or(event.topic())
                        .to_owned(),
                );
            }
            local_subscriptions.extend(
                event
                    .subscriptions()
                    .iter()
                    .filter(|subscription| {
                        local_domains
                            .iter()
                            .any(|domain| domain.as_str() == subscription.consumer())
                    })
                    .map(|subscription| subscription.dispatch()),
            );
        }
        required_amqp_domains.sort_unstable();
        required_amqp_domains.dedup();
        let events = LocalEventExecutionPlan {
            active: !required_amqp_domains.is_empty(),
            local_producers,
            local_subscriptions,
            requires_audit_consumer_key,
            required_amqp_domains,
        };
        self.pending_worker_descriptors =
            Some(expected_runtime_worker_descriptors(&events, &local_domains));
        let mut plans = Vec::new();
        let mut catalog = Vec::new();
        for plan in self.plan.provider_plans() {
            anyhow::ensure!(
                crate::providers_gen::PROVIDER_CATALOG
                    .iter()
                    .any(|entry| entry.role().as_str() == plan.id()),
                "RuntimePlan provider set contains an unclassified provider"
            );
        }
        for entry in crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .filter(|entry| {
                self.plan
                    .provider_plans()
                    .iter()
                    .any(|plan| plan.id() == entry.role().as_str())
            })
        {
            let active = match entry.activation() {
                ProviderActivation::Process => true,
                ProviderActivation::DomainLocal(domain) => placement.is_local(domain),
                ProviderActivation::LocalEventExecution => events.is_active(),
            };
            let plan = self
                .plan
                .provider_plans()
                .iter()
                .find(|plan| plan.id() == entry.role().as_str())
                .unwrap_or_else(|| unreachable!("catalog was projected from RuntimePlan ids"));
            anyhow::ensure!(
                plan.activation() == entry.activation(),
                "RuntimePlan provider activation disagrees with generated catalog"
            );
            if active {
                plans.push(plan);
                catalog.push(entry);
            }
        }
        let plans = plans
            .into_iter()
            .map(|plan| ProviderExecutionSpec {
                id: plan.id().to_owned(),
                constructor: plan.constructor(),
                activation: plan.activation(),
                outputs: plan.outputs().to_vec(),
            })
            .collect();
        let source_runtime_plan_fingerprint =
            self.plan.runtime_plan_fingerprint().as_str().to_owned();
        Ok(PlacedRuntimePlan {
            runtime_plan: self,
            domain,
            listeners,
            providers: ProviderExecutionPlan {
                source_runtime_plan_fingerprint,
                plans,
                catalog,
            },
            events,
            security: RuntimeSecurityExecutionPlan { _private: () },
            placement,
        })
    }

    // Unit tests inspect projections directly. Production can only use the consuming `place`
    // transition above, so these helpers cannot become an alternate startup path.
    #[cfg(test)]
    pub(crate) fn placement_execution_plan(
        &self,
        topology: bootstrap::Topology,
        config: SnapshotConfig<'_>,
    ) -> anyhow::Result<PlacementExecutionPlan> {
        placement_exec::mint(&self.plan, &self.assembly_identity, topology, config)
    }

    #[cfg(test)]
    pub(crate) fn domain_execution_plan(
        &self,
        placement: &PlacementExecutionPlan,
    ) -> DomainExecutionPlan {
        domain_exec::mint(&self.plan, placement)
    }

    #[cfg(any(test, feature = "integration"))]
    pub(crate) fn listener_execution_plan(&self) -> ListenerExecutionPlan {
        listener_execution_plan_from_typed(&self.plan, None, None)
    }

    #[cfg(test)]
    pub(crate) fn listener_execution_plan_for_placement(
        &self,
        placement: &PlacementExecutionPlan,
    ) -> ListenerExecutionPlan {
        listener_execution_plan_from_typed(&self.plan, Some(placement), None)
    }
}

fn expected_runtime_worker_descriptors(
    events: &LocalEventExecutionPlan,
    local_domains: &[AssemblyDomain],
) -> Vec<bootstrap::WorkerDescriptor> {
    use bootstrap::{WorkerAdmissionLane as Lane, WorkerDescriptor as Worker};

    let mut expected = vec![
        Worker::expected(
            "assemblies.runtime.src.provider_output.01",
            Lane::Observational,
        ),
        Worker::expected("assemblies.runtime.src.phase.infra.01", Lane::Observational),
        Worker::expected("assemblies.runtime.src.phase.maintenance.01", Lane::Writes),
    ];
    if events.is_active() {
        expected.extend([
            Worker::expected("assemblies.runtime.src.event_transport.03", Lane::Writes),
            Worker::expected("assemblies.runtime.src.infra.s3.01", Lane::Observational),
            Worker::expected("assemblies.runtime.src.phase.maintenance.02", Lane::Writes),
            Worker::expected("assemblies.runtime.src.phase.maintenance.03", Lane::Writes),
            Worker::expected("assemblies.runtime.src.event_transport.07", Lane::Writes),
            Worker::expected("assemblies.runtime.src.event_transport.08", Lane::Writes),
        ]);
    }
    for producer in events.local_producers() {
        expected.push(Worker::expected(
            format!("outbox-relay:{}", producer.as_str()),
            Lane::Relay,
        ));
    }
    for event in generated::event::EVENTS {
        for subscription in event.subscriptions().iter().filter(|subscription| {
            local_domains
                .iter()
                .any(|domain| domain.as_str() == subscription.consumer())
        }) {
            expected.push(Worker::expected(
                format!(
                    "event-consumer:event-consumer:{}:{}",
                    subscription.consumer(),
                    event.topic()
                ),
                Lane::Consumer,
            ));
        }
    }
    expected
}

fn listener_execution_plan_from_typed(
    plan: &TypedRuntimePlan,
    placement: Option<&PlacementExecutionPlan>,
    official_routes: Option<Vec<String>>,
) -> ListenerExecutionPlan {
    let declared = plan
        .listener_plans()
        .iter()
        .map(|listener| ListenerExecutionSpec {
            id: listener.id().to_owned(),
            kind: runtime_listener_kind(listener.kind()),
            auth_scheme: runtime_auth_scheme(listener.auth()),
            domains: listener.domains().to_vec(),
        })
        .collect::<Vec<_>>();
    let listeners = declared
        .iter()
        .map(|listener| ListenerExecutionSpec {
            id: listener.id.clone(),
            kind: listener.kind,
            auth_scheme: listener.auth_scheme,
            domains: listener
                .domains
                .iter()
                .copied()
                .filter(|domain| placement.is_none_or(|plan| plan.is_local(*domain)))
                .collect(),
        })
        .collect();
    ListenerExecutionPlan {
        declared,
        listeners,
        official_routes,
    }
}

pub(crate) fn is_kebab_case_workload(value: &str) -> bool {
    let mut chars = value.chars().peekable();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    let mut prev_hyphen = false;
    for ch in chars {
        match ch {
            'a'..='z' | '0'..='9' => prev_hyphen = false,
            '-' if !prev_hyphen => prev_hyphen = true,
            _ => return false,
        }
    }
    !prev_hyphen
}

#[cfg(feature = "integration")]
pub(crate) fn fixture_listener_spec(
    kind: AssemblyListenerKind,
) -> anyhow::Result<ListenerExecutionSpec> {
    let repository = RepositoryAssemblySnapshotV2::from_json_slice(BUNDLED_REPOSITORY_SNAPSHOT)
        .map_err(|error| anyhow::anyhow!("verify bundled fixture repository: {error}"))?;
    let parsed = assembly_schema::ParsedRuntimePlan::from_json_slice_bound(
        include_bytes!("../runtime-plan.json"),
        repository.manifest(),
        repository.lock(),
    )
    .map_err(|error| anyhow::anyhow!("parse fingerprint-verified RuntimePlan fixture: {error}"))?;
    listener_execution_plan_from_typed(parsed.as_plan(), None, None)
        .into_listeners()
        .into_iter()
        .find(|listener| listener.kind() == runtime_listener_kind(kind))
        .ok_or_else(|| anyhow::anyhow!("RuntimePlan fixture does not declare requested listener"))
}

const fn runtime_listener_kind(kind: AssemblyListenerKind) -> ListenerKind {
    match kind {
        AssemblyListenerKind::Primary => ListenerKind::Primary,
        AssemblyListenerKind::Internal => ListenerKind::Internal,
        AssemblyListenerKind::Admin => ListenerKind::Admin,
        AssemblyListenerKind::Health => ListenerKind::Health,
    }
}

const fn runtime_auth_scheme(auth: ListenerAuth) -> AuthScheme {
    match auth {
        ListenerAuth::NoAuth => AuthScheme::NoAuth,
        ListenerAuth::RssAccessToken => AuthScheme::RssAccessToken,
        ListenerAuth::FederatedAccessToken => AuthScheme::FederatedAccessToken,
        ListenerAuth::Mtls => AuthScheme::Mtls,
        ListenerAuth::ServiceToken => AuthScheme::ServiceToken,
    }
}

impl fmt::Debug for RuntimePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.plan.fmt(f)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RuntimePlanError {
    #[error("verify bundled runtime repository snapshot failed")]
    RepositorySnapshot(#[source] assembly_schema::AssemblyLockError),
    #[error(
        "resolve RSS_PRIMARY_TOKEN_PROFILE, RSS_ADMIN_TOKEN_PROFILE, or RSS_INTERNAL_AUTH_SCHEME failed; expected rss-access/federated-access and mtls/service-token"
    )]
    ListenerAuth,
    #[error("resolve RSS_RUNTIME_PLAN_KIND failed; expected the closed value generic or core")]
    PlanKind,
    #[error("Core official profile forbids configured Eventing capability `{env}`")]
    CoreExtraConfig { env: String },
    #[error("resolve {env} failed; expected a non-empty lowercase kebab-case workload name")]
    PlacementWorkload {
        /// Exact `RSS_<DOMAIN>_DOMAIN_PLACEMENT_WORKLOAD` env key that failed validation.
        env: String,
    },
    #[error("compile bundled RuntimePlan protocol failed: {0}")]
    Protocol(#[source] assembly_schema::RuntimePlanError),
    #[error("project bundled RuntimePlan telemetry identity failed")]
    TelemetryResource(#[source] observ::TelemetryResourceError),
    #[error("compile bundled workflow runtime plan failed: {0}")]
    WorkflowRuntime(#[source] eventexec::WorkflowRuntimeError),
    #[error("bundled workflow runtime plan was already bound")]
    WorkflowRuntimeAlreadyBound,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    // reason: bundled protocol/golden tests should stop at the exact local drift assertion.

    use super::*;
    use crate::config::{generic_test_snapshot, unbound_test_snapshot};
    use assembly_schema::{
        AssemblyDomain, AssemblyListenerKind, AssemblyManifest, CanonicalAssemblyManifestV2,
        DomainLifecyclePhase, ListenerAuth, ParsedAssemblyLock, ProviderLifecycle,
        RepositoryVerifiedAssemblyLock, RuntimePlanErrorStage,
    };
    use std::collections::BTreeMap;
    use std::error::Error as _;
    use std::path::{Path, PathBuf};

    const SECRET_BAIT: &str = "ZZ_RUNTIME_PLAN_SECRET_1788";
    const IDENTITY_AUDIT_ASSEMBLY_LOCK: &[u8] =
        include_bytes!("../../identityaudit/assembly.lock.json");

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Mutation {
        DuplicateProvider,
        MissingListener,
        DuplicateListener,
        MissingDomain,
        DuplicateDomain,
        MissingPlacement,
        DuplicatePlacement,
        DanglingListener,
        DanglingPlacement,
        ReverseListeners,
        ReversePlacements,
    }

    #[test]
    fn official_profile_exact_id_join_rejects_missing_extra_duplicate_and_wrong_id() {
        let core = bundled(&[("RSS_RUNTIME_PLAN_KIND", "core")]);
        let inventory = core
            .official_inventory_profile()
            .expect("Core plan carries manifest-derived inventory");
        let categories = [
            (
                "listener",
                core.as_typed()
                    .listener_plans()
                    .iter()
                    .map(|listener| listener.id().to_owned())
                    .collect::<Vec<_>>(),
            ),
            (
                "provider",
                core.as_typed()
                    .provider_plans()
                    .iter()
                    .map(|provider| provider.id().to_owned())
                    .collect(),
            ),
            ("route", inventory.routes().to_vec()),
            ("worker", inventory.workers().to_vec()),
            ("probe", inventory.probes().to_vec()),
        ];

        for (label, expected) in categories {
            assert!(!expected.is_empty(), "Core {label} closure is vacuous");
            let mut reordered = expected.clone();
            reordered.reverse();
            validate_official_profile_exact_ids(label, &expected, reordered)
                .expect("live construction order is not identity drift");

            let mut missing = expected.clone();
            missing.pop();
            let mut extra = expected.clone();
            extra.push("zz-unclassified-extra".to_owned());
            let mut duplicate = expected.clone();
            duplicate.push(expected[0].clone());
            for actual in [missing, extra, duplicate] {
                assert!(
                    validate_official_profile_exact_ids(label, &expected, actual).is_err(),
                    "Core {label} mutation crossed the exact join"
                );
            }
        }
    }

    fn profile_snapshot(entries: &[(&str, &str)]) -> crate::config::RuntimeConfigSnapshot {
        let mut merged = BTreeMap::from([
            ("RSS_RUNTIME_PLAN_KIND", "generic"),
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ]);
        merged.extend(entries.iter().copied());
        let merged = merged.into_iter().collect::<Vec<_>>();
        generic_test_snapshot(&merged).expect("test snapshot")
    }

    fn bundled(entries: &[(&str, &str)]) -> RuntimePlan {
        let snapshot = profile_snapshot(entries);
        RuntimePlan::bundled(snapshot.view()).expect("bundled RuntimePlan")
    }

    #[test]
    fn runtime_plan_kind_is_mandatory_and_core_projects_exact_closure() {
        let missing = unbound_test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ])
        .expect("snapshot");
        assert!(matches!(
            RuntimePlan::bundled(missing.view()),
            Err(RuntimePlanError::PlanKind)
        ));

        let core = bundled(&[("RSS_RUNTIME_PLAN_KIND", "core")]);
        assert_eq!(
            core.as_typed().plan_kind().official_profile(),
            Some(OfficialAssemblyProfile::Core)
        );
        assert_eq!(
            core.as_typed()
                .provider_plans()
                .iter()
                .map(assembly_schema::ProviderPlan::id)
                .collect::<Vec<_>>(),
            ["auth-audit-sink", "listener-pdp", "listener-rate-limiter"]
        );
        assert_eq!(
            core.as_typed()
                .listener_plans()
                .iter()
                .map(assembly_schema::ListenerPlan::kind)
                .collect::<Vec<_>>(),
            [AssemblyListenerKind::Admin, AssemblyListenerKind::Health]
        );
        assert_eq!(
            core.as_typed()
                .domain_plans()
                .iter()
                .map(assembly_schema::DomainPlan::id)
                .collect::<Vec<_>>(),
            [AssemblyDomain::Audit]
        );
        for required in crate::modules_gen::OFFICIAL_CORE_PROBES {
            assert!(core.constructs_probe(required));
        }
        for forbidden in [
            crate::event_transport::DR_ADMISSION_PROBE_NAME,
            crate::infra::signing_rotation::RSS_ACCESS_TOKEN_SIGNING_ROTATION_PROBE_NAME,
        ] {
            assert!(
                !core.constructs_probe(forbidden),
                "Core constructed forbidden probe {forbidden}"
            );
        }
        assert!(bundled(&[]).constructs_probe(crate::event_transport::DR_ADMISSION_PROBE_NAME));

        let placed_snapshot = profile_snapshot(&[("RSS_RUNTIME_PLAN_KIND", "core")]);
        let placed = RuntimePlan::bundled(placed_snapshot.view())
            .expect("Core plan")
            .place(bootstrap::Topology::DurableShared, placed_snapshot.view())
            .expect("Core placement projects before construction")
            .into_parts();
        assert!(!placed.events.is_active());
        let (_, providers, catalog) = placed.providers.into_parts();
        assert_eq!(
            providers
                .iter()
                .map(ProviderExecutionSpec::id)
                .collect::<Vec<_>>(),
            ["auth-audit-sink", "listener-pdp", "listener-rate-limiter"]
        );
        assert_eq!(catalog.len(), providers.len());

        for key in [
            "RSS_AMQP_URL",
            "RSS_DLX_ARCHIVE_S3_BUCKET",
            "RSS_OUTBOX_SWEEP_INTERVAL_MS",
            "RSS_AUDIT_DOMAIN_TRANSPORT_URL",
            "RSS_FEDERATED_ACCESS_TOKEN_ISSUER",
            "RSS_SERVICE_TOKEN_ISSUER",
        ] {
            let snapshot = profile_snapshot(&[("RSS_RUNTIME_PLAN_KIND", "core"), (key, "set")]);
            assert!(matches!(
                RuntimePlan::bundled(snapshot.view()),
                Err(RuntimePlanError::CoreExtraConfig { env }) if env == key
            ));
        }
    }

    fn artifact_error(manifest_toml: &str, assembly_lock_json: &[u8]) -> RuntimePlanError {
        let snapshot = profile_snapshot(&[("RSS_VAULT_TOKEN", SECRET_BAIT)]);
        let mut value: serde_json::Value =
            serde_json::from_slice(BUNDLED_REPOSITORY_SNAPSHOT).expect("repository snapshot");
        value["assemblyManifest"]["content"] = manifest_toml.into();
        value["assemblyLock"]["content"] = std::str::from_utf8(assembly_lock_json)
            .unwrap_or("{")
            .into();
        let bytes = serde_json::to_vec(&value).expect("mutated snapshot");
        RuntimePlan::from_bundled_snapshot(&bytes, snapshot.view())
            .expect_err("invalid bundled artifact must fail")
    }

    fn canonical_manifest(source: &str) -> CanonicalAssemblyManifestV2 {
        AssemblyManifest::from_toml_str(source)
            .expect("manifest")
            .canonicalize_v2()
            .expect("canonical manifest")
    }

    // PreExpansionPass sees cfg'd-out `env!` (dylint --all has no --all-targets); allow test path helper.
    #[allow(unknown_lints, rss_runtime_env_funnel)] // reason: cfg(test) repo-root helper; PreExpansionPass sees cfg(test) env!
    fn repository_root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("runtime test repository root")
    }

    fn assembly_dir(name: &str) -> PathBuf {
        repository_root().join("assemblies").join(name)
    }

    fn verified_lock(source: &[u8], assembly: &str) -> RepositoryVerifiedAssemblyLock {
        let assembly_dir = assembly_dir(assembly);
        let manifest = assembly_schema::RepositoryAssemblyManifestV2::discover_v2(
            repository_root(),
            &assembly_dir,
        )
        .expect("repository assembly manifest");
        ParsedAssemblyLock::from_json_slice(source)
            .expect("AssemblyLock")
            .verify_repository_v2(&manifest)
            .expect("repository-verified AssemblyLock")
    }

    fn compile_error(
        manifest: &CanonicalAssemblyManifestV2,
        lock: &RepositoryVerifiedAssemblyLock,
    ) -> assembly_schema::RuntimePlanError {
        TypedRuntimePlan::compile_v4(manifest, lock, compiler_input(manifest, lock, None))
            .expect_err("mismatched manifest/lock must fail")
    }

    fn compiler_input(
        manifest: &CanonicalAssemblyManifestV2,
        lock: &RepositoryVerifiedAssemblyLock,
        mutation: Option<Mutation>,
    ) -> RuntimePlanV4Input {
        let mut input = RuntimePlanV4Input::generic_from_manifest(manifest);
        append_candidate_providers(manifest, mutation, &mut input);
        append_candidate_listeners(manifest, mutation, &mut input);
        append_candidate_domains(manifest, mutation, &mut input);
        append_candidate_placements(manifest, lock, mutation, &mut input);
        input
    }

    fn append_candidate_providers(
        manifest: &CanonicalAssemblyManifestV2,
        mutation: Option<Mutation>,
        input: &mut RuntimePlanV4Input,
    ) {
        if mutation != Some(Mutation::DuplicateProvider) {
            return;
        }
        let provider = manifest
            .diport_providers()
            .iter()
            .filter(|provider| provider.lifecycle == ProviderLifecycle::Active)
            .min_by_key(|provider| provider.id.as_str())
            .expect("runtime has an active provider");
        input.provider(provider.id, provider.provider, provider.outputs.clone());
    }

    fn append_candidate_listeners(
        manifest: &CanonicalAssemblyManifestV2,
        mutation: Option<Mutation>,
        input: &mut RuntimePlanV4Input,
    ) {
        let mut listeners = manifest
            .listeners()
            .iter()
            .map(|listener| {
                let auth = match listener.kind {
                    AssemblyListenerKind::Primary | AssemblyListenerKind::Admin => {
                        ListenerAuth::RssAccessToken
                    }
                    AssemblyListenerKind::Internal => ListenerAuth::Mtls,
                    AssemblyListenerKind::Health => ListenerAuth::NoAuth,
                };
                (listener.kind, auth, listener.domains.clone())
            })
            .collect::<Vec<_>>();
        listeners.sort_by_key(|(kind, _, _)| kind.as_str());
        if mutation == Some(Mutation::ReverseListeners) {
            listeners.reverse();
        }
        for (index, (kind, auth, domains)) in listeners.iter().enumerate() {
            if index == 0 && mutation == Some(Mutation::MissingListener) {
                continue;
            }
            let domains = if index == 0 && mutation == Some(Mutation::DanglingListener) {
                vec![AssemblyDomain::Contractreg]
            } else {
                domains.clone()
            };
            input.listener(*kind, *auth, domains.clone());
            if index == 0 && mutation == Some(Mutation::DuplicateListener) {
                input.listener(*kind, *auth, domains);
            }
        }
    }

    fn append_candidate_domains(
        manifest: &CanonicalAssemblyManifestV2,
        mutation: Option<Mutation>,
        input: &mut RuntimePlanV4Input,
    ) {
        for (index, domain) in manifest.domains().iter().enumerate() {
            if index == 0 && mutation == Some(Mutation::MissingDomain) {
                continue;
            }
            input.domain(*domain);
            if index == 0 && mutation == Some(Mutation::DuplicateDomain) {
                input.domain(*domain);
            }
        }
    }

    fn append_candidate_placements(
        manifest: &CanonicalAssemblyManifestV2,
        lock: &RepositoryVerifiedAssemblyLock,
        mutation: Option<Mutation>,
        input: &mut RuntimePlanV4Input,
    ) {
        let mut placements = manifest
            .domains()
            .iter()
            .map(|domain| (*domain, lock.identity().name()))
            .collect::<Vec<_>>();
        placements
            .sort_by(|left, right| (left.0.as_str(), left.1).cmp(&(right.0.as_str(), right.1)));
        if mutation == Some(Mutation::ReversePlacements) {
            placements.reverse();
        }
        for (index, (domain, workload)) in placements.iter().enumerate() {
            if index == 0 && mutation == Some(Mutation::MissingPlacement) {
                continue;
            }
            let domain = if index == 0 && mutation == Some(Mutation::DanglingPlacement) {
                AssemblyDomain::Contractreg
            } else {
                *domain
            };
            input.placement(domain, *workload);
            if index == 0 && mutation == Some(Mutation::DuplicatePlacement) {
                input.placement(domain, *workload);
            }
        }
    }

    #[test]
    fn runtime_plan_bundled_closes_every_declared_fact_in_stable_order() {
        let plan = bundled(&[]);
        let typed = plan.as_typed();
        let provider_ids = typed
            .provider_plans()
            .iter()
            .map(assembly_schema::ProviderPlan::id)
            .collect::<Vec<_>>();
        assert_eq!(
            provider_ids,
            [
                "auth-audit-sink",
                "device-revocation-store",
                "distributed-cas-store",
                "distributed-lock-store",
                "dlx-archive-key-provider",
                "dlx-archive-store",
                "dlx-lifecycle-repository",
                "event-publisher",
                "event-subscriber",
                "identity-signer",
                "listener-pdp",
                "listener-rate-limiter",
                "runtime-object-store",
                "service-token-replay-store",
                "settings-key-provider",
                "settings-secret-resolver",
            ]
        );
        assert_eq!(
            typed
                .listener_plans()
                .iter()
                .map(|listener| (listener.id(), listener.auth()))
                .collect::<Vec<_>>(),
            [
                ("admin-main", ListenerAuth::RssAccessToken),
                ("health-main", ListenerAuth::NoAuth),
                ("internal-main", ListenerAuth::Mtls),
                ("primary-main", ListenerAuth::RssAccessToken),
            ]
        );
        assert_eq!(
            typed
                .domain_plans()
                .iter()
                .map(|domain| domain.id().as_str())
                .collect::<Vec<_>>(),
            ["settings", "identity", "audit"]
        );
        assert!(typed.domain_plans().iter().all(|domain| domain.lifecycle()
            == [
                DomainLifecyclePhase::Construct,
                DomainLifecyclePhase::Ready,
                DomainLifecyclePhase::Shutdown
            ]));
        assert_eq!(
            typed
                .placement_plans()
                .iter()
                .map(|placement| (placement.domain().as_str(), placement.workload()))
                .collect::<Vec<_>>(),
            [
                ("audit", "runtime"),
                ("identity", "runtime"),
                ("settings", "runtime"),
            ]
        );
    }

    #[test]
    fn runtime_plan_listener_profiles_are_typed_but_secret_only_config_is_excluded() {
        let default = bundled(&[]);
        let service_token = bundled(&[("RSS_INTERNAL_AUTH_SCHEME", "service-token")]);
        assert_ne!(
            default.as_typed().runtime_plan_fingerprint().as_str(),
            service_token.as_typed().runtime_plan_fingerprint().as_str()
        );
        assert_eq!(
            service_token.as_typed().listener_plans()[2].auth(),
            ListenerAuth::ServiceToken
        );

        let federated = bundled(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "federated-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "federated-access"),
        ]);
        assert_ne!(
            default.as_typed().runtime_plan_fingerprint().as_str(),
            federated.as_typed().runtime_plan_fingerprint().as_str()
        );
        assert_eq!(
            federated.as_typed().listener_plans()[0].auth(),
            ListenerAuth::FederatedAccessToken
        );
        assert_eq!(
            federated.as_typed().listener_plans()[3].auth(),
            ListenerAuth::FederatedAccessToken
        );

        let secret_only = bundled(&[("RSS_VAULT_TOKEN", SECRET_BAIT)]);
        assert_eq!(
            default.as_typed().runtime_plan_fingerprint().as_str(),
            secret_only.as_typed().runtime_plan_fingerprint().as_str()
        );
        let json = serde_json::to_string(secret_only.as_typed()).expect("plan JSON");
        let debug = format!("{secret_only:?}");
        assert!(!json.contains(SECRET_BAIT));
        assert!(!debug.contains(SECRET_BAIT));
        assert!(!debug.contains("oidc::OidcProvider"));
    }

    #[test]
    fn telemetry_resource_projects_the_exact_verified_runtime_plan_identity() {
        let runtime_plan = bundled(&[]);
        let resource = runtime_plan.telemetry_resource();
        assert_eq!(resource.service_name(), runtime_plan.assembly_identity());
        assert_eq!(
            resource.assembly_fingerprint(),
            runtime_plan.as_typed().assembly_fingerprint().as_str()
        );
        assert_eq!(
            resource.runtime_plan_fingerprint(),
            runtime_plan.as_typed().runtime_plan_fingerprint().as_str()
        );
    }

    #[test]
    fn runtime_plan_unknown_internal_auth_fails_closed_without_echoing_value() {
        let snapshot = profile_snapshot(&[("RSS_INTERNAL_AUTH_SCHEME", SECRET_BAIT)]);
        let error = RuntimePlan::bundled(snapshot.view()).expect_err("invalid auth must fail");
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("RSS_INTERNAL_AUTH_SCHEME"));
        assert!(diagnostic.contains("mtls"));
        assert!(diagnostic.contains("service-token"));
        assert!(!diagnostic.contains(SECRET_BAIT));
        assert!(!format!("{error:?}").contains(SECRET_BAIT));
    }

    #[test]
    fn runtime_plan_rejects_asymmetric_federated_primary_selection() {
        let snapshot = profile_snapshot(&[("RSS_PRIMARY_TOKEN_PROFILE", "federated-access")]);
        let error = RuntimePlan::bundled(snapshot.view())
            .expect_err("federated Primary with RSS Admin must fail");
        assert!(error.to_string().contains("RSS_PRIMARY_TOKEN_PROFILE"));
    }

    #[test]
    fn runtime_plan_compiler_rejects_manifest_lock_name_mismatch() {
        let manifest = canonical_manifest(BUNDLED_ASSEMBLY_TOML);
        let lock = verified_lock(IDENTITY_AUDIT_ASSEMBLY_LOCK, "identityaudit");

        let error = compile_error(&manifest, &lock);
        assert_eq!(error.stage(), RuntimePlanErrorStage::AssemblyIdentity);
        assert_eq!(
            error.to_string(),
            "RuntimePlan identity does not match the canonical assembly manifest and lock"
        );
    }

    #[test]
    fn runtime_plan_compiler_rejects_manifest_lock_profile_mismatch() {
        let source =
            BUNDLED_ASSEMBLY_TOML.replacen("profile = \"production\"", "profile = \"demo\"", 1);
        let manifest = canonical_manifest(&source);
        let lock = verified_lock(BUNDLED_ASSEMBLY_LOCK, "runtime");

        let error = compile_error(&manifest, &lock);
        assert_eq!(error.stage(), RuntimePlanErrorStage::AssemblyIdentity);
        assert_eq!(
            error.to_string(),
            "RuntimePlan identity does not match the canonical assembly manifest and lock"
        );
    }

    #[test]
    fn runtime_plan_compiler_rejects_manifest_digest_mismatch() {
        let source = BUNDLED_ASSEMBLY_TOML.replacen(
            "purpose = \"device-certificate-revocation\"",
            "purpose = \"device-certificate-revocation-v2\"",
            1,
        );
        let manifest = canonical_manifest(&source);
        let lock = verified_lock(BUNDLED_ASSEMBLY_LOCK, "runtime");

        let error = compile_error(&manifest, &lock);
        assert_eq!(error.stage(), RuntimePlanErrorStage::ManifestDigest);
        assert_eq!(
            error.to_string(),
            "RuntimePlan canonical manifest digest does not match AssemblyLock"
        );
    }

    #[test]
    fn runtime_plan_bundled_manifest_parse_error_preserves_safe_source() {
        let error = artifact_error("name = [", BUNDLED_ASSEMBLY_LOCK);

        assert_eq!(
            error.to_string(),
            "verify bundled runtime repository snapshot failed"
        );
        let source = error.source().expect("repository snapshot source");
        assert!(source.is::<assembly_schema::AssemblyLockError>());
        assert!(
            source
                .source()
                .is_some_and(|source| source.is::<toml::de::Error>())
        );
        assert!(!format!("{error:?}").contains(SECRET_BAIT));
    }

    #[test]
    fn runtime_plan_bundled_manifest_canonicalization_error_preserves_safe_source() {
        let source = BUNDLED_ASSEMBLY_TOML.replacen(
            "domains = [\"settings\", \"identity\", \"audit\"]",
            "domains = []",
            1,
        );
        let error = artifact_error(&source, BUNDLED_ASSEMBLY_LOCK);

        assert_eq!(
            error.to_string(),
            "verify bundled runtime repository snapshot failed"
        );
        let source = error.source().expect("repository snapshot source");
        assert!(source.is::<assembly_schema::AssemblyLockError>());
        assert!(
            source.source().is_some_and(
                |source| format!("{source:?}").contains("Empty { field: \"domains\" }")
            )
        );
        assert!(!format!("{error:?}").contains(SECRET_BAIT));
    }

    #[test]
    fn runtime_plan_bundled_lock_parse_error_preserves_safe_source_chain() {
        let error = artifact_error(BUNDLED_ASSEMBLY_TOML, b"{");

        assert_eq!(
            error.to_string(),
            "verify bundled runtime repository snapshot failed"
        );
        let source = error.source().expect("AssemblyLock source");
        assert!(source.is::<assembly_schema::AssemblyLockError>());
        assert!(
            source
                .source()
                .is_some_and(|source| source.is::<serde_json::Error>())
        );
        assert!(!format!("{error:?}").contains(SECRET_BAIT));
    }

    #[test]
    fn runtime_plan_compiler_rejects_complete_negative_matrix() {
        let manifest = AssemblyManifest::from_toml_str(BUNDLED_ASSEMBLY_TOML)
            .expect("manifest")
            .canonicalize_v2()
            .expect("canonical manifest");
        let lock = verified_lock(BUNDLED_ASSEMBLY_LOCK, "runtime");

        TypedRuntimePlan::compile_v4(&manifest, &lock, compiler_input(&manifest, &lock, None))
            .expect("unmutated candidate facts must compile");
        for mutation in [
            Mutation::DuplicateProvider,
            Mutation::MissingListener,
            Mutation::DuplicateListener,
            Mutation::MissingDomain,
            Mutation::DuplicateDomain,
            Mutation::MissingPlacement,
            Mutation::DuplicatePlacement,
            Mutation::DanglingListener,
            Mutation::DanglingPlacement,
            Mutation::ReverseListeners,
            Mutation::ReversePlacements,
        ] {
            assert!(
                TypedRuntimePlan::compile_v4(
                    &manifest,
                    &lock,
                    compiler_input(&manifest, &lock, Some(mutation))
                )
                .is_err(),
                "compiler accepted {mutation:?}"
            );
        }
    }

    #[test]
    fn runtime_plan_bundled_json_matches_full_golden() {
        let mut actual =
            serde_json::to_string_pretty(bundled(&[]).as_typed()).expect("RuntimePlan JSON");
        actual.push('\n');
        assert_eq!(
            actual.as_bytes(),
            include_bytes!("../runtime-plan.json"),
            "runtime RuntimePlan artifact drift"
        );
    }

    #[test]
    fn listener_plan_execution_projects_bundled_four_listener_baseline() {
        let runtime_plan = bundled(&[]);
        let execution = runtime_plan.listener_execution_plan();
        let actual = execution
            .listeners()
            .iter()
            .map(|listener| {
                (
                    listener.id(),
                    listener.kind(),
                    listener.auth_scheme(),
                    listener.domains().to_vec(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            actual,
            vec![
                (
                    "admin-main",
                    primitives::ListenerKind::Admin,
                    primitives::AuthScheme::RssAccessToken,
                    vec![AssemblyDomain::Audit],
                ),
                (
                    "health-main",
                    primitives::ListenerKind::Health,
                    primitives::AuthScheme::NoAuth,
                    vec![],
                ),
                (
                    "internal-main",
                    primitives::ListenerKind::Internal,
                    primitives::AuthScheme::Mtls,
                    vec![],
                ),
                (
                    "primary-main",
                    primitives::ListenerKind::Primary,
                    primitives::AuthScheme::RssAccessToken,
                    vec![AssemblyDomain::Settings, AssemblyDomain::Identity],
                ),
            ]
        );
    }

    #[test]
    fn auth_plan_execution_projects_every_closed_listener_scheme() {
        let service_token = bundled(&[("RSS_INTERNAL_AUTH_SCHEME", "service-token")]);
        let service_token_schemes = service_token
            .listener_execution_plan()
            .listeners()
            .iter()
            .map(|listener| (listener.kind(), listener.auth_scheme()))
            .collect::<Vec<_>>();
        assert!(service_token_schemes.contains(&(
            primitives::ListenerKind::Internal,
            primitives::AuthScheme::ServiceToken,
        )));

        let federated = bundled(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "federated-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "federated-access"),
        ]);
        let federated_schemes = federated
            .listener_execution_plan()
            .listeners()
            .iter()
            .map(|listener| (listener.kind(), listener.auth_scheme()))
            .collect::<Vec<_>>();
        assert!(federated_schemes.contains(&(
            primitives::ListenerKind::Primary,
            primitives::AuthScheme::FederatedAccessToken,
        )));
        assert!(federated_schemes.contains(&(
            primitives::ListenerKind::Admin,
            primitives::AuthScheme::FederatedAccessToken,
        )));
        assert!(federated_schemes.contains(&(
            primitives::ListenerKind::Health,
            primitives::AuthScheme::NoAuth,
        )));
    }
}
