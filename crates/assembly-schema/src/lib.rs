#[doc(hidden)]
pub mod contract_manifest;
mod contract_owner;
mod lock;
mod provider;
#[doc(hidden)]
pub mod repository_contract;
pub mod runtime_inventory;
mod runtime_plan;

pub use contract_owner::ContractOwner;
pub use lock::{
    AssemblyDigests, AssemblyFingerprint, AssemblyIdentity, AssemblyLock, AssemblyLockError,
    AssemblyLockErrorStage, GENERATED_MODULE_OWNERSHIP_MARKER, GENERATED_PROVIDER_OWNERSHIP_MARKER,
    ParsedAssemblyLock, RepositoryAssemblyManifestV2, RepositoryAssemblySnapshotV2,
    RepositoryVerifiedAssemblyLock,
};
pub use provider::{
    DiportPort, DiportProvider, LifecycleChannel, ProviderActivation, ProviderCapabilityEvidence,
    ProviderCatalogEntry, ProviderConstructor, ProviderConsumer, ProviderDurability,
    ProviderFactorySymbol, ProviderFailurePosture, ProviderLifecycle, ProviderRole, ProviderScope,
    has_domain_local_provider_activation,
};
pub use runtime_plan::{
    DomainLifecyclePhase, DomainPlan, ListenerAuth, ListenerPlan, ParsedRuntimePlan, PlacementPlan,
    ProviderPlan, RuntimePlan, RuntimePlanError, RuntimePlanErrorStage, RuntimePlanFingerprint,
    RuntimePlanJsonCategory, RuntimePlanJsonPath, RuntimePlanV3Input, WorkflowPlan,
    validate_runtime_plan_json_slice,
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub const REGISTERED_DOMAIN_LABELS: &[&str] =
    &["identity", "settings", "audit", "contractreg", "syshealth"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "u32", into = "u32")]
/// Supported wire schema versions for an assembly manifest.
///
/// Deserialization is intentionally strict: the v2 reader accepts only the
/// integer `2` and provides no compatibility path for older manifests.
pub enum AssemblyManifestSchemaVersion {
    /// Assembly manifest schema version 2.
    V2,
}

impl TryFrom<u32> for AssemblyManifestSchemaVersion {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(Self::V2),
            _ => Err("assembly manifest schemaVersion must be 2"),
        }
    }
}

impl From<AssemblyManifestSchemaVersion> for u32 {
    fn from(value: AssemblyManifestSchemaVersion) -> Self {
        match value {
            AssemblyManifestSchemaVersion::V2 => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
/// A workflow definition pin and its assembly-local activation state.
///
/// The tagged `mode` is part of the wire format. Capability requirements are
/// deliberately absent from the wire and are derived exhaustively from the
/// mode-specific activation state.
pub enum WorkflowActivation {
    /// A projection workflow activation.
    Projection {
        /// Repository-unique workflow definition identifier.
        id: String,
        /// Exact workflow definition version pinned by this assembly.
        #[serde(rename = "definitionVersion")]
        definition_version: String,
        /// Exact schema digest pinned by this assembly.
        #[serde(rename = "definitionSchemaDigest")]
        definition_schema_digest: vocab::CanonicalSha256Digest,
        /// Exact materialized target generation pinned independently of the definition version.
        #[serde(rename = "targetGeneration")]
        target_generation: String,
        /// Projection-specific activation state.
        activation: ProjectionActivation,
    },
    /// A saga workflow activation.
    Saga {
        /// Repository-unique workflow definition identifier.
        id: String,
        /// Exact workflow definition version pinned by this assembly.
        #[serde(rename = "definitionVersion")]
        definition_version: String,
        /// Exact schema digest pinned by this assembly.
        #[serde(rename = "definitionSchemaDigest")]
        definition_schema_digest: vocab::CanonicalSha256Digest,
        /// Saga-specific activation state.
        activation: SagaActivation,
    },
}

impl WorkflowActivation {
    /// Returns the pinned workflow definition identifier.
    pub fn id(&self) -> &str {
        match self {
            Self::Projection { id, .. } | Self::Saga { id, .. } => id,
        }
    }

    /// Returns the exact pinned workflow definition version.
    pub fn definition_version(&self) -> &str {
        match self {
            Self::Projection {
                definition_version, ..
            }
            | Self::Saga {
                definition_version, ..
            } => definition_version,
        }
    }

    /// Returns the exact pinned workflow definition schema digest.
    pub fn definition_schema_digest(&self) -> &str {
        match self {
            Self::Projection {
                definition_schema_digest,
                ..
            }
            | Self::Saga {
                definition_schema_digest,
                ..
            } => definition_schema_digest.as_str(),
        }
    }

    /// Returns the independently pinned materialized target generation for a Projection.
    pub fn projection_target_generation(&self) -> Option<&str> {
        match self {
            Self::Projection {
                target_generation, ..
            } => Some(target_generation),
            Self::Saga { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
/// Closed activation states for projection workflows.
///
/// Repository validation is the single source of truth for lifecycle
/// compatibility: disabled accepts draft, active, or deprecated definitions;
/// capture-only accepts draft or active definitions; shadow and active require
/// an active definition.
pub enum ProjectionActivation {
    /// The projection has no runtime capability requirements.
    Disabled,
    /// Capture source events without projecting or serving results.
    CaptureOnly,
    /// Project captured events without serving the projection as authoritative.
    Shadow,
    /// Project and serve the projection as authoritative.
    Active,
}

impl ProjectionActivation {
    /// Returns the complete capability requirements derived for this state.
    ///
    /// This exhaustive mapping is the sole source of capability facts; those
    /// facts are never duplicated in the serialized manifest.
    pub const fn requirements(self) -> &'static [ProjectionCapabilityRequirement] {
        match self {
            Self::Disabled => &[],
            Self::CaptureOnly => &[
                ProjectionCapabilityRequirement::Source,
                ProjectionCapabilityRequirement::CaptureStore,
            ],
            Self::Shadow => &[
                ProjectionCapabilityRequirement::Source,
                ProjectionCapabilityRequirement::CaptureStore,
                ProjectionCapabilityRequirement::Target,
                ProjectionCapabilityRequirement::CheckpointStore,
                ProjectionCapabilityRequirement::DeadLetterStore,
                ProjectionCapabilityRequirement::Worker,
                ProjectionCapabilityRequirement::Probe,
            ],
            Self::Active => &[
                ProjectionCapabilityRequirement::Source,
                ProjectionCapabilityRequirement::CaptureStore,
                ProjectionCapabilityRequirement::Target,
                ProjectionCapabilityRequirement::CheckpointStore,
                ProjectionCapabilityRequirement::DeadLetterStore,
                ProjectionCapabilityRequirement::Worker,
                ProjectionCapabilityRequirement::Probe,
                ProjectionCapabilityRequirement::Serving,
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
/// Closed activation states for saga workflows.
///
/// Repository validation is the single source of truth for lifecycle
/// compatibility: disabled accepts draft, active, or deprecated definitions,
/// while active requires an active definition.
pub enum SagaActivation {
    /// The saga has no runtime capability requirements.
    Disabled,
    /// Execute the saga with its complete persistence and worker capabilities.
    Active,
}

impl SagaActivation {
    /// Returns the complete capability requirements derived for this state.
    ///
    /// This exhaustive mapping is the sole source of capability facts; those
    /// facts are never duplicated in the serialized manifest.
    pub const fn requirements(self) -> &'static [SagaCapabilityRequirement] {
        match self {
            Self::Disabled => &[],
            Self::Active => &[
                SagaCapabilityRequirement::TypedActions,
                SagaCapabilityRequirement::DefinitionRegistry,
                SagaCapabilityRequirement::DurableStore,
                SagaCapabilityRequirement::Hydrator,
                SagaCapabilityRequirement::EffectProbe,
                SagaCapabilityRequirement::DeadLetterStore,
                SagaCapabilityRequirement::Worker,
                SagaCapabilityRequirement::Readiness,
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A projection runtime capability derived from its activation state.
///
/// Values of this type are derived facts and are not part of the manifest wire
/// format.
pub enum ProjectionCapabilityRequirement {
    /// Source from which projection input events are captured.
    Source,
    /// Durable store for captured input events.
    CaptureStore,
    /// Projection target receiving materialized results.
    Target,
    /// Durable projection progress checkpoint store.
    CheckpointStore,
    /// Store for input that cannot be processed successfully.
    DeadLetterStore,
    /// Worker that advances the projection.
    Worker,
    /// Probe that reports projection health and progress.
    Probe,
    /// Serving path that exposes authoritative projection results.
    Serving,
}

impl ProjectionCapabilityRequirement {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::CaptureStore => "capture-store",
            Self::Target => "target",
            Self::CheckpointStore => "checkpoint-store",
            Self::DeadLetterStore => "dead-letter-store",
            Self::Worker => "worker",
            Self::Probe => "probe",
            Self::Serving => "serving",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A saga runtime capability derived from its activation state.
///
/// Values of this type are derived facts and are not part of the manifest wire
/// format.
pub enum SagaCapabilityRequirement {
    /// Statically typed actions executed by the saga.
    TypedActions,
    /// Immutable exact-version registry used to resolve every pinned saga definition.
    DefinitionRegistry,
    /// Single durable owner of instance/lease, append-only journal cursor, and protected receipts.
    DurableStore,
    /// Typed receipt hydrator used to recover action and compensation inputs.
    Hydrator,
    /// Typed external-effect probe used to resolve interrupted intents without blind retries.
    EffectProbe,
    /// Store for work that cannot be processed successfully.
    DeadLetterStore,
    /// Worker that advances saga instances.
    Worker,
    /// Readiness projection that reports worker health and progress.
    Readiness,
}

impl SagaCapabilityRequirement {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TypedActions => "typed-actions",
            Self::DefinitionRegistry => "definition-registry",
            Self::DurableStore => "durable-store",
            Self::Hydrator => "hydrator",
            Self::EffectProbe => "effect-probe",
            Self::DeadLetterStore => "dead-letter-store",
            Self::Worker => "worker",
            Self::Readiness => "readiness",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: AssemblyManifestSchemaVersion,
    pub name: String,
    pub profile: AssemblyProfile,
    pub domains: Vec<AssemblyDomain>,
    pub topology: AssemblyTopology,
    #[serde(default, rename = "typedDomainInputs")]
    pub typed_domain_inputs: bool,
    #[serde(rename = "frameworkContracts")]
    pub framework_contracts: Vec<FrameworkContractMount>,
    #[serde(rename = "workflowActivations")]
    pub workflow_activations: Vec<WorkflowActivation>,
    pub listeners: Vec<AssemblyListener>,
    #[serde(rename = "diportProviders")]
    pub diport_providers: Vec<DiportProvider>,
}

impl AssemblyManifest {
    pub fn from_toml_str(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    pub fn validate_basic(&self) -> Result<(), ManifestValidationErrors> {
        let errors = self.basic_validation_errors();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ManifestValidationErrors { errors })
        }
    }

    pub fn basic_validation_errors(&self) -> Vec<ManifestValidationError> {
        let mut errors = Vec::new();
        ensure_non_empty_string(&self.name, "name", &mut errors);
        ensure_non_empty_slice(&self.domains, "domains", &mut errors);
        if !self.is_listenerless_identity_demo() {
            ensure_non_empty_slice(&self.listeners, "listeners", &mut errors);
        }
        ensure_non_empty_slice(&self.diport_providers, "diportProviders", &mut errors);

        ensure_unique(self.domains.iter().copied(), "domains", &mut errors);
        ensure_unique(
            self.framework_contracts
                .iter()
                .map(|mount| mount.id.as_str()),
            "frameworkContracts",
            &mut errors,
        );
        for mount in &self.framework_contracts {
            ensure_non_empty_string(&mount.id, "frameworkContracts", &mut errors);
        }
        ensure_unique(
            self.workflow_activations.iter().map(WorkflowActivation::id),
            "workflowActivations.id",
            &mut errors,
        );
        for activation in &self.workflow_activations {
            ensure_non_empty_string(activation.id(), "workflowActivations.id", &mut errors);
            ensure_non_empty_string(
                activation.definition_version(),
                "workflowActivations.definitionVersion",
                &mut errors,
            );
            if let Some(target_generation) = activation.projection_target_generation() {
                ensure_non_empty_string(
                    target_generation,
                    "workflowActivations.targetGeneration",
                    &mut errors,
                );
            }
        }
        ensure_unique(
            self.listeners.iter().map(|listener| listener.kind),
            "listeners",
            &mut errors,
        );
        ensure_unique_provider_keys(&self.diport_providers, &mut errors);
        ensure_unique(
            self.diport_providers.iter().map(|provider| provider.id),
            "diportProviders.id",
            &mut errors,
        );

        for provider in &self.diport_providers {
            ensure_non_empty_string(
                &provider.provider_crate,
                "diportProviders.providerCrate",
                &mut errors,
            );
            ensure_non_empty_string(&provider.purpose, "diportProviders.purpose", &mut errors);
            for feature in &provider.required_features {
                ensure_non_empty_string(feature, "diportProviders.requiredFeatures", &mut errors);
            }
            ensure_unique(
                provider.required_features.iter().map(String::as_str),
                "diportProviders.requiredFeatures",
                &mut errors,
            );
            errors.extend(
                provider
                    .registry_mismatch_fields()
                    .into_iter()
                    .map(
                        |mismatch| ManifestValidationError::ProviderRegistryMismatch {
                            role: provider.id,
                            field: mismatch.field,
                            expected: mismatch.expected,
                            actual: mismatch.actual,
                        },
                    ),
            );
        }

        errors
    }

    pub fn validate_graph_evidence(&self) -> Result<(), GraphEvidenceValidationErrors> {
        let mut errors = Vec::new();
        let declared_domains: BTreeSet<_> = self.domains.iter().copied().collect();
        let mut bound_domains = BTreeSet::new();
        let mut bindings = BTreeSet::new();
        let listener_kinds = self
            .listeners
            .iter()
            .map(|listener| listener.kind)
            .collect::<BTreeSet<_>>();
        for mount in &self.framework_contracts {
            if !listener_kinds.contains(&mount.listener) {
                errors.push(GraphEvidenceValidationError::UnknownFrameworkListener {
                    contract_id: mount.id.clone(),
                    listener: mount.listener,
                });
            }
        }
        for listener in &self.listeners {
            for domain in &listener.domains {
                if !declared_domains.contains(domain) {
                    errors.push(GraphEvidenceValidationError::UnknownDomain { domain: *domain });
                }
                if !bindings.insert((*domain, listener.kind)) {
                    errors.push(GraphEvidenceValidationError::DuplicateDomainListener {
                        domain: *domain,
                        listener: listener.kind,
                    });
                }
                bound_domains.insert(*domain);
            }
        }
        if !self.is_listenerless_identity_demo() {
            for domain in declared_domains.difference(&bound_domains) {
                errors.push(GraphEvidenceValidationError::UnboundDomain { domain: *domain });
            }
        }
        for provider in &self.diport_providers {
            let mut seen = BTreeSet::new();
            for channel in &provider.outputs {
                if !seen.insert(*channel) {
                    errors.push(GraphEvidenceValidationError::DuplicateProviderOutput {
                        channel: *channel,
                    });
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(GraphEvidenceValidationErrors { errors })
        }
    }

    fn is_listenerless_identity_demo(&self) -> bool {
        self.profile == AssemblyProfile::Demo
            && self.topology == AssemblyTopology::Demo
            && self.domains == [AssemblyDomain::Identity]
            && self.listeners.is_empty()
            && self.framework_contracts.is_empty()
            && self.workflow_activations.is_empty()
    }

    /// Validate and compile this manifest into the sole v2 semantic view.
    ///
    /// Code generation and manifest identity both consume this type, so set-like
    /// declarations cannot drift between their rendered and fingerprinted forms.
    pub fn canonicalize_v2(
        self,
    ) -> Result<CanonicalAssemblyManifestV2, AssemblyManifestCanonicalizationError> {
        self.validate_basic().map_err(|source| {
            AssemblyManifestCanonicalizationError(AssemblyManifestCanonicalizationErrorKind::Basic(
                source,
            ))
        })?;
        self.validate_graph_evidence().map_err(|source| {
            AssemblyManifestCanonicalizationError(AssemblyManifestCanonicalizationErrorKind::Graph(
                source,
            ))
        })?;

        // Intentionally exhaustive: a future source field must fail compilation until its
        // sequence/set semantics are reviewed for both codegen and fingerprinting.
        let AssemblyManifest {
            schema_version,
            name,
            profile,
            domains,
            topology,
            typed_domain_inputs,
            framework_contracts,
            mut workflow_activations,
            listeners,
            mut diport_providers,
        } = self;
        let declaration_ordered_diport_providers = diport_providers.clone();

        for provider in &mut diport_providers {
            provider.required_features.sort();
            provider.outputs.sort();
        }
        diport_providers.sort_by(|left, right| provider_key(left).cmp(&provider_key(right)));
        workflow_activations.sort_by(|left, right| left.id().cmp(right.id()));

        let value = CanonicalAssemblyManifestV2Value {
            schema_version,
            name,
            profile,
            domains,
            topology,
            typed_domain_inputs,
            framework_contracts,
            workflow_activations,
            listeners,
            diport_providers,
        };
        let manifest_digest = lock::canonical_manifest_digest(&value).map_err(|source| {
            AssemblyManifestCanonicalizationError(
                AssemblyManifestCanonicalizationErrorKind::Digest(source),
            )
        })?;
        Ok(CanonicalAssemblyManifestV2 {
            value,
            declaration_ordered_diport_providers,
            manifest_digest,
        })
    }
}

/// Read-only v2 semantic manifest shared by code generation and AssemblyLock identity.
#[derive(Clone)]
pub struct CanonicalAssemblyManifestV2 {
    value: CanonicalAssemblyManifestV2Value,
    declaration_ordered_diport_providers: Vec<DiportProvider>,
    manifest_digest: vocab::CanonicalSha256Digest,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalAssemblyManifestV2Value {
    schema_version: AssemblyManifestSchemaVersion,
    name: String,
    profile: AssemblyProfile,
    domains: Vec<AssemblyDomain>,
    topology: AssemblyTopology,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    typed_domain_inputs: bool,
    framework_contracts: Vec<FrameworkContractMount>,
    workflow_activations: Vec<WorkflowActivation>,
    listeners: Vec<AssemblyListener>,
    diport_providers: Vec<DiportProvider>,
}

impl CanonicalAssemblyManifestV2 {
    pub const fn schema_version(&self) -> AssemblyManifestSchemaVersion {
        self.value.schema_version
    }

    pub fn name(&self) -> &str {
        &self.value.name
    }

    pub const fn profile(&self) -> AssemblyProfile {
        self.value.profile
    }

    pub fn domains(&self) -> &[AssemblyDomain] {
        &self.value.domains
    }

    pub const fn topology(&self) -> AssemblyTopology {
        self.value.topology
    }

    pub const fn typed_domain_inputs(&self) -> bool {
        self.value.typed_domain_inputs
    }

    pub fn framework_contracts(&self) -> &[FrameworkContractMount] {
        &self.value.framework_contracts
    }

    pub fn workflow_activations(&self) -> &[WorkflowActivation] {
        &self.value.workflow_activations
    }

    pub fn listeners(&self) -> &[AssemblyListener] {
        &self.value.listeners
    }

    pub fn diport_providers(&self) -> &[DiportProvider] {
        &self.value.diport_providers
    }

    /// Validated provider declarations in source order for byte-stable presentation artifacts.
    ///
    /// Semantic consumers must use [`Self::diport_providers`], whose set-like fields are
    /// canonicalized and sorted. This projection exists only where declaration order is part of
    /// an established rendered format.
    pub fn declaration_ordered_diport_providers(&self) -> &[DiportProvider] {
        &self.declaration_ordered_diport_providers
    }

    pub const fn manifest_digest(&self) -> &vocab::CanonicalSha256Digest {
        &self.manifest_digest
    }
}

/// Closed error returned while compiling an AssemblyManifest into its v2 semantic form.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct AssemblyManifestCanonicalizationError(AssemblyManifestCanonicalizationErrorKind);

#[derive(Debug, thiserror::Error)]
enum AssemblyManifestCanonicalizationErrorKind {
    #[error("invalid assembly declarations: {0}")]
    Basic(#[source] ManifestValidationErrors),
    #[error("invalid assembly graph evidence: {0}")]
    Graph(#[source] GraphEvidenceValidationErrors),
    #[error("canonical manifest digest failed: {0}")]
    Digest(#[source] AssemblyLockError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEvidenceValidationErrors {
    errors: Vec<GraphEvidenceValidationError>,
}

impl GraphEvidenceValidationErrors {
    pub fn as_slice(&self) -> &[GraphEvidenceValidationError] {
        &self.errors
    }

    pub fn into_vec(self) -> Vec<GraphEvidenceValidationError> {
        self.errors
    }
}

impl fmt::Display for GraphEvidenceValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_error_list(f, &self.errors)
    }
}

impl std::error::Error for GraphEvidenceValidationErrors {}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GraphEvidenceValidationError {
    #[error("framework contract `{contract_id}` references undeclared listener `{listener}")]
    UnknownFrameworkListener {
        contract_id: String,
        listener: AssemblyListenerKind,
    },
    #[error("listener references undeclared domain `{domain}`")]
    UnknownDomain { domain: AssemblyDomain },
    #[error("declared domain `{domain}` has no listener")]
    UnboundDomain { domain: AssemblyDomain },
    #[error("duplicate domain/listener binding `{domain}/{listener}`")]
    DuplicateDomainListener {
        domain: AssemblyDomain,
        listener: AssemblyListenerKind,
    },
    #[error("duplicate provider output `{channel}`")]
    DuplicateProviderOutput { channel: LifecycleChannel },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestValidationErrors {
    errors: Vec<ManifestValidationError>,
}

impl ManifestValidationErrors {
    pub fn as_slice(&self) -> &[ManifestValidationError] {
        &self.errors
    }

    pub fn into_vec(self) -> Vec<ManifestValidationError> {
        self.errors
    }
}

impl fmt::Display for ManifestValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_error_list(f, &self.errors)
    }
}

impl std::error::Error for ManifestValidationErrors {}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestValidationError {
    #[error("field={field} empty declaration")]
    Empty { field: &'static str },
    #[error("field={field} duplicate declaration")]
    Duplicate { field: &'static str },
    #[error("field={field} invalid declaration")]
    Invalid { field: &'static str },
    #[error(
        "provider={role} field={field} does not match canonical registry: expected={expected} actual={actual}"
    )]
    ProviderRegistryMismatch {
        role: ProviderRole,
        field: &'static str,
        expected: String,
        actual: String,
    },
}

fn write_error_list<T: fmt::Display>(f: &mut fmt::Formatter<'_>, errors: &[T]) -> fmt::Result {
    for (index, error) in errors.iter().enumerate() {
        if index > 0 {
            f.write_str("; ")?;
        }
        write!(f, "{error}")?;
    }
    Ok(())
}

macro_rules! display_as_str {
    ($($ty:ty),+ $(,)?) => {$(
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    )+};
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AssemblyProfile {
    Production,
    Demo,
    Test,
}

impl AssemblyProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Demo => "demo",
            Self::Test => "test",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum AssemblyDomain {
    Identity,
    Settings,
    Audit,
    Contractreg,
    Syshealth,
}

impl AssemblyDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Settings => "settings",
            Self::Audit => "audit",
            Self::Contractreg => "contractreg",
            Self::Syshealth => "syshealth",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssemblyTopology {
    Demo,
    DurableShared,
    DurableIsolated,
}

impl AssemblyTopology {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Demo => "demo",
            Self::DurableShared => "durable-shared",
            Self::DurableIsolated => "durable-isolated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyListener {
    pub kind: AssemblyListenerKind,
    pub domains: Vec<AssemblyDomain>,
}

/// One explicit framework-owned contract mount in an assembly.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrameworkContractMount {
    pub id: String,
    pub listener: AssemblyListenerKind,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum AssemblyListenerKind {
    Primary,
    Internal,
    Admin,
    Health,
}

impl AssemblyListenerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Internal => "internal",
            Self::Admin => "admin",
            Self::Health => "health",
        }
    }
}

display_as_str!(AssemblyDomain, AssemblyListenerKind);

fn ensure_non_empty_string(
    value: &str,
    field: &'static str,
    errors: &mut Vec<ManifestValidationError>,
) {
    if value.trim().is_empty() {
        errors.push(ManifestValidationError::Empty { field });
    }
}

fn ensure_non_empty_slice<T>(
    values: &[T],
    field: &'static str,
    errors: &mut Vec<ManifestValidationError>,
) {
    if values.is_empty() {
        errors.push(ManifestValidationError::Empty { field });
    }
}

fn ensure_unique<T>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
    errors: &mut Vec<ManifestValidationError>,
) where
    T: Ord,
{
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            errors.push(ManifestValidationError::Duplicate { field });
            return;
        }
    }
}

fn ensure_unique_provider_keys(
    providers: &[DiportProvider],
    errors: &mut Vec<ManifestValidationError>,
) {
    let mut seen = BTreeSet::new();
    for provider in providers {
        let key = (
            provider.id.as_str(),
            provider.port.as_str(),
            provider.provider.as_str(),
            provider.provider_crate.as_str(),
            provider.consumer.as_str(),
        );
        if !seen.insert(key) {
            errors.push(ManifestValidationError::Duplicate {
                field: "diportProviders",
            });
            return;
        }
    }
}

fn provider_key(provider: &DiportProvider) -> (&str, &str, &str, &str, &str) {
    (
        provider.id.as_str(),
        provider.port.as_str(),
        provider.provider.as_str(),
        provider.provider_crate.as_str(),
        provider.consumer.as_str(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    // reason: schema parser tests use direct fixture assertions; parse failures should panic with local context.

    use super::*;

    const MINIMAL: &str = r#"
schemaVersion = 2
name = "runtime"
profile = "demo"
domains = ["identity", "settings", "audit"]
topology = "durable-shared"
frameworkContracts = []
workflowActivations = []

[[listeners]]
kind = "primary"
domains = ["identity", "settings", "audit"]

[[diportProviders]]
id = "listener-pdp"
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
requiredFeatures = ["backend"]
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-credential-verification"
outputs = ["probes", "resources"]
"#;

    #[test]
    fn parses_minimal_manifest() {
        let manifest = AssemblyManifest::from_toml_str(MINIMAL).expect("manifest");

        assert_eq!(manifest.schema_version, AssemblyManifestSchemaVersion::V2);
        assert!(manifest.workflow_activations.is_empty());
        assert_eq!(manifest.name, "runtime");
        assert_eq!(
            manifest
                .domains
                .iter()
                .map(|domain| domain.as_str())
                .collect::<Vec<_>>(),
            ["identity", "settings", "audit"]
        );
        assert_eq!(manifest.diport_providers[0].required_features, ["backend"]);
        assert!(manifest.framework_contracts.is_empty());
        assert_eq!(
            manifest.listeners[0].domains.as_slice(),
            [
                AssemblyDomain::Identity,
                AssemblyDomain::Settings,
                AssemblyDomain::Audit
            ]
        );
        assert_eq!(
            manifest.diport_providers[0].outputs.as_slice(),
            [LifecycleChannel::Probes, LifecycleChannel::Resources]
        );
        manifest.validate_basic().expect("valid manifest");
    }

    #[test]
    fn listenerless_shape_is_closed_to_demo_identity_library_assembly() {
        let pilot = AssemblyManifest::from_toml_str(include_str!(
            "../../../assemblies/deviceidentity/assembly.toml"
        ))
        .expect("listenerless pilot parses");
        assert!(pilot.listeners.is_empty());
        assert!(pilot.basic_validation_errors().is_empty());
        pilot
            .validate_graph_evidence()
            .expect("exact demo identity library shape has no HTTP binding");

        let mut settings = pilot.clone();
        settings.domains = vec![AssemblyDomain::Settings];
        assert!(
            settings
                .basic_validation_errors()
                .contains(&ManifestValidationError::Empty { field: "listeners" })
        );
        assert!(matches!(
            settings.validate_graph_evidence(),
            Err(errors) if errors.as_slice().contains(&GraphEvidenceValidationError::UnboundDomain {
                domain: AssemblyDomain::Settings,
            })
        ));
    }

    #[test]
    fn manifest_v2_requires_closed_schema_version_and_explicit_workflow_activations() {
        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace("schemaVersion = 2\n", "")).is_err()
        );
        assert!(
            AssemblyManifest::from_toml_str(
                &MINIMAL.replace("schemaVersion = 2", "schemaVersion = 1")
            )
            .is_err()
        );
        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace("workflowActivations = []\n", ""))
                .is_err()
        );
    }

    #[test]
    fn workflow_activation_modes_are_closed_and_mode_specific() {
        let projection = MINIMAL.replace(
            "workflowActivations = []",
            r#"workflowActivations = [{ mode = "projection", id = "settings.config-projection", definitionVersion = "v3", definitionSchemaDigest = "sha256:11cd811ed051254c6ea2c8e6aa659b8b2d32c606f635456ece9ee56695cc0103", targetGeneration = "materialized-v7", activation = "capture-only" }]"#,
        );
        let manifest = AssemblyManifest::from_toml_str(&projection).expect("projection activation");
        assert!(matches!(
            manifest.workflow_activations.as_slice(),
            [WorkflowActivation::Projection {
                target_generation,
                activation: ProjectionActivation::CaptureOnly,
                ..
            }] if target_generation == "materialized-v7"
        ));

        let saga = projection
            .replace("mode = \"projection\"", "mode = \"saga\"")
            .replace(", targetGeneration = \"materialized-v7\"", "")
            .replace("activation = \"capture-only\"", "activation = \"active\"");
        let manifest = AssemblyManifest::from_toml_str(&saga).expect("saga activation");
        assert!(matches!(
            manifest.workflow_activations.as_slice(),
            [WorkflowActivation::Saga {
                activation: SagaActivation::Active,
                ..
            }]
        ));

        assert!(AssemblyManifest::from_toml_str(&saga.replace("active", "shadow")).is_err());
        assert!(
            AssemblyManifest::from_toml_str(&projection.replace("capture-only", "unknown"))
                .is_err()
        );
    }

    #[test]
    fn workflow_capability_requirements_are_exhaustive_derived_facts() {
        use ProjectionCapabilityRequirement as Projection;
        use SagaCapabilityRequirement as Saga;

        assert_eq!(ProjectionActivation::Disabled.requirements(), []);
        assert_eq!(
            ProjectionActivation::CaptureOnly.requirements(),
            [Projection::Source, Projection::CaptureStore]
        );
        assert_eq!(
            ProjectionActivation::Shadow.requirements(),
            [
                Projection::Source,
                Projection::CaptureStore,
                Projection::Target,
                Projection::CheckpointStore,
                Projection::DeadLetterStore,
                Projection::Worker,
                Projection::Probe,
            ]
        );
        assert_eq!(
            ProjectionActivation::Active.requirements(),
            [
                Projection::Source,
                Projection::CaptureStore,
                Projection::Target,
                Projection::CheckpointStore,
                Projection::DeadLetterStore,
                Projection::Worker,
                Projection::Probe,
                Projection::Serving,
            ]
        );
        assert_eq!(SagaActivation::Disabled.requirements(), []);
        assert_eq!(
            SagaActivation::Active.requirements(),
            [
                Saga::TypedActions,
                Saga::DefinitionRegistry,
                Saga::DurableStore,
                Saga::Hydrator,
                Saga::EffectProbe,
                Saga::DeadLetterStore,
                Saga::Worker,
                Saga::Readiness,
            ]
        );

        assert_eq!(Saga::DefinitionRegistry.as_str(), "definition-registry");
        assert_eq!(Saga::Hydrator.as_str(), "hydrator");
        assert_eq!(Saga::EffectProbe.as_str(), "effect-probe");
        assert_eq!(Saga::Readiness.as_str(), "readiness");
    }

    #[test]
    fn provider_roles_are_required_closed_and_unique() {
        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace("id = \"listener-pdp\"\n", ""))
                .is_err()
        );

        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace("listener-pdp", "Listener_Pdp"))
                .is_err()
        );

        let mut duplicate = AssemblyManifest::from_toml_str(MINIMAL).expect("manifest");
        duplicate
            .diport_providers
            .push(duplicate.diport_providers[0].clone());
        assert!(duplicate.basic_validation_errors().contains(
            &ManifestValidationError::Duplicate {
                field: "diportProviders.id"
            }
        ));
    }

    #[test]
    fn parses_closed_dlx_lifecycle_provider_ports() {
        for (port, expected) in [
            (
                "diport::DlxLifecycleRepository",
                DiportPort::DlxLifecycleRepository,
            ),
            ("diport::DlxArchiveStore", DiportPort::DlxArchiveStore),
        ] {
            let source = MINIMAL.replace("diport::Pdp", port);
            let manifest = AssemblyManifest::from_toml_str(&source).expect("DLX port parses");
            assert_eq!(manifest.diport_providers[0].port, expected);
        }
    }

    #[test]
    fn parses_service_token_replay_store_provider_port() {
        let source = MINIMAL.replace("diport::Pdp", "diport::ServiceTokenReplayStore");
        let manifest =
            AssemblyManifest::from_toml_str(&source).expect("service-token replay port parses");
        assert_eq!(
            manifest.diport_providers[0].port,
            DiportPort::ServiceTokenReplayStore
        );
    }

    #[test]
    fn rejects_retired_eventexec_dlx_ports_and_cipher_port() {
        for retired in [
            ["eventexec::DlxLifecycle", "Repository"].concat(),
            ["eventexec::DlxArchive", "Store"].concat(),
            ["eventexec::DlxArchive", "Cipher"].concat(),
        ] {
            let source = MINIMAL.replace("diport::Pdp", &retired);
            assert!(
                AssemblyManifest::from_toml_str(&source).is_err(),
                "retired port unexpectedly parsed: {retired}"
            );
        }
    }

    #[test]
    fn framework_contracts_are_required_non_empty_and_unique() {
        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace("frameworkContracts = []\n", ""))
                .is_err()
        );

        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace(
                "frameworkContracts = []",
                "frameworkContracts = [\"seed.echo\"]",
            ))
            .is_err(),
            "legacy string declarations must not parse"
        );

        let invalid = AssemblyManifest::from_toml_str(&MINIMAL.replace(
            "frameworkContracts = []",
            "frameworkContracts = [{ id = \"\", listener = \"admin\" }, { id = \"seed.echo\", listener = \"admin\" }, { id = \"seed.echo\", listener = \"primary\" }]",
        ))
        .expect("closed framework contract declarations parse before semantic validation");
        let errors = invalid.basic_validation_errors();
        assert!(errors.contains(&ManifestValidationError::Empty {
            field: "frameworkContracts"
        }));
        assert!(errors.contains(&ManifestValidationError::Duplicate {
            field: "frameworkContracts"
        }));
    }

    #[test]
    fn framework_contract_listener_must_be_declared() {
        let invalid = AssemblyManifest::from_toml_str(&MINIMAL.replace(
            "frameworkContracts = []",
            "frameworkContracts = [{ id = \"seed.echo\", listener = \"admin\" }]",
        ))
        .expect("typed framework mount parses before graph validation");
        let errors = invalid
            .validate_graph_evidence()
            .expect_err("undeclared listener must fail")
            .into_vec();
        assert!(
            errors.contains(&GraphEvidenceValidationError::UnknownFrameworkListener {
                contract_id: "seed.echo".to_string(),
                listener: AssemblyListenerKind::Admin,
            })
        );
    }

    #[test]
    fn rejects_unknown_fields_and_closed_values() {
        assert!(AssemblyManifest::from_toml_str(&format!("{MINIMAL}\nlegacy = true\n")).is_err());
        assert!(AssemblyManifest::from_toml_str(&MINIMAL.replace("identity", "billing")).is_err());
        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace("durable-shared", "global")).is_err()
        );
        assert!(AssemblyManifest::from_toml_str(&MINIMAL.replace("primary", "public")).is_err());
        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace("diport::Pdp", "diport::Unknown"))
                .is_err()
        );
        assert!(AssemblyManifest::from_toml_str(&MINIMAL.replace("active", "enabled")).is_err());
        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace("persistent", "durable")).is_err()
        );
    }

    #[test]
    fn reports_empty_and_duplicate_declarations() {
        let empty_domains = AssemblyManifest::from_toml_str(&MINIMAL.replace(
            r#"domains = ["identity", "settings", "audit"]"#,
            "domains = []",
        ))
        .expect("parse empty domains");
        assert!(
            empty_domains
                .basic_validation_errors()
                .contains(&ManifestValidationError::Empty { field: "domains" })
        );

        let duplicate_domains = AssemblyManifest::from_toml_str(&MINIMAL.replace(
            r#"domains = ["identity", "settings", "audit"]"#,
            r#"domains = ["identity", "identity"]"#,
        ))
        .expect("parse duplicate domains");
        assert!(
            duplicate_domains
                .basic_validation_errors()
                .contains(&ManifestValidationError::Duplicate { field: "domains" })
        );
    }

    #[test]
    fn graph_evidence_is_closed_and_non_vacuous() {
        let manifest = AssemblyManifest::from_toml_str(MINIMAL).expect("manifest");
        manifest
            .validate_graph_evidence()
            .expect("complete graph evidence");

        let missing_listener = MINIMAL.replace(
            "kind = \"primary\"\ndomains = [\"identity\", \"settings\", \"audit\"]",
            "kind = \"primary\"",
        );
        assert!(AssemblyManifest::from_toml_str(&missing_listener).is_err());
        let missing_provider = MINIMAL.replace("outputs = [\"probes\", \"resources\"]\n", "");
        assert!(AssemblyManifest::from_toml_str(&missing_provider).is_err());
    }
}
