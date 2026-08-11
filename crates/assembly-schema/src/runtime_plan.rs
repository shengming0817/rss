//! Canonical RuntimePlan v3 protocol.
//!
//! INVARIANT: RUNTIME-PLAN-CONSTRUCTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private plan fields plus the validated compile_v3 funnel" } — callers can describe candidate facts, but only a manifest/lock-bound compiler or the strict reader can mint a RuntimePlan.

use crate::{
    AssemblyDomain, AssemblyFingerprint, AssemblyListenerKind, CanonicalAssemblyManifestV2,
    LifecycleChannel, ProviderActivation, ProviderConstructor, ProviderLifecycle, ProviderRole,
    RepositoryVerifiedAssemblyLock, WorkflowActivation,
};
use schemars::JsonSchema;
use schemars::schema::{RootSchema, Schema};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use vocab::CanonicalSha256Digest;

const RUNTIME_PLAN_TAG: &str = "rss-runtime-plan-v3";
const SCHEMA_VERSION: u32 = 3;
const FIXED_DOMAIN_LIFECYCLE: [DomainLifecyclePhase; 3] = [
    DomainLifecyclePhase::Construct,
    DomainLifecyclePhase::Ready,
    DomainLifecyclePhase::Shutdown,
];

/// Validated, closed RuntimePlan v3 value.
#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePlan {
    schema_version: u32,
    assembly_fingerprint: AssemblyFingerprint,
    runtime_plan_fingerprint: RuntimePlanFingerprint,
    provider_plans: Vec<ProviderPlan>,
    listener_plans: Vec<ListenerPlan>,
    domain_plans: Vec<DomainPlan>,
    placement_plans: Vec<PlacementPlan>,
    workflow_plans: Vec<WorkflowPlan>,
}

impl JsonSchema for RuntimePlan {
    fn schema_name() -> String {
        "RuntimePlan target contract".to_owned()
    }

    fn is_referenceable() -> bool {
        false
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> Schema {
        let Ok(mut committed) =
            serde_json::from_str::<RootSchema>(include_str!("../schemas/runtime-plan.schema.json"))
        else {
            return Schema::Bool(false);
        };
        generator
            .definitions_mut()
            .append(&mut committed.definitions);
        Schema::Object(committed.schema)
    }
}

impl RuntimePlan {
    /// Validate candidate facts against the exact canonical manifest and a provenance proof.
    pub fn compile_v3(
        manifest: &CanonicalAssemblyManifestV2,
        lock: &RepositoryVerifiedAssemblyLock,
        input: RuntimePlanV3Input,
    ) -> Result<Self, RuntimePlanError> {
        validate_manifest_lock(manifest, lock)?;
        validate_candidates(manifest, lock, &input)?;
        Self::from_parts(
            lock.fingerprint().clone(),
            input.provider_plans,
            input.listener_plans,
            input.domain_plans,
            input.placement_plans,
            input.workflow_plans,
        )
    }

    fn from_parts(
        assembly_fingerprint: AssemblyFingerprint,
        provider_plans: Vec<ProviderPlan>,
        listener_plans: Vec<ListenerPlan>,
        domain_plans: Vec<DomainPlan>,
        placement_plans: Vec<PlacementPlan>,
        workflow_plans: Vec<WorkflowPlan>,
    ) -> Result<Self, RuntimePlanError> {
        validate_plan_facts(
            &provider_plans,
            &listener_plans,
            &domain_plans,
            &placement_plans,
            &workflow_plans,
        )?;
        let runtime_plan_fingerprint = fingerprint_for(
            &assembly_fingerprint,
            &provider_plans,
            &listener_plans,
            &domain_plans,
            &placement_plans,
            &workflow_plans,
        )?;
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            assembly_fingerprint,
            runtime_plan_fingerprint,
            provider_plans,
            listener_plans,
            domain_plans,
            placement_plans,
            workflow_plans,
        })
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub const fn assembly_fingerprint(&self) -> &AssemblyFingerprint {
        &self.assembly_fingerprint
    }

    pub const fn runtime_plan_fingerprint(&self) -> &RuntimePlanFingerprint {
        &self.runtime_plan_fingerprint
    }

    pub fn provider_plans(&self) -> &[ProviderPlan] {
        &self.provider_plans
    }

    pub fn listener_plans(&self) -> &[ListenerPlan] {
        &self.listener_plans
    }

    pub fn domain_plans(&self) -> &[DomainPlan] {
        &self.domain_plans
    }

    pub fn placement_plans(&self) -> &[PlacementPlan] {
        &self.placement_plans
    }

    pub fn workflow_plans(&self) -> &[WorkflowPlan] {
        &self.workflow_plans
    }
}

impl fmt::Debug for RuntimePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimePlan")
            .field("assembly_fingerprint", &self.assembly_fingerprint.as_str())
            .field(
                "runtime_plan_fingerprint",
                &self.runtime_plan_fingerprint.as_str(),
            )
            .field(
                "provider_ids",
                &Ids(self.provider_plans.iter().map(ProviderPlan::id)),
            )
            .field(
                "listener_ids",
                &Ids(self.listener_plans.iter().map(ListenerPlan::id)),
            )
            .field(
                "domain_ids",
                &Ids(self.domain_plans.iter().map(|plan| plan.id.as_str())),
            )
            .field("placement_count", &self.placement_plans.len())
            .field(
                "workflow_ids",
                &Ids(self.workflow_plans.iter().map(WorkflowPlan::id)),
            )
            .finish()
    }
}

struct Ids<I>(I);

impl<I> fmt::Debug for Ids<I>
where
    I: Clone + Iterator,
    I::Item: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.clone()).finish()
    }
}

/// Strictly parsed RuntimePlan whose self-excluding fingerprint and internal graph are valid.
pub struct ParsedRuntimePlan(RuntimePlan);

impl ParsedRuntimePlan {
    /// Parse an executable RuntimePlan and bind it to its canonical manifest and a
    /// repository-verified AssemblyLock.
    pub fn from_json_slice_bound(
        bytes: &[u8],
        manifest: &CanonicalAssemblyManifestV2,
        lock: &RepositoryVerifiedAssemblyLock,
    ) -> Result<Self, RuntimePlanError> {
        let candidate = parse_unbound_runtime_plan(bytes)?;
        validate_manifest_lock(manifest, lock)?;
        if candidate.assembly_fingerprint().as_str() != lock.fingerprint().as_str() {
            return Err(RuntimePlanError::new(
                RuntimePlanErrorKind::AssemblyIdentityMismatch,
            ));
        }

        let RuntimePlan {
            runtime_plan_fingerprint: expected_fingerprint,
            provider_plans,
            listener_plans,
            domain_plans,
            placement_plans,
            workflow_plans,
            ..
        } = candidate;
        let plan = RuntimePlan::compile_v3(
            manifest,
            lock,
            RuntimePlanV3Input {
                provider_plans,
                listener_plans,
                domain_plans,
                placement_plans,
                workflow_plans,
            },
        )?;
        if plan.runtime_plan_fingerprint() != &expected_fingerprint {
            return Err(RuntimePlanError::new(
                RuntimePlanErrorKind::FingerprintMismatch,
            ));
        }
        Ok(Self(plan))
    }

    pub const fn as_plan(&self) -> &RuntimePlan {
        &self.0
    }

    pub const fn schema_version(&self) -> u32 {
        self.0.schema_version()
    }

    pub const fn assembly_fingerprint(&self) -> &AssemblyFingerprint {
        self.0.assembly_fingerprint()
    }

    pub const fn runtime_plan_fingerprint(&self) -> &RuntimePlanFingerprint {
        self.0.runtime_plan_fingerprint()
    }

    pub fn provider_plans(&self) -> &[ProviderPlan] {
        self.0.provider_plans()
    }

    pub fn listener_plans(&self) -> &[ListenerPlan] {
        self.0.listener_plans()
    }

    pub fn domain_plans(&self) -> &[DomainPlan] {
        self.0.domain_plans()
    }

    pub fn placement_plans(&self) -> &[PlacementPlan] {
        self.0.placement_plans()
    }

    pub fn workflow_plans(&self) -> &[WorkflowPlan] {
        self.0.workflow_plans()
    }
}

impl fmt::Debug for ParsedRuntimePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Validate only the closed RuntimePlan JSON wire and its self-excluding fingerprint.
///
/// This function deliberately returns no executable plan. Callers that execute a [`RuntimePlan`]
/// must use [`ParsedRuntimePlan::from_json_slice_bound`] with the canonical manifest and
/// AssemblyLock.
pub fn validate_runtime_plan_json_slice(bytes: &[u8]) -> Result<(), RuntimePlanError> {
    parse_unbound_runtime_plan(bytes).map(drop)
}

fn parse_unbound_runtime_plan(bytes: &[u8]) -> Result<RuntimePlan, RuntimePlanError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire: WireRuntimePlan =
        serde_path_to_error::deserialize(&mut deserializer).map_err(strict_json_error)?;
    deserializer
        .end()
        .map_err(|source| strict_json_root_error(&source))?;
    if wire.schema_version != SCHEMA_VERSION {
        return Err(RuntimePlanError::new(
            RuntimePlanErrorKind::UnsupportedVersion {
                actual: wire.schema_version,
                supported: SCHEMA_VERSION,
            },
        ));
    }
    let expected_fingerprint = wire.runtime_plan_fingerprint;
    let plan = RuntimePlan::from_parts(
        AssemblyFingerprint::from_validated(wire.assembly_fingerprint),
        wire.provider_plans.into_iter().map(Into::into).collect(),
        wire.listener_plans.into_iter().map(Into::into).collect(),
        wire.domain_plans.into_iter().map(Into::into).collect(),
        wire.placement_plans.into_iter().map(Into::into).collect(),
        wire.workflow_plans.into_iter().map(WorkflowPlan).collect(),
    )?;
    if plan.runtime_plan_fingerprint.as_str() != expected_fingerprint.as_str() {
        return Err(RuntimePlanError::new(
            RuntimePlanErrorKind::FingerprintMismatch,
        ));
    }
    Ok(plan)
}

/// Candidate carrier consumed by [`RuntimePlan::compile_v3`].
///
/// Its methods deliberately accept duplicate or incomplete declarations so the compiler can
/// exercise a single fail-closed validation path. It is not serializable.
#[derive(Default)]
pub struct RuntimePlanV3Input {
    provider_plans: Vec<ProviderPlan>,
    listener_plans: Vec<ListenerPlan>,
    domain_plans: Vec<DomainPlan>,
    placement_plans: Vec<PlacementPlan>,
    workflow_plans: Vec<WorkflowPlan>,
}

impl RuntimePlanV3Input {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the only executable provider candidate set from active canonical declarations.
    pub fn from_manifest(manifest: &CanonicalAssemblyManifestV2) -> Self {
        let mut input = Self::new();
        input.workflow_plans = manifest
            .workflow_activations()
            .iter()
            .cloned()
            .map(WorkflowPlan)
            .collect();
        let mut providers = manifest
            .diport_providers()
            .iter()
            .filter(|provider| provider.lifecycle == ProviderLifecycle::Active)
            .collect::<Vec<_>>();
        providers.sort_by_key(|provider| provider.id.as_str());
        for provider in providers {
            input.provider(provider.id, provider.provider, provider.outputs.clone());
        }
        input
    }

    pub fn provider(
        &mut self,
        role: ProviderRole,
        constructor: ProviderConstructor,
        outputs: Vec<LifecycleChannel>,
    ) {
        self.provider_plans.push(ProviderPlan {
            id: role.as_str().to_owned(),
            constructor,
            activation: role.activation(),
            outputs,
        });
    }

    pub fn listener(
        &mut self,
        kind: AssemblyListenerKind,
        auth: ListenerAuth,
        domains: Vec<AssemblyDomain>,
    ) {
        self.listener_plans.push(ListenerPlan {
            id: format!("{}-main", kind.as_str()),
            kind,
            auth,
            domains,
        });
    }

    pub fn domain(&mut self, id: AssemblyDomain) {
        self.domain_plans.push(DomainPlan {
            id,
            lifecycle: FIXED_DOMAIN_LIFECYCLE.to_vec(),
        });
    }

    pub fn placement(&mut self, domain: AssemblyDomain, workload: impl Into<String>) {
        self.placement_plans.push(PlacementPlan {
            domain,
            workload: workload.into(),
        });
    }
}

#[derive(Serialize)]
#[serde(transparent)]
pub struct WorkflowPlan(WorkflowActivation);

impl WorkflowPlan {
    pub fn id(&self) -> &str {
        self.0.id()
    }

    pub const fn activation(&self) -> &WorkflowActivation {
        &self.0
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPlan {
    id: String,
    constructor: ProviderConstructor,
    activation: ProviderActivation,
    outputs: Vec<LifecycleChannel>,
}

impl ProviderPlan {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn constructor(&self) -> ProviderConstructor {
        self.constructor
    }

    pub const fn activation(&self) -> ProviderActivation {
        self.activation
    }

    pub fn outputs(&self) -> &[LifecycleChannel] {
        &self.outputs
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerPlan {
    id: String,
    kind: AssemblyListenerKind,
    auth: ListenerAuth,
    domains: Vec<AssemblyDomain>,
}

impl ListenerPlan {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn kind(&self) -> AssemblyListenerKind {
        self.kind
    }

    pub const fn auth(&self) -> ListenerAuth {
        self.auth
    }

    pub fn domains(&self) -> &[AssemblyDomain] {
        &self.domains
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub struct DomainPlan {
    id: AssemblyDomain,
    lifecycle: Vec<DomainLifecyclePhase>,
}

impl DomainPlan {
    pub const fn id(&self) -> AssemblyDomain {
        self.id
    }

    pub fn lifecycle(&self) -> &[DomainLifecyclePhase] {
        &self.lifecycle
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementPlan {
    domain: AssemblyDomain,
    workload: String,
}

impl PlacementPlan {
    pub const fn domain(&self) -> AssemblyDomain {
        self.domain
    }

    pub fn workload(&self) -> &str {
        &self.workload
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ListenerAuth {
    NoAuth,
    RssAccessToken,
    FederatedAccessToken,
    Mtls,
    ServiceToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DomainLifecyclePhase {
    Construct,
    Ready,
    Shutdown,
}

/// Domain-separated identity of the unsigned RuntimePlan.
#[derive(Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct RuntimePlanFingerprint(
    #[schemars(with = "String", regex(pattern = "^sha256:[0-9a-f]{64}$"))] CanonicalSha256Digest,
);

impl RuntimePlanFingerprint {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn from_validated(value: CanonicalSha256Digest) -> Self {
        Self(value)
    }
}

/// Closed RuntimePlan protocol error. Values from candidate facts are never formatted.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct RuntimePlanError(RuntimePlanErrorKind);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePlanErrorStage {
    WireDecode,
    SchemaVersion,
    AssemblyIdentity,
    ManifestDigest,
    PlanFacts,
    CanonicalSerialization,
    Fingerprint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePlanJsonCategory {
    Syntax,
    Data,
    Eof,
    Io,
}

impl fmt::Display for RuntimePlanJsonCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Syntax => "syntax",
            Self::Data => "data",
            Self::Eof => "eof",
            Self::Io => "io",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePlanJsonPath(String);

impl RuntimePlanJsonPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuntimePlanJsonPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, thiserror::Error)]
enum RuntimePlanErrorKind {
    #[error("invalid strict RuntimePlan JSON at `{path}` ({category})")]
    StrictJson {
        path: RuntimePlanJsonPath,
        category: RuntimePlanJsonCategory,
    },
    #[error(
        "unsupported RuntimePlan schemaVersion {actual}; supported schemaVersion is {supported}; regenerate the RuntimePlan"
    )]
    UnsupportedVersion { actual: u32, supported: u32 },
    #[error("RuntimePlan {0} is not a lowercase sha256 digest")]
    InvalidDigest(&'static str),
    #[error("RuntimePlan identity does not match the canonical assembly manifest and lock")]
    AssemblyIdentityMismatch,
    #[error("RuntimePlan canonical manifest digest does not match AssemblyLock")]
    ManifestDigestMismatch,
    #[error("RuntimePlan field `{0}` must not be empty")]
    Empty(&'static str),
    #[error("RuntimePlan field `{0}` contains an invalid stable identifier")]
    InvalidId(&'static str),
    #[error("RuntimePlan field `{0}` contains duplicate keyed facts")]
    Duplicate(&'static str),
    #[error("RuntimePlan field `{0}` is not in canonical order")]
    NonCanonicalOrder(&'static str),
    #[error("RuntimePlan field `{0}` does not exactly cover assembly declarations")]
    DeclarationMismatch(&'static str),
    #[error("RuntimePlan field `{0}` contains a dangling reference")]
    DanglingReference(&'static str),
    #[error("RuntimePlan listener auth is incompatible with its listener kind")]
    InvalidListenerAuth,
    #[error("RuntimePlan domain lifecycle must be construct, ready, shutdown")]
    InvalidDomainLifecycle,
    #[error("RuntimePlan RFC8785 canonical serialization failed: {0}")]
    CanonicalJson(#[source] serde_json::Error),
    #[error("RuntimePlan fingerprint mismatch")]
    FingerprintMismatch,
}

impl RuntimePlanError {
    fn new(kind: RuntimePlanErrorKind) -> Self {
        Self(kind)
    }

    pub const fn stage(&self) -> RuntimePlanErrorStage {
        match &self.0 {
            RuntimePlanErrorKind::StrictJson { .. } => RuntimePlanErrorStage::WireDecode,
            RuntimePlanErrorKind::UnsupportedVersion { .. } => RuntimePlanErrorStage::SchemaVersion,
            RuntimePlanErrorKind::AssemblyIdentityMismatch => {
                RuntimePlanErrorStage::AssemblyIdentity
            }
            RuntimePlanErrorKind::ManifestDigestMismatch => RuntimePlanErrorStage::ManifestDigest,
            RuntimePlanErrorKind::CanonicalJson(_) => RuntimePlanErrorStage::CanonicalSerialization,
            RuntimePlanErrorKind::FingerprintMismatch => RuntimePlanErrorStage::Fingerprint,
            RuntimePlanErrorKind::InvalidDigest(_)
            | RuntimePlanErrorKind::Empty(_)
            | RuntimePlanErrorKind::InvalidId(_)
            | RuntimePlanErrorKind::Duplicate(_)
            | RuntimePlanErrorKind::NonCanonicalOrder(_)
            | RuntimePlanErrorKind::DeclarationMismatch(_)
            | RuntimePlanErrorKind::DanglingReference(_)
            | RuntimePlanErrorKind::InvalidListenerAuth
            | RuntimePlanErrorKind::InvalidDomainLifecycle => RuntimePlanErrorStage::PlanFacts,
        }
    }

    pub const fn json_category(&self) -> Option<RuntimePlanJsonCategory> {
        match &self.0 {
            RuntimePlanErrorKind::StrictJson { category, .. } => Some(*category),
            _ => None,
        }
    }

    pub fn json_path(&self) -> Option<&RuntimePlanJsonPath> {
        match &self.0 {
            RuntimePlanErrorKind::StrictJson { path, .. } => Some(path),
            _ => None,
        }
    }
}

fn strict_json_error(source: serde_path_to_error::Error<serde_json::Error>) -> RuntimePlanError {
    let category = json_category(source.inner());
    let path = safe_json_path(source.path());
    RuntimePlanError::new(RuntimePlanErrorKind::StrictJson { path, category })
}

fn strict_json_root_error(source: &serde_json::Error) -> RuntimePlanError {
    RuntimePlanError::new(RuntimePlanErrorKind::StrictJson {
        path: RuntimePlanJsonPath("$".to_owned()),
        category: json_category(source),
    })
}

fn json_category(source: &serde_json::Error) -> RuntimePlanJsonCategory {
    match source.classify() {
        serde_json::error::Category::Syntax => RuntimePlanJsonCategory::Syntax,
        serde_json::error::Category::Data => RuntimePlanJsonCategory::Data,
        serde_json::error::Category::Eof => RuntimePlanJsonCategory::Eof,
        serde_json::error::Category::Io => RuntimePlanJsonCategory::Io,
    }
}

fn safe_json_path(path: &serde_path_to_error::Path) -> RuntimePlanJsonPath {
    const FIELDS: &[&str] = &[
        "schemaVersion",
        "assemblyFingerprint",
        "runtimePlanFingerprint",
        "providerPlans",
        "listenerPlans",
        "domainPlans",
        "placementPlans",
        "workflowPlans",
        "id",
        "constructor",
        "activation",
        "outputs",
        "kind",
        "auth",
        "domains",
        "lifecycle",
        "domain",
        "workload",
        "mode",
        "definitionVersion",
        "definitionSchemaDigest",
        "activation",
    ];

    let mut rendered = "$".to_owned();
    for segment in path {
        match segment {
            serde_path_to_error::Segment::Seq { index } => {
                use std::fmt::Write as _;
                let _ = write!(rendered, "[{index}]");
            }
            serde_path_to_error::Segment::Map { key } if FIELDS.contains(&key.as_str()) => {
                rendered.push('.');
                rendered.push_str(key);
            }
            serde_path_to_error::Segment::Map { .. }
            | serde_path_to_error::Segment::Enum { .. }
            | serde_path_to_error::Segment::Unknown => break,
        }
    }
    RuntimePlanJsonPath(rendered)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireRuntimePlan {
    schema_version: u32,
    assembly_fingerprint: CanonicalSha256Digest,
    runtime_plan_fingerprint: CanonicalSha256Digest,
    provider_plans: Vec<WireProviderPlan>,
    listener_plans: Vec<WireListenerPlan>,
    domain_plans: Vec<WireDomainPlan>,
    placement_plans: Vec<WirePlacementPlan>,
    workflow_plans: Vec<WorkflowActivation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProviderPlan {
    id: String,
    constructor: ProviderConstructor,
    activation: ProviderActivation,
    outputs: Vec<LifecycleChannel>,
}

impl From<WireProviderPlan> for ProviderPlan {
    fn from(wire: WireProviderPlan) -> Self {
        Self {
            id: wire.id,
            constructor: wire.constructor,
            activation: wire.activation,
            outputs: wire.outputs,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireListenerPlan {
    id: String,
    kind: AssemblyListenerKind,
    auth: ListenerAuth,
    domains: Vec<AssemblyDomain>,
}

impl From<WireListenerPlan> for ListenerPlan {
    fn from(wire: WireListenerPlan) -> Self {
        Self {
            id: wire.id,
            kind: wire.kind,
            auth: wire.auth,
            domains: wire.domains,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDomainPlan {
    id: AssemblyDomain,
    lifecycle: Vec<DomainLifecyclePhase>,
}

impl From<WireDomainPlan> for DomainPlan {
    fn from(wire: WireDomainPlan) -> Self {
        Self {
            id: wire.id,
            lifecycle: wire.lifecycle,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePlacementPlan {
    domain: AssemblyDomain,
    workload: String,
}

impl From<WirePlacementPlan> for PlacementPlan {
    fn from(wire: WirePlacementPlan) -> Self {
        Self {
            domain: wire.domain,
            workload: wire.workload,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedRuntimePlan<'a> {
    schema_version: u32,
    assembly_fingerprint: &'a AssemblyFingerprint,
    provider_plans: &'a [ProviderPlan],
    listener_plans: &'a [ListenerPlan],
    domain_plans: &'a [DomainPlan],
    placement_plans: &'a [PlacementPlan],
    workflow_plans: &'a [WorkflowPlan],
}

fn validate_manifest_lock(
    manifest: &CanonicalAssemblyManifestV2,
    lock: &RepositoryVerifiedAssemblyLock,
) -> Result<(), RuntimePlanError> {
    if manifest.name() != lock.identity().name() || manifest.profile() != lock.identity().profile()
    {
        return Err(RuntimePlanError::new(
            RuntimePlanErrorKind::AssemblyIdentityMismatch,
        ));
    }
    if manifest.manifest_digest() != lock.digests().manifest() {
        return Err(RuntimePlanError::new(
            RuntimePlanErrorKind::ManifestDigestMismatch,
        ));
    }
    Ok(())
}

fn validate_candidates(
    manifest: &CanonicalAssemblyManifestV2,
    _lock: &RepositoryVerifiedAssemblyLock,
    input: &RuntimePlanV3Input,
) -> Result<(), RuntimePlanError> {
    let expected_workflows = manifest.workflow_activations();
    let actual_workflows = input
        .workflow_plans
        .iter()
        .map(WorkflowPlan::activation)
        .cloned()
        .collect::<Vec<_>>();
    if actual_workflows != expected_workflows {
        return Err(RuntimePlanError::new(
            RuntimePlanErrorKind::DeclarationMismatch("workflowPlans"),
        ));
    }

    let expected_providers = executable_provider_declarations(manifest);
    let actual_providers = input
        .provider_plans
        .iter()
        .map(|provider| {
            (
                provider.id.as_str(),
                provider.constructor,
                provider.activation,
                provider.outputs.as_slice(),
            )
        })
        .collect::<BTreeSet<_>>();
    if expected_providers != actual_providers
        || expected_providers.len() != input.provider_plans.len()
    {
        return Err(RuntimePlanError::new(
            RuntimePlanErrorKind::DeclarationMismatch("providerPlans"),
        ));
    }

    let expected_listeners = manifest
        .listeners()
        .iter()
        .map(|listener| (listener.kind, listener.domains.as_slice()))
        .collect::<BTreeMap<_, _>>();
    let actual_listeners = input
        .listener_plans
        .iter()
        .map(|listener| (listener.kind, listener.domains.as_slice()))
        .collect::<BTreeMap<_, _>>();
    if expected_listeners != actual_listeners
        || expected_listeners.len() != input.listener_plans.len()
    {
        return Err(RuntimePlanError::new(
            RuntimePlanErrorKind::DeclarationMismatch("listenerPlans"),
        ));
    }

    let actual_domains = input
        .domain_plans
        .iter()
        .map(|plan| plan.id)
        .collect::<Vec<_>>();
    if actual_domains != manifest.domains() {
        return Err(RuntimePlanError::new(
            RuntimePlanErrorKind::DeclarationMismatch("domainPlans"),
        ));
    }

    let mut expected_domains = manifest.domains().to_vec();
    expected_domains.sort_by_key(|domain| domain.as_str());
    let actual_placement_domains = input
        .placement_plans
        .iter()
        .map(|plan| plan.domain)
        .collect::<Vec<_>>();
    if actual_placement_domains != expected_domains {
        return Err(RuntimePlanError::new(
            RuntimePlanErrorKind::DeclarationMismatch("placementPlans"),
        ));
    }
    Ok(())
}

fn executable_provider_declarations(
    manifest: &CanonicalAssemblyManifestV2,
) -> BTreeSet<(
    &str,
    ProviderConstructor,
    ProviderActivation,
    &[LifecycleChannel],
)> {
    manifest
        .diport_providers()
        .iter()
        .filter(|provider| provider.lifecycle == ProviderLifecycle::Active)
        .map(|provider| {
            (
                provider.id.as_str(),
                provider.provider,
                provider.id.activation(),
                provider.outputs.as_slice(),
            )
        })
        .collect()
}

fn validate_plan_facts(
    providers: &[ProviderPlan],
    listeners: &[ListenerPlan],
    domains: &[DomainPlan],
    placements: &[PlacementPlan],
    workflows: &[WorkflowPlan],
) -> Result<(), RuntimePlanError> {
    for (field, empty) in [
        ("providerPlans", providers.is_empty()),
        ("domainPlans", domains.is_empty()),
        ("placementPlans", placements.is_empty()),
    ] {
        if empty {
            return Err(RuntimePlanError::new(RuntimePlanErrorKind::Empty(field)));
        }
    }

    validate_providers(providers)?;
    validate_domains(domains)?;
    validate_listeners(listeners, domains)?;
    validate_placements(placements, domains)?;
    validate_workflows(workflows)
}

fn validate_workflows(workflows: &[WorkflowPlan]) -> Result<(), RuntimePlanError> {
    validate_sorted_unique(workflows, |plan| plan.id().to_owned(), "workflowPlans")?;
    for plan in workflows {
        let activation = plan.activation();
        if !valid_workflow_id(activation.id()) {
            return Err(RuntimePlanError::new(RuntimePlanErrorKind::InvalidId(
                "workflowPlans.id",
            )));
        }
        if !valid_definition_version(activation.definition_version()) {
            return Err(RuntimePlanError::new(RuntimePlanErrorKind::InvalidId(
                "workflowPlans.definitionVersion",
            )));
        }
        if activation
            .projection_target_generation()
            .is_some_and(|generation| !valid_projection_target_generation(generation))
        {
            return Err(RuntimePlanError::new(RuntimePlanErrorKind::InvalidId(
                "workflowPlans.targetGeneration",
            )));
        }
    }
    Ok(())
}

fn validate_providers(providers: &[ProviderPlan]) -> Result<(), RuntimePlanError> {
    validate_sorted_unique(providers, |provider| provider.id.clone(), "providerPlans")?;
    for provider in providers {
        if !valid_stable_id(&provider.id) {
            return Err(RuntimePlanError::new(RuntimePlanErrorKind::InvalidId(
                "providerPlans.id",
            )));
        }
        validate_sorted_unique(
            &provider.outputs,
            |channel| *channel,
            "providerPlans.outputs",
        )?;
    }
    Ok(())
}

fn validate_domains(domains: &[DomainPlan]) -> Result<(), RuntimePlanError> {
    let mut seen = BTreeSet::new();
    for domain in domains {
        if !seen.insert(domain.id) {
            return Err(RuntimePlanError::new(RuntimePlanErrorKind::Duplicate(
                "domainPlans.id",
            )));
        }
        if domain.lifecycle != FIXED_DOMAIN_LIFECYCLE {
            return Err(RuntimePlanError::new(
                RuntimePlanErrorKind::InvalidDomainLifecycle,
            ));
        }
    }
    Ok(())
}

fn validate_listeners(
    listeners: &[ListenerPlan],
    domains: &[DomainPlan],
) -> Result<(), RuntimePlanError> {
    validate_sorted_unique(listeners, |listener| listener.id.clone(), "listenerPlans")?;
    let declared_domains = domains
        .iter()
        .map(|domain| domain.id)
        .collect::<BTreeSet<_>>();
    for listener in listeners {
        if !valid_stable_id(&listener.id)
            || listener.id != format!("{}-main", listener.kind.as_str())
        {
            return Err(RuntimePlanError::new(RuntimePlanErrorKind::InvalidId(
                "listenerPlans.id",
            )));
        }
        match (listener.kind, listener.auth) {
            (
                AssemblyListenerKind::Primary | AssemblyListenerKind::Admin,
                ListenerAuth::RssAccessToken | ListenerAuth::FederatedAccessToken,
            )
            | (AssemblyListenerKind::Health, ListenerAuth::NoAuth)
            | (AssemblyListenerKind::Internal, ListenerAuth::Mtls | ListenerAuth::ServiceToken) => {
            }
            _ => {
                return Err(RuntimePlanError::new(
                    RuntimePlanErrorKind::InvalidListenerAuth,
                ));
            }
        }
        let mut seen = BTreeSet::new();
        for domain in &listener.domains {
            if !seen.insert(*domain) {
                return Err(RuntimePlanError::new(RuntimePlanErrorKind::Duplicate(
                    "listenerPlans.domains",
                )));
            }
            if !declared_domains.contains(domain) {
                return Err(RuntimePlanError::new(
                    RuntimePlanErrorKind::DanglingReference("listenerPlans.domains"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_placements(
    placements: &[PlacementPlan],
    domains: &[DomainPlan],
) -> Result<(), RuntimePlanError> {
    let keys = placements
        .iter()
        .map(|plan| (plan.domain.as_str(), plan.workload.as_str()))
        .collect::<Vec<_>>();
    validate_sorted_unique(&keys, |key| *key, "placementPlans")?;
    let declared = domains.iter().map(|plan| plan.id).collect::<BTreeSet<_>>();
    let mut placed = BTreeSet::new();
    for placement in placements {
        if placement.workload.trim().is_empty() {
            return Err(RuntimePlanError::new(RuntimePlanErrorKind::Empty(
                "placementPlans.workload",
            )));
        }
        if !valid_stable_id(&placement.workload) {
            return Err(RuntimePlanError::new(RuntimePlanErrorKind::InvalidId(
                "placementPlans.workload",
            )));
        }
        if !declared.contains(&placement.domain) {
            return Err(RuntimePlanError::new(
                RuntimePlanErrorKind::DanglingReference("placementPlans.domain"),
            ));
        }
        if !placed.insert(placement.domain) {
            return Err(RuntimePlanError::new(RuntimePlanErrorKind::Duplicate(
                "placementPlans.domain",
            )));
        }
    }
    if placed != declared {
        return Err(RuntimePlanError::new(
            RuntimePlanErrorKind::DeclarationMismatch("placementPlans"),
        ));
    }
    Ok(())
}

fn validate_sorted_unique<T, K>(
    values: &[T],
    key: impl Fn(&T) -> K,
    field: &'static str,
) -> Result<(), RuntimePlanError>
where
    K: Ord,
{
    for pair in values.windows(2) {
        match key(&pair[0]).cmp(&key(&pair[1])) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                return Err(RuntimePlanError::new(RuntimePlanErrorKind::Duplicate(
                    field,
                )));
            }
            std::cmp::Ordering::Greater => {
                return Err(RuntimePlanError::new(
                    RuntimePlanErrorKind::NonCanonicalOrder(field),
                ));
            }
        }
    }
    Ok(())
}

fn valid_stable_id(value: &str) -> bool {
    !value.is_empty()
        && value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn valid_workflow_id(value: &str) -> bool {
    let mut segments = value.split('.');
    let Some(domain) = segments.next() else {
        return false;
    };
    let Some(name) = segments.next() else {
        return false;
    };
    segments.next().is_none() && valid_stable_id(domain) && valid_stable_id(name)
}

fn valid_definition_version(value: &str) -> bool {
    value.strip_prefix('v').is_some_and(|number| {
        !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn valid_projection_target_generation(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        && value.as_bytes()[0].is_ascii_alphanumeric()
}

fn fingerprint_for(
    assembly_fingerprint: &AssemblyFingerprint,
    provider_plans: &[ProviderPlan],
    listener_plans: &[ListenerPlan],
    domain_plans: &[DomainPlan],
    placement_plans: &[PlacementPlan],
    workflow_plans: &[WorkflowPlan],
) -> Result<RuntimePlanFingerprint, RuntimePlanError> {
    let unsigned = UnsignedRuntimePlan {
        schema_version: SCHEMA_VERSION,
        assembly_fingerprint,
        provider_plans,
        listener_plans,
        domain_plans,
        placement_plans,
        workflow_plans,
    };
    let canonical = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|source| RuntimePlanError::new(RuntimePlanErrorKind::CanonicalJson(source)))?;
    let mut hasher = Sha256::new();
    hasher.update(RUNTIME_PLAN_TAG.as_bytes());
    hasher.update([0]);
    hasher.update(canonical);
    let digest = CanonicalSha256Digest::parse(format!("sha256:{:x}", hasher.finalize()))
        .map_err(|_| RuntimePlanError::new(RuntimePlanErrorKind::InvalidDigest("computed")))?;
    Ok(RuntimePlanFingerprint(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AssemblyManifest;
    use anyhow::Context as _;
    use std::path::Path;

    #[test]
    fn unsupported_version_error_preserves_actual_and_supported_versions() -> anyhow::Result<()> {
        let mut wire = serde_json::from_slice::<serde_json::Value>(include_bytes!(
            "../../../assemblies/runtime/runtime-plan.json"
        ))?;
        wire["schemaVersion"] = serde_json::json!(1);

        let error = match parse_unbound_runtime_plan(&serde_json::to_vec(&wire)?) {
            Ok(_) => anyhow::bail!("RuntimePlan v1 unexpectedly parsed"),
            Err(error) => error,
        };
        assert!(matches!(
            error.0,
            RuntimePlanErrorKind::UnsupportedVersion {
                actual: 1,
                supported: 3
            }
        ));
        Ok(())
    }

    #[test]
    fn executable_provider_declarations_exclude_draft_roles() -> anyhow::Result<()> {
        let manifest = AssemblyManifest::from_toml_str(
            r#"
schemaVersion = 2
name = "runtime-plan-fixture"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []
workflowActivations = []

[[listeners]]
kind = "primary"
domains = ["contractreg"]

[[diportProviders]]
id = "device-revocation-store"
port = "diport::RevocationStore"
provider = "postgres::PgRevocationStore"
providerCrate = "postgres"
requiredFeatures = []
consumer = "deviceloop"
lifecycle = "active"
durability = "persistent"
purpose = "active-fixture"
outputs = ["probes", "workers"]

[[diportProviders]]
id = "distributed-cas-store-alternative"
port = "diport::CasStore"
provider = "redis::RedisCasStore"
providerCrate = "redis"
requiredFeatures = ["backend"]
consumer = "distributed"
lifecycle = "draft"
durability = "persistent"
purpose = "draft-fixture"
outputs = ["resources"]
"#,
        )?
        .canonicalize_v2()?;

        let declarations = executable_provider_declarations(&manifest);
        assert_eq!(declarations.len(), 1);
        assert!(
            declarations
                .iter()
                .all(|(id, _, _, _)| *id != "distributed-cas-store-alternative")
        );
        let input = RuntimePlanV3Input::from_manifest(&manifest);
        assert!(
            input.workflow_plans.is_empty(),
            "omitted workflows must derive an explicit empty RuntimePlan workflow set"
        );
        let actual = input
            .provider_plans
            .iter()
            .map(|plan| {
                (
                    plan.id(),
                    plan.constructor(),
                    plan.activation(),
                    plan.outputs(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, declarations);
        Ok(())
    }

    #[test]
    fn manifest_bound_reader_rejects_self_consistent_extra_provider() -> anyhow::Result<()> {
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .context("repository root")?;
        let source = crate::RepositoryAssemblyManifestV2::discover_v2(
            repository_root,
            &repository_root.join("assemblies/runtime"),
        )?;
        let manifest = source.canonical();
        let lock = crate::ParsedAssemblyLock::from_json_slice(include_bytes!(
            "../../../assemblies/runtime/assembly.lock.json"
        ))?
        .verify_repository_v2(&source)?;
        let candidate = parse_unbound_runtime_plan(include_bytes!(
            "../../../assemblies/runtime/runtime-plan.json"
        ))?;
        let RuntimePlan {
            mut provider_plans,
            listener_plans,
            domain_plans,
            placement_plans,
            workflow_plans,
            ..
        } = candidate;
        provider_plans.push(ProviderPlan {
            id: "distributed-cas-store-alternative".to_owned(),
            constructor: ProviderConstructor::RedisCasStore,
            activation: ProviderRole::DistributedCasStoreAlternative.activation(),
            outputs: vec![LifecycleChannel::Resources],
        });
        provider_plans.sort_by(|left, right| left.id.cmp(&right.id));
        let forged = RuntimePlan::from_parts(
            lock.fingerprint().clone(),
            provider_plans,
            listener_plans,
            domain_plans,
            placement_plans,
            workflow_plans,
        )?;
        let bytes = serde_json::to_vec(&forged)?;

        validate_runtime_plan_json_slice(&bytes)?;
        let error = match ParsedRuntimePlan::from_json_slice_bound(&bytes, manifest, &lock) {
            Ok(_) => anyhow::bail!("manifest-bound reader accepted an extra provider"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("providerPlans"));
        Ok(())
    }
}
