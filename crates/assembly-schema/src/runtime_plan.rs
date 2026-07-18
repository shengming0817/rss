//! Canonical RuntimePlan v1 protocol.
//!
//! INVARIANT: RUNTIME-PLAN-CONSTRUCTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private plan fields plus the validated compile_v1 funnel" } — callers can describe candidate facts, but only a manifest/lock-bound compiler or the strict reader can mint a RuntimePlan.

use crate::{
    AssemblyDomain, AssemblyFingerprint, AssemblyListenerKind, CanonicalAssemblyManifestV1,
    LifecycleChannel, ParsedAssemblyLock, ProviderConstructor,
};
use schemars::JsonSchema;
use schemars::schema::{RootSchema, Schema};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const RUNTIME_PLAN_TAG: &str = "rss-runtime-plan-v1";
const SCHEMA_VERSION: u32 = 1;
const SHA256_PREFIX: &str = "sha256:";
const FIXED_DOMAIN_LIFECYCLE: [DomainLifecyclePhase; 3] = [
    DomainLifecyclePhase::Construct,
    DomainLifecyclePhase::Ready,
    DomainLifecyclePhase::Shutdown,
];

/// Validated, closed RuntimePlan v1 value.
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
}

impl JsonSchema for RuntimePlan {
    fn schema_name() -> String {
        "RuntimePlan target contract".to_owned()
    }

    fn is_referenceable() -> bool {
        false
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> Schema {
        let Ok(mut committed) = serde_json::from_str::<RootSchema>(include_str!(
            "../../../docs/spec/007-runtime-deployment-executable-plan/contracts/runtime-plan.schema.json"
        )) else {
            return Schema::Bool(false);
        };
        generator
            .definitions_mut()
            .append(&mut committed.definitions);
        Schema::Object(committed.schema)
    }
}

impl RuntimePlan {
    /// Validate candidate facts against the exact canonical manifest and AssemblyLock.
    pub fn compile_v1(
        manifest: &CanonicalAssemblyManifestV1,
        lock: &ParsedAssemblyLock,
        input: RuntimePlanV1Input,
    ) -> Result<Self, RuntimePlanError> {
        validate_manifest_lock(manifest, lock)?;
        validate_candidates(manifest, lock, &input)?;
        Self::from_parts(
            lock.fingerprint().clone(),
            input.provider_plans,
            input.listener_plans,
            input.domain_plans,
            input.placement_plans,
        )
    }

    fn from_parts(
        assembly_fingerprint: AssemblyFingerprint,
        provider_plans: Vec<ProviderPlan>,
        listener_plans: Vec<ListenerPlan>,
        domain_plans: Vec<DomainPlan>,
        placement_plans: Vec<PlacementPlan>,
    ) -> Result<Self, RuntimePlanError> {
        validate_plan_facts(
            &provider_plans,
            &listener_plans,
            &domain_plans,
            &placement_plans,
        )?;
        let runtime_plan_fingerprint = fingerprint_for(
            &assembly_fingerprint,
            &provider_plans,
            &listener_plans,
            &domain_plans,
            &placement_plans,
        )?;
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            assembly_fingerprint,
            runtime_plan_fingerprint,
            provider_plans,
            listener_plans,
            domain_plans,
            placement_plans,
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
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, RuntimePlanError> {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let wire: WireRuntimePlan =
            serde_path_to_error::deserialize(&mut deserializer).map_err(strict_json_error)?;
        deserializer
            .end()
            .map_err(|source| strict_json_root_error(&source))?;
        if wire.schema_version != SCHEMA_VERSION {
            return Err(RuntimePlanError::new(
                RuntimePlanErrorKind::UnsupportedVersion,
            ));
        }
        validate_sha256("assemblyFingerprint", wire.assembly_fingerprint.as_str())?;
        validate_sha256(
            "runtimePlanFingerprint",
            wire.runtime_plan_fingerprint.as_str(),
        )?;
        let assembly_fingerprint = AssemblyFingerprint::from_validated(wire.assembly_fingerprint);
        let plan = RuntimePlan::from_parts(
            assembly_fingerprint,
            wire.provider_plans.into_iter().map(Into::into).collect(),
            wire.listener_plans.into_iter().map(Into::into).collect(),
            wire.domain_plans.into_iter().map(Into::into).collect(),
            wire.placement_plans.into_iter().map(Into::into).collect(),
        )?;
        if plan.runtime_plan_fingerprint.as_str() != wire.runtime_plan_fingerprint {
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
}

impl fmt::Debug for ParsedRuntimePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Candidate carrier consumed by [`RuntimePlan::compile_v1`].
///
/// Its methods deliberately accept duplicate or incomplete declarations so the compiler can
/// exercise a single fail-closed validation path. It is not serializable.
#[derive(Default)]
pub struct RuntimePlanV1Input {
    provider_plans: Vec<ProviderPlan>,
    listener_plans: Vec<ListenerPlan>,
    domain_plans: Vec<DomainPlan>,
    placement_plans: Vec<PlacementPlan>,
}

impl RuntimePlanV1Input {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn provider(
        &mut self,
        id: impl Into<String>,
        constructor: ProviderConstructor,
        outputs: Vec<LifecycleChannel>,
    ) {
        self.provider_plans.push(ProviderPlan {
            id: id.into(),
            constructor,
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
#[serde(deny_unknown_fields)]
pub struct ProviderPlan {
    id: String,
    constructor: ProviderConstructor,
    outputs: Vec<LifecycleChannel>,
}

impl ProviderPlan {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn constructor(&self) -> ProviderConstructor {
        self.constructor
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
    Jwt,
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
pub struct RuntimePlanFingerprint(#[schemars(regex(pattern = "^sha256:[0-9a-f]{64}$"))] String);

impl RuntimePlanFingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
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
    #[error("unsupported RuntimePlan schemaVersion")]
    UnsupportedVersion,
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
            RuntimePlanErrorKind::UnsupportedVersion => RuntimePlanErrorStage::SchemaVersion,
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
        "id",
        "constructor",
        "outputs",
        "kind",
        "auth",
        "domains",
        "lifecycle",
        "domain",
        "workload",
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
    assembly_fingerprint: String,
    runtime_plan_fingerprint: String,
    provider_plans: Vec<WireProviderPlan>,
    listener_plans: Vec<WireListenerPlan>,
    domain_plans: Vec<WireDomainPlan>,
    placement_plans: Vec<WirePlacementPlan>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProviderPlan {
    id: String,
    constructor: ProviderConstructor,
    outputs: Vec<LifecycleChannel>,
}

impl From<WireProviderPlan> for ProviderPlan {
    fn from(wire: WireProviderPlan) -> Self {
        Self {
            id: wire.id,
            constructor: wire.constructor,
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
}

fn validate_manifest_lock(
    manifest: &CanonicalAssemblyManifestV1,
    lock: &ParsedAssemblyLock,
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
    manifest: &CanonicalAssemblyManifestV1,
    lock: &ParsedAssemblyLock,
    input: &RuntimePlanV1Input,
) -> Result<(), RuntimePlanError> {
    let expected_providers = manifest
        .diport_providers()
        .iter()
        .map(|provider| {
            (
                provider.id.as_str(),
                provider.provider,
                provider.outputs.as_slice(),
            )
        })
        .collect::<BTreeSet<_>>();
    let actual_providers = input
        .provider_plans
        .iter()
        .map(|provider| {
            (
                provider.id.as_str(),
                provider.constructor,
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

    let mut expected_placements = manifest
        .domains()
        .iter()
        .map(|domain| (*domain, lock.identity().name()))
        .collect::<Vec<_>>();
    expected_placements
        .sort_by(|left, right| (left.0.as_str(), left.1).cmp(&(right.0.as_str(), right.1)));
    if !input
        .placement_plans
        .iter()
        .map(|plan| (plan.domain, plan.workload.as_str()))
        .eq(expected_placements)
    {
        return Err(RuntimePlanError::new(
            RuntimePlanErrorKind::DeclarationMismatch("placementPlans"),
        ));
    }
    Ok(())
}

fn validate_plan_facts(
    providers: &[ProviderPlan],
    listeners: &[ListenerPlan],
    domains: &[DomainPlan],
    placements: &[PlacementPlan],
) -> Result<(), RuntimePlanError> {
    for (field, empty) in [
        ("providerPlans", providers.is_empty()),
        ("listenerPlans", listeners.is_empty()),
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
    validate_placements(placements, domains)
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
            (AssemblyListenerKind::Primary | AssemblyListenerKind::Admin, ListenerAuth::Jwt)
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

fn fingerprint_for(
    assembly_fingerprint: &AssemblyFingerprint,
    provider_plans: &[ProviderPlan],
    listener_plans: &[ListenerPlan],
    domain_plans: &[DomainPlan],
    placement_plans: &[PlacementPlan],
) -> Result<RuntimePlanFingerprint, RuntimePlanError> {
    let unsigned = UnsignedRuntimePlan {
        schema_version: SCHEMA_VERSION,
        assembly_fingerprint,
        provider_plans,
        listener_plans,
        domain_plans,
        placement_plans,
    };
    let canonical = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|source| RuntimePlanError::new(RuntimePlanErrorKind::CanonicalJson(source)))?;
    let mut hasher = Sha256::new();
    hasher.update(RUNTIME_PLAN_TAG.as_bytes());
    hasher.update([0]);
    hasher.update(canonical);
    Ok(RuntimePlanFingerprint(format!(
        "{SHA256_PREFIX}{:x}",
        hasher.finalize()
    )))
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), RuntimePlanError> {
    let Some(hex) = value.strip_prefix(SHA256_PREFIX) else {
        return Err(RuntimePlanError::new(RuntimePlanErrorKind::InvalidDigest(
            field,
        )));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RuntimePlanError::new(RuntimePlanErrorKind::InvalidDigest(
            field,
        )));
    }
    Ok(())
}
