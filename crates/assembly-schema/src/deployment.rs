//! Canonical DeploymentPlan v1 protocol.
//!
//! INVARIANT: DEPLOYMENT-PLAN-CONSTRUCTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private plan fields plus compile_v1 and runtime-bound reader" }.
//! INVARIANT: DEPLOYMENT-PLAN-UPSTREAM-IDENTITY-01 { level = "Hard", exec = "native-compile", source = "code", native = "assembly/runtime fingerprints copied from RuntimePlan" }.
//! INVARIANT: DEPLOYMENT-PLAN-SECRET-BOUNDARY-01 { level = "Hard", exec = "native-compile", source = "code", native = "closed typed SecretRef with redacted Debug and diagnostics" }.

use crate::{AssemblyFingerprint, AssemblyListenerKind, RuntimePlan, RuntimePlanFingerprint};
use schemars::JsonSchema;
use schemars::schema::{RootSchema, Schema};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const TAG: &str = "rss-deployment-plan-v1";
const SCHEMA_VERSION: u32 = 1;
const SHA256_PREFIX: &str = "sha256:";

macro_rules! validated_name_type {
    ($name:ident, $validator:path) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
        #[serde(transparent)]
        struct $name(String);

        impl $name {
            fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl $name {
            fn parse(value: String, field: &'static str) -> Result<Self, DeploymentPlanError> {
                if !$validator(&value) {
                    return Err(DeploymentPlanError::new(DeploymentPlanErrorKind::Invalid(
                        field,
                    )));
                }
                Ok(Self(value))
            }
        }
    };
}

validated_name_type!(WorkloadName, valid_dns_label);
validated_name_type!(ServiceName, valid_dns_label);
validated_name_type!(ServiceAccountName, valid_dns_name);
validated_name_type!(PortName, valid_service_port_name);

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
struct ImmutableImageIdentity(String);
impl ImmutableImageIdentity {
    fn parse(value: String) -> Result<Self, DeploymentPlanError> {
        validate_image(&value)?;
        Ok(Self(value))
    }
    fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
/// Validated Kubernetes DNS-1123 subdomain used only as a secret reference coordinate.
pub struct KubernetesSecretName(String);
impl KubernetesSecretName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    fn parse(value: String) -> Result<Self, DeploymentPlanError> {
        if !valid_dns_name(&value) {
            return Err(DeploymentPlanError::new(DeploymentPlanErrorKind::Invalid(
                "workloads.secretRefs.name",
            )));
        }
        Ok(Self(value))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Validated DeploymentPlan v1; fields can only be minted by the RuntimePlan-bound compiler.
pub struct DeploymentPlan {
    schema_version: u32,
    assembly_fingerprint: AssemblyFingerprint,
    runtime_plan_fingerprint: RuntimePlanFingerprint,
    deployment_fingerprint: DeploymentFingerprint,
    workloads: Vec<WorkloadPlan>,
    services: Vec<ServicePlan>,
}

impl JsonSchema for DeploymentPlan {
    fn schema_name() -> String {
        "DeploymentPlan target contract".to_owned()
    }
    fn is_referenceable() -> bool {
        false
    }
    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> Schema {
        let Ok(mut committed) = serde_json::from_str::<RootSchema>(include_str!(
            "../../../docs/spec/007-runtime-deployment-executable-plan/contracts/deployment-plan.schema.json"
        )) else {
            return Schema::Bool(false);
        };
        generator
            .definitions_mut()
            .append(&mut committed.definitions);
        Schema::Object(committed.schema)
    }
}

impl DeploymentPlan {
    /// Compile closed candidate facts while copying both upstream identities from `runtime`.
    pub fn compile_v1(
        runtime: &RuntimePlan,
        input: DeploymentPlanV1Input,
    ) -> Result<Self, DeploymentPlanError> {
        let workloads = input
            .workloads
            .into_iter()
            .map(WorkloadPlan::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let services = input
            .services
            .into_iter()
            .map(ServicePlan::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_parts(runtime, workloads, services)
    }

    fn from_parts(
        runtime: &RuntimePlan,
        workloads: Vec<WorkloadPlan>,
        services: Vec<ServicePlan>,
    ) -> Result<Self, DeploymentPlanError> {
        validate_facts(runtime, &workloads, &services)?;
        let assembly_fingerprint = runtime.assembly_fingerprint().clone();
        let runtime_plan_fingerprint = runtime.runtime_plan_fingerprint().clone();
        let deployment_fingerprint = fingerprint_for(
            &assembly_fingerprint,
            &runtime_plan_fingerprint,
            &workloads,
            &services,
        )?;
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            assembly_fingerprint,
            runtime_plan_fingerprint,
            deployment_fingerprint,
            workloads,
            services,
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
    pub const fn deployment_fingerprint(&self) -> &DeploymentFingerprint {
        &self.deployment_fingerprint
    }
    pub fn workloads(&self) -> &[WorkloadPlan] {
        &self.workloads
    }
    pub fn services(&self) -> &[ServicePlan] {
        &self.services
    }
}

impl fmt::Debug for DeploymentPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeploymentPlan")
            .field("assembly_fingerprint", &self.assembly_fingerprint.as_str())
            .field(
                "runtime_plan_fingerprint",
                &self.runtime_plan_fingerprint.as_str(),
            )
            .field(
                "deployment_fingerprint",
                &self.deployment_fingerprint.as_str(),
            )
            .field("workload_count", &self.workloads.len())
            .field("service_count", &self.services.len())
            .finish()
    }
}

/// Strict wire result that has exact-matched the supplied current RuntimePlan.
pub struct ParsedDeploymentPlan(DeploymentPlan);

impl ParsedDeploymentPlan {
    pub fn from_json_slice(
        runtime: &RuntimePlan,
        bytes: &[u8],
    ) -> Result<Self, DeploymentPlanError> {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let wire: WireDeploymentPlan =
            serde_path_to_error::deserialize(&mut deserializer).map_err(strict_json_error)?;
        deserializer
            .end()
            .map_err(|source| strict_json_root_error(&source))?;
        if wire.schema_version != SCHEMA_VERSION {
            return Err(DeploymentPlanError::new(
                DeploymentPlanErrorKind::UnsupportedVersion,
            ));
        }
        validate_sha256("assemblyFingerprint", &wire.assembly_fingerprint)?;
        validate_sha256("runtimePlanFingerprint", &wire.runtime_plan_fingerprint)?;
        validate_sha256("deploymentFingerprint", &wire.deployment_fingerprint)?;
        if wire.assembly_fingerprint != runtime.assembly_fingerprint().as_str()
            || wire.runtime_plan_fingerprint != runtime.runtime_plan_fingerprint().as_str()
        {
            return Err(DeploymentPlanError::new(
                DeploymentPlanErrorKind::UpstreamIdentityMismatch,
            ));
        }
        let mut input = DeploymentPlanV1Input::new();
        for workload in wire.workloads {
            input.workload(workload.try_into()?);
        }
        for service in wire.services {
            input.service(service.try_into()?);
        }
        let plan = DeploymentPlan::compile_v1(runtime, input)?;
        if plan.deployment_fingerprint.as_str() != wire.deployment_fingerprint {
            return Err(DeploymentPlanError::new(
                DeploymentPlanErrorKind::FingerprintMismatch,
            ));
        }
        Ok(Self(plan))
    }
    pub const fn as_plan(&self) -> &DeploymentPlan {
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
    pub const fn deployment_fingerprint(&self) -> &DeploymentFingerprint {
        self.0.deployment_fingerprint()
    }
    pub fn workloads(&self) -> &[WorkloadPlan] {
        self.0.workloads()
    }
    pub fn services(&self) -> &[ServicePlan] {
        self.0.services()
    }
}

impl fmt::Debug for ParsedDeploymentPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Default)]
/// Candidate collection; set-like workloads and services must already use canonical ID order.
pub struct DeploymentPlanV1Input {
    workloads: Vec<DeploymentWorkloadV1Input>,
    services: Vec<DeploymentServiceV1Input>,
}
impl DeploymentPlanV1Input {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn workload(&mut self, workload: DeploymentWorkloadV1Input) {
        self.workloads.push(workload);
    }
    pub fn service(&mut self, service: DeploymentServiceV1Input) {
        self.services.push(service);
    }
}

/// Candidate workload facts validated in full by [`DeploymentPlan::compile_v1`].
pub struct DeploymentWorkloadV1Input {
    name: String,
    image: String,
    identity: DeploymentIdentityV1Input,
    secret_refs: Vec<SecretRefV1Input>,
    resources: ResourceRequirementsV1Input,
    probes: Vec<ProbeV1Input>,
}
impl DeploymentWorkloadV1Input {
    pub fn new(
        name: impl Into<String>,
        image: impl Into<String>,
        identity: DeploymentIdentityV1Input,
        secret_refs: Vec<SecretRefV1Input>,
        resources: ResourceRequirementsV1Input,
        probes: Vec<ProbeV1Input>,
    ) -> Self {
        Self {
            name: name.into(),
            image: image.into(),
            identity,
            secret_refs,
            resources,
            probes,
        }
    }
}
/// Candidate workload identity and Kubernetes service-account reference.
pub struct DeploymentIdentityV1Input {
    name: String,
    service_account: String,
}
impl DeploymentIdentityV1Input {
    pub fn new(name: impl Into<String>, service_account: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            service_account: service_account.into(),
        }
    }
}
/// Candidate secret reference; no variant can represent an inline secret value.
pub enum SecretRefV1Input {
    Kubernetes {
        name: String,
        key: String,
    },
    Vault {
        store_id: String,
        ref_key: String,
        ref_version: Option<String>,
    },
}
impl SecretRefV1Input {
    pub fn kubernetes(name: impl Into<String>, key: impl Into<String>) -> Self {
        Self::Kubernetes {
            name: name.into(),
            key: key.into(),
        }
    }
    pub fn vault(
        store_id: impl Into<String>,
        ref_key: impl Into<String>,
        ref_version: Option<String>,
    ) -> Self {
        Self::Vault {
            store_id: store_id.into(),
            ref_key: ref_key.into(),
            ref_version,
        }
    }
}
impl fmt::Debug for SecretRefV1Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Kubernetes { .. } => "KubernetesSecretRef(<redacted>)",
            Self::Vault { .. } => "VaultRef(<redacted>)",
        })
    }
}
/// Candidate request/limit pair; compilation rejects request greater than limit.
pub struct ResourceRequirementsV1Input {
    requests: ResourceListV1Input,
    limits: ResourceListV1Input,
}
impl ResourceRequirementsV1Input {
    pub fn new(requests: ResourceListV1Input, limits: ResourceListV1Input) -> Self {
        Self { requests, limits }
    }
}
/// Candidate canonical integer CPU and memory quantities (no float or exponent forms).
pub struct ResourceListV1Input {
    cpu: String,
    memory: String,
}
impl ResourceListV1Input {
    pub fn new(cpu: impl Into<String>, memory: impl Into<String>) -> Self {
        Self {
            cpu: cpu.into(),
            memory: memory.into(),
        }
    }
}
/// Candidate ordered lifecycle probe referencing a declared service port.
pub struct ProbeV1Input {
    kind: ProbeKind,
    port: u16,
}
impl ProbeV1Input {
    /// Constructs a probe whose route is derived exclusively from its closed lifecycle kind.
    pub const fn new(kind: ProbeKind, port: u16) -> Self {
        Self { kind, port }
    }
}
/// Candidate service and its canonically name-sorted ports.
pub struct DeploymentServiceV1Input {
    name: String,
    workload: String,
    ports: Vec<PortV1Input>,
}
impl DeploymentServiceV1Input {
    pub fn new(
        name: impl Into<String>,
        workload: impl Into<String>,
        ports: Vec<PortV1Input>,
    ) -> Self {
        Self {
            name: name.into(),
            workload: workload.into(),
            ports,
        }
    }
}
/// Candidate named listener port.
pub struct PortV1Input {
    name: String,
    port: u16,
    exposure: PortExposure,
}
impl PortV1Input {
    pub fn new(name: impl Into<String>, port: u16, exposure: PortExposure) -> Self {
        Self {
            name: name.into(),
            port,
            exposure,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Validated workload in canonical workload-ID order.
pub struct WorkloadPlan {
    name: WorkloadName,
    image: ImmutableImageIdentity,
    identity: WorkloadIdentity,
    secret_refs: Vec<SecretRef>,
    resources: ResourceRequirements,
    probes: Vec<ProbePlan>,
}
impl WorkloadPlan {
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
    pub fn image(&self) -> &str {
        self.image.as_str()
    }
    pub const fn identity(&self) -> &WorkloadIdentity {
        &self.identity
    }
    pub fn secret_refs(&self) -> &[SecretRef] {
        &self.secret_refs
    }
    pub const fn resources(&self) -> &ResourceRequirements {
        &self.resources
    }
    pub fn probes(&self) -> &[ProbePlan] {
        &self.probes
    }
}
impl TryFrom<DeploymentWorkloadV1Input> for WorkloadPlan {
    type Error = DeploymentPlanError;

    fn try_from(input: DeploymentWorkloadV1Input) -> Result<Self, Self::Error> {
        Ok(Self {
            name: WorkloadName::parse(input.name, "workloads.name")?,
            image: ImmutableImageIdentity::parse(input.image)?,
            identity: input.identity.try_into()?,
            secret_refs: input
                .secret_refs
                .into_iter()
                .map(SecretRef::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            resources: input.resources.into(),
            probes: input.probes.into_iter().map(Into::into).collect(),
        })
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Validated non-secret workload identity.
pub struct WorkloadIdentity {
    name: WorkloadName,
    service_account: ServiceAccountName,
}
impl WorkloadIdentity {
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
    pub fn service_account(&self) -> &str {
        self.service_account.as_str()
    }
}
impl TryFrom<DeploymentIdentityV1Input> for WorkloadIdentity {
    type Error = DeploymentPlanError;

    fn try_from(value: DeploymentIdentityV1Input) -> Result<Self, Self::Error> {
        Ok(Self {
            name: WorkloadName::parse(value.name, "workloads.identity.name")?,
            service_account: ServiceAccountName::parse(
                value.service_account,
                "workloads.identity.serviceAccount",
            )?,
        })
    }
}

#[derive(Serialize)]
#[serde(tag = "kind")]
/// Validated Kubernetes or Vault reference with redacted `Debug`; never a secret value.
pub enum SecretRef {
    #[serde(rename = "kubernetesSecret")]
    Kubernetes {
        name: KubernetesSecretName,
        key: String,
    },
    #[serde(rename = "vaultRef")]
    Vault {
        #[serde(rename = "storeId")]
        store_id: String,
        #[serde(rename = "refKey")]
        ref_key: String,
        #[serde(rename = "refVersion", skip_serializing_if = "Option::is_none")]
        ref_version: Option<String>,
    },
}
impl SecretRef {
    pub const fn kind(&self) -> SecretRefKind {
        match self {
            Self::Kubernetes { .. } => SecretRefKind::KubernetesSecret,
            Self::Vault { .. } => SecretRefKind::VaultRef,
        }
    }
}
impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Kubernetes { .. } => "KubernetesSecretRef(<redacted>)",
            Self::Vault { .. } => "VaultRef(<redacted>)",
        })
    }
}
impl TryFrom<SecretRefV1Input> for SecretRef {
    type Error = DeploymentPlanError;

    fn try_from(value: SecretRefV1Input) -> Result<Self, Self::Error> {
        Ok(match value {
            SecretRefV1Input::Kubernetes { name, key } => Self::Kubernetes {
                name: KubernetesSecretName::parse(name)?,
                key,
            },
            SecretRefV1Input::Vault {
                store_id,
                ref_key,
                ref_version,
            } => Self::Vault {
                store_id,
                ref_key,
                ref_version,
            },
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Closed discriminator for validated secret-reference variants.
pub enum SecretRefKind {
    KubernetesSecret,
    VaultRef,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
/// Validated canonical CPU and memory quantity strings.
pub struct ResourceList {
    cpu: String,
    memory: String,
}
impl ResourceList {
    pub fn cpu(&self) -> &str {
        &self.cpu
    }
    pub fn memory(&self) -> &str {
        &self.memory
    }
}
impl From<ResourceListV1Input> for ResourceList {
    fn from(value: ResourceListV1Input) -> Self {
        Self {
            cpu: value.cpu,
            memory: value.memory,
        }
    }
}
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
/// Validated resource requests and limits.
pub struct ResourceRequirements {
    requests: ResourceList,
    limits: ResourceList,
}
impl ResourceRequirements {
    pub const fn requests(&self) -> &ResourceList {
        &self.requests
    }
    pub const fn limits(&self) -> &ResourceList {
        &self.limits
    }
}
impl From<ResourceRequirementsV1Input> for ResourceRequirements {
    fn from(value: ResourceRequirementsV1Input) -> Self {
        Self {
            requests: value.requests.into(),
            limits: value.limits.into(),
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
/// Validated probe; probe array order retains lifecycle declaration order.
pub struct ProbePlan {
    kind: ProbeKind,
    path: String,
    port: u16,
}
impl ProbePlan {
    pub const fn kind(&self) -> ProbeKind {
        self.kind
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub const fn port(&self) -> u16 {
        self.port
    }
}
impl From<ProbeV1Input> for ProbePlan {
    fn from(value: ProbeV1Input) -> Self {
        Self {
            kind: value.kind,
            path: value.kind.canonical_path().to_owned(),
            port: value.port,
        }
    }
}
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
/// Closed probe lifecycle kind.
pub enum ProbeKind {
    Startup,
    Readiness,
    Liveness,
}
impl ProbeKind {
    /// Canonical runtimeexec health route; deployment authoring cannot override it.
    pub const fn canonical_path(self) -> &'static str {
        match self {
            Self::Readiness => "/health/v1/readyz",
            Self::Startup | Self::Liveness => "/health/v1/healthz",
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
/// Validated named service port.
pub struct PortPlan {
    name: PortName,
    port: u16,
    exposure: PortExposure,
}
impl PortPlan {
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
    pub const fn port(&self) -> u16 {
        self.port
    }
    pub const fn exposure(&self) -> PortExposure {
        self.exposure
    }
}
impl TryFrom<PortV1Input> for PortPlan {
    type Error = DeploymentPlanError;

    fn try_from(value: PortV1Input) -> Result<Self, Self::Error> {
        Ok(Self {
            name: PortName::parse(value.name, "services.ports.name")?,
            port: value.port,
            exposure: value.exposure,
        })
    }
}
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
/// Closed deployment reachability for a listener port.
pub enum PortExposure {
    ServiceExposed,
    WorkloadOnly,
}
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
/// Validated service in canonical service-ID order.
pub struct ServicePlan {
    name: ServiceName,
    workload: WorkloadName,
    ports: Vec<PortPlan>,
}
impl ServicePlan {
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
    pub fn workload(&self) -> &str {
        self.workload.as_str()
    }
    pub fn ports(&self) -> &[PortPlan] {
        &self.ports
    }
}
impl TryFrom<DeploymentServiceV1Input> for ServicePlan {
    type Error = DeploymentPlanError;

    fn try_from(value: DeploymentServiceV1Input) -> Result<Self, Self::Error> {
        Ok(Self {
            name: ServiceName::parse(value.name, "services.name")?,
            workload: WorkloadName::parse(value.workload, "services.workload")?,
            ports: value
                .ports
                .into_iter()
                .map(PortPlan::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
/// Unforgeable deployment-stage RFC8785/SHA-256 identity.
pub struct DeploymentFingerprint(#[schemars(regex(pattern = "^sha256:[0-9a-f]{64}$"))] String);
impl DeploymentFingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
/// Sanitized DeploymentPlan failure; it never retains secret-reference coordinates or values.
pub struct DeploymentPlanError(DeploymentPlanErrorKind);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Closed high-level failure stage for safe diagnostics and policy routing.
pub enum DeploymentPlanErrorStage {
    WireDecode,
    SchemaVersion,
    UpstreamIdentity,
    PlanFacts,
    CanonicalSerialization,
    Fingerprint,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Closed serde JSON category without source text.
pub enum DeploymentPlanJsonCategory {
    Syntax,
    Data,
    Eof,
    Io,
}
impl fmt::Display for DeploymentPlanJsonCategory {
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
/// Sanitized path composed only from known schema fields and numeric array indexes.
pub struct DeploymentPlanJsonPath(String);
impl DeploymentPlanJsonPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for DeploymentPlanJsonPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, thiserror::Error)]
enum DeploymentPlanErrorKind {
    #[error("invalid strict DeploymentPlan JSON at `{path}` ({category})")]
    StrictJson {
        path: DeploymentPlanJsonPath,
        category: DeploymentPlanJsonCategory,
    },
    #[error("unsupported DeploymentPlan schemaVersion")]
    UnsupportedVersion,
    #[error("DeploymentPlan {0} is not a lowercase sha256 digest")]
    InvalidDigest(&'static str),
    #[error("DeploymentPlan identity does not match the supplied RuntimePlan")]
    UpstreamIdentityMismatch,
    #[error("DeploymentPlan field `{0}` must not be empty")]
    Empty(&'static str),
    #[error("DeploymentPlan field `{0}` contains an invalid closed value")]
    Invalid(&'static str),
    #[error("DeploymentPlan field `{0}` contains duplicate keyed facts")]
    Duplicate(&'static str),
    #[error("DeploymentPlan field `{0}` is not in canonical order")]
    NonCanonicalOrder(&'static str),
    #[error("DeploymentPlan field `{0}` does not exactly cover RuntimePlan facts")]
    RuntimeClosure(&'static str),
    #[error("DeploymentPlan field `{0}` contains a dangling reference")]
    DanglingReference(&'static str),
    #[error("DeploymentPlan resource request exceeds its limit")]
    RequestExceedsLimit,
    #[error("DeploymentPlan RFC8785 canonical serialization failed: {0}")]
    CanonicalJson(#[source] serde_json::Error),
    #[error("DeploymentPlan fingerprint mismatch")]
    FingerprintMismatch,
}
impl DeploymentPlanError {
    fn new(kind: DeploymentPlanErrorKind) -> Self {
        Self(kind)
    }
    pub const fn stage(&self) -> DeploymentPlanErrorStage {
        match self.0 {
            DeploymentPlanErrorKind::StrictJson { .. } => DeploymentPlanErrorStage::WireDecode,
            DeploymentPlanErrorKind::UnsupportedVersion => DeploymentPlanErrorStage::SchemaVersion,
            DeploymentPlanErrorKind::UpstreamIdentityMismatch => {
                DeploymentPlanErrorStage::UpstreamIdentity
            }
            DeploymentPlanErrorKind::CanonicalJson(_) => {
                DeploymentPlanErrorStage::CanonicalSerialization
            }
            DeploymentPlanErrorKind::FingerprintMismatch => DeploymentPlanErrorStage::Fingerprint,
            _ => DeploymentPlanErrorStage::PlanFacts,
        }
    }
    pub const fn json_category(&self) -> Option<DeploymentPlanJsonCategory> {
        if let DeploymentPlanErrorKind::StrictJson { category, .. } = self.0 {
            Some(category)
        } else {
            None
        }
    }
    pub fn json_path(&self) -> Option<&DeploymentPlanJsonPath> {
        if let DeploymentPlanErrorKind::StrictJson { path, .. } = &self.0 {
            Some(path)
        } else {
            None
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireDeploymentPlan {
    schema_version: u32,
    assembly_fingerprint: String,
    runtime_plan_fingerprint: String,
    deployment_fingerprint: String,
    workloads: Vec<WireWorkload>,
    services: Vec<WireService>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireWorkload {
    name: String,
    image: String,
    identity: WireIdentity,
    secret_refs: Vec<WireSecretRef>,
    resources: WireResources,
    probes: Vec<WireProbe>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireIdentity {
    name: String,
    service_account: String,
}
#[derive(Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum WireSecretRef {
    #[serde(rename = "kubernetesSecret")]
    Kubernetes { name: String, key: String },
    #[serde(rename = "vaultRef")]
    Vault {
        #[serde(rename = "storeId")]
        store_id: String,
        #[serde(rename = "refKey")]
        ref_key: String,
        #[serde(rename = "refVersion")]
        ref_version: Option<String>,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResourceList {
    cpu: String,
    memory: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResources {
    requests: WireResourceList,
    limits: WireResourceList,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProbe {
    kind: ProbeKind,
    path: String,
    port: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePort {
    name: String,
    port: u16,
    exposure: PortExposure,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireService {
    name: String,
    workload: String,
    ports: Vec<WirePort>,
}
impl TryFrom<WireWorkload> for DeploymentWorkloadV1Input {
    type Error = DeploymentPlanError;

    fn try_from(v: WireWorkload) -> Result<Self, Self::Error> {
        let probes = v
            .probes
            .into_iter()
            .map(|probe| {
                if probe.path != probe.kind.canonical_path() {
                    return Err(DeploymentPlanError::new(DeploymentPlanErrorKind::Invalid(
                        "workloads.probes.path",
                    )));
                }
                Ok(ProbeV1Input::new(probe.kind, probe.port))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let secret_refs = v
            .secret_refs
            .into_iter()
            .map(|secret| match secret {
                WireSecretRef::Kubernetes { name, key } => SecretRefV1Input::kubernetes(name, key),
                WireSecretRef::Vault {
                    store_id,
                    ref_key,
                    ref_version,
                } => SecretRefV1Input::vault(store_id, ref_key, ref_version),
            })
            .collect();
        Ok(Self::new(
            v.name,
            v.image,
            DeploymentIdentityV1Input::new(v.identity.name, v.identity.service_account),
            secret_refs,
            ResourceRequirementsV1Input::new(
                ResourceListV1Input::new(v.resources.requests.cpu, v.resources.requests.memory),
                ResourceListV1Input::new(v.resources.limits.cpu, v.resources.limits.memory),
            ),
            probes,
        ))
    }
}
impl TryFrom<WireService> for DeploymentServiceV1Input {
    type Error = DeploymentPlanError;

    fn try_from(v: WireService) -> Result<Self, Self::Error> {
        Ok(Self::new(
            v.name,
            v.workload,
            v.ports
                .into_iter()
                .map(|port| PortV1Input::new(port.name, port.port, port.exposure))
                .collect(),
        ))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Unsigned<'a> {
    schema_version: u32,
    assembly_fingerprint: &'a AssemblyFingerprint,
    runtime_plan_fingerprint: &'a RuntimePlanFingerprint,
    workloads: &'a [WorkloadPlan],
    services: &'a [ServicePlan],
}

fn validate_facts(
    runtime: &RuntimePlan,
    workloads: &[WorkloadPlan],
    services: &[ServicePlan],
) -> Result<(), DeploymentPlanError> {
    if workloads.is_empty() {
        return Err(DeploymentPlanError::new(DeploymentPlanErrorKind::Empty(
            "workloads",
        )));
    }
    validate_sorted_unique(workloads, |w| w.name.clone(), "workloads")?;
    validate_sorted_unique(services, |s| s.name.clone(), "services")?;
    let workload_names = workloads
        .iter()
        .map(|w| w.name.as_str())
        .collect::<BTreeSet<_>>();
    let runtime_workloads = runtime
        .placement_plans()
        .iter()
        .map(|p| p.workload())
        .collect::<BTreeSet<_>>();
    if workload_names != runtime_workloads {
        return Err(DeploymentPlanError::new(
            DeploymentPlanErrorKind::RuntimeClosure("workloads"),
        ));
    }
    for workload in workloads {
        validate_workload(workload)?;
    }
    for service in services {
        if !workload_names.contains(service.workload.as_str()) {
            return Err(DeploymentPlanError::new(
                DeploymentPlanErrorKind::DanglingReference("services.workload"),
            ));
        }
        if service.ports.is_empty() {
            return Err(DeploymentPlanError::new(DeploymentPlanErrorKind::Empty(
                "services.ports",
            )));
        }
        validate_sorted_unique(&service.ports, |p| p.name.clone(), "services.ports")?;
        for port in &service.ports {
            if port.port == 0 {
                return Err(DeploymentPlanError::new(DeploymentPlanErrorKind::Invalid(
                    "services.ports",
                )));
            }
        }
    }
    validate_runtime_ports(runtime, workloads, services)?;
    Ok(())
}

fn validate_runtime_ports(
    runtime: &RuntimePlan,
    workloads: &[WorkloadPlan],
    services: &[ServicePlan],
) -> Result<(), DeploymentPlanError> {
    let expected: BTreeMap<(&str, PortExposure), usize> = runtime
        .listener_plans()
        .iter()
        .map(|listener| match listener.kind() {
            AssemblyListenerKind::Primary => ("http", PortExposure::ServiceExposed, 1),
            AssemblyListenerKind::Admin => ("admin", PortExposure::ServiceExposed, 1),
            AssemblyListenerKind::Health => {
                ("health", PortExposure::ServiceExposed, workloads.len())
            }
            AssemblyListenerKind::Internal => ("internal", PortExposure::WorkloadOnly, 1),
        })
        .fold(BTreeMap::new(), |mut counts, (name, exposure, count)| {
            *counts.entry((name, exposure)).or_default() += count;
            counts
        });
    let actual: BTreeMap<(&str, PortExposure), usize> = services
        .iter()
        .flat_map(|service| {
            service
                .ports
                .iter()
                .map(|port| (port.name.as_str(), port.exposure))
        })
        .fold(BTreeMap::new(), |mut counts, key| {
            *counts.entry(key).or_default() += 1;
            counts
        });
    if actual != expected {
        return Err(DeploymentPlanError::new(
            DeploymentPlanErrorKind::RuntimeClosure("services.ports"),
        ));
    }
    for workload in workloads {
        let health_ports = services
            .iter()
            .filter(|service| service.workload == workload.name)
            .flat_map(|service| service.ports.iter())
            .filter(|port| {
                port.name.as_str() == "health" && port.exposure == PortExposure::ServiceExposed
            })
            .map(|port| port.port)
            .collect::<Vec<_>>();
        if health_ports.len() != 1
            || workload
                .probes
                .iter()
                .any(|probe| probe.port != health_ports[0])
        {
            return Err(DeploymentPlanError::new(
                DeploymentPlanErrorKind::DanglingReference("workloads.probes.port"),
            ));
        }
    }
    Ok(())
}

fn validate_workload(workload: &WorkloadPlan) -> Result<(), DeploymentPlanError> {
    if workload.identity.name != workload.name {
        return Err(DeploymentPlanError::new(
            DeploymentPlanErrorKind::RuntimeClosure("workloads.identity.name"),
        ));
    }
    validate_image(workload.image.as_str())?;
    validate_secret_refs(&workload.secret_refs)?;
    let request_cpu = parse_cpu(&workload.resources.requests.cpu)?;
    let limit_cpu = parse_cpu(&workload.resources.limits.cpu)?;
    let request_memory = parse_memory(&workload.resources.requests.memory)?;
    let limit_memory = parse_memory(&workload.resources.limits.memory)?;
    if request_cpu > limit_cpu || request_memory > limit_memory {
        return Err(DeploymentPlanError::new(
            DeploymentPlanErrorKind::RequestExceedsLimit,
        ));
    }
    if workload.probes.is_empty() {
        return Err(DeploymentPlanError::new(DeploymentPlanErrorKind::Empty(
            "workloads.probes",
        )));
    }
    let mut kinds = BTreeSet::new();
    for probe in &workload.probes {
        if !kinds.insert(probe.kind) {
            return Err(DeploymentPlanError::new(
                DeploymentPlanErrorKind::Duplicate("workloads.probes.kind"),
            ));
        }
        if probe.port == 0 || probe.path != probe.kind.canonical_path() {
            return Err(DeploymentPlanError::new(DeploymentPlanErrorKind::Invalid(
                "workloads.probes",
            )));
        }
    }
    Ok(())
}

fn validate_image(value: &str) -> Result<(), DeploymentPlanError> {
    let Some((repository, digest)) = value.rsplit_once("@sha256:") else {
        return Err(DeploymentPlanError::new(DeploymentPlanErrorKind::Invalid(
            "workloads.image",
        )));
    };
    if !valid_image_repository(repository)
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(DeploymentPlanError::new(DeploymentPlanErrorKind::Invalid(
            "workloads.image",
        )));
    }
    Ok(())
}

fn valid_image_repository(repository: &str) -> bool {
    if repository.is_empty() || repository.len() > 255 || !repository.is_ascii() {
        return false;
    }
    let components = repository.split('/').collect::<Vec<_>>();
    if components.iter().any(|component| component.is_empty()) {
        return false;
    }
    let path_start = usize::from(
        components.len() > 1
            && (components[0].contains('.')
                || components[0].contains(':')
                || components[0] == "localhost"),
    );
    if path_start == 1 && !valid_registry_domain(components[0]) {
        return false;
    }
    components[path_start..].iter().all(|component| {
        let bytes = component.as_bytes();
        bytes
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && bytes
                .last()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && bytes.iter().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            })
            && !bytes.windows(2).any(|pair| {
                matches!(pair[0], b'.' | b'_' | b'-') && matches!(pair[1], b'.' | b'_' | b'-')
            })
    })
}

fn valid_registry_domain(value: &str) -> bool {
    let (host, port) = value
        .rsplit_once(':')
        .map_or((value, None), |(host, port)| (host, Some(port)));
    !host.is_empty()
        && host.split('.').all(valid_dns_label)
        && port
            .is_none_or(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
}

fn validate_secret_refs(values: &[SecretRef]) -> Result<(), DeploymentPlanError> {
    let keys = values.iter().map(secret_key).collect::<Vec<_>>();
    validate_sorted_unique(&keys, |key| *key, "workloads.secretRefs")?;
    for value in values {
        match value {
            SecretRef::Kubernetes { name, key } => {
                if !valid_dns_name(name.as_str())
                    || key.is_empty()
                    || key.len() > 253
                    || !key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                {
                    return Err(DeploymentPlanError::new(DeploymentPlanErrorKind::Invalid(
                        "workloads.secretRefs",
                    )));
                }
            }
            SecretRef::Vault {
                store_id,
                ref_key,
                ref_version,
            } => {
                if store_id.is_empty()
                    || store_id.len() > 256
                    || !store_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                    || !valid_vault_path(ref_key)
                    || ref_version.as_ref().is_some_and(|v| {
                        v.is_empty() || v.len() > 256 || v.bytes().any(invalid_secret_byte)
                    })
                {
                    return Err(DeploymentPlanError::new(DeploymentPlanErrorKind::Invalid(
                        "workloads.secretRefs",
                    )));
                }
            }
        }
    }
    Ok(())
}
fn secret_key(value: &SecretRef) -> (u8, &str, &str, &str) {
    match value {
        SecretRef::Kubernetes { name, key } => (0, name.as_str(), key, ""),
        SecretRef::Vault {
            store_id,
            ref_key,
            ref_version,
        } => (1, store_id, ref_key, ref_version.as_deref().unwrap_or("")),
    }
}
fn valid_vault_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.bytes().any(invalid_secret_byte)
        })
}
fn invalid_secret_byte(byte: u8) -> bool {
    byte.is_ascii_whitespace() || byte.is_ascii_control() || byte == b'/'
}

fn parse_cpu(value: &str) -> Result<u128, DeploymentPlanError> {
    let (digits, factor) = value
        .strip_suffix('m')
        .map_or((value, 1000_u128), |v| (v, 1));
    parse_quantity(digits, factor, "workloads.resources.cpu")
}
fn parse_memory(value: &str) -> Result<u128, DeploymentPlanError> {
    let suffixes = [
        ("Ki", 1024_u128),
        ("Mi", 1024_u128.pow(2)),
        ("Gi", 1024_u128.pow(3)),
        ("Ti", 1024_u128.pow(4)),
        ("K", 1000_u128),
        ("M", 1000_u128.pow(2)),
        ("G", 1000_u128.pow(3)),
        ("T", 1000_u128.pow(4)),
    ];
    for (suffix, factor) in suffixes {
        if let Some(digits) = value.strip_suffix(suffix) {
            return parse_quantity(digits, factor, "workloads.resources.memory");
        }
    }
    parse_quantity(value, 1, "workloads.resources.memory")
}
fn parse_quantity(
    digits: &str,
    factor: u128,
    field: &'static str,
) -> Result<u128, DeploymentPlanError> {
    if digits.is_empty()
        || digits.len() > 20
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(DeploymentPlanError::new(DeploymentPlanErrorKind::Invalid(
            field,
        )));
    }
    digits
        .parse::<u128>()
        .ok()
        .and_then(|v| v.checked_mul(factor))
        .ok_or_else(|| DeploymentPlanError::new(DeploymentPlanErrorKind::Invalid(field)))
}
fn valid_dns_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.split('.').all(valid_dns_label)
}
fn valid_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && value
            .as_bytes()
            .last()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}
fn valid_service_port_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value.bytes().any(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && !value.as_bytes().windows(2).any(|pair| pair == b"--")
}
fn validate_sorted_unique<T, K: Ord>(
    values: &[T],
    key: impl Fn(&T) -> K,
    field: &'static str,
) -> Result<(), DeploymentPlanError> {
    for pair in values.windows(2) {
        match key(&pair[0]).cmp(&key(&pair[1])) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                return Err(DeploymentPlanError::new(
                    DeploymentPlanErrorKind::Duplicate(field),
                ));
            }
            std::cmp::Ordering::Greater => {
                return Err(DeploymentPlanError::new(
                    DeploymentPlanErrorKind::NonCanonicalOrder(field),
                ));
            }
        }
    }
    Ok(())
}

fn fingerprint_for(
    assembly: &AssemblyFingerprint,
    runtime: &RuntimePlanFingerprint,
    workloads: &[WorkloadPlan],
    services: &[ServicePlan],
) -> Result<DeploymentFingerprint, DeploymentPlanError> {
    let canonical = serde_json_canonicalizer::to_vec(&Unsigned {
        schema_version: SCHEMA_VERSION,
        assembly_fingerprint: assembly,
        runtime_plan_fingerprint: runtime,
        workloads,
        services,
    })
    .map_err(|e| DeploymentPlanError::new(DeploymentPlanErrorKind::CanonicalJson(e)))?;
    let mut hasher = Sha256::new();
    hasher.update(TAG.as_bytes());
    hasher.update([0]);
    hasher.update(canonical);
    Ok(DeploymentFingerprint(format!(
        "{SHA256_PREFIX}{:x}",
        hasher.finalize()
    )))
}
fn validate_sha256(field: &'static str, value: &str) -> Result<(), DeploymentPlanError> {
    let valid = value.strip_prefix(SHA256_PREFIX).is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    });
    if valid {
        Ok(())
    } else {
        Err(DeploymentPlanError::new(
            DeploymentPlanErrorKind::InvalidDigest(field),
        ))
    }
}

fn strict_json_error(source: serde_path_to_error::Error<serde_json::Error>) -> DeploymentPlanError {
    DeploymentPlanError::new(DeploymentPlanErrorKind::StrictJson {
        path: safe_json_path(source.path()),
        category: json_category(source.inner()),
    })
}
fn strict_json_root_error(source: &serde_json::Error) -> DeploymentPlanError {
    DeploymentPlanError::new(DeploymentPlanErrorKind::StrictJson {
        path: DeploymentPlanJsonPath("$".to_owned()),
        category: json_category(source),
    })
}
fn json_category(source: &serde_json::Error) -> DeploymentPlanJsonCategory {
    match source.classify() {
        serde_json::error::Category::Syntax => DeploymentPlanJsonCategory::Syntax,
        serde_json::error::Category::Data => DeploymentPlanJsonCategory::Data,
        serde_json::error::Category::Eof => DeploymentPlanJsonCategory::Eof,
        serde_json::error::Category::Io => DeploymentPlanJsonCategory::Io,
    }
}
fn safe_json_path(path: &serde_path_to_error::Path) -> DeploymentPlanJsonPath {
    const FIELDS: &[&str] = &[
        "schemaVersion",
        "assemblyFingerprint",
        "runtimePlanFingerprint",
        "deploymentFingerprint",
        "workloads",
        "services",
        "name",
        "image",
        "identity",
        "serviceAccount",
        "secretRefs",
        "kind",
        "key",
        "storeId",
        "refKey",
        "refVersion",
        "resources",
        "requests",
        "limits",
        "cpu",
        "memory",
        "probes",
        "path",
        "port",
        "workload",
        "ports",
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
            _ => break,
        }
    }
    DeploymentPlanJsonPath(rendered)
}

#[cfg(test)]
mod deployment_plan_name_grammar_tests {
    use super::*;

    #[test]
    fn deployment_plan_field_name_newtypes_have_distinct_kubernetes_boundaries() {
        assert!(WorkloadName::parse("a".repeat(63), "workloads.name").is_ok());
        assert!(WorkloadName::parse("a".repeat(64), "workloads.name").is_err());
        assert!(WorkloadName::parse("runtime.team".to_owned(), "workloads.name").is_err());

        assert!(ServiceName::parse("a".repeat(63), "services.name").is_ok());
        assert!(ServiceName::parse("a".repeat(64), "services.name").is_err());

        assert!(ServiceAccountName::parse("runtime.team".to_owned(), "serviceAccount").is_ok());
        assert!(
            ServiceAccountName::parse(format!("{}.team", "a".repeat(64)), "serviceAccount")
                .is_err()
        );
        assert!(ServiceAccountName::parse("a".repeat(254), "serviceAccount").is_err());

        for valid in ["http", "h2", "http-main"] {
            assert!(
                PortName::parse(valid.to_owned(), "ports.name").is_ok(),
                "{valid}"
            );
        }
        for invalid in [
            "",
            "abcdefghijklmnop",
            "123",
            "-http",
            "http-",
            "http--main",
            "HTTP",
        ] {
            assert!(
                PortName::parse(invalid.to_owned(), "ports.name").is_err(),
                "{invalid}"
            );
        }
    }
}
