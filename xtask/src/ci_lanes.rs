//! CI gate taxonomy and ordered registry.
//!
//! INVARIANT: CI-LANE-REGISTRY-01 { level = "Hard", exec = "native-compile", source = "code", native = "gate_catalog generates GateId ALL/COUNT, executor dispatch, carrier binding, and registry identity proof" } ——
//! every closed [`GateId`] has exactly one complete [`GateSpec`]. The exhaustive lookup makes any
//! new variant a compile error first; the const proof then rejects missing, duplicate, mismatched,
//! or out-of-order entries.
//! INVARIANT: CI-LANE-PLAN-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "ci_lane_registry_rejects_duplicate_and_missing_red", anti_vacuity = "ci_lane_registry_accepts_canonical_green" } —— lane and
//! compatibility plans are derived from this registry and guarded by non-vacuous red/green tests.
//! INVARIANT: CI-SLO-JOB-TYPE-01 { level = "Hard", exec = "native-compile", source = "code", native = "CiJobKey is a closed enum whose ALL catalog and exhaustive mappings admit exactly the reusable workflow job matrix" }.
//! INVARIANT: CI-IMPACT-CATALOG-01 { level = "Hard", exec = "native-compile", source = "code", native = "ci_job_catalog generates CiJobKey, ALL, workflow identity, artifact identity, and planner matrix fields from one descriptor" }.
//! INVARIANT: CI-REQUIRED-EVIDENCE-OWNER-01 { level = "Hard", exec = "native-compile", source = "code", native = "the closed CI job descriptor catalog makes every job choose a RequiredEvidenceKind and const identity proofs admit exactly one LocalTx owner plus exactly one LocalOnly owner" }.

use anyhow::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

use crate::execution_profiles::ExecutionProfile;
use crate::integration_shards::IntegrationShard;
use crate::nextest::{CoreTestScope, HashPartition};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequiredEvidenceKind {
    LocalTx,
    LocalOnly,
}

impl RequiredEvidenceKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::LocalTx => "localtx",
            Self::LocalOnly => "localonly",
        }
    }

    /// Canonical upload location consumed by `ci-gate`. Workflow staging is projected from this
    /// closed kind through the typed planner matrix; it must not rebuild the owner catalog.
    pub(crate) const fn staged_artifact_path(self) -> &'static str {
        match self {
            Self::LocalTx => "target/job-evidence/integration/localtx-required.json",
            Self::LocalOnly => "target/job-evidence/local-only/localonly-execution.json",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CiJobDescriptor {
    key: CiJobKey,
    name: &'static str,
    lane: CiLane,
    shard: Option<&'static str>,
    partition: Option<&'static str>,
    required_evidence: Option<RequiredEvidenceKind>,
}

macro_rules! ci_job_catalog {
    ($( $variant:ident => ($name:literal, $lane:ident, $shard:expr, $partition:expr, $required_evidence:expr) ),+ $(,)?) => {
        const CI_JOB_COUNT: usize = [$(stringify!($variant)),+].len();

        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub(crate) enum CiJobKey {
            $( $variant, )+
        }

        const CI_JOB_DESCRIPTORS: [CiJobDescriptor; CI_JOB_COUNT] = [
            $(CiJobDescriptor {
                key: CiJobKey::$variant,
                name: $name,
                lane: CiLane::$lane,
                shard: $shard,
                partition: $partition,
                required_evidence: $required_evidence,
            },)+
        ];

        impl CiJobKey {
            pub(crate) const ALL: [Self; CI_JOB_COUNT] = [$(Self::$variant),+];

            const fn descriptor(self) -> &'static CiJobDescriptor {
                match self {
                    $(Self::$variant => &CI_JOB_DESCRIPTORS[Self::$variant as usize],)+
                }
            }

            pub(crate) const fn as_str(self) -> &'static str {
                self.descriptor().name
            }

            pub(crate) const fn required_evidence(self) -> Option<RequiredEvidenceKind> {
                self.descriptor().required_evidence
            }

            pub(crate) const fn required_evidence_staged_artifact_path(self) -> Option<&'static str> {
                match self.required_evidence() {
                    Some(kind) => Some(kind.staged_artifact_path()),
                    None => None,
                }
            }
        }
    };
}

ci_job_catalog! {
    CiMeta => ("ci-meta", Meta, None, None, None),
    CiCorePrerequisites => ("ci-core-prerequisites", CorePrerequisites, None, None, None),
    CiCoreTests1Of2 => ("ci-core-tests/1-of-2", CoreTests, None, Some("1/2"), None),
    CiCoreTests2Of2 => ("ci-core-tests/2-of-2", CoreTests, None, Some("2/2"), None),
    CiSecurity => ("ci-security", Security, None, None, None),
    CiCoverage => ("ci-coverage", Coverage, None, None, None),
    CiLocalOnly => (
        "ci-local-only",
        LocalOnly,
        None,
        None,
        Some(RequiredEvidenceKind::LocalOnly)
    ),
    IntegrationPostgresDomain => (
        "integration/postgres-domain",
        Integration,
        Some("postgres-domain"),
        None,
        Some(RequiredEvidenceKind::LocalTx)
    ),
    IntegrationEventTransport1Of2 => (
        "integration/event-transport/1-of-2",
        Integration,
        Some("event-transport"),
        Some("1/2"),
        None
    ),
    IntegrationEventTransport2Of2 => (
        "integration/event-transport/2-of-2",
        Integration,
        Some("event-transport"),
        Some("2/2"),
        None
    ),
    IntegrationRuntimeHttpAuth1Of2 => (
        "integration/runtime-http-auth/1-of-2",
        Integration,
        Some("runtime-http-auth"),
        Some("1/2"),
        None
    ),
    IntegrationRuntimeHttpAuth2Of2 => (
        "integration/runtime-http-auth/2-of-2",
        Integration,
        Some("runtime-http-auth"),
        Some("2/2"),
        None
    ),
    IntegrationConsistencyFault => (
        "integration/consistency-fault",
        Integration,
        Some("consistency-fault"),
        None,
        None
    ),
    IntegrationCdcProjectionSaga => (
        "integration/cdc-projection-saga",
        Integration,
        Some("cdc-projection-saga"),
        None,
        None
    ),
    IntegrationObjectStorage => (
        "integration/object-storage",
        Integration,
        Some("object-storage"),
        None,
        None
    ),
    IntegrationProductionRuntime => (
        "integration/production-runtime",
        Integration,
        Some("production-runtime"),
        None,
        None
    ),
    Audit => ("audit", Nightly, None, None, None),
}

const _: () = {
    let mut index = 0;
    let mut localtx_owners = 0;
    let mut localonly_owners = 0;
    while index < CI_JOB_DESCRIPTORS.len() {
        if matches!(
            CI_JOB_DESCRIPTORS[index].required_evidence,
            Some(RequiredEvidenceKind::LocalTx)
        ) {
            localtx_owners += 1;
        }
        if matches!(
            CI_JOB_DESCRIPTORS[index].required_evidence,
            Some(RequiredEvidenceKind::LocalOnly)
        ) {
            localonly_owners += 1;
        }
        index += 1;
    }
    assert!(localtx_owners == 1);
    assert!(localonly_owners == 1);
    assert!(matches!(
        CiJobKey::IntegrationPostgresDomain.required_evidence(),
        Some(RequiredEvidenceKind::LocalTx)
    ));
    assert!(matches!(
        CiJobKey::CiLocalOnly.required_evidence(),
        Some(RequiredEvidenceKind::LocalOnly)
    ));
};

impl CiJobKey {
    pub(crate) const COUNT: usize = Self::ALL.len();

    pub(crate) fn from_workflow_parts(
        lane: &str,
        shard: Option<IntegrationShard>,
        partition: Option<HashPartition>,
    ) -> Result<Self> {
        let shard = shard.map(IntegrationShard::as_str);
        let partition = partition.map(|value| value.to_string());
        CI_JOB_DESCRIPTORS
            .iter()
            .find(|descriptor| {
                descriptor.lane.workflow_name() == lane
                    && descriptor.shard == shard
                    && descriptor.partition == partition.as_deref()
            })
            .map(|descriptor| descriptor.key)
            .ok_or_else(|| {
                anyhow::anyhow!("invalid closed CI job lane/shard/partition combination")
            })
    }

    pub(crate) fn artifact_parts(self) -> (&'static str, &'static str, &'static str) {
        let descriptor = self.descriptor();
        let shard = descriptor.shard.unwrap_or("workspace");
        let partition = match descriptor.partition {
            Some("1/2") => "1-of-2",
            Some("2/2") => "2-of-2",
            Some(_) => unreachable!(),
            None => "unpartitioned",
        };
        (descriptor.lane.workflow_name(), shard, partition)
    }

    pub(crate) fn expected_artifact(self, run_id: &str, run_attempt: &str) -> String {
        let prefix = self.artifact_prefix();
        format!("{prefix}{run_id}-{run_attempt}")
    }

    pub(crate) fn artifact_prefix(self) -> String {
        let (lane, shard, partition) = self.artifact_parts();
        format!("ci-evidence-{lane}-{shard}-{partition}-")
    }

    pub(crate) const fn lane_kind(self) -> CiLane {
        self.descriptor().lane
    }

    pub(crate) const fn shard(self) -> Option<&'static str> {
        self.descriptor().shard
    }

    /// Closed projection from every integration shard to its non-empty executor set. Adding a
    /// shard without deciding its workflow partitioning is therefore a compile error.
    pub(crate) const fn for_shard(shard: IntegrationShard) -> &'static [Self] {
        match shard {
            IntegrationShard::PostgresDomain => &[Self::IntegrationPostgresDomain],
            IntegrationShard::EventTransport => &[
                Self::IntegrationEventTransport1Of2,
                Self::IntegrationEventTransport2Of2,
            ],
            IntegrationShard::RuntimeHttpAuth => &[
                Self::IntegrationRuntimeHttpAuth1Of2,
                Self::IntegrationRuntimeHttpAuth2Of2,
            ],
            IntegrationShard::ConsistencyFault => &[Self::IntegrationConsistencyFault],
            IntegrationShard::CdcProjectionSaga => &[Self::IntegrationCdcProjectionSaga],
            IntegrationShard::ObjectStorage => &[Self::IntegrationObjectStorage],
            IntegrationShard::ProductionRuntime => &[Self::IntegrationProductionRuntime],
        }
    }

    pub(crate) const fn partition(self) -> Option<&'static str> {
        self.descriptor().partition
    }

    pub(crate) fn partition_label(self) -> &'static str {
        match self.descriptor().partition {
            Some("1/2") => "1-of-2",
            Some("2/2") => "2-of-2",
            Some(_) => "invalid",
            None => "unpartitioned",
        }
    }
}

impl fmt::Display for CiJobKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CiJobKey {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|job| job.as_str() == value)
            .ok_or_else(|| {
                let expected = Self::ALL
                    .into_iter()
                    .map(|job| job.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                anyhow::anyhow!(
                    "unknown CI job key '{value}'; expected one of: {expected}; integration jobs use integration/<shard>"
                )
            })
    }
}

impl Serialize for CiJobKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CiJobKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CiLane {
    Meta,
    Core,
    CorePrerequisites,
    CoreTests,
    Security,
    Coverage,
    LocalOnly,
    Integration,
    Nightly,
}

impl CiLane {
    pub(crate) const fn workflow_name(self) -> &'static str {
        match self {
            Self::Meta => "ci-meta",
            Self::Core => "ci-core",
            Self::CorePrerequisites => "ci-core-prerequisites",
            Self::CoreTests => "ci-core-tests",
            Self::Security => "ci-security",
            Self::Coverage => "ci-coverage",
            Self::LocalOnly => "ci-local-only",
            Self::Integration => "integration",
            Self::Nightly => "audit",
        }
    }

    pub(crate) const fn command_name(self) -> &'static str {
        match self {
            Self::Meta => "ci-meta",
            Self::Core => "ci-core",
            Self::CorePrerequisites => "ci-core-prerequisites",
            Self::CoreTests => "ci-core-tests",
            Self::Security => "ci-security",
            Self::Coverage => "ci-coverage",
            Self::LocalOnly => "ci-local-only",
            Self::Integration => "ci-integration",
            Self::Nightly => "audit",
        }
    }
}

impl Serialize for CiLane {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.workflow_name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CostClass {
    Fast,
    Standard,
    Expensive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompileKind {
    NoCompile,
    Workspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolRequirement {
    InProcess,
    CargoBuiltin(crate::cmd::CargoSubcommand),
    Nextest,
    CoverageTools,
    CargoTool {
        tool: crate::cmd::CargoSubcommand,
        install_hint: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceKind {
    Source,
    Test,
    SupplyChain,
    Coverage,
    PublicApi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateExecutor {
    Metadata,
    CorePrerequisite,
    CoreTest(CoreTestScope),
    RequiredEvidence,
    SupplyChain,
    Coverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatePolicy {
    OnChange,
    ReleaseOnChange,
    ReleaseScheduled,
    RequiredEvidence,
    Subsumed(SubsumptionProof),
}

/// Closed semantic proofs for the only release-check substitutions the catalog admits.
///
/// Unlike a raw `GateId` edge, a proof names the execution relationship itself. Its
/// source and target are exhaustive, and registry validation also checks the executor,
/// evidence, compile and tool shapes attached to that relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubsumptionProof {
    AssemblyTestsByCoverage,
    WorkspaceBuildByAllFeatures,
    IntegrationCompileByAllFeatures,
    WorkspaceClippyByAllFeatures,
    WorkspaceTestsByCoverage,
}

impl SubsumptionProof {
    const fn source(self) -> GateId {
        match self {
            Self::AssemblyTestsByCoverage => GateId::AssemblyLockProtocolTests,
            Self::WorkspaceBuildByAllFeatures => GateId::BuildWorkspace,
            Self::IntegrationCompileByAllFeatures => GateId::IntegrationCompile,
            Self::WorkspaceClippyByAllFeatures => GateId::ClippyWorkspace,
            Self::WorkspaceTestsByCoverage => GateId::DefaultNextest,
        }
    }

    pub(crate) const fn target(self) -> GateId {
        match self {
            Self::AssemblyTestsByCoverage | Self::WorkspaceTestsByCoverage => GateId::Coverage,
            Self::WorkspaceBuildByAllFeatures | Self::IntegrationCompileByAllFeatures => {
                GateId::BuildAllFeatures
            }
            Self::WorkspaceClippyByAllFeatures => GateId::ClippyAllFeatures,
        }
    }
}

macro_rules! gate_catalog {
    ($emit:ident) => {
        $emit! {
            Fmt => (step_fmt, None,
                gate(
                        GateId::Fmt,
                        "fmt",
                        META,
                        CompileKind::NoCompile,
                        ToolRequirement::CargoBuiltin(crate::cmd::CargoSubcommand::Fmt),
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            ContractValidate => (step_contract_validate, Some("xtask/src/contract/validate.rs"),
                gate(
                        GateId::ContractValidate,
                        "contract-validate",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            AssemblyValidate => (step_assembly_validate, Some("xtask/src/assembly.rs"),
                gate(
                        GateId::AssemblyValidate,
                        "assembly-validate",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            AssemblyArtifactsCheck => (step_assembly_artifacts_check, Some("xtask/src/assembly_artifacts.rs"),
                gate(
                        GateId::AssemblyArtifactsCheck,
                        "assembly-artifacts-check",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            AssemblyModulesCheck => (step_assembly_modules_check, Some("xtask/src/assembly_codegen.rs"),
                gate(
                        GateId::AssemblyModulesCheck,
                        "assembly-modules-check",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            AssemblyProvidersCheck => (step_assembly_providers_check, Some("xtask/src/assembly_codegen.rs"),
                gate(
                        GateId::AssemblyProvidersCheck,
                        "assembly-providers-check",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            AssemblyLockCheck => (step_assembly_lock_check, Some("xtask/src/assembly_lock.rs"),
                gate(
                        GateId::AssemblyLockCheck,
                        "assembly-lock-check",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            AssemblyRuntimePlanCheck => (step_assembly_runtime_plan_check, Some("xtask/src/assembly_runtime_plan.rs"),
                gate(
                        GateId::AssemblyRuntimePlanCheck,
                        "assembly-runtime-plan-check",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            AssemblyGraphCheck => (step_assembly_graph_check, Some("xtask/src/graph.rs"),
                gate(
                        GateId::AssemblyGraphCheck,
                        "assembly-graph-check",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            ContractBreaking => (step_contract_breaking, Some("xtask/src/contract/breaking.rs"),
                gate(
                        GateId::ContractBreaking,
                        "contract-breaking",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            LayerDeps => (step_layer_deps, Some("xtask/src/layerdeps.rs"),
                gate(
                        GateId::LayerDeps,
                        "layer-deps",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            ShippedFeatureGuard => (step_shipped_feature_guard, Some("xtask/src/shipped_feature_guard.rs"),
                gate(
                        GateId::ShippedFeatureGuard,
                        "shipped-feature-guard",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            WsDepsDrift => (step_wsdeps_drift, Some("xtask/src/wsdeps.rs"),
                gate(
                        GateId::WsDepsDrift,
                        "wsdeps-drift",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            SourceSemanticGuard => (step_source_semantic_guard, Some("xtask/src/source_semantic_guard.rs"),
                gate(
                        GateId::SourceSemanticGuard,
                        "source-semantic-guard",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            PromtoolRules => (step_promtool_rules, Some("xtask/src/promtool.rs"),
                gate(
                        GateId::PromtoolRules,
                        "promtool-rules",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            OutboxSameIdGuard => (step_outbox_same_id_guard, Some("xtask/src/outbox_same_id_guard.rs"),
                gate(
                        GateId::OutboxSameIdGuard,
                        "outbox-same-id-guard",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            ConsistencyFixtures => (step_consistency_fixtures, Some("xtask/src/consistency_fixtures.rs"),
                gate(
                        GateId::ConsistencyFixtures,
                        "consistency-fixtures",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            EventTransportGuard => (step_event_transport_guard, Some("xtask/src/event_transport_guard.rs"),
                gate(
                        GateId::EventTransportGuard,
                        "event-transport-guard",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            InboxCutoverGuard => (step_inbox_cutover_guard, Some("xtask/src/inbox_cutover_guard.rs"),
                gate(
                        GateId::InboxCutoverGuard,
                        "inbox-cutover-guard",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            DlxLifecycleFunnel => (step_dlx_lifecycle_funnel, Some("xtask/src/dlx_lifecycle_funnel.rs"),
                gate(
                        GateId::DlxLifecycleFunnel,
                        "dlx-lifecycle-funnel",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            RuntimeBaseline => (step_runtime_baseline, Some("xtask/src/runtime_baseline.rs"),
                gate(
                        GateId::RuntimeBaseline,
                        "runtime-baseline",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            RuntimeRootGuard => (step_runtime_root_guard, Some("xtask/src/runtime_root_guard.rs"),
                gate(
                        GateId::RuntimeRootGuard,
                        "runtime-root-guard",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            RuntimeEnvGuard => (step_runtime_env_guard, Some("xtask/src/runtime_env_guard.rs"),
                gate(
                        GateId::RuntimeEnvGuard,
                        "runtime-env-guard",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            RuntimeDepsGuard => (step_runtime_deps_guard, Some("xtask/src/runtime_deps_guard.rs"),
                gate(
                        GateId::RuntimeDepsGuard,
                        "runtime-deps-guard",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            ArchRules => (step_archrules, Some("xtask/src/archrules.rs"),
                gate(
                        GateId::ArchRules,
                        "archrules",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            CodegenCheck => (step_codegen_check, Some("xtask/src/codegen.rs"),
                gate(
                        GateId::CodegenCheck,
                        "codegen-check",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            L2AssuranceCheck => (step_l2_assurance_check, Some("xtask/src/l2_assurance.rs"),
                gate(
                        GateId::L2AssuranceCheck,
                        "l2-assurance-check",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            ProviderCapabilitiesCheck => (step_provider_capabilities_check, Some("xtask/src/provider_capabilities.rs"),
                gate(
                        GateId::ProviderCapabilitiesCheck,
                        "provider-capabilities-check",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            LocalTxCoverage => (step_localtx_coverage, Some("xtask/src/localtx_coverage.rs"),
                gate(
                        GateId::LocalTxCoverage,
                        "localtx-coverage",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            LocalOnlyEffects => (step_local_only_effects, Some("xtask/src/consistency_effects.rs"),
                gate(
                        GateId::LocalOnlyEffects,
                        "local-only-effects",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            LocalOnlyExecution => (step_local_only_execution, Some("xtask/src/localonly_evidence.rs"),
                gate(
                        GateId::LocalOnlyExecution,
                        "local-only-execution",
                        LOCALONLY,
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        GatePolicy::RequiredEvidence,
                    )
            ),
            PdpAllowGuard => (step_pdp_allow_guard, Some("xtask/src/pdpallow.rs"),
                gate(
                        GateId::PdpAllowGuard,
                        "pdp-allow-guard",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            ContractBindingGuard => (step_contract_binding_guard, Some("xtask/src/contract_binding_guard.rs"),
                gate(
                        GateId::ContractBindingGuard,
                        "contract-binding-guard",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            SchemaRls => (step_schema_rls_guard, Some("xtask/src/schema_rls.rs"),
                gate(
                        GateId::SchemaRls,
                        "schema-rls",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            SetLocalFunnel => (step_setlocal_funnel, Some("xtask/src/setlocal_funnel.rs"),
                gate(
                        GateId::SetLocalFunnel,
                        "setlocal-funnel",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            PgTenantTxGuard => (step_pg_tenant_tx_guard, Some("xtask/src/pg_tenant_tx_guard.rs"),
                gate(
                        GateId::PgTenantTxGuard,
                        "pg-tenant-tx-guard",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            RepoScopeGuard => (step_repo_scope_guard, Some("xtask/src/repo_scope_guard.rs"),
                gate(
                        GateId::RepoScopeGuard,
                        "repo-scope-guard",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            TenancyCloseout => (step_tenancy_closeout, Some("xtask/src/tenancy_closeout.rs"),
                gate(
                        GateId::TenancyCloseout,
                        "tenancy-closeout",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            MigrationsSerial => (step_migrations_serial, Some("xtask/src/migrations.rs"),
                gate(
                        GateId::MigrationsSerial,
                        "migrations-serial",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            CommandSymmetry => (step_command_symmetry, Some("xtask/src/command_symmetry.rs"),
                gate(
                        GateId::CommandSymmetry,
                        "command-symmetry",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            CiEntryGuard => (step_ci_entry_guard, Some("xtask/src/ci_entry_guard.rs"),
                gate(
                        GateId::CiEntryGuard,
                        "ci-entry-guard",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            ReconcileOutboxCommandGuard => (step_reconcile_outbox_command_guard, Some("xtask/src/reconcile_outbox_command_guard.rs"),
                gate(
                        GateId::ReconcileOutboxCommandGuard,
                        "reconcile-outbox-command-guard",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            DeferGate => (step_defer_gate, Some("xtask/src/defergate.rs"),
                gate(
                        GateId::DeferGate,
                        "defer-gate",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            AssemblyLockProtocolTests => (step_assembly_lock_protocol_tests, None,
                gate(
                        GateId::AssemblyLockProtocolTests,
                        "assembly-lock-protocol-tests",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::CargoBuiltin(crate::cmd::CargoSubcommand::Test),
                        EvidenceKind::Test,
                        GatePolicy::Subsumed(SubsumptionProof::AssemblyTestsByCoverage),
                    )
            ),
            BuildWorkspace => (step_build_workspace, None,
                gate(
                        GateId::BuildWorkspace,
                        "build",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::CargoBuiltin(crate::cmd::CargoSubcommand::Build),
                        SOURCE,
                        GatePolicy::Subsumed(SubsumptionProof::WorkspaceBuildByAllFeatures),
                    )
            ),
            PostgresFeatureMatrix => (step_postgres_feature_matrix, None,
                gate(
                        GateId::PostgresFeatureMatrix,
                        "postgres-feature-matrix",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::InProcess,
                        EvidenceKind::Test,
                        GatePolicy::OnChange,
                    )
            ),
            IntegrationCompile => (step_integration_compile, None,
                gate(
                        GateId::IntegrationCompile,
                        "integration-compile",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::CargoBuiltin(crate::cmd::CargoSubcommand::Test),
                        EvidenceKind::Test,
                        GatePolicy::Subsumed(SubsumptionProof::IntegrationCompileByAllFeatures),
                    )
            ),
            ClippyWorkspace => (step_clippy_workspace, None,
                gate(
                        GateId::ClippyWorkspace,
                        "clippy",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::CargoBuiltin(crate::cmd::CargoSubcommand::Clippy),
                        SOURCE,
                        GatePolicy::Subsumed(SubsumptionProof::WorkspaceClippyByAllFeatures),
                    )
            ),
            BuildAllFeatures => (step_build_all_features, None,
                gate(
                        GateId::BuildAllFeatures,
                        "build",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::CargoBuiltin(crate::cmd::CargoSubcommand::Build),
                        SOURCE,
                        GatePolicy::ReleaseOnChange,
                    )
            ),
            ClippyAllFeatures => (step_clippy_all_features, None,
                gate(
                        GateId::ClippyAllFeatures,
                        "clippy",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::CargoBuiltin(crate::cmd::CargoSubcommand::Clippy),
                        SOURCE,
                        GatePolicy::ReleaseOnChange,
                    )
            ),
            Coverage => (step_coverage, Some("xtask/src/coverage.rs"),
                expensive_gate(
                        GateId::Coverage,
                        "coverage",
                        GateExecutor::Coverage,
                        CompileKind::Workspace,
                        ToolRequirement::CoverageTools,
                        EvidenceKind::Coverage,
                        GatePolicy::ReleaseOnChange,
                    )
            ),
            DefaultNextest => (step_nextest, None,
                gate(
                        GateId::DefaultNextest,
                        "default-test-runner",
                        GateExecutor::CoreTest(CoreTestScope::Workspace),
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        GatePolicy::Subsumed(SubsumptionProof::WorkspaceTestsByCoverage),
                    )
            ),
            SecureProductionTrybuild => (step_secure_production_trybuild, None,
                gate(
                        GateId::SecureProductionTrybuild,
                        "secure-production-trybuild",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::CargoBuiltin(crate::cmd::CargoSubcommand::Test),
                        EvidenceKind::Test,
                        GatePolicy::OnChange,
                    )
            ),
            S3BackendTests => (step_s3_backend_tests, None,
                gate(
                        GateId::S3BackendTests,
                        "s3-backend-tests",
                        GateExecutor::CoreTest(CoreTestScope::S3Backend),
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        GatePolicy::OnChange,
                    )
            ),
            RedisBackendTests => (step_redis_backend_tests, None,
                gate(
                        GateId::RedisBackendTests,
                        "redis-backend-tests",
                        GateExecutor::CoreTest(CoreTestScope::RedisBackend),
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        GatePolicy::OnChange,
                    )
            ),
            OidcBackendTests => (step_oidc_backend_tests, None,
                gate(
                        GateId::OidcBackendTests,
                        "oidc-backend-tests",
                        GateExecutor::CoreTest(CoreTestScope::OidcBackend),
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        GatePolicy::OnChange,
                    )
            ),
            PrometheusBackendTests => (step_prometheus_backend_tests, None,
                gate(
                        GateId::PrometheusBackendTests,
                        "prometheus-backend-tests",
                        GateExecutor::CoreTest(CoreTestScope::PrometheusBackend),
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        GatePolicy::OnChange,
                    )
            ),
            OtelBackendTests => (step_otel_backend_tests, None,
                gate(
                        GateId::OtelBackendTests,
                        "otel-backend-tests",
                        GateExecutor::CoreTest(CoreTestScope::OtelBackend),
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        GatePolicy::OnChange,
                    )
            ),
            GrpcBackendTests => (step_grpc_backend_tests, None,
                gate(
                        GateId::GrpcBackendTests,
                        "grpc-backend-tests",
                        GateExecutor::CoreTest(CoreTestScope::GrpcBackend),
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        GatePolicy::OnChange,
                    )
            ),
            VaultBackendTests => (step_vault_backend_tests, None,
                gate(
                        GateId::VaultBackendTests,
                        "vault-backend-tests",
                        GateExecutor::CoreTest(CoreTestScope::VaultBackend),
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        GatePolicy::OnChange,
                    )
            ),
            SettingsOnlyTests => (step_settingsonly_tests, None,
                gate(
                        GateId::SettingsOnlyTests,
                        "settingsonly-tests",
                        GateExecutor::CoreTest(CoreTestScope::SettingsOnly),
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        GatePolicy::OnChange,
                    )
            ),
            IdentityAuditTests => (step_identityaudit_tests, None,
                gate(
                        GateId::IdentityAuditTests,
                        "identityaudit-tests",
                        GateExecutor::CoreTest(CoreTestScope::IdentityAudit),
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        GatePolicy::OnChange,
                    )
            ),
            TestkitContainerTests => (step_testkit_container_tests, None,
                gate(
                        GateId::TestkitContainerTests,
                        "testkit-container-tests",
                        GateExecutor::CoreTest(CoreTestScope::TestkitContainers),
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        GatePolicy::OnChange,
                    )
            ),
            Deny => (step_deny, None,
                gate(
                        GateId::Deny,
                        "deny",
                        GateExecutor::SupplyChain,
                        CompileKind::NoCompile,
                        ToolRequirement::CargoTool {
                            tool: crate::cmd::CargoSubcommand::Deny,
                            install_hint: DENY_HINT,
                        },
                        EvidenceKind::SupplyChain,
                        GatePolicy::OnChange,
                    )
            ),
            CargoAudit => (step_cargo_audit, None,
                GateSpec {
                        id: GateId::CargoAudit,
                        label: "audit",
                        primary_owner: ExecutionProfile::ReleaseCheck,
                        executor: GateExecutor::SupplyChain,
                        policy: GatePolicy::ReleaseOnChange,
                        cost: CostClass::Fast,
                        compile: CompileKind::NoCompile,
                        tool: ToolRequirement::CargoTool {
                            tool: crate::cmd::CargoSubcommand::Audit,
                            install_hint: AUDIT_HINT,
                        },
                        evidence: EvidenceKind::SupplyChain,
                    }
            ),
            Dylint => (step_dylint, None,
                expensive_gate(
                        GateId::Dylint,
                        "dylint",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::CargoTool {
                            tool: crate::cmd::CargoSubcommand::Dylint,
                            install_hint: DYLINT_HINT,
                        },
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            DylintTestNoBareSleep => (step_dylint_test_no_bare_sleep, None,
                expensive_gate(
                        GateId::DylintTestNoBareSleep,
                        "dylint-test-no-bare-sleep",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::CargoTool {
                            tool: crate::cmd::CargoSubcommand::Dylint,
                            install_hint: DYLINT_HINT,
                        },
                        SOURCE,
                        GatePolicy::OnChange,
                    )
            ),
            RuntimeDylintUiTests => (step_runtime_dylint_ui_tests, None,
                expensive_gate(
                        GateId::RuntimeDylintUiTests,
                        "runtime-dylint-ui-tests",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::CargoBuiltin(crate::cmd::CargoSubcommand::Test),
                        EvidenceKind::Test,
                        GatePolicy::OnChange,
                    )
            ),
            PublicApi => (step_public_api, Some("xtask/src/publicapi.rs"),
                expensive_gate(
                        GateId::PublicApi,
                        "public-api",
                        GateExecutor::Coverage,
                        CompileKind::Workspace,
                        ToolRequirement::CargoTool {
                            tool: crate::cmd::CargoSubcommand::PublicApi,
                            install_hint: PUBLIC_API_HINT,
                        },
                        EvidenceKind::PublicApi,
                        GatePolicy::ReleaseOnChange,
                    )
            ),
            DenyAdvisories => (step_deny_advisories, None,
                gate(
                        GateId::DenyAdvisories,
                        "deny-advisories",
                        GateExecutor::SupplyChain,
                        CompileKind::NoCompile,
                        ToolRequirement::CargoTool {
                            tool: crate::cmd::CargoSubcommand::Deny,
                            install_hint: DENY_HINT,
                        },
                        EvidenceKind::SupplyChain,
                        GatePolicy::ReleaseScheduled,
                    )
            ),
        }
    };
}
pub(crate) use gate_catalog;

macro_rules! define_gate_ids {
    ($( $id:ident => ($step:ident, $carrier:expr, $spec:expr), )*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(usize)]
        pub(crate) enum GateId { $( $id, )* }

        impl GateId {
            pub(crate) const ALL: &'static [Self] = &[$(Self::$id),*];
            pub(crate) const COUNT: usize = Self::ALL.len();

            pub(crate) fn carrier_file(self) -> Option<&'static str> {
                match self { $( Self::$id => $carrier, )* }
            }
        }
    };
}
gate_catalog!(define_gate_ids);

impl GateId {
    pub(crate) const fn spec(self) -> &'static GateSpec {
        &REGISTRY[self as usize]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateSpec {
    id: GateId,
    label: &'static str,
    primary_owner: ExecutionProfile,
    executor: GateExecutor,
    policy: GatePolicy,
    cost: CostClass,
    compile: CompileKind,
    tool: ToolRequirement,
    evidence: EvidenceKind,
}

impl GateSpec {
    pub(crate) const fn id(self) -> GateId {
        self.id
    }
    pub(crate) fn label(self) -> &'static str {
        self.label
    }
    pub(crate) const fn primary_owner(self) -> ExecutionProfile {
        self.primary_owner
    }
    pub(crate) const fn executor(self) -> GateExecutor {
        self.executor
    }
    #[cfg(test)]
    pub(crate) fn cost(self) -> CostClass {
        self.cost
    }
    pub(crate) fn compile_kind(self) -> CompileKind {
        self.compile
    }
    pub(crate) fn tool(self) -> ToolRequirement {
        self.tool
    }
    #[cfg(test)]
    pub(crate) fn evidence(self) -> EvidenceKind {
        self.evidence
    }
    #[cfg(test)]
    pub(crate) const fn policy(self) -> GatePolicy {
        self.policy
    }
    pub(crate) const fn included_in_profile(self, profile: ExecutionProfile) -> bool {
        profile.includes_owner(self.primary_owner())
            && !(profile as u8 == ExecutionProfile::ReleaseCheck as u8
                && matches!(self.policy, GatePolicy::Subsumed(_)))
    }
    #[cfg(test)]
    pub(crate) const fn included_in_verify(self) -> bool {
        matches!(
            self.primary_owner,
            ExecutionProfile::Check | ExecutionProfile::Test
        )
    }
    pub(crate) const fn included_in_compatibility_ci(self) -> bool {
        matches!(
            self.policy,
            GatePolicy::OnChange | GatePolicy::ReleaseOnChange
        )
    }
    pub(crate) fn lanes(self) -> [Option<CiLane>; 2] {
        match (self.executor, self.policy) {
            (GateExecutor::Metadata, _) => [Some(CiLane::Meta), None],
            (GateExecutor::CorePrerequisite | GateExecutor::CoreTest(_), _) => {
                [Some(CiLane::Core), None]
            }
            (GateExecutor::RequiredEvidence, _) => [Some(CiLane::LocalOnly), None],
            (GateExecutor::Coverage, _) => [Some(CiLane::Coverage), None],
            (GateExecutor::SupplyChain, GatePolicy::ReleaseScheduled) => {
                [Some(CiLane::Nightly), None]
            }
            (GateExecutor::SupplyChain, GatePolicy::ReleaseOnChange) => {
                [Some(CiLane::Security), Some(CiLane::Nightly)]
            }
            (GateExecutor::SupplyChain, _) => [Some(CiLane::Security), None],
        }
    }
    pub(crate) fn belongs_to(self, lane: CiLane) -> bool {
        self.lanes().contains(&Some(lane))
    }
}

const DENY_HINT: &str = concat!(
    "cargo install cargo-deny@",
    env!("RSS_TOOL_VERSION_CARGO_DENY"),
    " --locked"
);
const AUDIT_HINT: &str = concat!(
    "cargo install cargo-audit@",
    env!("RSS_TOOL_VERSION_CARGO_AUDIT"),
    " --locked"
);
const DYLINT_HINT: &str = concat!(
    "cargo install cargo-dylint@",
    env!("RSS_TOOL_VERSION_CARGO_DYLINT"),
    " dylint-link@",
    env!("RSS_TOOL_VERSION_DYLINT_LINK"),
    " --locked"
);
pub(crate) const LLVM_COV_HINT: &str = concat!(
    "cargo install cargo-llvm-cov@",
    env!("RSS_TOOL_VERSION_CARGO_LLVM_COV"),
    " --locked"
);
const PUBLIC_API_HINT: &str = concat!(
    "rustup toolchain install nightly-2026-04-16 && cargo install cargo-public-api@",
    env!("RSS_TOOL_VERSION_CARGO_PUBLIC_API"),
    " --locked"
);
const fn gate(
    id: GateId,
    label: &'static str,
    executor: GateExecutor,
    compile: CompileKind,
    tool: ToolRequirement,
    evidence: EvidenceKind,
    policy: GatePolicy,
) -> GateSpec {
    let cost = match compile {
        CompileKind::NoCompile => CostClass::Fast,
        CompileKind::Workspace => CostClass::Standard,
    };
    let primary_owner = match policy {
        GatePolicy::ReleaseOnChange | GatePolicy::ReleaseScheduled => {
            ExecutionProfile::ReleaseCheck
        }
        GatePolicy::OnChange | GatePolicy::RequiredEvidence | GatePolicy::Subsumed(_) => {
            match evidence {
                EvidenceKind::Test => ExecutionProfile::Test,
                EvidenceKind::Source | EvidenceKind::SupplyChain => ExecutionProfile::Check,
                EvidenceKind::Coverage | EvidenceKind::PublicApi => ExecutionProfile::ReleaseCheck,
            }
        }
    };
    GateSpec {
        id,
        label,
        primary_owner,
        executor,
        policy,
        cost,
        compile,
        tool,
        evidence,
    }
}

const fn expensive_gate(
    id: GateId,
    label: &'static str,
    executor: GateExecutor,
    compile: CompileKind,
    tool: ToolRequirement,
    evidence: EvidenceKind,
    policy: GatePolicy,
) -> GateSpec {
    let mut spec = gate(id, label, executor, compile, tool, evidence, policy);
    spec.cost = CostClass::Expensive;
    spec
}

const META: GateExecutor = GateExecutor::Metadata;
const CORE: GateExecutor = GateExecutor::CorePrerequisite;
const LOCALONLY: GateExecutor = GateExecutor::RequiredEvidence;
const SOURCE: EvidenceKind = EvidenceKind::Source;
const INTERNAL: ToolRequirement = ToolRequirement::InProcess;
macro_rules! define_registry {
    ($( $id:ident => ($step:ident, $carrier:expr, $spec:expr), )*) => {
        pub(crate) const REGISTRY: &[GateSpec] = &[$($spec),*];
    };
}
gate_catalog!(define_registry);

const fn registry_const_valid() -> bool {
    if REGISTRY.len() != GateId::COUNT {
        return false;
    }
    let mut seen = [false; GateId::COUNT];
    let mut core_test_scope_counts = [0u8; CoreTestScope::COUNT];
    let mut i = 0;
    while i < REGISTRY.len() {
        let spec = REGISTRY[i];
        let index = spec.id as usize;
        if index >= seen.len() || seen[index] || index != i {
            return false;
        }
        let cost_valid = match spec.compile {
            CompileKind::NoCompile => matches!(spec.cost, CostClass::Fast),
            CompileKind::Workspace => {
                matches!(spec.cost, CostClass::Standard | CostClass::Expensive)
            }
        };
        let evidence_classified = matches!(
            spec.evidence,
            EvidenceKind::Source
                | EvidenceKind::Test
                | EvidenceKind::SupplyChain
                | EvidenceKind::Coverage
                | EvidenceKind::PublicApi
        );
        if !cost_valid || !evidence_classified || !executor_const_valid(spec) {
            return false;
        }
        if let GateExecutor::CoreTest(scope) = spec.executor {
            let scope_index = scope as usize;
            if scope_index >= core_test_scope_counts.len()
                || core_test_scope_counts[scope_index] != 0
            {
                return false;
            }
            core_test_scope_counts[scope_index] = 1;
        }
        if let GatePolicy::Subsumed(proof) = spec.policy {
            let target_index = proof.target() as usize;
            if target_index >= REGISTRY.len()
                || !subsumption_const_valid(spec, REGISTRY[target_index], proof)
            {
                return false;
            }
        }
        seen[index] = true;
        i += 1;
    }
    let mut scope_index = 0;
    while scope_index < core_test_scope_counts.len() {
        if core_test_scope_counts[scope_index] != 1 {
            return false;
        }
        scope_index += 1;
    }
    true
}

const fn subsumption_const_valid(
    source: GateSpec,
    target: GateSpec,
    proof: SubsumptionProof,
) -> bool {
    if source.id as usize != proof.source() as usize
        || target.id as usize != proof.target() as usize
        || source.compile as u8 != target.compile as u8
        || !target.included_in_compatibility_ci()
        || target.primary_owner as u8 != ExecutionProfile::ReleaseCheck as u8
    {
        return false;
    }
    match proof {
        SubsumptionProof::AssemblyTestsByCoverage => assembly_coverage_shape(source, target),
        SubsumptionProof::WorkspaceBuildByAllFeatures => build_all_features_shape(source, target),
        SubsumptionProof::IntegrationCompileByAllFeatures => {
            integration_compile_shape(source, target)
        }
        SubsumptionProof::WorkspaceClippyByAllFeatures => clippy_all_features_shape(source, target),
        SubsumptionProof::WorkspaceTestsByCoverage => workspace_coverage_shape(source, target),
    }
}

const fn core_prerequisite_with(
    spec: GateSpec,
    evidence: EvidenceKind,
    command: crate::cmd::CargoSubcommand,
) -> bool {
    matches!(spec.executor, GateExecutor::CorePrerequisite)
        && spec.evidence as u8 == evidence as u8
        && matches!(spec.tool, ToolRequirement::CargoBuiltin(actual) if actual as u8 == command as u8)
}

const fn coverage_shape(spec: GateSpec) -> bool {
    matches!(spec.executor, GateExecutor::Coverage)
        && matches!(spec.evidence, EvidenceKind::Coverage)
        && matches!(spec.tool, ToolRequirement::CoverageTools)
}

const fn assembly_coverage_shape(source: GateSpec, target: GateSpec) -> bool {
    core_prerequisite_with(
        source,
        EvidenceKind::Test,
        crate::cmd::CargoSubcommand::Test,
    ) && coverage_shape(target)
}

const fn build_all_features_shape(source: GateSpec, target: GateSpec) -> bool {
    core_prerequisite_with(
        source,
        EvidenceKind::Source,
        crate::cmd::CargoSubcommand::Build,
    ) && core_prerequisite_with(
        target,
        EvidenceKind::Source,
        crate::cmd::CargoSubcommand::Build,
    )
}

const fn integration_compile_shape(source: GateSpec, target: GateSpec) -> bool {
    core_prerequisite_with(
        source,
        EvidenceKind::Test,
        crate::cmd::CargoSubcommand::Test,
    ) && core_prerequisite_with(
        target,
        EvidenceKind::Source,
        crate::cmd::CargoSubcommand::Build,
    )
}

const fn clippy_all_features_shape(source: GateSpec, target: GateSpec) -> bool {
    core_prerequisite_with(
        source,
        EvidenceKind::Source,
        crate::cmd::CargoSubcommand::Clippy,
    ) && core_prerequisite_with(
        target,
        EvidenceKind::Source,
        crate::cmd::CargoSubcommand::Clippy,
    )
}

const fn workspace_coverage_shape(source: GateSpec, target: GateSpec) -> bool {
    matches!(
        source.executor,
        GateExecutor::CoreTest(CoreTestScope::Workspace)
    ) && matches!(source.evidence, EvidenceKind::Test)
        && matches!(source.tool, ToolRequirement::Nextest)
        && coverage_shape(target)
}

const fn executor_const_valid(spec: GateSpec) -> bool {
    match spec.executor {
        GateExecutor::Metadata => {
            matches!(spec.compile, CompileKind::NoCompile)
                && spec.primary_owner as u8 == ExecutionProfile::Check as u8
        }
        GateExecutor::CoreTest(_) => {
            matches!(spec.tool, ToolRequirement::Nextest)
                && matches!(spec.evidence, EvidenceKind::Test)
                && spec.primary_owner as u8 == ExecutionProfile::Test as u8
        }
        GateExecutor::CorePrerequisite => !matches!(spec.tool, ToolRequirement::Nextest),
        GateExecutor::RequiredEvidence => {
            matches!(spec.policy, GatePolicy::RequiredEvidence)
                && spec.primary_owner as u8 == ExecutionProfile::Test as u8
        }
        GateExecutor::SupplyChain => matches!(spec.evidence, EvidenceKind::SupplyChain),
        GateExecutor::Coverage => {
            matches!(
                spec.evidence,
                EvidenceKind::Coverage | EvidenceKind::PublicApi
            ) && spec.primary_owner as u8 == ExecutionProfile::ReleaseCheck as u8
        }
    }
}

const _: () = assert!(registry_const_valid());

#[cfg(test)]
pub(crate) fn validate_registry(registry: &[GateSpec]) -> Result<(), &'static str> {
    if registry.len() != GateId::COUNT {
        return Err("registry must cover every GateId");
    }
    let mut seen = [false; GateId::COUNT];
    let mut core_test_scope_counts = [0u8; CoreTestScope::COUNT];
    for spec in registry {
        let index = spec.id as usize;
        if index >= seen.len() || seen[index] {
            return Err("duplicate GateId");
        }
        seen[index] = true;
        if let GateExecutor::CoreTest(scope) = spec.executor {
            let scope_index = scope as usize;
            if scope_index >= core_test_scope_counts.len() {
                return Err("unknown CoreTestScope");
            }
            core_test_scope_counts[scope_index] += 1;
        }
    }
    for spec in registry {
        if spec.included_in_compatibility_ci() {
            let split_memberships = [
                CiLane::Meta,
                CiLane::Core,
                CiLane::Security,
                CiLane::Coverage,
            ]
            .into_iter()
            .filter(|lane| spec.belongs_to(*lane))
            .count();
            if split_memberships != 1 {
                return Err("compatibility gate must belong to exactly one split CI lane");
            }
        }
        if let GatePolicy::Subsumed(proof) = spec.policy {
            let Some(target_spec) = registry
                .iter()
                .find(|candidate| candidate.id == proof.target())
            else {
                return Err("missing supersession target");
            };
            if !subsumption_const_valid(*spec, *target_spec, proof) {
                return Err("invalid typed subsumption proof");
            }
        }
    }
    if core_test_scope_counts.into_iter().any(|count| count != 1) {
        return Err("CoreTestScope executor catalog must be exact-once");
    }
    if seen.into_iter().all(|present| present) {
        Ok(())
    } else {
        Err("missing GateId")
    }
}

#[cfg(test)]
pub(crate) fn specs_for_lane(lane: CiLane) -> impl Iterator<Item = &'static GateSpec> {
    REGISTRY.iter().filter(move |spec| spec.belongs_to(lane))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_slo_job_catalog_roundtrips_every_workflow_job() -> anyhow::Result<()> {
        let one_of_two = HashPartition::new(1, 2)?;
        assert_eq!(CI_JOB_DESCRIPTORS.len(), CiJobKey::ALL.len());
        for (index, descriptor) in CI_JOB_DESCRIPTORS.iter().enumerate() {
            assert_eq!(descriptor.key, CiJobKey::ALL[index]);
            let shard = descriptor.shard.map(str::parse).transpose()?;
            let partition = descriptor.partition.map(str::parse).transpose()?;
            let job =
                CiJobKey::from_workflow_parts(descriptor.lane.workflow_name(), shard, partition)?;
            assert_eq!(job, descriptor.key);
            assert_eq!(job.to_string(), job.as_str());
            assert_eq!(job.as_str().parse::<CiJobKey>()?, job);
            let json = serde_json::to_string(&job)?;
            assert_eq!(serde_json::from_str::<CiJobKey>(&json)?, job);
        }
        assert!(CiJobKey::from_workflow_parts("ci-meta", None, Some(one_of_two)).is_err());
        assert!(
            CiJobKey::from_workflow_parts(
                "integration",
                Some(IntegrationShard::PostgresDomain),
                Some(one_of_two)
            )
            .is_err()
        );
        assert!("unknown".parse::<CiJobKey>().is_err());
        Ok(())
    }

    #[test]
    fn required_evidence_catalog_has_exactly_one_localtx_owner() {
        let owners = CiJobKey::ALL
            .into_iter()
            .filter(|job| job.required_evidence() == Some(RequiredEvidenceKind::LocalTx))
            .collect::<Vec<_>>();
        assert!(!owners.is_empty(), "required-evidence owner anti-vacuity");
        assert_eq!(owners, [CiJobKey::IntegrationPostgresDomain]);
    }

    #[test]
    fn required_evidence_catalog_has_exactly_one_localonly_owner() {
        let owners = CiJobKey::ALL
            .into_iter()
            .filter(|job| job.required_evidence() == Some(RequiredEvidenceKind::LocalOnly))
            .collect::<Vec<_>>();
        assert!(
            !owners.is_empty(),
            "LocalOnly required-evidence owner anti-vacuity"
        );
        assert_eq!(owners, [CiJobKey::CiLocalOnly]);
        assert_eq!(CiJobKey::CiLocalOnly.as_str(), "ci-local-only");
        assert_eq!(
            CiJobKey::CiLocalOnly.artifact_parts(),
            ("ci-local-only", "workspace", "unpartitioned")
        );
    }

    #[test]
    fn required_evidence_staging_paths_are_derived_from_the_closed_kind() {
        assert_eq!(
            RequiredEvidenceKind::LocalTx.staged_artifact_path(),
            "target/job-evidence/integration/localtx-required.json"
        );
        assert_eq!(
            RequiredEvidenceKind::LocalOnly.staged_artifact_path(),
            "target/job-evidence/local-only/localonly-execution.json"
        );
        for job in CiJobKey::ALL {
            assert_eq!(
                job.required_evidence_staged_artifact_path(),
                job.required_evidence()
                    .map(RequiredEvidenceKind::staged_artifact_path),
                "{job}"
            );
        }
    }

    #[test]
    fn every_integration_shard_projects_to_all_and_only_its_jobs() {
        let mut projected = Vec::new();
        for shard in IntegrationShard::ALL {
            let jobs = CiJobKey::for_shard(*shard);
            assert!(!jobs.is_empty(), "shard {shard} must own an executor");
            assert!(
                jobs.iter().all(|job| job.shard() == Some(shard.as_str())),
                "shard {shard} contains a foreign executor"
            );
            projected.extend_from_slice(jobs);
        }
        let catalog = CiJobKey::ALL
            .into_iter()
            .filter(|job| job.shard().is_some())
            .collect::<Vec<_>>();
        assert_eq!(
            projected, catalog,
            "shard projection must cover the catalog"
        );
    }

    #[test]
    fn ci_lane_registry_accepts_canonical_green() {
        assert!(validate_registry(REGISTRY).is_ok());
        assert!(GateId::ALL.contains(&GateId::IdentityAuditTests));
        assert_eq!(REGISTRY.len(), GateId::COUNT);
        assert!(
            REGISTRY
                .iter()
                .all(|spec| spec.id().spec().id() == spec.id())
        );
        assert!(REGISTRY.iter().any(|spec| spec.included_in_verify()));
        assert!(REGISTRY.iter().any(|spec| !spec.included_in_verify()));
        assert!(REGISTRY.iter().all(|spec| matches!(
            (spec.cost(), spec.evidence()),
            (
                CostClass::Fast | CostClass::Standard | CostClass::Expensive,
                EvidenceKind::Source
                    | EvidenceKind::Test
                    | EvidenceKind::SupplyChain
                    | EvidenceKind::Coverage
                    | EvidenceKind::PublicApi
            )
        )));
        let testkit = REGISTRY
            .iter()
            .filter(|spec| spec.label() == "testkit-container-tests")
            .collect::<Vec<_>>();
        assert_eq!(
            testkit.len(),
            1,
            "feature-gated testkit container tests need one registry-owned CI gate"
        );
        assert_eq!(testkit[0].evidence(), EvidenceKind::Test);
        assert!(testkit[0].belongs_to(CiLane::Core));
        assert!(testkit[0].included_in_verify());
        assert_eq!(testkit[0].primary_owner(), ExecutionProfile::Test);
    }

    #[test]
    fn canonical_profiles_own_every_gate_and_release_is_the_subsumed_union() {
        assert!(
            REGISTRY
                .iter()
                .all(|spec| ExecutionProfile::ALL.contains(&spec.primary_owner()))
        );
        assert!(REGISTRY.iter().all(|spec| {
            spec.included_in_profile(ExecutionProfile::ReleaseCheck)
                || matches!(spec.policy(), GatePolicy::Subsumed(proof) if proof.target().spec().included_in_profile(ExecutionProfile::ReleaseCheck))
        }));
        assert!(
            REGISTRY
                .iter()
                .all(|spec| { spec.primary_owner() != ExecutionProfile::IntegrationCritical }),
            "#1884 owns activation of integration-critical"
        );
    }

    #[test]
    fn core_test_scope_catalog_is_projected_exactly_once() {
        let scopes = REGISTRY
            .iter()
            .filter_map(|spec| match spec.executor() {
                GateExecutor::CoreTest(scope) => Some(scope),
                _ => None,
            })
            .collect::<Vec<_>>();
        let unique = scopes
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            unique,
            CoreTestScope::ALL.into_iter().collect(),
            "CoreTestScope must be referenced only by the typed unit executor catalog"
        );
        assert_eq!(
            scopes.len(),
            CoreTestScope::COUNT,
            "duplicate CoreTestScope executor"
        );
    }

    #[test]
    fn ci_job_key_diagnostic_is_generic_and_actionable() -> Result<()> {
        let error = match "integration/not-registered".parse::<CiJobKey>() {
            Err(error) => error.to_string(),
            Ok(_) => anyhow::bail!("unknown job key must fail closed"),
        };
        assert!(error.contains("unknown CI job key"), "{error}");
        assert!(error.contains("integration/not-registered"), "{error}");
        assert!(error.contains("ci-meta"), "{error}");
        assert!(error.contains("integration/<shard>"), "{error}");
        assert!(!error.contains("SLO"), "{error}");
        Ok(())
    }

    #[test]
    fn ci_lane_registry_rejects_duplicate_and_missing_red() {
        let duplicate = [REGISTRY[0]; GateId::COUNT];
        assert!(validate_registry(&duplicate).is_err());
        assert!(validate_registry(&REGISTRY[..REGISTRY.len() - 1]).is_err());
    }

    #[test]
    fn ci_lane_registry_rejects_invalid_supersession_relations_red() {
        let mut wrong_source = REGISTRY.to_vec();
        wrong_source[GateId::DefaultNextest as usize].policy =
            GatePolicy::Subsumed(SubsumptionProof::WorkspaceBuildByAllFeatures);
        assert!(validate_registry(&wrong_source).is_err());

        let mut invalid_target_shape = REGISTRY.to_vec();
        invalid_target_shape[GateId::Coverage as usize].executor = GateExecutor::CorePrerequisite;
        assert!(validate_registry(&invalid_target_shape).is_err());

        let mut invalid_evidence_shape = REGISTRY.to_vec();
        invalid_evidence_shape[GateId::AssemblyLockProtocolTests as usize].evidence =
            EvidenceKind::Source;
        assert!(validate_registry(&invalid_evidence_shape).is_err());

        let mut invalid_compile_shape = REGISTRY.to_vec();
        invalid_compile_shape[GateId::AssemblyLockProtocolTests as usize].compile =
            CompileKind::NoCompile;
        invalid_compile_shape[GateId::AssemblyLockProtocolTests as usize].cost = CostClass::Fast;
        assert!(validate_registry(&invalid_compile_shape).is_err());
    }

    #[test]
    fn ci_lane_registry_rejects_duplicate_core_test_scope_red() {
        let mut duplicate_scope = REGISTRY.to_vec();
        duplicate_scope[GateId::S3BackendTests as usize].executor =
            GateExecutor::CoreTest(CoreTestScope::Workspace);
        assert!(validate_registry(&duplicate_scope).is_err());
    }

    #[test]
    fn ci_lane_registry_rejects_compat_gate_outside_split_lanes_red() {
        let mut wrong_lane = REGISTRY.to_vec();
        wrong_lane[GateId::BuildAllFeatures as usize].executor = GateExecutor::RequiredEvidence;
        assert!(
            validate_registry(&wrong_lane).is_err(),
            "compatibility gate outside the typed split executors escaped validation"
        );
    }

    #[test]
    fn scheduled_advisory_projection_is_typed_and_closed() {
        let shared: Vec<_> = REGISTRY
            .iter()
            .filter(|spec| spec.lanes()[1].is_some())
            .collect();
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].id(), GateId::CargoAudit);
        assert_eq!(
            shared[0].lanes(),
            [Some(CiLane::Security), Some(CiLane::Nightly)]
        );
    }

    #[test]
    fn ci_lane_meta_is_strictly_no_compile() {
        let meta: Vec<_> = specs_for_lane(CiLane::Meta).collect();
        assert!(!meta.is_empty());
        assert!(
            meta.iter()
                .all(|spec| spec.compile_kind() == CompileKind::NoCompile)
        );
    }
}
