//! CI gate taxonomy and ordered registry.
//!
//! INVARIANT: CI-LANE-REGISTRY-01 { level = "Hard", exec = "native-compile", source = "code", native = "gate_catalog generates GateId ALL/COUNT, executor dispatch, carrier binding, and registry identity proof" } ——
//! every closed [`GateId`] has exactly one complete [`GateSpec`]. The exhaustive lookup makes any
//! new variant a compile error first; the const proof then rejects missing, duplicate, mismatched,
//! or out-of-order entries.
//! INVARIANT: CI-LANE-PLAN-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "ci_lane_registry_rejects_duplicate_and_missing_red", anti_vacuity = "ci_lane_registry_accepts_canonical_green" } —— lane and
//! canonical profile plans are derived from this registry and guarded by non-vacuous red/green tests.

use anyhow::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

use crate::execution_profiles::ExecutionProfile;
#[cfg(test)]
use crate::integration_shards::IntegrationShard;

/// The complete, stable set of remote CI execution jobs.
///
/// INVARIANT: CI-FIXED-JOB-01 { level = "Hard", exec = "native-compile", source = "code", native = "FixedCiJob is a closed three-variant enum and every dispatch site matches it exhaustively" }.
/// INVARIANT: CI-EXECUTION-PARTITION-01 { level = "Hard", exec = "native-compile", source = "code", native = "the closed FixedCiJob enum and exhaustive SelectionMode projection assign every selected execution unit to exactly one fixed executor" }.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum FixedCiJob {
    Check,
    TestAffected,
    IntegrationCritical,
}

impl FixedCiJob {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 3] = [Self::Check, Self::TestAffected, Self::IntegrationCritical];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::TestAffected => "test-affected",
            Self::IntegrationCritical => "integration-critical",
        }
    }
}

impl fmt::Display for FixedCiJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for FixedCiJob {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "check" => Ok(Self::Check),
            "test-affected" => Ok(Self::TestAffected),
            "integration-critical" => Ok(Self::IntegrationCritical),
            _ => anyhow::bail!(
                "unknown fixed CI job '{value}'; expected check, test-affected, or integration-critical"
            ),
        }
    }
}

impl Serialize for FixedCiJob {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for FixedCiJob {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateGroup {
    Meta,
    Core,
    Security,
    Coverage,
    LocalOnly,
    Nightly,
}

impl GateGroup {
    pub(crate) const fn workflow_name(self) -> &'static str {
        match self {
            Self::Meta => "ci-meta",
            Self::Core => "ci-core",
            Self::Security => "ci-security",
            Self::Coverage => "ci-coverage",
            Self::LocalOnly => "ci-local-only",
            Self::Nightly => "audit",
        }
    }
}

impl Serialize for GateGroup {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.workflow_name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompileKind {
    NoCompile,
    Workspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum LocalImpactDomain {
    RuntimeEventing,
    AssemblyGeneration,
    Consistency,
    TenancyPostgres,
    Pdp,
    ContractBinding,
    CommandSymmetry,
}

impl LocalImpactDomain {
    pub(crate) const ALL: [Self; 7] = [
        Self::RuntimeEventing,
        Self::AssemblyGeneration,
        Self::Consistency,
        Self::TenancyPostgres,
        Self::Pdp,
        Self::ContractBinding,
        Self::CommandSymmetry,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalMetaPolicy {
    Always,
    OnImpact(LocalImpactDomain),
    FullOnly,
    NeverLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolRequirement {
    InProcess,
    CargoBuiltin(crate::cmd::CargoSubcommand),
    Nextest,
    CoverageTools,
    PublicApiTools {
        install_hint: &'static str,
    },
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
    CoreTest,
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
    WorkspaceBuildByAllFeatures,
    IntegrationCompileByAllFeatures,
    WorkspaceClippyByAllFeatures,
    ComponentTestsByCoverage,
}

impl SubsumptionProof {
    const fn source(self) -> GateId {
        match self {
            Self::WorkspaceBuildByAllFeatures => GateId::BuildWorkspace,
            Self::IntegrationCompileByAllFeatures => GateId::IntegrationCompile,
            Self::WorkspaceClippyByAllFeatures => GateId::ClippyWorkspace,
            Self::ComponentTestsByCoverage => GateId::ComponentTests,
        }
    }

    pub(crate) const fn target(self) -> GateId {
        match self {
            Self::ComponentTestsByCoverage => GateId::Coverage,
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
            SagaDurableRecoveryGuard => (step_saga_durable_recovery_guard, Some("xtask/src/saga_durable_recovery_guard.rs"),
                gate(
                        GateId::SagaDurableRecoveryGuard,
                        "saga-durable-recovery-guard",
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
                gate(
                        GateId::Coverage,
                        "coverage",
                        GateExecutor::Coverage,
                        CompileKind::Workspace,
                        ToolRequirement::CoverageTools,
                        EvidenceKind::Coverage,
                        GatePolicy::ReleaseOnChange,
                    )
            ),
            ComponentTests => (step_component_tests, None,
                gate(
                        GateId::ComponentTests,
                        "component-tests",
                        GateExecutor::CoreTest,
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        GatePolicy::Subsumed(SubsumptionProof::ComponentTestsByCoverage),
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
                        compile: CompileKind::NoCompile,
                        tool: ToolRequirement::CargoTool {
                            tool: crate::cmd::CargoSubcommand::Audit,
                            install_hint: AUDIT_HINT,
                        },
                        evidence: EvidenceKind::SupplyChain,
                    }
            ),
            Dylint => (step_dylint, None,
                gate(
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
                gate(
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
            DylintWorkspaceUiTests => (step_dylint_workspace_ui_tests, None,
                gate(
                        GateId::DylintWorkspaceUiTests,
                        "dylint-ui-goldens",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::CargoBuiltin(crate::cmd::CargoSubcommand::Test),
                        EvidenceKind::Test,
                        GatePolicy::ReleaseOnChange,
                    )
            ),
            PublicApi => (step_public_api, Some("xtask/src/publicapi.rs"),
                gate(
                        GateId::PublicApi,
                        "public-api",
                        GateExecutor::Coverage,
                        CompileKind::Workspace,
                        ToolRequirement::PublicApiTools {
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

    pub(crate) const fn local_meta_policy(self) -> LocalMetaPolicy {
        use LocalImpactDomain as Domain;
        use LocalMetaPolicy as Policy;

        match self {
            Self::Fmt
            | Self::ContractValidate
            | Self::AssemblyValidate
            | Self::ContractBreaking
            | Self::LayerDeps
            | Self::ShippedFeatureGuard
            | Self::WsDepsDrift
            | Self::CiEntryGuard
            | Self::DeferGate => Policy::Always,

            Self::RuntimeRootGuard
            | Self::RuntimeEnvGuard
            | Self::RuntimeDepsGuard
            | Self::EventTransportGuard
            | Self::DlxLifecycleFunnel
            | Self::InboxCutoverGuard
            | Self::OutboxSameIdGuard
            | Self::ReconcileOutboxCommandGuard => Policy::OnImpact(Domain::RuntimeEventing),

            Self::AssemblyArtifactsCheck
            | Self::AssemblyModulesCheck
            | Self::AssemblyProvidersCheck
            | Self::AssemblyLockCheck
            | Self::AssemblyRuntimePlanCheck
            | Self::AssemblyGraphCheck => Policy::OnImpact(Domain::AssemblyGeneration),

            Self::ConsistencyFixtures | Self::LocalTxCoverage | Self::LocalOnlyEffects => {
                Policy::OnImpact(Domain::Consistency)
            }

            Self::SchemaRls
            | Self::PgTenantTxGuard
            | Self::RepoScopeGuard
            | Self::TenancyCloseout => Policy::OnImpact(Domain::TenancyPostgres),

            Self::PdpAllowGuard => Policy::OnImpact(Domain::Pdp),
            Self::ContractBindingGuard | Self::CodegenCheck => {
                Policy::OnImpact(Domain::ContractBinding)
            }
            Self::CommandSymmetry => Policy::OnImpact(Domain::CommandSymmetry),

            Self::RuntimeBaseline
            | Self::L2AssuranceCheck
            | Self::ArchRules
            | Self::ProviderCapabilitiesCheck
            | Self::SourceSemanticGuard
            | Self::SagaDurableRecoveryGuard => Policy::FullOnly,

            _ => Policy::NeverLocal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateSpec {
    id: GateId,
    label: &'static str,
    primary_owner: ExecutionProfile,
    executor: GateExecutor,
    policy: GatePolicy,
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
    pub(crate) fn compile_kind(self) -> CompileKind {
        self.compile
    }
    pub(crate) fn tool(self) -> ToolRequirement {
        self.tool
    }
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
    pub(crate) fn lanes(self) -> [Option<GateGroup>; 2] {
        match (self.executor, self.policy) {
            (GateExecutor::Metadata, _) => [Some(GateGroup::Meta), None],
            (GateExecutor::CorePrerequisite | GateExecutor::CoreTest, _) => {
                [Some(GateGroup::Core), None]
            }
            (GateExecutor::RequiredEvidence, _) => [Some(GateGroup::LocalOnly), None],
            (GateExecutor::Coverage, _) => [Some(GateGroup::Coverage), None],
            (GateExecutor::SupplyChain, GatePolicy::ReleaseScheduled) => {
                [Some(GateGroup::Nightly), None]
            }
            (GateExecutor::SupplyChain, GatePolicy::ReleaseOnChange) => {
                [Some(GateGroup::Security), Some(GateGroup::Nightly)]
            }
            (GateExecutor::SupplyChain, _) => [Some(GateGroup::Security), None],
        }
    }
    pub(crate) fn belongs_to(self, lane: GateGroup) -> bool {
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
    " --locked && cargo install cargo-semver-checks@",
    env!("RSS_TOOL_VERSION_CARGO_SEMVER_CHECKS"),
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
        compile,
        tool,
        evidence,
    }
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
    let mut component_test_count = 0u8;
    let mut i = 0;
    while i < REGISTRY.len() {
        let spec = REGISTRY[i];
        let index = spec.id as usize;
        if index >= seen.len() || seen[index] || index != i {
            return false;
        }
        let evidence_classified = matches!(
            spec.evidence,
            EvidenceKind::Source
                | EvidenceKind::Test
                | EvidenceKind::SupplyChain
                | EvidenceKind::Coverage
                | EvidenceKind::PublicApi
        );
        if !evidence_classified || !executor_const_valid(spec) {
            return false;
        }
        if matches!(spec.executor, GateExecutor::CoreTest) {
            if component_test_count != 0 {
                return false;
            }
            component_test_count = 1;
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
    component_test_count == 1
}

const fn subsumption_const_valid(
    source: GateSpec,
    target: GateSpec,
    proof: SubsumptionProof,
) -> bool {
    if source.id as usize != proof.source() as usize
        || target.id as usize != proof.target() as usize
        || source.compile as u8 != target.compile as u8
        || !target.included_in_profile(ExecutionProfile::ReleaseCheck)
        || target.primary_owner as u8 != ExecutionProfile::ReleaseCheck as u8
    {
        return false;
    }
    match proof {
        SubsumptionProof::WorkspaceBuildByAllFeatures => build_all_features_shape(source, target),
        SubsumptionProof::IntegrationCompileByAllFeatures => {
            integration_compile_shape(source, target)
        }
        SubsumptionProof::WorkspaceClippyByAllFeatures => clippy_all_features_shape(source, target),
        SubsumptionProof::ComponentTestsByCoverage => component_coverage_shape(source, target),
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

const fn component_coverage_shape(source: GateSpec, target: GateSpec) -> bool {
    matches!(source.executor, GateExecutor::CoreTest)
        && matches!(source.evidence, EvidenceKind::Test)
        && matches!(source.tool, ToolRequirement::Nextest)
        && coverage_shape(target)
}

const fn executor_const_valid(spec: GateSpec) -> bool {
    match spec.executor {
        GateExecutor::Metadata => {
            matches!(spec.compile, CompileKind::NoCompile)
                && spec.primary_owner as u8 == ExecutionProfile::Check as u8
        }
        GateExecutor::CoreTest => {
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
    let mut component_test_count = 0u8;
    for spec in registry {
        let index = spec.id as usize;
        if index >= seen.len() || seen[index] {
            return Err("duplicate GateId");
        }
        seen[index] = true;
        if matches!(spec.executor, GateExecutor::CoreTest) {
            component_test_count += 1;
        }
    }
    for spec in registry {
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
    if component_test_count != 1 {
        return Err("component-test executor catalog must be exact-once");
    }
    if seen.into_iter().all(|present| present) {
        Ok(())
    } else {
        Err("missing GateId")
    }
}

#[cfg(test)]
pub(crate) fn specs_for_lane(lane: GateGroup) -> impl Iterator<Item = &'static GateSpec> {
    REGISTRY.iter().filter(move |spec| spec.belongs_to(lane))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn ci_lane_registry_accepts_canonical_green() {
        assert!(validate_registry(REGISTRY).is_ok());
        assert!(GateId::ALL.contains(&GateId::ComponentTests));
        assert_eq!(REGISTRY.len(), GateId::COUNT);
        assert!(
            REGISTRY
                .iter()
                .all(|spec| spec.id().spec().id() == spec.id())
        );
        assert!(REGISTRY.iter().any(|spec| spec.included_in_verify()));
        assert!(REGISTRY.iter().any(|spec| !spec.included_in_verify()));
        assert!(REGISTRY.iter().all(|spec| matches!(
            spec.evidence(),
            EvidenceKind::Source
                | EvidenceKind::Test
                | EvidenceKind::SupplyChain
                | EvidenceKind::Coverage
                | EvidenceKind::PublicApi
        )));
        let component = GateId::ComponentTests.spec();
        assert_eq!(component.executor(), GateExecutor::CoreTest);
        assert_eq!(component.primary_owner(), ExecutionProfile::Test);
    }

    #[test]
    fn local_meta_policy_is_exact_9_25_6_partition() {
        let labels = |policy: fn(LocalMetaPolicy) -> bool| {
            GateId::ALL
                .iter()
                .copied()
                .filter(|id| policy(id.local_meta_policy()))
                .map(|id| id.spec().label())
                .collect::<BTreeSet<_>>()
        };
        let always = labels(|policy| matches!(policy, LocalMetaPolicy::Always));
        let affected = labels(|policy| matches!(policy, LocalMetaPolicy::OnImpact(_)));
        let full_only = labels(|policy| matches!(policy, LocalMetaPolicy::FullOnly));

        assert_eq!(
            always,
            BTreeSet::from([
                "fmt",
                "contract-validate",
                "contract-breaking",
                "assembly-validate",
                "layer-deps",
                "wsdeps-drift",
                "shipped-feature-guard",
                "ci-entry-guard",
                "defer-gate",
            ])
        );
        assert_eq!(
            affected,
            BTreeSet::from([
                "runtime-root-guard",
                "runtime-env-guard",
                "runtime-deps-guard",
                "event-transport-guard",
                "dlx-lifecycle-funnel",
                "inbox-cutover-guard",
                "outbox-same-id-guard",
                "reconcile-outbox-command-guard",
                "assembly-artifacts-check",
                "assembly-modules-check",
                "assembly-providers-check",
                "assembly-lock-check",
                "assembly-runtime-plan-check",
                "assembly-graph-check",
                "consistency-fixtures",
                "localtx-coverage",
                "local-only-effects",
                "schema-rls",
                "pg-tenant-tx-guard",
                "repo-scope-guard",
                "tenancy-closeout",
                "pdp-allow-guard",
                "codegen-check",
                "contract-binding-guard",
                "command-symmetry",
            ])
        );
        let on_impact_labels = |domain: LocalImpactDomain| {
            GateId::ALL
                .iter()
                .copied()
                .filter(|id| matches!(id.local_meta_policy(), LocalMetaPolicy::OnImpact(d) if d == domain))
                .map(|id| id.spec().label())
                .collect::<BTreeSet<_>>()
        };
        let domain_fixtures: &[(LocalImpactDomain, &[&str])] = &[
            (
                LocalImpactDomain::RuntimeEventing,
                &[
                    "runtime-root-guard",
                    "runtime-env-guard",
                    "runtime-deps-guard",
                    "event-transport-guard",
                    "dlx-lifecycle-funnel",
                    "inbox-cutover-guard",
                    "outbox-same-id-guard",
                    "reconcile-outbox-command-guard",
                ],
            ),
            (
                LocalImpactDomain::AssemblyGeneration,
                &[
                    "assembly-artifacts-check",
                    "assembly-modules-check",
                    "assembly-providers-check",
                    "assembly-lock-check",
                    "assembly-runtime-plan-check",
                    "assembly-graph-check",
                ],
            ),
            (
                LocalImpactDomain::Consistency,
                &[
                    "consistency-fixtures",
                    "localtx-coverage",
                    "local-only-effects",
                ],
            ),
            (
                LocalImpactDomain::TenancyPostgres,
                &[
                    "schema-rls",
                    "pg-tenant-tx-guard",
                    "repo-scope-guard",
                    "tenancy-closeout",
                ],
            ),
            (LocalImpactDomain::Pdp, &["pdp-allow-guard"]),
            (
                LocalImpactDomain::ContractBinding,
                &["codegen-check", "contract-binding-guard"],
            ),
            (LocalImpactDomain::CommandSymmetry, &["command-symmetry"]),
        ];
        let mut union = BTreeSet::new();
        for &(domain, expected) in domain_fixtures {
            let expected: BTreeSet<_> = expected.iter().copied().collect();
            assert_eq!(on_impact_labels(domain), expected, "{domain:?}");
            union.extend(expected);
        }
        assert_eq!(union, affected);
        assert_eq!(
            full_only,
            BTreeSet::from([
                "runtime-baseline",
                "l2-assurance-check",
                "archrules",
                "provider-capabilities-check",
                "source-semantic-guard",
                "saga-durable-recovery-guard",
            ])
        );
        assert_eq!(always.len(), 9);
        assert_eq!(affected.len(), 25);
        assert_eq!(full_only.len(), 6);
        assert!(
            !GateId::ALL
                .iter()
                .any(|id| id.spec().label() == "setlocal-funnel"),
            "retired gate label must not exist: setlocal-funnel"
        );

        for id in GateId::ALL
            .iter()
            .copied()
            .filter(|id| !matches!(id.local_meta_policy(), LocalMetaPolicy::NeverLocal))
        {
            let spec = id.spec();
            assert_eq!(spec.compile_kind(), CompileKind::NoCompile, "{id:?}");
            assert_eq!(spec.primary_owner(), ExecutionProfile::Check, "{id:?}");
            assert_eq!(spec.executor(), GateExecutor::Metadata, "{id:?}");
        }
    }

    #[test]
    fn canonical_profiles_own_every_gate_and_critical_projects_owned_integration_units() {
        use crate::execution_profiles::{ExecutionProfile, ExecutionUnitSpec};
        use crate::integration_shards::IntegrationUnitId;

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
            "integration-critical must own only integration units"
        );

        let critical =
            ExecutionUnitSpec::project(ExecutionProfile::IntegrationCritical).collect::<Vec<_>>();
        assert!(!critical.is_empty(), "integration-critical must be active");
        assert!(critical.iter().all(|unit| matches!(
            unit,
            ExecutionUnitSpec::Integration(spec)
                if spec.primary_owner == ExecutionProfile::IntegrationCritical
        )));

        let critical_ids = critical
            .iter()
            .filter_map(|unit| match unit {
                ExecutionUnitSpec::Integration(spec) => Some(spec.id),
                ExecutionUnitSpec::Gate(_) => None,
            })
            .collect::<BTreeSet<_>>();
        let critical_owners = IntegrationUnitId::ALL
            .into_iter()
            .filter(|id| id.spec().primary_owner == ExecutionProfile::IntegrationCritical)
            .collect::<BTreeSet<_>>();
        assert_eq!(critical_ids, critical_owners);
        assert!(
            critical_ids
                .iter()
                .all(|id| id.spec().shard != IntegrationShard::ProductionRuntime)
        );
        assert!(
            IntegrationShard::ProductionRuntime
                .spec()
                .units
                .iter()
                .all(|spec| spec.primary_owner == ExecutionProfile::ReleaseCheck)
        );
    }

    #[test]
    fn component_test_owner_is_projected_exactly_once() {
        let owners = REGISTRY
            .iter()
            .filter(|spec| spec.executor() == GateExecutor::CoreTest)
            .collect::<Vec<_>>();
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].id(), GateId::ComponentTests);
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
        wrong_source[GateId::ComponentTests as usize].policy =
            GatePolicy::Subsumed(SubsumptionProof::WorkspaceBuildByAllFeatures);
        assert!(validate_registry(&wrong_source).is_err());

        let mut invalid_target_shape = REGISTRY.to_vec();
        invalid_target_shape[GateId::Coverage as usize].executor = GateExecutor::CorePrerequisite;
        assert!(validate_registry(&invalid_target_shape).is_err());

        let mut invalid_evidence_shape = REGISTRY.to_vec();
        invalid_evidence_shape[GateId::ComponentTests as usize].evidence = EvidenceKind::Source;
        assert!(validate_registry(&invalid_evidence_shape).is_err());

        let mut invalid_compile_shape = REGISTRY.to_vec();
        invalid_compile_shape[GateId::ComponentTests as usize].compile = CompileKind::NoCompile;
        assert!(validate_registry(&invalid_compile_shape).is_err());
    }

    #[test]
    fn ci_lane_registry_rejects_duplicate_component_test_owner_red() {
        let mut duplicate_owner = REGISTRY.to_vec();
        duplicate_owner[GateId::BuildWorkspace as usize].executor = GateExecutor::CoreTest;
        assert!(validate_registry(&duplicate_owner).is_err());
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
            [Some(GateGroup::Security), Some(GateGroup::Nightly)]
        );
    }

    #[test]
    fn ci_lane_meta_is_strictly_no_compile() {
        let meta: Vec<_> = specs_for_lane(GateGroup::Meta).collect();
        assert!(!meta.is_empty());
        assert!(
            meta.iter()
                .all(|spec| spec.compile_kind() == CompileKind::NoCompile)
        );
    }
}
