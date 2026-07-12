//! CI gate taxonomy and ordered registry.
//!
//! INVARIANT: CI-LANE-REGISTRY-01 { level = "Hard", exec = "native-compile", source = "code", native = "gate_catalog generates GateId ALL/COUNT, executor dispatch, carrier binding, and registry identity proof" } ——
//! every closed [`GateId`] has exactly one complete [`GateSpec`]. The exhaustive lookup makes any
//! new variant a compile error first; the const proof then rejects missing, duplicate, mismatched,
//! or out-of-order entries.
//! INVARIANT: CI-LANE-PLAN-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "ci_lane_registry_rejects_duplicate_and_missing_red", anti_vacuity = "ci_lane_registry_accepts_canonical_green" } —— lane and
//! compatibility plans are derived from this registry and guarded by non-vacuous red/green tests.
//! INVARIANT: CI-SLO-JOB-TYPE-01 { level = "Hard", exec = "native-compile", source = "code", native = "CiJobKey is a closed enum whose ALL catalog and exhaustive mappings admit exactly the reusable workflow job matrix" }.

use anyhow::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

use crate::integration_shards::IntegrationShard;
use crate::nextest::HashPartition;

#[derive(Debug, Clone, Copy)]
struct CiJobDescriptor {
    key: CiJobKey,
    name: &'static str,
    lane: &'static str,
    shard: Option<&'static str>,
    partition: Option<&'static str>,
}

macro_rules! ci_job_catalog {
    ($( $variant:ident => ($name:literal, $lane:literal, $shard:expr, $partition:expr) ),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub(crate) enum CiJobKey {
            $( $variant, )+
        }

        const CI_JOB_DESCRIPTORS: [CiJobDescriptor; 14] = [
            $(CiJobDescriptor {
                key: CiJobKey::$variant,
                name: $name,
                lane: $lane,
                shard: $shard,
                partition: $partition,
            },)+
        ];

        impl CiJobKey {
            pub(crate) const ALL: [Self; 14] = [$(Self::$variant),+];

            const fn descriptor(self) -> &'static CiJobDescriptor {
                match self {
                    $(Self::$variant => &CI_JOB_DESCRIPTORS[Self::$variant as usize],)+
                }
            }

            pub(crate) const fn as_str(self) -> &'static str {
                self.descriptor().name
            }
        }
    };
}

ci_job_catalog! {
    CiMeta => ("ci-meta", "ci-meta", None, None),
    CiCorePrerequisites => ("ci-core-prerequisites", "ci-core-prerequisites", None, None),
    CiCoreTests1Of2 => ("ci-core-tests/1-of-2", "ci-core-tests", None, Some("1/2")),
    CiCoreTests2Of2 => ("ci-core-tests/2-of-2", "ci-core-tests", None, Some("2/2")),
    CiSecurity => ("ci-security", "ci-security", None, None),
    CiCoverage => ("ci-coverage", "ci-coverage", None, None),
    IntegrationPostgresDomain => (
        "integration/postgres-domain",
        "integration",
        Some("postgres-domain"),
        None
    ),
    IntegrationEventTransport1Of2 => (
        "integration/event-transport/1-of-2",
        "integration",
        Some("event-transport"),
        Some("1/2")
    ),
    IntegrationEventTransport2Of2 => (
        "integration/event-transport/2-of-2",
        "integration",
        Some("event-transport"),
        Some("2/2")
    ),
    IntegrationRuntimeHttpAuth1Of2 => (
        "integration/runtime-http-auth/1-of-2",
        "integration",
        Some("runtime-http-auth"),
        Some("1/2")
    ),
    IntegrationRuntimeHttpAuth2Of2 => (
        "integration/runtime-http-auth/2-of-2",
        "integration",
        Some("runtime-http-auth"),
        Some("2/2")
    ),
    IntegrationConsistencyFault => (
        "integration/consistency-fault",
        "integration",
        Some("consistency-fault"),
        None
    ),
    IntegrationCdcProjectionSaga => (
        "integration/cdc-projection-saga",
        "integration",
        Some("cdc-projection-saga"),
        None
    ),
    Audit => ("audit", "audit", None, None),
}

impl CiJobKey {
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
                descriptor.lane == lane
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
        (descriptor.lane, shard, partition)
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
            .ok_or_else(|| anyhow::anyhow!("unknown CI SLO job"))
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
    Security,
    Coverage,
    Nightly,
}

impl CiLane {
    pub(crate) const fn command_name(self) -> &'static str {
        match self {
            Self::Meta => "ci-meta",
            Self::Core => "ci-core",
            Self::Security => "ci-security",
            Self::Coverage => "ci-coverage",
            Self::Nightly => "audit",
        }
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
pub(crate) enum SharedReason {
    ScheduledAdvisoryBackstop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LaneAssignment {
    Primary(CiLane),
    Shared {
        primary: CiLane,
        secondary: CiLane,
        reason: SharedReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StandaloneReason {
    VerifyOnly,
    ScheduledAdvisory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompatMembership {
    Included,
    SupersededBy(GateId),
    Standalone(StandaloneReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyMembership {
    Included,
    Excluded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GateMembership {
    verify: VerifyMembership,
    compat: CompatMembership,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
                    )
            ),
            DocContracts => (step_doc_contracts, Some("xtask/src/doc_contracts.rs"),
                gate(
                        GateId::DocContracts,
                        "doc-contracts",
                        META,
                        CompileKind::NoCompile,
                        INTERNAL,
                        SOURCE,
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        BOTH_INCLUDED,
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
                        VERIFY_ONLY,
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
                        BOTH_INCLUDED,
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
                        VERIFY_ONLY,
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
                        VERIFY_ONLY,
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
                        CI_INCLUDED,
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
                        CI_INCLUDED,
                    )
            ),
            Coverage => (step_coverage, Some("xtask/src/coverage.rs"),
                expensive_gate(
                        GateId::Coverage,
                        "coverage",
                        CiLane::Coverage,
                        CompileKind::Workspace,
                        ToolRequirement::CoverageTools,
                        EvidenceKind::Coverage,
                        CI_INCLUDED,
                    )
            ),
            DefaultNextest => (step_nextest, None,
                gate(
                        GateId::DefaultNextest,
                        "default-test-runner",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        VERIFY_SUPERSEDED_BY_COVERAGE,
                    )
            ),
            S3BackendTests => (step_s3_backend_tests, None,
                gate(
                        GateId::S3BackendTests,
                        "s3-backend-tests",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        BOTH_INCLUDED,
                    )
            ),
            RedisBackendTests => (step_redis_backend_tests, None,
                gate(
                        GateId::RedisBackendTests,
                        "redis-backend-tests",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        BOTH_INCLUDED,
                    )
            ),
            OidcBackendTests => (step_oidc_backend_tests, None,
                gate(
                        GateId::OidcBackendTests,
                        "oidc-backend-tests",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        BOTH_INCLUDED,
                    )
            ),
            PrometheusBackendTests => (step_prometheus_backend_tests, None,
                gate(
                        GateId::PrometheusBackendTests,
                        "prometheus-backend-tests",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        BOTH_INCLUDED,
                    )
            ),
            OtelBackendTests => (step_otel_backend_tests, None,
                gate(
                        GateId::OtelBackendTests,
                        "otel-backend-tests",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        BOTH_INCLUDED,
                    )
            ),
            GrpcBackendTests => (step_grpc_backend_tests, None,
                gate(
                        GateId::GrpcBackendTests,
                        "grpc-backend-tests",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        BOTH_INCLUDED,
                    )
            ),
            VaultBackendTests => (step_vault_backend_tests, None,
                gate(
                        GateId::VaultBackendTests,
                        "vault-backend-tests",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        BOTH_INCLUDED,
                    )
            ),
            SettingsOnlyTests => (step_settingsonly_tests, None,
                gate(
                        GateId::SettingsOnlyTests,
                        "settingsonly-tests",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        BOTH_INCLUDED,
                    )
            ),
            IdentityAuditTests => (step_identityaudit_tests, None,
                gate(
                        GateId::IdentityAuditTests,
                        "identityaudit-tests",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        BOTH_INCLUDED,
                    )
            ),
            TestkitContainerTests => (step_testkit_container_tests, None,
                gate(
                        GateId::TestkitContainerTests,
                        "testkit-container-tests",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::Nextest,
                        EvidenceKind::Test,
                        BOTH_INCLUDED,
                    )
            ),
            Deny => (step_deny, None,
                gate(
                        GateId::Deny,
                        "deny",
                        CiLane::Security,
                        CompileKind::NoCompile,
                        ToolRequirement::CargoTool {
                            tool: crate::cmd::CargoSubcommand::Deny,
                            install_hint: DENY_HINT,
                        },
                        EvidenceKind::SupplyChain,
                        BOTH_INCLUDED,
                    )
            ),
            CargoAudit => (step_cargo_audit, None,
                GateSpec {
                        id: GateId::CargoAudit,
                        label: "audit",
                        assignment: LaneAssignment::Shared {
                            primary: CiLane::Security,
                            secondary: CiLane::Nightly,
                            reason: SharedReason::ScheduledAdvisoryBackstop,
                        },
                        cost: CostClass::Fast,
                        compile: CompileKind::NoCompile,
                        tool: ToolRequirement::CargoTool {
                            tool: crate::cmd::CargoSubcommand::Audit,
                            install_hint: AUDIT_HINT,
                        },
                        evidence: EvidenceKind::SupplyChain,
                        verify: VerifyMembership::Excluded,
                        compat: CompatMembership::Included,
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
                        BOTH_INCLUDED,
                    )
            ),
            PublicApi => (step_public_api, Some("xtask/src/publicapi.rs"),
                expensive_gate(
                        GateId::PublicApi,
                        "public-api",
                        CiLane::Coverage,
                        CompileKind::Workspace,
                        ToolRequirement::CargoTool {
                            tool: crate::cmd::CargoSubcommand::PublicApi,
                            install_hint: PUBLIC_API_HINT,
                        },
                        EvidenceKind::PublicApi,
                        CI_INCLUDED,
                    )
            ),
            DenyAdvisories => (step_deny_advisories, None,
                gate(
                        GateId::DenyAdvisories,
                        "deny-advisories",
                        CiLane::Nightly,
                        CompileKind::NoCompile,
                        ToolRequirement::CargoTool {
                            tool: crate::cmd::CargoSubcommand::Deny,
                            install_hint: DENY_HINT,
                        },
                        EvidenceKind::SupplyChain,
                        NIGHTLY_ONLY,
                    )
            ),
        }
    };
}
pub(crate) use gate_catalog;

macro_rules! define_gate_ids {
    ($( $id:ident => ($step:ident, $carrier:expr, $spec:expr), )*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(usize)]
        pub(crate) enum GateId { $( $id, )* }

        impl GateId {
            pub(crate) const ALL: &'static [Self] = &[$(Self::$id),*];
            pub(crate) const COUNT: usize = Self::ALL.len();

            #[cfg(test)]
            pub(crate) fn carrier_file(self) -> Option<&'static str> {
                match self { $( Self::$id => $carrier, )* }
            }
        }
    };
}
gate_catalog!(define_gate_ids);

impl GateId {
    pub(crate) fn spec(self) -> &'static GateSpec {
        &REGISTRY[self as usize]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateSpec {
    id: GateId,
    label: &'static str,
    assignment: LaneAssignment,
    cost: CostClass,
    compile: CompileKind,
    tool: ToolRequirement,
    evidence: EvidenceKind,
    verify: VerifyMembership,
    compat: CompatMembership,
}

impl GateSpec {
    pub(crate) fn id(self) -> GateId {
        self.id
    }
    pub(crate) fn label(self) -> &'static str {
        self.label
    }
    #[cfg(test)]
    pub(crate) fn assignment(self) -> LaneAssignment {
        self.assignment
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
    pub(crate) fn verify_membership(self) -> VerifyMembership {
        self.verify
    }
    pub(crate) fn compat(self) -> CompatMembership {
        self.compat
    }
    pub(crate) fn lanes(self) -> [Option<CiLane>; 2] {
        match self.assignment {
            LaneAssignment::Primary(lane) => [Some(lane), None],
            LaneAssignment::Shared {
                primary, secondary, ..
            } => [Some(primary), Some(secondary)],
        }
    }
    pub(crate) fn belongs_to(self, lane: CiLane) -> bool {
        self.lanes().contains(&Some(lane))
    }
}

const DENY_HINT: &str = "cargo install cargo-deny@0.19.9 --locked";
const AUDIT_HINT: &str = "cargo install cargo-audit@0.22.2 --locked";
const DYLINT_HINT: &str = "cargo install cargo-dylint@6.0.1 dylint-link@6.0.1 --locked";
pub(crate) const LLVM_COV_HINT: &str = "cargo install cargo-llvm-cov@0.8.7 --locked";
const PUBLIC_API_HINT: &str =
    "rustup toolchain install nightly-2026-04-16 && cargo install cargo-public-api@0.52.0 --locked";

const fn gate(
    id: GateId,
    label: &'static str,
    lane: CiLane,
    compile: CompileKind,
    tool: ToolRequirement,
    evidence: EvidenceKind,
    membership: GateMembership,
) -> GateSpec {
    let cost = match compile {
        CompileKind::NoCompile => CostClass::Fast,
        CompileKind::Workspace => CostClass::Standard,
    };
    GateSpec {
        id,
        label,
        assignment: LaneAssignment::Primary(lane),
        cost,
        compile,
        tool,
        evidence,
        verify: membership.verify,
        compat: membership.compat,
    }
}

const fn expensive_gate(
    id: GateId,
    label: &'static str,
    lane: CiLane,
    compile: CompileKind,
    tool: ToolRequirement,
    evidence: EvidenceKind,
    membership: GateMembership,
) -> GateSpec {
    let mut spec = gate(id, label, lane, compile, tool, evidence, membership);
    spec.cost = CostClass::Expensive;
    spec
}

const META: CiLane = CiLane::Meta;
const CORE: CiLane = CiLane::Core;
const BOTH_INCLUDED: GateMembership = GateMembership {
    verify: VerifyMembership::Included,
    compat: CompatMembership::Included,
};
const CI_INCLUDED: GateMembership = GateMembership {
    verify: VerifyMembership::Excluded,
    compat: CompatMembership::Included,
};
const VERIFY_ONLY: GateMembership = GateMembership {
    verify: VerifyMembership::Included,
    compat: CompatMembership::Standalone(StandaloneReason::VerifyOnly),
};
const VERIFY_SUPERSEDED_BY_COVERAGE: GateMembership = GateMembership {
    verify: VerifyMembership::Included,
    compat: CompatMembership::SupersededBy(GateId::Coverage),
};
const NIGHTLY_ONLY: GateMembership = GateMembership {
    verify: VerifyMembership::Excluded,
    compat: CompatMembership::Standalone(StandaloneReason::ScheduledAdvisory),
};
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
        let verify_classified = matches!(
            spec.verify,
            VerifyMembership::Included | VerifyMembership::Excluded
        );
        if !cost_valid || !evidence_classified || !verify_classified {
            return false;
        }
        if let CompatMembership::SupersededBy(target) = spec.compat {
            let target_index = target as usize;
            if target_index == index
                || target_index >= REGISTRY.len()
                || !matches!(REGISTRY[target_index].compat, CompatMembership::Included)
            {
                return false;
            }
        }
        seen[index] = true;
        i += 1;
    }
    true
}

const _: () = assert!(registry_const_valid());

#[cfg(test)]
pub(crate) fn validate_registry(registry: &[GateSpec]) -> Result<(), &'static str> {
    if registry.len() != GateId::COUNT {
        return Err("registry must cover every GateId");
    }
    let mut seen = [false; GateId::COUNT];
    for spec in registry {
        let index = spec.id as usize;
        if index >= seen.len() || seen[index] {
            return Err("duplicate GateId");
        }
        seen[index] = true;
    }
    for spec in registry {
        if spec.compat == CompatMembership::Included {
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
        if let CompatMembership::SupersededBy(target) = spec.compat {
            if target == spec.id {
                return Err("invalid supersession target");
            }
            let Some(target_spec) = registry.iter().find(|candidate| candidate.id == target) else {
                return Err("missing supersession target");
            };
            if target_spec.compat != CompatMembership::Included {
                return Err("supersession target must be included in compatibility CI");
            }
        }
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
            let job = CiJobKey::from_workflow_parts(descriptor.lane, shard, partition)?;
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
    fn ci_lane_registry_accepts_canonical_green() {
        assert!(validate_registry(REGISTRY).is_ok());
        assert!(GateId::ALL.contains(&GateId::IdentityAuditTests));
        assert_eq!(REGISTRY.len(), GateId::COUNT);
        assert!(
            REGISTRY
                .iter()
                .all(|spec| spec.id().spec().id() == spec.id())
        );
        assert!(
            REGISTRY
                .iter()
                .any(|spec| spec.verify_membership() == VerifyMembership::Included)
        );
        assert!(
            REGISTRY
                .iter()
                .any(|spec| spec.verify_membership() == VerifyMembership::Excluded)
        );
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
        assert_eq!(testkit[0].verify_membership(), VerifyMembership::Included);
    }

    #[test]
    fn ci_lane_registry_rejects_duplicate_and_missing_red() {
        let duplicate = [REGISTRY[0]; GateId::COUNT];
        assert!(validate_registry(&duplicate).is_err());
        assert!(validate_registry(&REGISTRY[..REGISTRY.len() - 1]).is_err());
    }

    #[test]
    fn ci_lane_registry_rejects_invalid_supersession_relations_red() {
        let mut self_cycle = REGISTRY.to_vec();
        self_cycle[GateId::DefaultNextest as usize].compat =
            CompatMembership::SupersededBy(GateId::DefaultNextest);
        assert!(validate_registry(&self_cycle).is_err());

        let mut excluded_target = REGISTRY.to_vec();
        excluded_target[GateId::Coverage as usize].compat =
            CompatMembership::Standalone(StandaloneReason::VerifyOnly);
        assert!(validate_registry(&excluded_target).is_err());

        let mut missing_target = REGISTRY.to_vec();
        missing_target.pop();
        missing_target[GateId::DefaultNextest as usize].compat =
            CompatMembership::SupersededBy(GateId::DenyAdvisories);
        assert!(validate_registry(&missing_target).is_err());
    }

    #[test]
    fn ci_lane_registry_rejects_compat_gate_outside_split_lanes_red() {
        let invalid_lane = CiLane::Nightly;
        let mut wrong_lane = REGISTRY.to_vec();
        wrong_lane[GateId::BuildAllFeatures as usize].assignment =
            LaneAssignment::Primary(invalid_lane);
        assert!(
            validate_registry(&wrong_lane).is_err(),
            "compatibility gate assigned to {invalid_lane:?} escaped split-lane validation"
        );
    }

    #[test]
    fn ci_lane_shared_assignments_require_a_closed_reason() {
        let shared: Vec<_> = REGISTRY
            .iter()
            .filter(|spec| matches!(spec.assignment(), LaneAssignment::Shared { .. }))
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
