//! CI gate taxonomy and ordered registry.
//!
//! INVARIANT: CI-LANE-REGISTRY-01 { level = "Hard", exec = "native-compile", source = "code", native = "gate_catalog generates GateId ALL/COUNT, executor dispatch, carrier binding, and registry identity proof" } ——
//! every closed [`GateId`] has exactly one complete [`GateSpec`]. The exhaustive lookup makes any
//! new variant a compile error first; the const proof then rejects missing, duplicate, mismatched,
//! or out-of-order entries.
//! INVARIANT: CI-LANE-PLAN-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "ci_lane_registry_rejects_duplicate_and_missing_red", anti_vacuity = "ci_lane_registry_accepts_canonical_green" } —— lane and
//! compatibility plans are derived from this registry and guarded by non-vacuous red/green tests.

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
    CargoBuiltin,
    CargoTool {
        probe: &'static str,
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
                        ToolRequirement::CargoBuiltin,
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
                        ToolRequirement::CargoBuiltin,
                        SOURCE,
                        VERIFY_ONLY,
                    )
            ),
            IntegrationCompile => (step_integration_compile, None,
                gate(
                        GateId::IntegrationCompile,
                        "integration-compile",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::CargoBuiltin,
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
                        ToolRequirement::CargoBuiltin,
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
                        ToolRequirement::CargoBuiltin,
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
                        ToolRequirement::CargoBuiltin,
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
                        ToolRequirement::CargoTool {
                            probe: "llvm-cov",
                            install_hint: LLVM_COV_HINT,
                        },
                        EvidenceKind::Coverage,
                        CI_INCLUDED,
                    )
            ),
            DefaultNextest => (step_nextest, None,
                gate(
                        GateId::DefaultNextest,
                        "nextest",
                        CORE,
                        CompileKind::Workspace,
                        ToolRequirement::CargoTool {
                            probe: "nextest",
                            install_hint: NEXTEST_HINT,
                        },
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
                        ToolRequirement::CargoTool {
                            probe: "nextest",
                            install_hint: NEXTEST_HINT,
                        },
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
                        ToolRequirement::CargoTool {
                            probe: "nextest",
                            install_hint: NEXTEST_HINT,
                        },
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
                        ToolRequirement::CargoTool {
                            probe: "nextest",
                            install_hint: NEXTEST_HINT,
                        },
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
                        ToolRequirement::CargoTool {
                            probe: "nextest",
                            install_hint: NEXTEST_HINT,
                        },
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
                        ToolRequirement::CargoTool {
                            probe: "nextest",
                            install_hint: NEXTEST_HINT,
                        },
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
                        ToolRequirement::CargoTool {
                            probe: "nextest",
                            install_hint: NEXTEST_HINT,
                        },
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
                        ToolRequirement::CargoTool {
                            probe: "nextest",
                            install_hint: NEXTEST_HINT,
                        },
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
                            probe: "deny",
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
                            probe: "audit",
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
                            probe: "dylint",
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
                            probe: "public-api",
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
                            probe: "deny",
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
const NEXTEST_HINT: &str = "cargo install cargo-nextest@0.9.137 --locked";
const LLVM_COV_HINT: &str = "cargo install cargo-llvm-cov@0.8.7 --locked";
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
    fn ci_lane_registry_accepts_canonical_green() {
        assert!(validate_registry(REGISTRY).is_ok());
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
