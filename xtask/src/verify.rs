//! `cargo xtask verify` —— 本地全量治理门聚合入口。
//!
//! RSS 本地全量治理门。Azure 是 active PR forge；GitHub typed lanes 当前用于 adaptive 取证，
//! `ci-gate` 尚不是 required check。完整门集与顺序只由 typed registry 派生，本说明不复制 gate inventory。
//! 本地聚合默认 keep-going，显式 `--fail-fast` 可恢复首错停止：no-compile Meta 证明优先，随后是 workspace/feature 编译、lint、默认与
//! feature-gated 行为测试、供应链检查和注册 lint。
//!
//! `--fast` 的 inner typed plan 只跑不依赖 Docker、额外 Cargo 工具或 crate 编译的轻量
//! registry 中显式标记为 `LocalMetaPolicy::Always` 的轻量 gate，
//! 供快速迭代；冷缓存或 xtask 变更时，外层 Cargo 仍会构建 xtask 启动器。`--allow-missing-tools`
//! 在缺外部工具时显式宽限（默认 fail-closed）。
//! 本地聚合默认 keep-going；`--fail-fast` 恢复首错停止，重复 `--only <gate-label>` 仅运行
//! registry 中属于当前计划的 gate，并明确标记为 partial 诊断。远端 typed job 始终 fail-fast。
//!
//! **`cargo xtask ci full`（[`run_ci`]）= 本地完整 CI 聚合**（issue #1132）：
//! verify 全门 + build/clippy 升 `--all-features --all-targets` + 覆盖率门（`cargo llvm-cov nextest` 替
//! nextest，强制 basis/engine ≥90%，见 `coverage.rs`）+ `public-api --check`（轴 A，见 `publicapi.rs`）。
//! `verify` 仍是 **stable-only 本地快门**（不需 nightly / llvm-cov）；`ci full` 只供本地一次性跑全部
//! CI 门。两者与固定 GitHub jobs 均经 [`plan_for`] 与 [`FixedCiJob`] 的 Hard 闭集派生，杜绝门集漂移。
//!
//! **`cargo xtask ci audit`（[`run_audit`]）= 供应链漏洞定时刷新入口**（issue #1133，GitHub Actions
//! `schedule:` 调用入口）：advisory-scoped `cargo deny check advisories` + `cargo audit` 两门
//! （皆 no-compile、快）。PR-triggered adaptive plan 按影响选择 `deny check`
//! （advisories+licenses+bans+sources）+ cargo-audit；scheduled audit 专攻**时间维度**，捕获未改依赖的新披露
//! CVE。两者在各自 run 内 fail-closed；`ci-gate` 激活为 required check 或建立 forge bridge 前均不阻断 Azure 合入。
//!
//! **`cargo-udeps` 仍不入三者**（多余/未声明依赖，需 nightly `-Z`，与根 stable 1.96 冲突）——独立可选门。
//! `cargo-semver-checks`（轴 A 语义破坏检测）当前所有 crate `publish = false` ⇒ `--workspace` 选 0 包、门
//! 空转，故本轮不入 ci（public-api --check 已非空转兜轴 A）；待 crate 可发布后 follow-up 接入（见 PR body）。
//!
//! INVARIANT: VERIFY-AGGREGATE-01 { level = "Medium", exec = "check", source = "code" }—— 本地 verify/ci-full 默认 keep-going、显式 fail-fast；远端 typed job 保持 fail-fast；任一门步失败均非零退出。
//! INVARIANT: VERIFY-TOOL-GATE-01 { level = "Medium", exec = "check", source = "code" }—— 缺外部工具默认 fail-closed；豁免仅经显式 `--allow-missing-tools`。
//! INVARIANT: ASSEMBLY-PROVIDERS-VERIFY-GATE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "assembly_provider_codegen_gate_is_typed_once_and_ordered_in_all_aggregate_plans", anti_vacuity = "assembly_codegen::tests::assembly_provider_codegen_generated_provider_catalogs_are_non_empty_and_check_clean" }—— provider catalog drift is an independent typed no-compile gate exactly once between modules drift and AssemblyLock in every aggregate plan.
//! INVARIANT: ASSEMBLY-RUNTIME-PLAN-VERIFY-GATE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "assembly_runtime_plan_gate_is_typed_once_and_ordered_in_all_aggregate_plans", anti_vacuity = "assembly_runtime_plan::tests::committed_runtime_plans_are_check_clean" }—— committed runtime plans are checked by one typed in-process no-compile gate exactly once between assembly lock and graph checks in every aggregate plan.
//! INVARIANT: RUNTIME-DYLINT-UI-GATE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "dylint_workspace_ui_gate_is_release_owned_once", anti_vacuity = "dylint_workspace_ui_gate_is_release_owned_once" }—— Dylint UI goldens run once as typed `cargo test --locked --workspace` from `lints` in release-check; fast remains no-compile.
//! INVARIANT: L2-ASSURANCE-VERIFY-GATE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "l2_assurance_gate_is_typed_once_and_ordered_in_all_aggregate_plans", anti_vacuity = "l2_assurance::tests::workspace_inventory_is_exact_and_deterministic" }—— L2 assurance drift check is a typed, in-process, no-compile gate present exactly once immediately after codegen in every aggregate plan.
//! Fixed PR execution is projected by the closed [`FixedCiJob`] enum below. The committed caller
//! and reusable workflow are guarded structurally by `CI-FIXED-WORKFLOW-01`; integration uses one
//! aggregate scope with bounded diagnostics and always-cleanup, while LocalTx/LocalOnly reports
//! are validated by their producers rather than reconciled by a central receipt gate.
//! INVARIANT: CI-SELFTEST-TEMP-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "ci_selftest_temp_root_guard_rejects_unsafe_fixtures", anti_vacuity = "committed_ci_selftest_temp_roots_are_atomic" }—— 所有 GitHub shell selftest 必须递归自动发现；可执行源码中的 PID 临时路径与非原子 TMP_ROOT 均 fail-closed，实际 TMP_ROOT 必须以带 `.XXXXXX` 模板的原子 `mktemp -d` 创建独占根目录；注释不能充当合规证据或触发误报。

#[cfg(test)]
use crate::ci_lanes::CompileKind;
use crate::ci_lanes::{EvidenceKind, FixedCiJob};
use crate::ci_lanes::{
    GateExecutor, GateGroup, GateId, LocalMetaPolicy, REGISTRY, ToolRequirement,
};
use crate::diagnostic::run_check;
use crate::execution_profiles::{ExecutionProfile, ExecutionUnitSpec};
use crate::integration_shards::{
    self, IntegrationSelection, IntegrationShard, IntegrationUnitId, Scheduling,
};
use crate::workspace_root;
use crate::{
    archrules, assembly, assembly_lock, codegen, consistency_effects, consistency_fixtures,
    contract, layerdeps, reconcile_outbox_command_guard, repo_scope_guard, runtime_baseline,
    runtime_deps_guard, runtime_env_guard, runtime_root_guard, shipped_feature_guard, wsdeps,
};
use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

trait AggregateClock {
    type Tick: Copy;

    fn now(&self) -> Self::Tick;
    fn elapsed(&self, start: Self::Tick, end: Self::Tick) -> Duration;
}

struct SystemAggregateClock;

impl AggregateClock for SystemAggregateClock {
    type Tick = Instant;

    #[allow(clippy::disallowed_methods)] // system clock adapter boundary for local CLI timing
    fn now(&self) -> Self::Tick {
        Instant::now()
    }

    #[allow(clippy::disallowed_methods)] // system clock adapter boundary for local CLI timing
    fn elapsed(&self, start: Self::Tick, end: Self::Tick) -> Duration {
        end.duration_since(start)
    }
}

/// verify 选项。
#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifyOpts {
    /// Inner typed plan 只跑不依赖 Docker、额外 Cargo 工具或 crate 编译的轻量
    /// `LocalMetaPolicy::Always` gate；外层 Cargo 仍可能构建 xtask 启动器。
    fast: bool,
    /// 缺外部工具时显式宽限（默认 fail-closed，唯一门不建议）。
    allow_missing_tools: bool,
    partition: Option<crate::nextest::HashPartition>,
    nextest_lane: crate::nextest::NextestLane,
    core_test_selection: crate::nextest::CoreTestSelection,
    contract_against: String,
    /// ReleaseCheck 的固定 `test-affected` Job：用与 selection 同 base 的 CoverageProjection。
    /// `ci full` / release-check：恒 Workspace。
    coverage_typed_job: bool,
    execution_policy: crate::cmd::ExecutionPolicy,
}

/// in-process Rust 门（无外部进程 / 自管子进程）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InternalCheck {
    ContractValidate,
    /// assembly-level DI provider 声明校验（RevocationStore active provider 必须持久）。
    AssemblyValidate,
    /// assembly lifecycle 与应用 artifact exact closure 门（#1798）。
    AssemblyArtifactsCheck,
    /// assembly.toml domains → committed modules_gen.rs 漂移门（ASSEMBLY-MODULES-CODEGEN-01）。
    AssemblyModulesCheck,
    /// assembly.toml providers → committed providers_gen.rs 漂移门（ASSEMBLY-PROVIDERS-CODEGEN-01）。
    AssemblyProvidersCheck,
    /// repository-verified committed assembly.lock.json raw-byte 漂移门（#1781）。
    AssemblyLockCheck,
    /// committed runtime-plan.json raw-byte drift gate.
    AssemblyRuntimePlanCheck,
    /// committed runtime assembly Mermaid/JSON graph 漂移与 source closure 门。
    AssemblyGraphCheck,
    /// wire JSON-Schema/manifest 跨版本破坏检测门（ADR-008，WIRE-BREAKING-01）。
    /// active 默认 deny；三个固定 review rules 为 warn，但未确认 fail-closed；against = origin/develop。
    ContractBreaking,
    LayerDeps,
    /// server/rss 的 WorkspaceFacts CargoSet root selection 禁止启用登记的非生产 features。
    ShippedFeatureGuard,
    WsDepsDrift,
    /// Production Rustdoc semantic and token-profile trust-chain source guard.
    SourceSemanticGuard,
    /// Saga durable intent/permit/effect/completion and unknown-no-retry AST guard.
    SagaDurableRecoveryGuard,
    /// digest-pinned promtool rules + consuming tests（PROMTOOL-RULES-01）。
    PromtoolRules,
    /// same-ID SQL/Rust/ops cross-carrier closure（OUTBOX-SAME-ID-WINDOW-01）。
    OutboxSameIdGuard,
    /// consistency crash matrix fixture/DSL 骨架门（CONSISTENCY-CRASH-FIXTURE-01）。
    ConsistencyFixtures,
    /// runtime event transport consumer 禁回 Redis claimer（EVENT-TRANSPORT-PG-INBOX-01）。
    EventTransportGuard,
    /// inbox receipt runtime cutover 旧 token 回流守卫（INBOX-RECEIPTS-CUTOVER-01）。
    InboxCutoverGuard,
    /// DLX verified WORM archive-before-purge 单漏斗守卫（DLX-LIFECYCLE-FUNNEL-01）。
    DlxLifecycleFunnel,
    /// runtime assembly baseline 漂移门（RUNTIME-BASELINE-DRIFT-01）。
    RuntimeBaseline,
    /// runtime composition-root 单调职责 ratchet（RUNTIME-ROOT-RATCHET-01）。
    RuntimeRootGuard,
    /// runtime production ambient environment reader closure（RUNTIME-ENV-FUNNEL-01）。
    RuntimeEnvGuard,
    /// SharedRuntimeDeps infra-only 字段类型守卫（WIRING-DEPS-INFRA-ONLY-01）。
    RuntimeDepsGuard,
    /// ArchRules 派生索引 + 14 行持久化 funnel matrix 文档漂移门。
    ArchRules,
    CodegenCheck,
    /// committed L2 assurance inventory raw-byte drift gate.
    L2AssuranceCheck,
    /// provider declaration ↔ live runner ↔ integration shard ↔ committed matrix drift gate.
    ProviderCapabilitiesCheck,
    /// active LocalTx manifest/generated/owner route/test typed marker closure.
    LocalTxCoverage,
    /// active LocalOnly effect closure + canonical source receipt coverage
    /// （LOCAL-ONLY-EFFECTS-01 / LOCAL-ONLY-RECEIPT-COVERAGE-01）。
    LocalOnlyEffects,
    /// bins 生产 src 的 `#[allow(rss_pdp_impl_adapter_only)]` 逃生门计数门（信任根二次门，PDP-ALLOW-CONFINE-01）。
    PdpAllowGuard,
    /// 生产代码禁止裸调用 `ContractBinding::from_static`，只能使用 generated `CONTRACT`。
    ContractBindingGuard,
    /// tenant 表 RLS/ACL 终态 meta 守卫（TENANCY-RLS-FORCE-01 / TENANCY-PG-READER-ACL-01；内容扫描迁移 SQL，no-compile）。
    SchemaRlsGuard,
    /// Postgres tenant-table raw-pool / TxManager bypass guard（TENANCY-PG-TX-FUNNEL-01；no-compile）。
    PgTenantTxGuard,
    /// domain repo port 禁裸 TenantId / RowVisibility / RowScope 签名守卫（TENANCY-REPO-SCOPE-SIGNATURE-01）。
    RepoScopeGuard,
    /// tenancy/AuthZ/projection closeout reverse self-check（TENANCY-CLOSEOUT-REVERSE-01；no-compile）。
    TenancyCloseout,
    /// generated command policy 与生产 provider impl/callsite 集合守卫（COMMAND-IMPL-ALLOWLIST-01）。
    CommandSymmetry,
    /// Makefile 的 canonical `ci` / `ci-full` executable 入口守卫（CI-LOCAL-ENTRY-01）。
    CiEntryGuard,
    /// reconcile scheduler transactional command outbox seam guard（RECONCILE-COMMAND-OUTBOX-SEAM-01）。
    ReconcileOutboxCommandGuard,
    /// 根 `deny.toml` / `clippy.toml` 结构化 defer 完整性 + 经典注解门
    /// （DEFER-GATE-01；只扫描机器拥有的 TOML，no-compile）。
    DeferGate,
    /// Postgres 无默认、三个单域及 all-features 编译矩阵；由 xtask 自管 cargo 子进程。
    PostgresFeatureMatrix,
    /// ci 专用：`cargo llvm-cov nextest`（兼 nextest 门）+ basis/engine ≥90% 覆盖率判定（见 `coverage.rs`）。
    Coverage,
    /// ci 专用：`public-api --check`（basis+engine+curated extras 封装面 baseline 漂移门 = 轴 A，见 `publicapi.rs`）。
    PublicApiCheck,
}

/// 门步 executor。工具要求、探测和安装提示只由 gate registry 提供。
#[derive(Debug, Clone, PartialEq, Eq)]
enum StepKind {
    Internal(InternalCheck),
    LocalOnlyExecution,
    Cargo,
    /// The three runtime governance lints live in the nested nightly workspace; cwd and package
    /// closure are represented by this variant instead of caller-controlled argv.
    LintWorkspaceTests,
    Nextest,
}

/// 单个门步。`program` 恒为 `cargo`，故只存 `args`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Step {
    id: GateId,
    args: &'static [&'static str],
    kind: StepKind,
    /// 该步额外设置的环境变量（如 dylint 的 `DYLINT_RUSTFLAGS=-D warnings` 把 lint 升为 fail-closed）。
    env: &'static [(&'static str, &'static str)],
}

impl Step {
    pub(crate) fn label(&self) -> &'static str {
        self.id.spec().label()
    }

    #[cfg(test)]
    fn needs_compile(&self) -> bool {
        self.id.spec().compile_kind() != CompileKind::NoCompile
    }

    fn uses_nextest(&self) -> bool {
        matches!(self.kind, StepKind::Nextest | StepKind::LocalOnlyExecution)
            || matches!(self.kind, StepKind::Internal(InternalCheck::Coverage))
    }

    /// 该步对应的 xtask carrier 源文件——仅 in-process 检查（`Internal` / `ToolGatedInternal`）有；
    /// `CargoBuiltin`（fmt/build/clippy…）与外部 `Tool`（deny/audit/dylint/nextest）非 archrules carrier，返回 `None`。
    /// 供 gate↔plan 绑定测试遍历（ARCHRULES-GATE-PLAN-BIND-01，#1574）。
    #[cfg(test)]
    pub(crate) fn carrier_file(&self) -> Option<&'static str> {
        self.id.carrier_file()
    }
}

/// 缺工具决策（纯函数，INVARIANT VERIFY-TOOL-GATE-01）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolAction {
    /// 工具在 → 跑该步。
    Run,
    /// 工具缺 + 显式宽限 → 警告跳过。
    SkipWarn,
    /// 工具缺 + 未宽限 → fail-closed。
    Fail,
}

// ---- 门步构造（单一事实源）。verify 与 ci 共用 fmt/meta/deny/dylint 的同一构造，杜绝两份计划漂移。----

fn step_fmt() -> Step {
    Step {
        id: GateId::Fmt,
        args: &["fmt", "--all", "--", "--check"],
        kind: StepKind::Cargo,
        env: &[],
    }
}
fn step_contract_validate() -> Step {
    Step {
        id: GateId::ContractValidate,
        args: &[],
        kind: StepKind::Internal(InternalCheck::ContractValidate),
        env: &[],
    }
}
fn step_assembly_validate() -> Step {
    Step {
        id: GateId::AssemblyValidate,
        args: &[],
        kind: StepKind::Internal(InternalCheck::AssemblyValidate),
        env: &[],
    }
}
fn step_assembly_artifacts_check() -> Step {
    Step {
        id: GateId::AssemblyArtifactsCheck,
        args: &[],
        kind: StepKind::Internal(InternalCheck::AssemblyArtifactsCheck),
        env: &[],
    }
}
fn step_assembly_modules_check() -> Step {
    Step {
        id: GateId::AssemblyModulesCheck,
        args: &[],
        kind: StepKind::Internal(InternalCheck::AssemblyModulesCheck),
        env: &[],
    }
}
fn step_assembly_providers_check() -> Step {
    Step {
        id: GateId::AssemblyProvidersCheck,
        args: &[],
        kind: StepKind::Internal(InternalCheck::AssemblyProvidersCheck),
        env: &[],
    }
}
fn step_assembly_lock_check() -> Step {
    Step {
        id: GateId::AssemblyLockCheck,
        args: &[],
        kind: StepKind::Internal(InternalCheck::AssemblyLockCheck),
        env: &[],
    }
}
fn step_assembly_runtime_plan_check() -> Step {
    Step {
        id: GateId::AssemblyRuntimePlanCheck,
        args: &[],
        kind: StepKind::Internal(InternalCheck::AssemblyRuntimePlanCheck),
        env: &[],
    }
}
fn step_assembly_graph_check() -> Step {
    Step {
        id: GateId::AssemblyGraphCheck,
        args: &[],
        kind: StepKind::Internal(InternalCheck::AssemblyGraphCheck),
        env: &[],
    }
}
fn step_contract_breaking() -> Step {
    Step {
        id: GateId::ContractBreaking,
        args: &[],
        kind: StepKind::Internal(InternalCheck::ContractBreaking),
        env: &[],
    }
}
fn step_layer_deps() -> Step {
    Step {
        id: GateId::LayerDeps,
        args: &[],
        kind: StepKind::Internal(InternalCheck::LayerDeps),
        env: &[],
    }
}
fn step_shipped_feature_guard() -> Step {
    Step {
        id: GateId::ShippedFeatureGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::ShippedFeatureGuard),
        env: &[],
    }
}
fn step_wsdeps_drift() -> Step {
    Step {
        id: GateId::WsDepsDrift,
        args: &[],
        kind: StepKind::Internal(InternalCheck::WsDepsDrift),
        env: &[],
    }
}
fn step_source_semantic_guard() -> Step {
    Step {
        id: GateId::SourceSemanticGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::SourceSemanticGuard),
        env: &[],
    }
}
fn step_saga_durable_recovery_guard() -> Step {
    Step {
        id: GateId::SagaDurableRecoveryGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::SagaDurableRecoveryGuard),
        env: &[],
    }
}
fn step_promtool_rules() -> Step {
    Step {
        id: GateId::PromtoolRules,
        args: &[],
        kind: StepKind::Internal(InternalCheck::PromtoolRules),
        env: &[],
    }
}
fn step_outbox_same_id_guard() -> Step {
    Step {
        id: GateId::OutboxSameIdGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::OutboxSameIdGuard),
        env: &[],
    }
}
fn step_consistency_fixtures() -> Step {
    Step {
        id: GateId::ConsistencyFixtures,
        args: &[],
        kind: StepKind::Internal(InternalCheck::ConsistencyFixtures),
        env: &[],
    }
}
fn step_event_transport_guard() -> Step {
    Step {
        id: GateId::EventTransportGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::EventTransportGuard),
        env: &[],
    }
}
fn step_inbox_cutover_guard() -> Step {
    Step {
        id: GateId::InboxCutoverGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::InboxCutoverGuard),
        env: &[],
    }
}
fn step_dlx_lifecycle_funnel() -> Step {
    Step {
        id: GateId::DlxLifecycleFunnel,
        args: &[],
        kind: StepKind::Internal(InternalCheck::DlxLifecycleFunnel),
        env: &[],
    }
}
fn step_runtime_baseline() -> Step {
    Step {
        id: GateId::RuntimeBaseline,
        args: &[],
        kind: StepKind::Internal(InternalCheck::RuntimeBaseline),
        env: &[],
    }
}
fn step_runtime_root_guard() -> Step {
    Step {
        id: GateId::RuntimeRootGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::RuntimeRootGuard),
        env: &[],
    }
}
fn step_runtime_env_guard() -> Step {
    Step {
        id: GateId::RuntimeEnvGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::RuntimeEnvGuard),
        env: &[],
    }
}
fn step_runtime_deps_guard() -> Step {
    Step {
        id: GateId::RuntimeDepsGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::RuntimeDepsGuard),
        env: &[],
    }
}
fn step_archrules() -> Step {
    Step {
        id: GateId::ArchRules,
        args: &[],
        kind: StepKind::Internal(InternalCheck::ArchRules),
        env: &[],
    }
}
fn step_codegen_check() -> Step {
    Step {
        id: GateId::CodegenCheck,
        args: &[],
        kind: StepKind::Internal(InternalCheck::CodegenCheck),
        env: &[],
    }
}
fn step_l2_assurance_check() -> Step {
    Step {
        id: GateId::L2AssuranceCheck,
        args: &[],
        kind: StepKind::Internal(InternalCheck::L2AssuranceCheck),
        env: &[],
    }
}
fn step_provider_capabilities_check() -> Step {
    Step {
        id: GateId::ProviderCapabilitiesCheck,
        args: &[],
        kind: StepKind::Internal(InternalCheck::ProviderCapabilitiesCheck),
        env: &[],
    }
}
fn step_localtx_coverage() -> Step {
    Step {
        id: GateId::LocalTxCoverage,
        args: &[],
        kind: StepKind::Internal(InternalCheck::LocalTxCoverage),
        env: &[],
    }
}
fn step_local_only_effects() -> Step {
    Step {
        id: GateId::LocalOnlyEffects,
        args: &[],
        kind: StepKind::Internal(InternalCheck::LocalOnlyEffects),
        env: &[],
    }
}
fn step_local_only_execution() -> Step {
    Step {
        id: GateId::LocalOnlyExecution,
        args: &[],
        kind: StepKind::LocalOnlyExecution,
        env: &[],
    }
}
fn step_pdp_allow_guard() -> Step {
    Step {
        id: GateId::PdpAllowGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::PdpAllowGuard),
        env: &[],
    }
}
fn step_contract_binding_guard() -> Step {
    Step {
        id: GateId::ContractBindingGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::ContractBindingGuard),
        env: &[],
    }
}
fn step_schema_rls_guard() -> Step {
    Step {
        id: GateId::SchemaRls,
        args: &[],
        kind: StepKind::Internal(InternalCheck::SchemaRlsGuard),
        env: &[],
    }
}
fn step_pg_tenant_tx_guard() -> Step {
    Step {
        id: GateId::PgTenantTxGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::PgTenantTxGuard),
        env: &[],
    }
}
fn step_repo_scope_guard() -> Step {
    Step {
        id: GateId::RepoScopeGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::RepoScopeGuard),
        env: &[],
    }
}
fn step_tenancy_closeout() -> Step {
    Step {
        id: GateId::TenancyCloseout,
        args: &[],
        kind: StepKind::Internal(InternalCheck::TenancyCloseout),
        env: &[],
    }
}
fn step_command_symmetry() -> Step {
    Step {
        id: GateId::CommandSymmetry,
        args: &[],
        kind: StepKind::Internal(InternalCheck::CommandSymmetry),
        env: &[],
    }
}
fn step_ci_entry_guard() -> Step {
    Step {
        id: GateId::CiEntryGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::CiEntryGuard),
        env: &[],
    }
}
fn step_reconcile_outbox_command_guard() -> Step {
    Step {
        id: GateId::ReconcileOutboxCommandGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::ReconcileOutboxCommandGuard),
        env: &[],
    }
}
fn step_defer_gate() -> Step {
    Step {
        id: GateId::DeferGate,
        args: &[],
        kind: StepKind::Internal(InternalCheck::DeferGate),
        env: &[],
    }
}
fn step_deny() -> Step {
    Step {
        id: GateId::Deny,
        args: &["deny", "check"],
        kind: StepKind::Cargo,
        env: &[],
    }
}
/// audit 定时 lane 专用：advisory-scoped `cargo deny check advisories`（只查 RustSec 漏洞库，
/// licenses/bans 留给 PR-triggered adaptive plan 的 [`step_deny`]）。issue #1133 每日 cron 只刷新漏洞维度。
fn step_deny_advisories() -> Step {
    Step {
        id: GateId::DenyAdvisories,
        args: &["deny", "check", "advisories"],
        kind: StepKind::Cargo,
        env: &[],
    }
}
/// 供应链漏洞门（issue #1133）：`cargo audit` 查 RustSec advisory-db，命中漏洞即非零退出。
/// 与 [`step_deny_advisories`] 同查 RustSec 的**独立第二实现**（防御纵深，防 deny.toml advisories 配置被
/// 误改架空）。朴素形（无 `--deny warnings`）：仅漏洞致非零，unmaintained/yanked 仅 warn。这**不**漏检
/// yanked——deny.toml `yanked = "deny"` 使**同 plan 并跑的** deny 门（ci 的全量 `deny check` / audit lane 的
/// [`step_deny_advisories`]）对 yanked 即非零退出；cargo-audit 无需重复 deny yanked，二者在**漏洞**维度对齐、
/// 避免一门红一门绿。
///
/// `--ignore` = cargo-audit 侧 ignore 单源（cwd-无关、机器可见，不依赖 audit.toml 自动发现——已实测 cargo-audit
/// 不从 cwd 加载 `audit.toml`）。两门 ignore 一致性（deny.toml ⊆ 本 ignore 集）由
/// `deny_audit_ignore_lists_reconciled` 守。
///
/// **RUSTSEC-2023-0071（rsa Marvin Attack）**：rsa 是 **phantom Cargo.lock 条目**——`cargo audit`（扫 Cargo.lock
/// 全量）报，但 `cargo deny advisories`（按 feature-resolved 依赖图，all-features）**不**报，且
/// `cargo tree -i rsa --all-features --target all` 为空 ⇒ 任何 feature/target 组合下都**不编译进产物**、无暴露面。
/// 且该 advisory「无可升级修复版」。故按 phantom-only 形态 ignore（deny 侧无需 ignore——其图里根本没有 rsa）。
fn step_cargo_audit() -> Step {
    Step {
        id: GateId::CargoAudit,
        args: &["audit", "--ignore", "RUSTSEC-2023-0071"],
        kind: StepKind::Cargo,
        env: &[],
    }
}

/// 从 cargo-audit 步 args 提取 ignore 的 advisory ID 集（每个 `--ignore` 后紧跟的 token）。
/// cargo-audit 侧 ignore 单源——`deny_audit_ignore_lists_reconciled` 据此与 deny.toml ignore 对账。
#[cfg(test)]
fn cargo_audit_ignored_ids() -> Vec<&'static str> {
    let args = step_cargo_audit().args;
    args.iter()
        .enumerate()
        .filter_map(|(i, &a)| {
            (a == "--ignore")
                .then(|| args.get(i + 1))
                .flatten()
                .copied()
        })
        .collect()
}
fn step_dylint() -> Step {
    Step {
        id: GateId::Dylint,
        args: &["dylint", "--all"],
        kind: StepKind::Cargo,
        // `rss_domain_no_serialize` 默认 `Warn`（warning 不退非零）；`-D warnings` 把它（及其它
        // 注册 lint）升为 deny ⇒ 违例即非零退出，使 dylint 成 fail-closed 门（#1023 的核心诉求）。
        // 已验证干净树下 exit 0、无 nightly 误报。
        env: &[("DYLINT_RUSTFLAGS", "-D warnings")],
    }
}

/// #1495：测试目标面禁裸 sleep。`--all-features --all-targets` 扫 `#[cfg(test)]` / tests/，
/// 并避免 workspace feature 统一启用 `testkit/containers` 时 optional dep 未齐导致的假红。
/// 与 `step_dylint`（默认不带 `--all-targets`）分立，保护其它 lint 的 cfg(test) 盲区。
fn step_dylint_test_no_bare_sleep() -> Step {
    Step {
        id: GateId::DylintTestNoBareSleep,
        args: &[
            "dylint",
            "--lib",
            "rss_test_no_bare_sleep",
            "--",
            "--all-features",
            "--all-targets",
        ],
        kind: StepKind::Cargo,
        // 只升本 lint：`--all-features` 会编到无关 crate，勿用全局 `-D warnings` 把 nightly 噪音变假红。
        env: &[("DYLINT_RUSTFLAGS", "-D rss_test_no_bare_sleep")],
    }
}

fn step_dylint_workspace_ui_tests() -> Step {
    Step {
        id: GateId::DylintWorkspaceUiTests,
        args: &["test", "--locked", "--workspace"],
        kind: StepKind::LintWorkspaceTests,
        env: &[],
    }
}

// verify 专用：workspace 默认 feature 的 build/clippy/nextest（stable-only 本地快门）。
fn step_build_workspace() -> Step {
    Step {
        id: GateId::BuildWorkspace,
        args: &["build", "--workspace"],
        kind: StepKind::Cargo,
        env: &[],
    }
}
fn step_postgres_feature_matrix() -> Step {
    Step {
        id: GateId::PostgresFeatureMatrix,
        args: &[],
        kind: StepKind::Internal(InternalCheck::PostgresFeatureMatrix),
        env: &[],
    }
}
/// F7 + #1137：postgres/redis/amqp 等集成测试由 Cargo `[[test]] required-features`（catalog
/// LocalEligibility / INTEGRATION-SHARD-ELIGIBILITY-01）门控，verify 的 build/clippy/nextest 仅
/// workspace 默认 feature ⇒ 关键状态机测试（崩溃重投 / CAS fencing / DLX / sweep / redis 幂等 /
/// amqp pub-sub + 跨 vhost / durable journey）默认门外、回归漏网。本步 `--no-run` 仅编译（不跑、
/// 无需真实后端 / docker）纳入默认 verify 抓**编译漂移**；有 docker / env URL 时经
/// 固定 `integration-critical` Job 按 typed selection 实跑。远端 check 经 `--all-features --all-targets`
/// 已覆盖该编译面，故 release-check 通过 typed subsumption 只保留 all-features owner。
fn step_integration_compile() -> Step {
    Step {
        id: GateId::IntegrationCompile,
        args: &[
            "test",
            "-p",
            "postgres",
            "-p",
            "redis-adapter",
            "-p",
            "amqp",
            "-p",
            "mqtt",
            "-p",
            "journeys",
            "-p",
            "runtime",
            "--features",
            "integration,mqtt/broker-tests",
            "--no-run",
        ],
        kind: StepKind::Cargo,
        env: &[],
    }
}

fn step_clippy_workspace() -> Step {
    Step {
        id: GateId::ClippyWorkspace,
        args: &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        kind: StepKind::Cargo,
        env: &[],
    }
}
fn core_test_step(id: GateId) -> Step {
    let GateExecutor::CoreTest = id.spec().executor() else {
        unreachable!("{id:?} must use the typed core-test executor")
    };
    Step {
        id,
        args: &[],
        kind: StepKind::Nextest,
        env: &[],
    }
}

fn step_component_tests() -> Step {
    core_test_step(GateId::ComponentTests)
}

/// Prove production password test constructors stay absent in an isolated Cargo feature graph.
/// Workspace test graphs legitimately unify `secure/test-support` through identity seed fixtures.
fn step_secure_production_trybuild() -> Step {
    Step {
        id: GateId::SecureProductionTrybuild,
        args: &[
            "test",
            "-p",
            "secure",
            "--no-default-features",
            "--test",
            "trybuild",
            "production_seams_absent",
            "--",
            "--exact",
        ],
        kind: StepKind::Cargo,
        env: &[],
    }
}

// ci 专用：build/clippy 升 `--all-features --all-targets`（编译态全覆盖，含 integration-gated 代码——
// 仅编译不运行 ⇒ 无需 DB/broker）；覆盖率门替 nextest（兼跑 workspace 测试 + basis/engine ≥90%）；
// public-api --check（轴 A）。
// ci 的 cargo 门带 `--locked`：CI 确定性构建——Cargo.lock 缺失/漂移即 fail（不静默改锁），与
// `cargo run --locked -p xtask -- ci` 入口共同锁全链（入口锁 xtask 子树，build --workspace --locked 锁
// 全 workspace 依赖解析）。verify（本地快门）**不**带 --locked，留本地迭代余地（review #206 codex F2）。
fn step_build_all_features() -> Step {
    Step {
        id: GateId::BuildAllFeatures,
        args: &[
            "build",
            "--workspace",
            "--all-features",
            "--all-targets",
            "--locked",
        ],
        kind: StepKind::Cargo,
        env: &[],
    }
}
fn step_clippy_all_features() -> Step {
    Step {
        id: GateId::ClippyAllFeatures,
        args: &[
            "clippy",
            "--workspace",
            "--all-features",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        kind: StepKind::Cargo,
        env: &[],
    }
}
fn step_coverage() -> Step {
    Step {
        id: GateId::Coverage,
        args: &[],
        kind: StepKind::Internal(InternalCheck::Coverage),
        env: &[],
    }
}
fn step_public_api() -> Step {
    Step {
        id: GateId::PublicApi,
        args: &[],
        kind: StepKind::Internal(InternalCheck::PublicApiCheck),
        env: &[],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanProjection {
    Profile(ExecutionProfile),
    Verify,
    Lane(GateGroup),
}

fn selected_for(target: PlanProjection, id: GateId) -> bool {
    let spec = id.spec();
    match target {
        PlanProjection::Profile(profile) => spec.included_in_profile(profile),
        PlanProjection::Lane(GateGroup::Core) => {
            matches!(
                spec.executor(),
                GateExecutor::CorePrerequisite | GateExecutor::CoreTest
            ) && (spec.included_in_profile(ExecutionProfile::ReleaseCheck)
                || matches!(spec.executor(), GateExecutor::CoreTest))
        }
        PlanProjection::Lane(lane) => spec.belongs_to(lane),
        PlanProjection::Verify => [ExecutionProfile::Check, ExecutionProfile::Test]
            .into_iter()
            .any(|profile| selected_for(PlanProjection::Profile(profile), id)),
    }
}

pub(crate) fn plan_for(target: PlanProjection) -> Vec<Step> {
    let profiles: &[ExecutionProfile] = match target {
        PlanProjection::Profile(ExecutionProfile::Check) => &[ExecutionProfile::Check],
        PlanProjection::Profile(ExecutionProfile::Test) => &[ExecutionProfile::Test],
        PlanProjection::Profile(ExecutionProfile::IntegrationCritical) => {
            &[ExecutionProfile::IntegrationCritical]
        }
        PlanProjection::Profile(ExecutionProfile::ReleaseCheck)
        | PlanProjection::Lane(
            GateGroup::Meta
            | GateGroup::Security
            | GateGroup::Coverage
            | GateGroup::LocalOnly
            | GateGroup::Nightly,
        ) => &[ExecutionProfile::ReleaseCheck],
        PlanProjection::Verify => &[ExecutionProfile::Check, ExecutionProfile::Test],
        PlanProjection::Lane(GateGroup::Core) => {
            &[ExecutionProfile::ReleaseCheck, ExecutionProfile::Test]
        }
    };
    let candidates = profiles
        .iter()
        .copied()
        .flat_map(ExecutionUnitSpec::project)
        .map(ExecutionUnitSpec::id)
        .collect::<std::collections::BTreeSet<_>>();
    let mut plan = ExecutionUnitSpec::all()
        .filter_map(|unit| match unit {
            ExecutionUnitSpec::Gate(spec) => Some(spec.id()),
            ExecutionUnitSpec::Integration(_) => None,
        })
        .filter(|id| {
            candidates.contains(&crate::execution_profiles::ExecutionUnitId::Gate(*id))
                && selected_for(target, *id)
        })
        .map(step_for_id)
        .collect::<Vec<_>>();
    if target == PlanProjection::Lane(GateGroup::Nightly) {
        plan.sort_by_key(|step| usize::from(step.id == GateId::CargoAudit));
    }
    plan
}

macro_rules! define_step_dispatch {
    ($( $id:ident => ($step:ident, $carrier:expr, $spec:expr), )*) => {
        fn step_for_id(id: GateId) -> Step {
            let step = match id { $( GateId::$id => $step(), )* };
            debug_assert_eq!(step.id, id);
            step
        }
    };
}
crate::ci_lanes::gate_catalog!(define_step_dispatch);

/// audit 精简供应链门步计划（issue #1133；统一 GitHub CI typed Audit job）。
/// advisory-scoped deny + cargo-audit 两门，皆 no-compile、快——定时刷新只查漏洞库（捕获「未变依赖」新
/// 披露 CVE）。**不含** licenses/bans：它们只随 Cargo.lock 变（= 随 PR 变），定时跑无增益；
/// `release-check` 计划已用全量 `deny check` + cargo-audit 覆盖。audit 步与 ci 共享同一
/// [`step_cargo_audit`] 构造。
///
/// Audit 亦经统一动态 executor 委托（不内联门命令），由 `CI-ADAPTIVE-WORKFLOW-01` 守。
fn audit_plan() -> Vec<Step> {
    plan_for(PlanProjection::Lane(GateGroup::Nightly))
}

/// docker daemon 是否可达（容器 self-provision 前置；`docker version` 退出 0）。经 [`crate::cmd::external_cmd`]
/// 漏斗构造（CMD-FUNNEL-01；docker 非 cargo 子命令，故不走 [`crate::cmd::tool_available`]）。
fn docker_available() -> bool {
    crate::cmd::external_cmd(crate::cmd::ExternalProgram::Docker, &["version"], &[], None)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

const INTEGRATION_ENV: &[(&str, &str)] = &[(
    "RSS_AUDIT_CHAIN_KEY_B64URL",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
)];

fn run_integration_batches(
    selection: &IntegrationSelection,
    shard: IntegrationShard,
    partition: Option<crate::nextest::HashPartition>,
    root: &Path,
    execution_policy: crate::cmd::ExecutionPolicy,
) -> Result<()> {
    let lane = shard.as_str();
    let batches = integration_shards::batches(selection, shard);
    execute_labeled_items(
        &format!("ci-integration/{lane}"),
        &batches,
        execution_policy,
        &SystemAggregateClock,
        |batch: &integration_shards::ShardBatch| match batch.scheduling {
            Scheduling::Serial => "serial".to_owned(),
            Scheduling::Parallel => "parallel".to_owned(),
        },
        |batch| {
            crate::nextest::NextestInvocation::for_integration_batch(selection, batch, partition)?
                .run(root, INTEGRATION_ENV)
        },
    )
}

fn run_ci_integration_with_policy(
    workspace: &integration_shards::ValidatedIntegrationWorkspace<'_>,
    shard: IntegrationShard,
    selection: &IntegrationSelection,
    allow_missing_tools: bool,
    partition: Option<crate::nextest::HashPartition>,
    execution_policy: crate::cmd::ExecutionPolicy,
) -> Result<()> {
    shard.validate_partition(partition)?;
    validate_integration_selection_for_shard(selection, shard)?;
    let root = workspace.root();
    let missing = integration_shards::missing_external_resources(selection, shard);
    if (selection.requires_docker_for_shard(shard) || !missing.is_empty()) && !docker_available() {
        let labels = missing
            .iter()
            .map(|resource| resource.label())
            .collect::<Vec<_>>()
            .join(", ");
        let requirement = if labels.is_empty() {
            "shard 声明的 Docker capability".to_owned()
        } else {
            format!("缺少外部资源: {labels}")
        };
        if allow_missing_tools {
            eprintln!("ci-integration/{shard}: [跳过] docker daemon 不可达，且{requirement}");
            return Ok(());
        }
        bail!(
            "ci-integration/{shard}: docker daemon 不可达，且{requirement}; \
             启动 Docker、提供该 shard 的外部测试资源，或本地显式使用 --allow-missing-tools"
        );
    }
    let ran = crate::nextest::run_gated(
        &format!("ci-integration/{shard}"),
        allow_missing_tools,
        "integration shard",
        || run_integration_batches(selection, shard, partition, root, execution_policy),
    )?;
    if ran.is_some() {
        eprintln!("ci-integration/{shard}: 全部通过");
    } else {
        eprintln!("ci-integration/{shard}: 执行完成（缺 nextest，shard 已跳过）");
    }
    Ok(())
}

pub(crate) fn run_nextest_replay(
    selection: &IntegrationSelection,
    shard: IntegrationShard,
    unit_ids: &std::collections::BTreeSet<IntegrationUnitId>,
    partition: Option<crate::nextest::HashPartition>,
) -> Result<()> {
    shard.validate_partition(partition)?;
    let root = workspace_root()?;
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
    integration_shards::with_validated_workspace(&command_facts, |workspace| {
        let matching = integration_shards::batches(selection, shard)
            .into_iter()
            .filter(|batch| &batch.unit_ids == unit_ids)
            .collect::<Vec<_>>();
        let [batch] = matching.as_slice() else {
            bail!("integration replay unitIds must uniquely match a selection-derived batch");
        };
        crate::nextest::NextestInvocation::for_integration_batch(selection, batch, partition)?
            .run(workspace.root(), INTEGRATION_ENV)
    })
}

/// 纯函数：`--fast` 只保留 registry 显式声明的 Always 本地 meta gate。
fn verify_plan(opts: &VerifyOpts) -> Vec<Step> {
    let plan = plan_for(PlanProjection::Verify);
    if opts.fast {
        plan.into_iter()
            .filter(|step| matches!(step.id.local_meta_policy(), LocalMetaPolicy::Always))
            .collect()
    } else {
        plan
    }
}

/// 缺工具决策（纯）。INVARIANT VERIFY-TOOL-GATE-01：缺工具默认 fail-closed，豁免仅经显式宽限。
fn resolve_tool(available: bool, allow_missing: bool) -> ToolAction {
    match (available, allow_missing) {
        (true, _) => ToolAction::Run,
        (false, true) => ToolAction::SkipWarn,
        (false, false) => ToolAction::Fail,
    }
}

/// spawn 一个 cargo 门步，继承 stdio（用户实时看输出），校验退出码。
/// INVARIANT VERIFY-AGGREGATE-01：非零退出 ⇒ `Err`（不吞错）。
fn run_step(
    lane: &str,
    label: &str,
    subcommand: crate::cmd::CargoSubcommand,
    args: &[&str],
    env: &[(&str, &str)],
    cwd: &Path,
    execution_policy: crate::cmd::ExecutionPolicy,
) -> Result<()> {
    let args = cargo_args_for_policy(subcommand, args, execution_policy);
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let rendered = std::iter::once(subcommand.as_str())
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    let status = crate::cmd::cargo_cmd(subcommand, &args, env, Some(cwd))
        .status()
        .map_err(|e| {
            anyhow::anyhow!("{lane}: 启动门步 `{label}`（cargo {}）失败: {e}", rendered)
        })?;
    if status.success() {
        return Ok(());
    }
    let code = status
        .code()
        .map_or_else(|| "signal".to_owned(), |c| c.to_string());
    bail!(
        "{lane}: 门步 `{label}` 失败（cargo {} 退出码 {code}）",
        rendered
    )
}

fn cargo_args_for_policy(
    subcommand: crate::cmd::CargoSubcommand,
    args: &[&str],
    execution_policy: crate::cmd::ExecutionPolicy,
) -> Vec<String> {
    let mut owned = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    let flag = if execution_policy.keeps_going() {
        match subcommand {
            crate::cmd::CargoSubcommand::Build
            | crate::cmd::CargoSubcommand::Check
            | crate::cmd::CargoSubcommand::Clippy => Some("--keep-going"),
            crate::cmd::CargoSubcommand::Test => Some("--no-fail-fast"),
            _ => None,
        }
    } else {
        None
    };
    if let Some(flag) = flag {
        let insert_at = owned
            .iter()
            .position(|arg| arg == "--")
            .unwrap_or(owned.len());
        owned.insert(insert_at, flag.to_owned());
    }
    owned
}

/// 跑单步：Internal 进程内执行；CargoBuiltin 直接 spawn；Tool 先探测再按决策分派。
fn run_one(
    lane: &str,
    step: &Step,
    opts: &VerifyOpts,
    root: &Path,
    command_facts: &crate::workspace_facts::CommandWorkspaceFacts,
    tool_available: impl Fn(crate::cmd::CargoSubcommand) -> bool,
) -> Result<()> {
    let execute = || match step.kind {
        StepKind::Internal(check) => run_internal(check, opts, root, command_facts),
        StepKind::LocalOnlyExecution => {
            let facts = command_facts
                .get()
                .context(command_scope_facts_context("localonly-evidence"))?;
            let request = crate::localonly_evidence::prepare_request(
                crate::localonly_evidence::OWNER,
                None,
                root,
            )?
            .context("verify must prepare LocalOnly execution evidence")?;
            crate::localonly_evidence::execute(root, facts, request, opts.execution_policy)
                .map(|_| ())
        }
        StepKind::Nextest => crate::nextest::NextestInvocation::for_core(
            opts.core_test_selection.clone(),
            opts.nextest_lane,
            opts.partition,
        )
        .with_execution_policy(opts.execution_policy)
        .run(root, step.env),
        StepKind::LintWorkspaceTests => {
            let subcommand = crate::cmd::CargoSubcommand::Test;
            let args = step
                .args
                .strip_prefix(&[subcommand.as_str()])
                .context("runtime Dylint UI gate typed test prefix drift")?;
            run_step(
                lane,
                step.label(),
                subcommand,
                args,
                step.env,
                &root.join("lints"),
                opts.execution_policy,
            )
        }
        StepKind::Cargo => {
            let subcommand = match step.id.spec().tool() {
                ToolRequirement::CargoTool { tool, .. } => tool,
                ToolRequirement::CargoBuiltin(subcommand) => subcommand,
                _ => bail!("{}: cargo step 缺 typed subcommand", step.label()),
            };
            let args = step
                .args
                .strip_prefix(&[subcommand.as_str()])
                .ok_or_else(|| {
                    anyhow::anyhow!("{}: typed cargo subcommand 与 argv 漂移", step.label())
                })?;
            run_step(
                lane,
                step.label(),
                subcommand,
                args,
                step.env,
                root,
                opts.execution_policy,
            )
        }
    };
    match step.id.spec().tool() {
        ToolRequirement::InProcess | ToolRequirement::CargoBuiltin(_) => execute(),
        ToolRequirement::Nextest => run_nextest_step_gated(
            lane,
            step,
            opts.allow_missing_tools,
            crate::nextest::is_available,
            execute,
        )
        .map(|_| ()),
        ToolRequirement::CoverageTools => run_coverage_tools_gated(
            lane,
            opts.allow_missing_tools,
            step.label(),
            tool_available(crate::cmd::CargoSubcommand::LlvmCovReport),
            crate::nextest::is_available,
            execute,
        ),
        ToolRequirement::CargoTool { tool, install_hint } => run_tool_gated(
            lane,
            tool_available(tool),
            opts.allow_missing_tools,
            tool.as_str(),
            install_hint,
            step.label(),
            execute,
        ),
    }
}

/// LocalOnly runtime evidence is a required full-verify claim, so the generic
/// `--allow-missing-tools` developer convenience must never turn it into a skip.
fn run_nextest_step_gated<T>(
    lane: &str,
    step: &Step,
    allow_missing_tools: bool,
    nextest_available: impl FnOnce() -> bool,
    execute: impl FnOnce() -> Result<T>,
) -> Result<Option<T>> {
    let allow_missing = allow_missing_tools && !matches!(&step.kind, StepKind::LocalOnlyExecution);
    crate::nextest::run_gated_with_probe(
        lane,
        allow_missing,
        step.label(),
        nextest_available,
        execute,
    )
}

fn run_coverage_tools_gated(
    lane: &str,
    allow_missing: bool,
    label: &str,
    llvm_cov_available: bool,
    nextest_available: impl FnOnce() -> bool,
    on_run: impl FnOnce() -> Result<()>,
) -> Result<()> {
    run_tool_gated(
        lane,
        llvm_cov_available,
        allow_missing,
        crate::cmd::CargoSubcommand::LlvmCovReport.as_str(),
        crate::ci_lanes::LLVM_COV_HINT,
        label,
        || {
            crate::nextest::run_gated_with_probe(
                lane,
                allow_missing,
                label,
                nextest_available,
                on_run,
            )
            .map(|_| ())
        },
    )
}

/// Registry 声明的工具门控分派：探测结果 + 宽限标志经
/// [`resolve_tool`] 决策——在则跑 `on_run`，缺+宽限则警告跳过，缺+不宽限则 fail-closed
/// （INVARIANT VERIFY-TOOL-GATE-01）。
fn run_tool_gated(
    lane: &str,
    available: bool,
    allow_missing: bool,
    probe: &str,
    install_hint: &str,
    label: &str,
    on_run: impl FnOnce() -> Result<()>,
) -> Result<()> {
    match resolve_tool(available, allow_missing) {
        ToolAction::Run => on_run(),
        ToolAction::SkipWarn => {
            eprintln!(
                "{lane}: [跳过] `{label}`（缺 `cargo {probe}`，--allow-missing-tools 宽限）。装：{install_hint}"
            );
            Ok(())
        }
        ToolAction::Fail => bail!(
            "{lane}: 缺 `cargo {probe}`（门步 `{label}`）。装：{install_hint}\n（门不建议绕过；确需可显式 --allow-missing-tools）"
        ),
    }
}

fn command_scope_facts_context(label: &str) -> String {
    format!("{label}: load command-scoped workspace facts")
}

fn run_internal(
    check: InternalCheck,
    opts: &VerifyOpts,
    root: &Path,
    command_facts: &crate::workspace_facts::CommandWorkspaceFacts,
) -> Result<()> {
    match check {
        InternalCheck::ContractValidate => run_check(&contract::validate::ContractValidate),
        InternalCheck::AssemblyValidate => run_check(&assembly::AssemblyValidate::new(
            root,
            command_facts
                .get()
                .context(command_scope_facts_context("assembly-validate"))?,
        )),
        InternalCheck::AssemblyArtifactsCheck => run_assembly_artifacts_check(
            root,
            command_facts,
            crate::assembly_artifacts::report_workspace_facts_failure,
        ),
        InternalCheck::AssemblyModulesCheck => crate::assembly_codegen::run(true),
        InternalCheck::AssemblyProvidersCheck => crate::assembly_codegen::run_providers(true),
        InternalCheck::AssemblyLockCheck => assembly_lock::run(
            root,
            assembly_lock::AssemblyLockAction::Check,
            command_facts
                .get()
                .context(command_scope_facts_context("assembly-lock-check"))?,
        ),
        InternalCheck::AssemblyRuntimePlanCheck => crate::assembly_runtime_plan::run(true),
        InternalCheck::AssemblyGraphCheck => crate::graph::run(
            root,
            &crate::graph::Options::check_runtime(),
            command_facts
                .get()
                .context(command_scope_facts_context("assembly-graph-check"))?,
        ),
        // active 默认 deny；固定 review rules 为 warn，但未确认 fail-closed。
        InternalCheck::ContractBreaking => contract::breaking::run(&opts.contract_against),
        InternalCheck::LayerDeps => run_check(&layerdeps::LayerDeps),
        InternalCheck::ShippedFeatureGuard => {
            let facts = command_facts
                .get()
                .context(command_scope_facts_context("shipped-feature-guard"))?;
            run_check(&shipped_feature_guard::ShippedFeatureGuard::new(facts))
        }
        InternalCheck::WsDepsDrift => run_check(&wsdeps::WsDepsDrift),
        InternalCheck::PromtoolRules => crate::promtool::run(),
        InternalCheck::OutboxSameIdGuard => {
            run_check(&crate::outbox_same_id_guard::OutboxSameIdGuard)
        }
        InternalCheck::ConsistencyFixtures => run_check(&consistency_fixtures::ConsistencyFixtures),
        InternalCheck::EventTransportGuard => {
            run_check(&crate::event_transport_guard::EventTransportGuard)
        }
        InternalCheck::InboxCutoverGuard => {
            run_check(&crate::inbox_cutover_guard::InboxCutoverGuard)
        }
        InternalCheck::DlxLifecycleFunnel => {
            run_check(&crate::dlx_lifecycle_funnel::DlxLifecycleFunnel)
        }
        InternalCheck::RuntimeBaseline => run_check(&runtime_baseline::RuntimeBaseline),
        InternalCheck::RuntimeRootGuard => run_check(&runtime_root_guard::RuntimeRootGuard),
        InternalCheck::RuntimeEnvGuard => run_check(&runtime_env_guard::RuntimeEnvGuard),
        InternalCheck::RuntimeDepsGuard => run_check(&runtime_deps_guard::RuntimeDepsGuard),
        InternalCheck::SourceSemanticGuard => {
            run_check(&crate::source_semantic_guard::SourceSemanticGuard)
        }
        InternalCheck::SagaDurableRecoveryGuard => {
            run_check(&crate::saga_durable_recovery_guard::SagaDurableRecoveryGuard)
        }
        InternalCheck::ArchRules => run_check(&archrules::ArchRules),
        InternalCheck::CodegenCheck => codegen::run(true),
        InternalCheck::L2AssuranceCheck => {
            let facts = command_facts
                .get()
                .context(command_scope_facts_context("l2-assurance"))?;
            crate::l2_assurance::run(root, facts, true)
        }
        InternalCheck::ProviderCapabilitiesCheck => crate::provider_capabilities::run(true),
        InternalCheck::LocalTxCoverage => {
            let facts = command_facts
                .get()
                .context(command_scope_facts_context("localtx-coverage"))?;
            run_check(&crate::localtx_coverage::LocalTxCoverage::new(root, facts))
        }
        InternalCheck::LocalOnlyEffects => {
            let facts = command_facts
                .get()
                .context(command_scope_facts_context("local-only-effects"))?;
            run_check(&consistency_effects::LocalOnlyEffects::new(root, facts))
        }
        InternalCheck::PdpAllowGuard => run_check(&crate::pdpallow::PdpAllowGuard),
        InternalCheck::ContractBindingGuard => {
            let facts = command_facts
                .get()
                .context(command_scope_facts_context("contract-binding-guard"))?;
            run_check(&crate::contract_binding_guard::ContractBindingGuard::new(
                root, facts,
            ))
        }
        InternalCheck::SchemaRlsGuard => run_check(&crate::schema_rls::SchemaRlsGuard),
        InternalCheck::PgTenantTxGuard => run_check(&crate::pg_tenant_tx_guard::PgTenantTxGuard),
        InternalCheck::RepoScopeGuard => run_check(&repo_scope_guard::RepoScopeGuard),
        InternalCheck::TenancyCloseout => run_check(&crate::tenancy_closeout::TenancyCloseout),
        InternalCheck::CommandSymmetry => run_check(&crate::command_symmetry::CommandSymmetry),
        InternalCheck::CiEntryGuard => crate::ci_entry_guard::run(),
        InternalCheck::ReconcileOutboxCommandGuard => {
            run_check(&reconcile_outbox_command_guard::ReconcileOutboxCommandGuard)
        }
        InternalCheck::DeferGate => run_check(&crate::defergate::DeferGate),
        InternalCheck::PostgresFeatureMatrix => {
            crate::postgres_feature_matrix::run(opts.execution_policy)
        }
        InternalCheck::Coverage => {
            let scope = if opts.coverage_typed_job {
                crate::ci_impact::coverage_scope_for_typed_job(root)?
            } else {
                crate::ci_impact::coverage_scope_for_full_ci()
            };
            crate::coverage::run(scope, opts.execution_policy)
        }
        // 轴 A 封装面：basis+engine+curated extras 全集（layer=None）；check=true 漂移门 fail-closed（PUBLICAPI-DRIFT-GATE-01）。
        InternalCheck::PublicApiCheck => crate::publicapi::run(true, false, None),
    }
}

fn run_assembly_artifacts_check(
    root: &Path,
    command_facts: &crate::workspace_facts::CommandWorkspaceFacts,
    report_facts_failure: impl FnOnce(),
) -> Result<()> {
    let prepared = crate::assembly_artifacts::prepare(root)?;
    match command_facts.get() {
        Ok(facts) => crate::assembly_artifacts::run_prepared(root, facts, prepared),
        Err(error) => {
            report_facts_failure();
            Err(anyhow::Error::msg(error.to_string()))
                .context(command_scope_facts_context("assembly-artifacts-check"))
        }
    }
}

fn run_labeled_plan(
    lane: &str,
    plan: &[Step],
    opts: &VerifyOpts,
    root: &Path,
    command_facts: &crate::workspace_facts::CommandWorkspaceFacts,
) -> Result<()> {
    execute_labeled_items_with_prerequisite(
        lane,
        plan,
        opts.execution_policy,
        &SystemAggregateClock,
        "nextest-workspace-validation",
        Step::uses_nextest,
        || {
            crate::nextest::validate_workspace(
                root,
                command_facts
                    .get()
                    .context(command_scope_facts_context("nextest-workspace-validation"))?,
            )
        },
        |step| step.label().to_owned(),
        |step| {
            run_one(
                lane,
                step,
                opts,
                root,
                command_facts,
                crate::cmd::tool_available,
            )
        },
    )
}

fn run_resumable_labeled_plan(
    lane: &str,
    plan: &[Step],
    opts: &VerifyOpts,
    root: &Path,
    command_facts: &crate::workspace_facts::CommandWorkspaceFacts,
    mut ledger: Option<&mut crate::local_run_ledger::LocalRunLedger>,
) -> Result<()> {
    execute_labeled_items_with_prerequisite(
        lane,
        plan,
        opts.execution_policy,
        &SystemAggregateClock,
        "nextest-workspace-validation",
        Step::uses_nextest,
        || {
            crate::nextest::validate_workspace(
                root,
                command_facts
                    .get()
                    .context(command_scope_facts_context("nextest-workspace-validation"))?,
            )
        },
        |step| step.label().to_owned(),
        |step| {
            let unit = format!("gate:{}", step.label());
            run_checkpointed_unit(&unit, step.label(), ledger.as_deref_mut(), || {
                run_one(
                    lane,
                    step,
                    opts,
                    root,
                    command_facts,
                    crate::cmd::tool_available,
                )
            })
        },
    )
}

fn run_checkpointed_unit(
    unit: &str,
    label: &str,
    ledger: Option<&mut crate::local_run_ledger::LocalRunLedger>,
    execute: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if ledger.as_ref().is_some_and(|ledger| ledger.contains(unit)) {
        eprintln!("verify：checkpoint 已通过，跳过 {label}");
        return Ok(());
    }
    let result = execute();
    if result.is_ok()
        && let Some(ledger) = ledger
    {
        ledger.mark_passed(unit.to_owned());
    }
    result
}

#[cfg(test)]
fn validate_nextest_for_plan(
    plan: &[Step],
    root: &Path,
    validate: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    if plan.iter().any(Step::uses_nextest) {
        validate(root)?;
    }
    Ok(())
}

fn execute_labeled_items<T>(
    lane: &str,
    items: &[T],
    execution_policy: crate::cmd::ExecutionPolicy,
    clock: &impl AggregateClock,
    label: impl Fn(&T) -> String,
    execute: impl FnMut(&T) -> Result<()>,
) -> Result<()> {
    execute_labeled_items_with_prerequisite(
        lane,
        items,
        execution_policy,
        clock,
        "unused-prerequisite",
        |_| false,
        || Ok(()),
        label,
        execute,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_labeled_items_with_prerequisite<T>(
    lane: &str,
    items: &[T],
    execution_policy: crate::cmd::ExecutionPolicy,
    clock: &impl AggregateClock,
    prerequisite_label: &str,
    requires_prerequisite: impl Fn(&T) -> bool,
    validate_prerequisite: impl FnOnce() -> Result<()>,
    label: impl Fn(&T) -> String,
    mut execute: impl FnMut(&T) -> Result<()>,
) -> Result<()> {
    let mut failures = Vec::new();
    let prerequisite_failed = if items.iter().any(&requires_prerequisite) {
        let started = clock.now();
        match validate_prerequisite() {
            Ok(()) => false,
            Err(error) if execution_policy.keeps_going() => {
                failures.push((
                    prerequisite_label.to_owned(),
                    clock.elapsed(started, clock.now()).as_secs_f64(),
                    format!("{error:#}"),
                ));
                true
            }
            Err(error) => return Err(error),
        }
    } else {
        false
    };
    for (i, item) in items.iter().enumerate() {
        let item_label = label(item);
        if prerequisite_failed && requires_prerequisite(item) {
            eprintln!(
                "{lane}: [{}/{}] {item_label}（跳过：{prerequisite_label} 失败）",
                i + 1,
                items.len()
            );
            continue;
        }
        eprintln!("{lane}: [{}/{}] {item_label}", i + 1, items.len());
        let started = clock.now();
        if let Err(error) = execute(item) {
            let elapsed = clock.elapsed(started, clock.now()).as_secs_f64();
            if !execution_policy.keeps_going() {
                return Err(error);
            }
            failures.push((item_label, elapsed, format!("{error:#}")));
        }
    }
    if !failures.is_empty() {
        eprintln!("{lane}: 失败汇总（{} 项）", failures.len());
        for (label, elapsed, error) in &failures {
            eprintln!("- {label}（{elapsed:.1} 秒）：{error}");
        }
        bail!("{lane}: {} 个门步失败", failures.len());
    }
    Ok(())
}

fn select_verify_plan(plan: Vec<Step>, only: &[String]) -> Result<Vec<Step>> {
    if only.is_empty() {
        return Ok(plan);
    }
    for label in only {
        if !REGISTRY.iter().any(|spec| spec.label() == label) {
            bail!("verify --only 未知 gate: {label}");
        }
        if !plan.iter().any(|step| step.label() == label) {
            bail!("verify --only gate 不属于当前计划: {label}");
        }
    }
    Ok(plan
        .into_iter()
        .filter(|step| only.iter().any(|label| label == step.label()))
        .collect())
}

/// verify 入口：按 registry 顺序执行所选 plan；默认 keep-going，显式 `--fail-fast` 首错停止。
pub(crate) fn run(
    fast: bool,
    fresh: bool,
    allow_missing_tools: bool,
    contract_against: Option<&str>,
    fail_fast: bool,
    only: &[String],
) -> Result<()> {
    let opts = VerifyOpts {
        fast,
        allow_missing_tools,
        partition: None,
        nextest_lane: crate::nextest::NextestLane::Verify,
        core_test_selection: crate::nextest::CoreTestSelection::workspace(),
        contract_against: contract_against
            .unwrap_or(contract::breaking::DEFAULT_AGAINST)
            .to_owned(),
        coverage_typed_job: false,
        execution_policy: crate::cmd::ExecutionPolicy::from_fail_fast(fail_fast),
    };
    let root = workspace_root()?;
    let plan = select_verify_plan(verify_plan(&opts), only)?;
    let mut ledger = crate::local_run_ledger::LocalRunLedger::for_verify(&root, fast)?;
    if fresh {
        ledger
            .as_mut()
            .context("verify --fresh 需要有分支的 worktree")?
            .fresh()?;
    }
    let mode = if fast { "fast" } else { "full" };
    if only.is_empty() {
        eprintln!("verify（{mode}）：{} 步", plan.len());
    } else {
        eprintln!(
            "verify（{mode} partial）：{} 步；仅供诊断，不代表完整 CI 通过",
            plan.len()
        );
    }
    // 每步开始打 label——build/clippy/nextest 各数分钟，让操作者实时知道卡在哪步。
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
    run_resumable_labeled_plan(
        "verify",
        &plan,
        &opts,
        &root,
        &command_facts,
        ledger.as_mut(),
    )?;
    if only.is_empty() {
        eprintln!("verify（{mode}）：全部通过");
    } else {
        eprintln!("verify（{mode} partial）：所选 gate 通过；不代表完整 CI 通过");
    }
    Ok(())
}

/// `ci full` 本地 release-check 薄入口（issue #1132）：按 [`plan_for`] 的 typed profile 顺序跑每步，
/// 默认 keep-going，显式 fail-fast。GitHub Actions 不调此聚合，而是分别调用四条 [`GateGroup`]。本地完整
/// canonical 入口是 `make ci-full`；`make ci` 仅执行 10 分钟有界 adaptive preflight，不调用本聚合。
/// `allow_missing_tools` 仅本地便利——CI 不传 = 缺工具 fail-closed。
pub(crate) fn run_ci(allow_missing_tools: bool, fail_fast: bool) -> Result<()> {
    let opts = VerifyOpts {
        fast: false,
        allow_missing_tools,
        partition: None,
        nextest_lane: crate::nextest::NextestLane::CiCore,
        core_test_selection: crate::nextest::CoreTestSelection::workspace(),
        contract_against: contract::breaking::DEFAULT_AGAINST.to_owned(),
        coverage_typed_job: false,
        execution_policy: crate::cmd::ExecutionPolicy::from_fail_fast(fail_fast),
    };
    let root = workspace_root()?;
    let plan = plan_for(PlanProjection::Profile(ExecutionProfile::ReleaseCheck));
    let integration_selection = IntegrationSelection::for_profile(ExecutionProfile::ReleaseCheck)?;
    eprintln!("ci：{} 步（CI lane 超集）", plan.len());
    let shards = release_check_integration_shards();
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
    execute_release_check_phases(
        opts.execution_policy,
        || run_labeled_plan("ci", &plan, &opts, &root, &command_facts),
        || {
            integration_shards::with_validated_workspace(&command_facts, |workspace| {
                execute_labeled_items(
                    "ci/integration",
                    &shards,
                    opts.execution_policy,
                    &SystemAggregateClock,
                    |shard| shard.as_str().to_owned(),
                    |shard| {
                        run_ci_integration_with_policy(
                            workspace,
                            *shard,
                            &integration_selection,
                            allow_missing_tools,
                            None,
                            opts.execution_policy,
                        )
                    },
                )
            })
        },
    )?;
    eprintln!("ci：全部通过");
    Ok(())
}

fn execute_release_check_phases(
    execution_policy: crate::cmd::ExecutionPolicy,
    run_gates: impl FnOnce() -> Result<()>,
    run_integrations: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let gate_result = run_gates();
    if !execution_policy.keeps_going() {
        gate_result?;
        return run_integrations();
    }
    let integration_result = run_integrations();
    match (gate_result, integration_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(_), Ok(())) => bail!("ci: gate phase failed"),
        (Ok(()), Err(_)) => bail!("ci: integration phase failed"),
        (Err(_), Err(_)) => bail!("ci: gate and integration phases failed"),
    }
}

fn release_check_integration_shards() -> Vec<IntegrationShard> {
    ExecutionUnitSpec::project(ExecutionProfile::ReleaseCheck)
        .filter_map(|unit| match unit {
            ExecutionUnitSpec::Gate(_) => None,
            ExecutionUnitSpec::Integration(spec) => Some(spec.shard),
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Unforgeable proof that the required LocalTx baseline within the passed postgres selection
/// completed successfully. The private field keeps construction inside this execution module.
pub(crate) struct PostgresDomainPassed(());

fn validate_localtx_required_selection(selection: &IntegrationSelection) -> Result<()> {
    let required = integration_shards::localtx_required_selection()?;
    if !required.unit_ids().is_subset(selection.unit_ids()) {
        let missing = required
            .unit_ids()
            .difference(selection.unit_ids())
            .map(|unit_id| unit_id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        bail!("postgres LocalTx selection misses required baseline units: {missing}");
    }
    Ok(())
}

fn validate_integration_selection_for_shard(
    selection: &IntegrationSelection,
    shard: IntegrationShard,
) -> Result<()> {
    if selection.unit_ids_for_shard(shard).is_empty() {
        bail!("integration selection has no unit in job shard `{shard}`");
    }
    if selection.profile() == ExecutionProfile::IntegrationCritical {
        let other_shards = selection
            .unit_ids()
            .iter()
            .filter(|unit_id| unit_id.spec().shard != shard)
            .map(|unit_id| unit_id.as_str())
            .collect::<Vec<_>>();
        if !other_shards.is_empty() {
            bail!(
                "integration-critical selection for job shard `{shard}` contains other-shard units: {}",
                other_shards.join(", ")
            );
        }
    }
    Ok(())
}

fn fixed_job_owns_gate(job: FixedCiJob, spec: crate::ci_lanes::GateSpec) -> bool {
    match spec.primary_owner() {
        ExecutionProfile::Check => job == FixedCiJob::Check,
        ExecutionProfile::Test => job == FixedCiJob::TestAffected,
        ExecutionProfile::IntegrationCritical => false,
        ExecutionProfile::ReleaseCheck => match spec.evidence() {
            EvidenceKind::Coverage => job == FixedCiJob::TestAffected,
            EvidenceKind::Source
            | EvidenceKind::Test
            | EvidenceKind::SupplyChain
            | EvidenceKind::PublicApi => job == FixedCiJob::Check,
        },
    }
}

fn fixed_gate_plan(job: FixedCiJob, selection: &crate::ci_impact::SelectionPlan) -> Vec<Step> {
    if job == FixedCiJob::IntegrationCritical {
        return Vec::new();
    }
    let profile = match selection.mode() {
        crate::ci_impact::SelectionMode::Adaptive | crate::ci_impact::SelectionMode::PrComplete => {
            match job {
                FixedCiJob::Check => ExecutionProfile::Check,
                FixedCiJob::TestAffected => ExecutionProfile::Test,
                FixedCiJob::IntegrationCritical => unreachable!(),
            }
        }
        crate::ci_impact::SelectionMode::ReleaseCheck => ExecutionProfile::ReleaseCheck,
    };
    ExecutionUnitSpec::project(profile)
        .filter_map(|unit| match unit {
            ExecutionUnitSpec::Gate(spec)
                if spec.included_in_profile(profile) && fixed_job_owns_gate(job, *spec) =>
            {
                Some(spec.id())
            }
            ExecutionUnitSpec::Gate(_) | ExecutionUnitSpec::Integration(_) => None,
        })
        .filter(|id| {
            !matches!(
                selection.test_selection(),
                crate::ci_impact::ProjectedTestSelection::None
            ) || *id != GateId::ComponentTests
        })
        .map(step_for_id)
        .collect()
}

fn core_selection_for_fixed_job(
    selection: &crate::ci_impact::SelectionPlan,
) -> Result<crate::nextest::CoreTestSelection> {
    match selection.test_selection() {
        crate::ci_impact::ProjectedTestSelection::None => {
            Ok(crate::nextest::CoreTestSelection::workspace())
        }
        crate::ci_impact::ProjectedTestSelection::Packages(packages) => {
            crate::nextest::CoreTestSelection::packages(packages.as_slice().to_vec())
                .context("selection contains an invalid or empty package set")
        }
        crate::ci_impact::ProjectedTestSelection::Workspace => {
            Ok(crate::nextest::CoreTestSelection::workspace())
        }
    }
}

fn run_fixed_gate_job(job: FixedCiJob, selection: &crate::ci_impact::SelectionPlan) -> Result<()> {
    let root = workspace_root()?;
    let plan = fixed_gate_plan(job, selection);
    let opts = VerifyOpts {
        fast: false,
        allow_missing_tools: false,
        partition: None,
        nextest_lane: crate::nextest::NextestLane::CiCore,
        core_test_selection: core_selection_for_fixed_job(selection)?,
        contract_against: contract::breaking::DEFAULT_AGAINST.to_owned(),
        coverage_typed_job: false,
        execution_policy: crate::cmd::ExecutionPolicy::FailFast,
    };
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
    run_labeled_plan(job.as_str(), &plan, &opts, &root, &command_facts)
}

fn run_fixed_integrations(selection: &crate::ci_impact::SelectionPlan) -> Result<()> {
    let integration = selection.integration_selection()?;
    validate_localtx_required_selection(&integration)?;
    let root = workspace_root()?;
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
    let selected_shards = IntegrationShard::ALL
        .iter()
        .copied()
        .filter(|shard| !integration.unit_ids_for_shard(*shard).is_empty())
        .collect::<Vec<_>>();
    let postgres_passed = std::cell::Cell::new(false);
    integration_shards::with_validated_workspace(&command_facts, |workspace| {
        execute_labeled_items(
            "integration-critical",
            &selected_shards,
            crate::cmd::ExecutionPolicy::KeepGoing,
            &SystemAggregateClock,
            |shard| shard.as_str().to_owned(),
            |shard| {
                run_ci_integration_with_policy(
                    workspace,
                    *shard,
                    &integration,
                    false,
                    None,
                    crate::cmd::ExecutionPolicy::FailFast,
                )?;
                if *shard == IntegrationShard::PostgresDomain {
                    postgres_passed.set(true);
                }
                Ok(())
            },
        )
    })?;
    if !postgres_passed.get() {
        bail!("fixed integration selection did not execute the LocalTx postgres owner");
    }
    let verified = crate::localtx_coverage::verify_required_evidence_set(
        &root,
        command_facts
            .get()
            .context(command_scope_facts_context("localtx-required-evidence"))?,
    )?;
    let request =
        crate::localtx_evidence::prepare_request(FixedCiJob::IntegrationCritical, None, &root)?;
    request.publish(PostgresDomainPassed(()), verified)
}

pub(crate) fn run_fixed_job(
    job: FixedCiJob,
    selection: &crate::ci_impact::SelectionPlan,
) -> Result<()> {
    match job {
        FixedCiJob::Check | FixedCiJob::TestAffected => run_fixed_gate_job(job, selection),
        FixedCiJob::IntegrationCritical => run_fixed_integrations(selection),
    }
}

/// audit 入口（issue #1133 供应链定时刷新 lane）：按 [`audit_plan`] 顺序跑每步，fail-fast。
/// GitHub Actions schedule 由 `ci audit` 调用。
/// `allow_missing_tools` 仅本地便利——CI 不传 = 缺 deny/audit 工具 fail-closed。
pub(crate) fn run_audit(allow_missing_tools: bool) -> Result<()> {
    let opts = VerifyOpts {
        fast: false,
        allow_missing_tools,
        partition: None,
        nextest_lane: crate::nextest::NextestLane::Verify,
        core_test_selection: crate::nextest::CoreTestSelection::workspace(),
        contract_against: contract::breaking::DEFAULT_AGAINST.to_owned(),
        coverage_typed_job: false,
        execution_policy: crate::cmd::ExecutionPolicy::FailFast,
    };
    let root = workspace_root()?;
    let plan = audit_plan();
    eprintln!("audit：{} 步（供应链漏洞刷新 lane）", plan.len());
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
    run_labeled_plan("audit", &plan, &opts, &root, &command_facts)?;
    eprintln!("audit：全部通过");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell_executable_prefix(line: &str) -> &str {
        let mut single_quoted = false;
        let mut double_quoted = false;
        let mut escaped = false;
        for (index, character) in line.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            match character {
                '\\' if !single_quoted => escaped = true,
                '\'' if !double_quoted => single_quoted = !single_quoted,
                '"' if !single_quoted => double_quoted = !double_quoted,
                '#' if !single_quoted && !double_quoted => {
                    let starts_shell_word = index == 0
                        || line[..index]
                            .chars()
                            .next_back()
                            .is_some_and(char::is_whitespace);
                    if starts_shell_word {
                        return &line[..index];
                    }
                }
                _ => {}
            }
        }
        line
    }

    fn ci_selftest_tmp_root_is_atomic(source: &str) -> bool {
        let executable = source
            .lines()
            .map(shell_executable_prefix)
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        fn assignment(line: &str) -> Option<(&str, &str)> {
            let line = line
                .strip_prefix("export ")
                .or_else(|| line.strip_prefix("readonly "))
                .unwrap_or(line);
            let (name, value) = line.split_once('=')?;
            let mut chars = name.chars();
            if !chars
                .next()
                .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
                || !chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
            {
                return None;
            }
            Some((name, value))
        }

        fn atomic_mktemp_dir(value: &str) -> bool {
            let Some(template) = value
                .strip_prefix("$(mktemp -d \"")
                .and_then(|value| value.strip_suffix("\")"))
            else {
                return false;
            };
            template.ends_with(".XXXXXX")
                && !template.contains('"')
                && !template.contains("$(")
                && !template.contains('`')
        }

        let assignments = executable
            .iter()
            .filter_map(|line| assignment(line))
            .collect::<Vec<_>>();
        let uses_tmp_root = executable.iter().any(|line| line.contains("TMP_ROOT"));
        let creators = assignments
            .iter()
            .filter(|(name, value)| *name == "TMP_ROOT" && atomic_mktemp_dir(value))
            .count();
        let unsafe_temp_assignment = assignments.iter().any(|(name, value)| {
            let references_temp_base =
                value.contains("/tmp") || value.contains("TMPDIR") || value.contains("TMP_BASE");
            references_temp_base
                && !(*name == "TMP_BASE" && *value == "${TMPDIR:-/tmp}")
                && !(*name == "TMP_ROOT" && atomic_mktemp_dir(value))
        });

        !executable.iter().any(|line| line.contains("$$"))
            && !unsafe_temp_assignment
            && (!uses_tmp_root
                || (creators == 1
                    && assignments.iter().all(|(name, value)| {
                        *name != "TMP_ROOT"
                            || atomic_mktemp_dir(value)
                            || *value == "$(CDPATH='' cd -- \"$TMP_ROOT\" && pwd -P)"
                    })))
    }

    fn ci_selftest_uses_tmp_root(source: &str) -> bool {
        source
            .lines()
            .map(shell_executable_prefix)
            .map(str::trim)
            .any(|line| !line.is_empty() && line.contains("TMP_ROOT"))
    }

    fn github_selftests(root: &Path) -> anyhow::Result<Vec<(String, String)>> {
        fn collect(
            path: &Path,
            root: &Path,
            discovered: &mut Vec<(String, String)>,
        ) -> anyhow::Result<()> {
            let metadata = std::fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() {
                if path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".selftest.sh"))
                {
                    anyhow::bail!("CI selftest 不得是 symlink: {}", path.display());
                }
                return Ok(());
            }
            if metadata.is_dir() {
                let mut entries = std::fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
                entries.sort_by_key(std::fs::DirEntry::file_name);
                for entry in entries {
                    collect(&entry.path(), root, discovered)?;
                }
            } else if metadata.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".selftest.sh"))
            {
                let source = std::fs::read_to_string(path)?;
                discovered.push((
                    path.strip_prefix(root)?
                        .to_string_lossy()
                        .replace('\\', "/"),
                    source,
                ));
            }
            Ok(())
        }

        let mut discovered = Vec::new();
        collect(&root.join(".github"), root, &mut discovered)?;
        Ok(discovered)
    }

    #[test]
    fn ci_selftest_temp_root_guard_rejects_unsafe_fixtures() {
        let green = "# ROOT=/tmp/comment-only.$$\n\
                     echo safe # ROOT=/tmp/inline-comment.$$\n\
                     TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/fixture.XXXXXX\")\n\
                     TMP_ROOT=$(CDPATH='' cd -- \"$TMP_ROOT\" && pwd -P)\n";
        assert!(ci_selftest_tmp_root_is_atomic(green), "synthetic green");
        for red in [
            "TMP_ROOT=${TMPDIR:-/tmp}/fixture.$$\n",
            "ROOT=/tmp/alternate-name.$$\n",
            "ROOT=/tmp/fixed-root\n",
            "TMP_ROOT=$(mktemp \"${TMPDIR:-/tmp}/fixture.XXXXXX\")\n",
            "TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/fixture\")\n",
            "TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/fixture.XXXXXX\" || printf /tmp/fixed)\n",
            "# TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/fixture.XXXXXX\")\n\
             TMP_ROOT=${TMPDIR:-/tmp}/fixture\n",
            "TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/fixture.XXXXXX\")\n\
             TMP_ROOT=${TMPDIR:-/tmp}/second\n",
        ] {
            assert!(
                !ci_selftest_tmp_root_is_atomic(red),
                "unsafe TMP_ROOT synthetic fixture must fail closed: {red}"
            );
        }
    }

    #[test]
    fn ci_selftest_temp_root_guard_discovers_nested_alternate_variable() -> anyhow::Result<()> {
        let fixture = crate::testutil::unique_tmp("ci-selftest-temp-guard-nested");
        let scripts = fixture.join(".github/scripts");
        let nested = fixture.join(".github/fixtures/nested");
        std::fs::create_dir_all(&scripts)?;
        std::fs::create_dir_all(&nested)?;
        std::fs::write(
            scripts.join("safe.selftest.sh"),
            "TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/safe.XXXXXX\")\n",
        )?;
        std::fs::write(
            nested.join("unsafe.selftest.sh"),
            "ROOT=/tmp/alternate-name.$$\n",
        )?;

        let discovered = github_selftests(&fixture);
        std::fs::remove_dir_all(&fixture)?;
        let discovered = discovered?;
        assert_eq!(
            discovered
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>(),
            [
                ".github/fixtures/nested/unsafe.selftest.sh",
                ".github/scripts/safe.selftest.sh",
            ],
            "所有嵌套 selftest 都必须自动发现，不能依赖 TMP_ROOT 变量名"
        );
        assert!(
            !ci_selftest_tmp_root_is_atomic(&discovered[0].1),
            "替代变量名的 PID 临时路径必须 fail closed"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn ci_selftest_temp_root_guard_rejects_symlinks() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = crate::testutil::unique_tmp("ci-selftest-temp-guard-symlink");
        let nested = fixture.join(".github/nested");
        std::fs::create_dir_all(&nested)?;
        let target = fixture.join("target.selftest.sh");
        std::fs::write(&target, "ROOT=/tmp/unsafe.$$\n")?;
        symlink(&target, nested.join("linked.selftest.sh"))?;

        let error = match github_selftests(&fixture) {
            Ok(_) => anyhow::bail!("selftest symlink 必须 fail closed"),
            Err(error) => error,
        };
        std::fs::remove_dir_all(&fixture)?;
        assert!(
            error.to_string().contains("CI selftest 不得是 symlink"),
            "unexpected symlink error: {error:#}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn ci_selftest_temp_root_guard_skips_unrelated_symlinks() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = crate::testutil::unique_tmp("ci-selftest-temp-guard-unrelated-link");
        let scripts = fixture.join(".github/scripts");
        let actions = fixture.join(".github/actions");
        std::fs::create_dir_all(&scripts)?;
        std::fs::create_dir_all(&actions)?;
        std::fs::write(
            scripts.join("safe.selftest.sh"),
            "TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/safe.XXXXXX\")\n",
        )?;
        let target = fixture.join("shared-action");
        std::fs::create_dir_all(&target)?;
        symlink(&target, actions.join("shared"))?;

        let discovered = github_selftests(&fixture)?;
        std::fs::remove_dir_all(&fixture)?;
        assert_eq!(
            discovered
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>(),
            [".github/scripts/safe.selftest.sh"],
            "unrelated GitHub symlinks must be skipped without traversal"
        );
        Ok(())
    }

    #[test]
    fn committed_ci_selftest_temp_roots_are_atomic() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let discovered = github_selftests(&root)?;
        assert!(
            !discovered.is_empty(),
            "anti-vacuity: 必须递归自动发现 committed GitHub selftest"
        );
        assert!(
            discovered
                .iter()
                .any(|(_, source)| ci_selftest_uses_tmp_root(source)),
            "anti-vacuity: committed GitHub selftest 中必须存在实际 TMP_ROOT carrier"
        );
        let unsafe_paths = discovered
            .iter()
            .filter_map(|(path, source)| {
                (!ci_selftest_tmp_root_is_atomic(source)).then_some(path.as_str())
            })
            .collect::<Vec<_>>();
        assert!(
            unsafe_paths.is_empty(),
            "CI-SELFTEST-TEMP-01: 以下 selftest 含可执行 PID 临时路径，或未用 `TMP_ROOT=$(mktemp -d \"...XXXXXX\")` 原子建立独占根目录: {}",
            unsafe_paths.join(", ")
        );
        Ok(())
    }

    #[test]
    fn localtx_proof_requires_the_complete_passed_baseline() -> anyhow::Result<()> {
        let required = integration_shards::localtx_required_selection()?;
        validate_localtx_required_selection(&required)?;
        let release = IntegrationSelection::for_profile(ExecutionProfile::ReleaseCheck)?;
        validate_localtx_required_selection(&release)?;

        let incomplete = IntegrationSelection::critical(
            required
                .unit_ids()
                .iter()
                .copied()
                .filter(|unit_id| *unit_id != IntegrationUnitId::PostgresLib),
        )?;
        assert!(validate_localtx_required_selection(&incomplete).is_err());
        Ok(())
    }

    #[test]
    fn fixed_jobs_partition_release_check_without_duplicates() -> anyhow::Result<()> {
        let selection = crate::ci_impact::test_selection_plan()?;
        let check = fixed_gate_plan(FixedCiJob::Check, &selection);
        let tests = fixed_gate_plan(FixedCiJob::TestAffected, &selection);
        let check_ids = check
            .iter()
            .map(|step| step.id)
            .collect::<std::collections::BTreeSet<_>>();
        let test_ids = tests
            .iter()
            .map(|step| step.id)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(check_ids.is_disjoint(&test_ids));
        let actual = check_ids
            .union(&test_ids)
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        let expected = ExecutionUnitSpec::project(ExecutionProfile::ReleaseCheck)
            .filter_map(|unit| match unit {
                ExecutionUnitSpec::Gate(spec)
                    if spec.included_in_profile(ExecutionProfile::ReleaseCheck) =>
                {
                    Some(spec.id())
                }
                ExecutionUnitSpec::Gate(_) | ExecutionUnitSpec::Integration(_) => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual, expected);
        assert!(fixed_gate_plan(FixedCiJob::IntegrationCritical, &selection).is_empty());
        Ok(())
    }

    #[test]
    fn pr_complete_excludes_release_only_work() -> anyhow::Result<()> {
        let pr = crate::ci_impact::test_pr_complete_selection_plan()?;
        let release = crate::ci_impact::test_selection_plan()?;
        let pr_ids = FixedCiJob::ALL
            .into_iter()
            .flat_map(|job| fixed_gate_plan(job, &pr))
            .map(|step| step.id)
            .collect::<std::collections::BTreeSet<_>>();
        let release_ids = FixedCiJob::ALL
            .into_iter()
            .flat_map(|job| fixed_gate_plan(job, &release))
            .map(|step| step.id)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            pr_ids
                .difference(&release_ids)
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            [
                GateId::BuildWorkspace,
                GateId::IntegrationCompile,
                GateId::ClippyWorkspace,
                GateId::ComponentTests,
            ]
            .into_iter()
            .collect(),
            "ReleaseCheck must replace the ordinary compile/test variants exactly"
        );
        assert_eq!(
            release_ids
                .difference(&pr_ids)
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            [
                GateId::BuildAllFeatures,
                GateId::ClippyAllFeatures,
                GateId::Coverage,
                GateId::CargoAudit,
                GateId::DylintWorkspaceUiTests,
                GateId::PublicApi,
                GateId::DenyAdvisories,
            ]
            .into_iter()
            .collect(),
            "ReleaseCheck must add exactly the release-only execution units"
        );
        assert!(!pr_ids.contains(&GateId::Coverage));
        assert!(!pr_ids.contains(&GateId::CargoAudit));
        assert!(!pr_ids.contains(&GateId::PublicApi));
        assert!(release_ids.contains(&GateId::Coverage));
        assert!(release_ids.contains(&GateId::CargoAudit));
        assert!(release_ids.contains(&GateId::PublicApi));
        assert_eq!(
            pr.integration_selection()?.profile(),
            ExecutionProfile::IntegrationCritical
        );
        assert_eq!(
            release.integration_selection()?.profile(),
            ExecutionProfile::ReleaseCheck
        );
        Ok(())
    }

    fn opts(fast: bool, allow_missing_tools: bool) -> VerifyOpts {
        VerifyOpts {
            fast,
            allow_missing_tools,
            partition: None,
            nextest_lane: crate::nextest::NextestLane::Verify,
            core_test_selection: crate::nextest::CoreTestSelection::workspace(),
            contract_against: contract::breaking::DEFAULT_AGAINST.to_owned(),
            coverage_typed_job: false,
            execution_policy: crate::cmd::ExecutionPolicy::FailFast,
        }
    }

    fn labels(plan: &[Step]) -> Vec<&'static str> {
        plan.iter().map(|s| s.label()).collect()
    }

    fn gate_id_set(ids: impl IntoIterator<Item = GateId>) -> std::collections::BTreeSet<GateId> {
        ids.into_iter().collect()
    }

    fn exact_gate_id_projection(
        plan: &[Step],
        expected: impl IntoIterator<Item = GateId>,
    ) -> Result<(), String> {
        let expected = gate_id_set(expected);
        let actual = gate_id_set(plan.iter().map(|step| step.id));
        let mut counts = std::collections::BTreeMap::new();
        for id in plan.iter().map(|step| step.id) {
            *counts.entry(id).or_insert(0usize) += 1;
        }
        let labels = |ids: Vec<GateId>| {
            let mut labels = ids
                .into_iter()
                .map(|id| id.spec().label())
                .collect::<Vec<_>>();
            labels.sort_unstable();
            labels.join(", ")
        };
        let missing = labels(expected.difference(&actual).copied().collect());
        let extra = labels(actual.difference(&expected).copied().collect());
        let duplicate = labels(
            counts
                .into_iter()
                .filter_map(|(id, count)| (count > 1).then_some(id))
                .collect(),
        );
        if missing.is_empty() && extra.is_empty() && duplicate.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "plan GateId closure drift: missing=[{missing}], extra=[{extra}], duplicate=[{duplicate}]"
            ))
        }
    }

    fn ensure_plan_has_exact_gate_ids(
        plan: &[Step],
        expected: impl IntoIterator<Item = GateId>,
    ) -> anyhow::Result<()> {
        exact_gate_id_projection(plan, expected).map_err(anyhow::Error::msg)
    }

    fn registry_gate_ids(
        predicate: impl Fn(crate::ci_lanes::GateSpec) -> bool,
    ) -> std::collections::BTreeSet<GateId> {
        REGISTRY
            .iter()
            .copied()
            .filter(|spec| predicate(*spec))
            .map(crate::ci_lanes::GateSpec::id)
            .collect()
    }

    const RELEASE_CHECK: PlanProjection = PlanProjection::Profile(ExecutionProfile::ReleaseCheck);

    fn assert_pairwise_disjoint(sets: &[std::collections::BTreeSet<GateId>]) {
        for (index, set) in sets.iter().enumerate() {
            for other in &sets[index + 1..] {
                assert!(set.is_disjoint(other), "split CI lanes must be disjoint");
            }
        }
    }

    #[test]
    fn exact_gate_id_projection_rejects_equal_cardinality_wrong_id() -> anyhow::Result<()> {
        let plan = plan_for(RELEASE_CHECK);
        let mut wrong_ids = plan.iter().map(|step| step.id).collect::<Vec<_>>();
        let first = wrong_ids
            .first_mut()
            .context("release-check plan anti-vacuity")?;
        *first = GateId::ComponentTests;

        assert_eq!(wrong_ids.len(), plan.len(), "fixture preserves cardinality");
        assert!(exact_gate_id_projection(&plan, wrong_ids).is_err());
        Ok(())
    }

    #[test]
    fn exact_gate_id_projection_reports_stable_set_differences() -> anyhow::Result<()> {
        let expected =
            registry_gate_ids(|spec| spec.included_in_profile(ExecutionProfile::ReleaseCheck));
        let mut plan = plan_for(RELEASE_CHECK);
        plan.retain(|step| step.id != GateId::Fmt);
        let contract = plan
            .iter_mut()
            .find(|step| step.id == GateId::ContractValidate)
            .context("contract gate anti-vacuity")?;
        contract.id = GateId::ComponentTests;
        let duplicate = plan
            .iter()
            .find(|step| step.id == GateId::AssemblyValidate)
            .context("assembly gate anti-vacuity")?
            .clone();
        plan.push(duplicate);

        assert_eq!(
            exact_gate_id_projection(&plan, expected),
            Err("plan GateId closure drift: missing=[contract-validate, fmt], extra=[component-tests], duplicate=[assembly-validate]".to_string())
        );
        Ok(())
    }

    #[test]
    fn verify_only_uses_registry_membership_and_canonical_order() -> anyhow::Result<()> {
        let plan = verify_plan(&opts(false, false));
        let selected = select_verify_plan(
            plan,
            &["clippy".to_owned(), "runtime-root-guard".to_owned()],
        )?;
        assert_eq!(labels(&selected), ["runtime-root-guard", "clippy"]);
        assert!(
            select_verify_plan(verify_plan(&opts(true, false)), &["build".to_owned()]).is_err()
        );
        assert!(
            select_verify_plan(verify_plan(&opts(false, false)), &["not-a-gate".to_owned()])
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn partial_non_nextest_plan_skips_unrelated_nextest_validation() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let fmt_only = select_verify_plan(verify_plan(&opts(false, false)), &["fmt".to_owned()])?;
        let mut called = false;
        validate_nextest_for_plan(&fmt_only, &root, |_| {
            called = true;
            Ok(())
        })?;
        assert!(
            !called,
            "non-nextest partial plan must not run nextest validation"
        );

        let nextest_only = select_verify_plan(
            verify_plan(&opts(false, false)),
            &["component-tests".to_owned()],
        )?;
        validate_nextest_for_plan(&nextest_only, &root, |_| {
            called = true;
            Ok(())
        })?;
        assert!(called, "nextest gate must retain workspace validation");
        Ok(())
    }

    #[test]
    fn native_cargo_keep_going_flags_are_local_policy_only() {
        use crate::cmd::{CargoSubcommand, ExecutionPolicy};

        assert_eq!(
            cargo_args_for_policy(
                CargoSubcommand::Build,
                &["--workspace"],
                ExecutionPolicy::KeepGoing
            ),
            ["--workspace", "--keep-going"]
        );
        assert_eq!(
            cargo_args_for_policy(
                CargoSubcommand::Test,
                &["--workspace"],
                ExecutionPolicy::KeepGoing
            ),
            ["--workspace", "--no-fail-fast"]
        );
        assert_eq!(
            cargo_args_for_policy(
                CargoSubcommand::Clippy,
                &["--workspace", "--", "-D", "warnings"],
                ExecutionPolicy::KeepGoing,
            ),
            ["--workspace", "--keep-going", "--", "-D", "warnings"]
        );
        assert_eq!(
            cargo_args_for_policy(
                CargoSubcommand::Build,
                &["--workspace"],
                ExecutionPolicy::FailFast
            ),
            ["--workspace"]
        );
        assert_eq!(
            cargo_args_for_policy(
                CargoSubcommand::Deny,
                &["check"],
                ExecutionPolicy::KeepGoing
            ),
            ["check"]
        );
    }

    #[test]
    fn aggregate_executor_collects_or_stops_according_to_policy() {
        use crate::cmd::ExecutionPolicy;

        let items = [1, 2, 3];
        let mut executed = Vec::new();
        let result = execute_labeled_items(
            "verify-test",
            &items,
            ExecutionPolicy::KeepGoing,
            &SystemAggregateClock,
            |item| format!("gate-{item}"),
            |item| {
                executed.push(*item);
                if *item < 3 {
                    bail!("failure-{item}");
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(executed, items);

        executed.clear();
        let result = execute_labeled_items(
            "verify-test",
            &items,
            ExecutionPolicy::FailFast,
            &SystemAggregateClock,
            |item| format!("gate-{item}"),
            |item| {
                executed.push(*item);
                if *item == 2 {
                    bail!("failure-{item}");
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(executed, [1, 2]);
    }

    #[test]
    fn resumable_keep_going_records_only_successes_and_retries_the_hole() -> Result<()> {
        use crate::cmd::ExecutionPolicy;
        use std::cell::RefCell;

        let root = crate::testutil::unique_tmp("verify-resume-runner");
        std::fs::create_dir_all(&root)?;
        let path = root.join("checkpoint.json");
        let items = ["first", "fails-once", "after-failure"];
        let attempts = RefCell::new(std::collections::BTreeMap::<String, usize>::new());

        let mut first_ledger =
            crate::local_run_ledger::LocalRunLedger::fixture(path.clone(), "feature/resume")?;
        let first = execute_labeled_items(
            "verify-test",
            &items,
            ExecutionPolicy::KeepGoing,
            &SystemAggregateClock,
            |item| (*item).to_owned(),
            |item| {
                let unit = format!("gate:{item}");
                run_checkpointed_unit(&unit, item, Some(&mut first_ledger), || {
                    let mut attempts = attempts.borrow_mut();
                    *attempts.entry((*item).to_owned()).or_default() += 1;
                    if *item == "fails-once" {
                        bail!("synthetic failure");
                    }
                    Ok(())
                })
            },
        );
        assert!(first.is_err());
        assert!(first_ledger.contains("gate:first"));
        assert!(!first_ledger.contains("gate:fails-once"));
        assert!(first_ledger.contains("gate:after-failure"));

        let mut resumed =
            crate::local_run_ledger::LocalRunLedger::fixture(path.clone(), "feature/resume")?;
        for item in items {
            let unit = format!("gate:{item}");
            run_checkpointed_unit(&unit, item, Some(&mut resumed), || {
                *attempts.borrow_mut().entry(item.to_owned()).or_default() += 1;
                Ok(())
            })?;
        }
        assert_eq!(attempts.borrow().get("first"), Some(&1));
        assert_eq!(attempts.borrow().get("fails-once"), Some(&2));
        assert_eq!(attempts.borrow().get("after-failure"), Some(&1));
        assert!(resumed.contains("gate:fails-once"));

        let before = attempts.borrow().clone();
        for item in items {
            let unit = format!("gate:{item}");
            run_checkpointed_unit(&unit, item, Some(&mut resumed), || {
                *attempts.borrow_mut().entry(item.to_owned()).or_default() += 1;
                Ok(())
            })?;
        }
        assert_eq!(*attempts.borrow(), before, "all passed units must skip");
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn prerequisite_failure_is_aggregated_or_fail_fast() {
        use crate::cmd::ExecutionPolicy;

        let items = [1, 2, 3];
        let mut executed = Vec::new();
        let result = execute_labeled_items_with_prerequisite(
            "verify-test",
            &items,
            ExecutionPolicy::KeepGoing,
            &SystemAggregateClock,
            "nextest-validation",
            |item| *item != 2,
            || bail!("invalid nextest workspace"),
            |item| format!("gate-{item}"),
            |item| {
                executed.push(*item);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(executed, [2], "independent gate must continue");

        executed.clear();
        let result = execute_labeled_items_with_prerequisite(
            "verify-test",
            &items,
            ExecutionPolicy::FailFast,
            &SystemAggregateClock,
            "nextest-validation",
            |_| true,
            || bail!("invalid nextest workspace"),
            |item| format!("gate-{item}"),
            |item| {
                executed.push(*item);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(executed.is_empty(), "fail-fast stops at prerequisite");
    }

    #[test]
    fn ci_lane_plans_are_registry_derived_and_partitioned() -> anyhow::Result<()> {
        for lane in [GateGroup::Meta, GateGroup::Security, GateGroup::Coverage] {
            let plan = plan_for(PlanProjection::Lane(lane));
            ensure_plan_has_exact_gate_ids(&plan, registry_gate_ids(|spec| spec.belongs_to(lane)))?;
        }
        assert_eq!(
            labels(&plan_for(PlanProjection::Lane(GateGroup::Security))),
            ["deny", "audit"],
            "supply-chain checks retain their local execution order"
        );
        assert_eq!(
            labels(&plan_for(PlanProjection::Lane(GateGroup::Coverage))),
            ["coverage", "public-api"],
            "coverage precedes its public API closeout"
        );
        let core = labels(&plan_for(PlanProjection::Lane(GateGroup::Core)));
        assert!(core.contains(&"build"));
        assert_eq!(core.first(), Some(&"postgres-feature-matrix"));
        assert!(core.contains(&"component-tests"));
        assert!(!core.contains(&"coverage"));
        assert!(!core.contains(&"integration-compile"));

        let release_check: std::collections::BTreeSet<_> = plan_for(RELEASE_CHECK)
            .into_iter()
            .map(|step| step.id)
            .collect();
        let split: Vec<std::collections::BTreeSet<_>> = [
            GateGroup::Meta,
            GateGroup::Core,
            GateGroup::Security,
            GateGroup::Coverage,
            GateGroup::LocalOnly,
            GateGroup::Nightly,
        ]
        .into_iter()
        .map(|lane| {
            plan_for(PlanProjection::Lane(lane))
                .into_iter()
                .filter(|step| {
                    step.id
                        .spec()
                        .included_in_profile(ExecutionProfile::ReleaseCheck)
                        && step.id.spec().lanes()[0] == Some(lane)
                })
                .map(|step| step.id)
                .collect()
        })
        .collect();
        assert_pairwise_disjoint(&split);
        let union: std::collections::BTreeSet<_> = split.into_iter().flatten().collect();
        assert_eq!(
            union, release_check,
            "split CI lanes must cover release-check"
        );
        Ok(())
    }

    #[test]
    fn local_release_check_derives_every_integration_shard_from_execution_units() {
        let derived = release_check_integration_shards();
        assert_eq!(derived, IntegrationShard::ALL);
        for unit in ExecutionUnitSpec::project(ExecutionProfile::ReleaseCheck) {
            if let ExecutionUnitSpec::Integration(spec) = unit {
                assert!(derived.contains(&spec.shard));
            }
        }
    }

    #[test]
    fn local_release_check_keep_going_reaches_integration_after_gate_failure() {
        use crate::cmd::ExecutionPolicy;
        use std::cell::RefCell;

        let phases = RefCell::new(Vec::new());
        let result = execute_release_check_phases(
            ExecutionPolicy::KeepGoing,
            || {
                phases.borrow_mut().push("gates");
                bail!("gate failure")
            },
            || {
                phases.borrow_mut().push("integrations");
                bail!("integration failure")
            },
        );
        assert!(result.is_err());
        assert_eq!(phases.into_inner(), ["gates", "integrations"]);

        let phases = RefCell::new(Vec::new());
        let result = execute_release_check_phases(
            ExecutionPolicy::FailFast,
            || {
                phases.borrow_mut().push("gates");
                bail!("gate failure")
            },
            || {
                phases.borrow_mut().push("integrations");
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(phases.into_inner(), ["gates"]);
    }

    #[test]
    fn dylint_workspace_ui_gate_is_release_owned_once() -> anyhow::Result<()> {
        let validate = |plan: &[Step]| -> anyhow::Result<()> {
            let gates = plan
                .iter()
                .filter(|step| step.id == GateId::DylintWorkspaceUiTests)
                .collect::<Vec<_>>();
            anyhow::ensure!(gates.len() == 1, "expected one workspace Dylint UI gate");
            let gate = gates[0];
            anyhow::ensure!(gate.label() == "dylint-ui-goldens");
            anyhow::ensure!(matches!(gate.kind, StepKind::LintWorkspaceTests));
            anyhow::ensure!(gate.args == ["test", "--locked", "--workspace"]);
            Ok(())
        };

        validate(&plan_for(RELEASE_CHECK))?;
        assert!(
            plan_for(PlanProjection::Verify)
                .iter()
                .all(|step| step.id != GateId::DylintWorkspaceUiTests)
        );

        let mut omitted = plan_for(RELEASE_CHECK);
        omitted.retain(|step| step.id != GateId::DylintWorkspaceUiTests);
        assert!(validate(&omitted).is_err());
        let mut weakened = plan_for(RELEASE_CHECK);
        weakened
            .iter_mut()
            .find(|step| step.id == GateId::DylintWorkspaceUiTests)
            .context("workspace Dylint UI gate")?
            .args = &["test", "-p", "rss_runtime_env_funnel"];
        assert!(validate(&weakened).is_err());
        Ok(())
    }

    #[test]
    fn secure_production_trybuild_gate_is_feature_isolated() -> anyhow::Result<()> {
        let release_check = plan_for(RELEASE_CHECK);
        let production = release_check
            .iter()
            .find(|step| step.id == GateId::SecureProductionTrybuild)
            .context("feature-isolated password proof must be a normal core test gate")?;
        assert_eq!(
            production.args,
            &[
                "test",
                "-p",
                "secure",
                "--no-default-features",
                "--test",
                "trybuild",
                "production_seams_absent",
                "--",
                "--exact",
            ]
        );
        assert_eq!(production.kind, StepKind::Cargo);
        Ok(())
    }

    #[test]
    fn release_check_matches_registry_and_supersedes_component_tests() -> anyhow::Result<()> {
        let plan = plan_for(RELEASE_CHECK);
        ensure_plan_has_exact_gate_ids(
            &plan,
            registry_gate_ids(|spec| spec.included_in_profile(ExecutionProfile::ReleaseCheck)),
        )?;
        assert!(!labels(&plan).contains(&"component-tests"));
        Ok(())
    }

    #[test]
    fn ci_lane_catalog_generates_executor_dispatch_for_every_gate() {
        for spec in REGISTRY {
            let step = step_for_id(spec.id());
            assert_eq!(step.id, spec.id());
        }
        assert_eq!(GateId::ALL.len(), REGISTRY.len());
    }

    #[test]
    fn aggregate_plans_exclude_human_document_content_enforcement() {
        for plan in [
            verify_plan(&opts(false, false)),
            plan_for(RELEASE_CHECK),
            plan_for(PlanProjection::Lane(GateGroup::Meta)),
        ] {
            assert!(!labels(&plan).contains(&"doc-contracts"));
            assert!(labels(&plan).contains(&"source-semantic-guard"));
            assert!(labels(&plan).contains(&"saga-durable-recovery-guard"));
        }
        let fast = verify_plan(&opts(true, false));
        assert!(!labels(&fast).contains(&"doc-contracts"));
        assert!(!labels(&fast).contains(&"source-semantic-guard"));
        assert!(!labels(&fast).contains(&"saga-durable-recovery-guard"));
    }

    #[test]
    fn verify_plan_matches_registry_membership() -> anyhow::Result<()> {
        let plan = verify_plan(&opts(false, false));
        ensure_plan_has_exact_gate_ids(&plan, registry_gate_ids(|spec| spec.included_in_verify()))?;
        Ok(())
    }

    #[test]
    fn localonly_execution_uses_one_full_verify_gate_and_fast_stays_static() {
        let full = verify_plan(&opts(false, false));
        let gates = full
            .iter()
            .filter(|step| step.id == GateId::LocalOnlyExecution)
            .collect::<Vec<_>>();
        assert_eq!(gates.len(), 1);
        let gate = gates[0];
        assert!(gate.needs_compile());
        assert_eq!(gate.id.spec().lanes(), [Some(GateGroup::LocalOnly), None]);
        assert_eq!(gate.id.spec().tool(), ToolRequirement::Nextest);
        assert_eq!(
            gate.id.spec().policy(),
            crate::ci_lanes::GatePolicy::RequiredEvidence
        );
        assert!(matches!(gate.kind, StepKind::LocalOnlyExecution));
        assert!(
            !verify_plan(&opts(true, false))
                .iter()
                .any(|step| step.id == GateId::LocalOnlyExecution),
            "verify --fast must not claim runtime LocalOnly evidence"
        );
    }

    #[test]
    fn localonly_full_verify_missing_nextest_is_fail_closed_without_report() {
        let root = crate::testutil::unique_tmp("verify-localonly-missing-nextest");
        let report = root
            .join("target")
            .join("localonly-execution")
            .join(crate::localonly_evidence::FILE_NAME);
        let step = step_local_only_execution();

        let result = run_nextest_step_gated(
            "verify",
            &step,
            true,
            || false,
            || {
                std::fs::create_dir_all(report.parent().context("report parent")?)?;
                std::fs::write(&report, b"must not be published")?;
                Ok(())
            },
        );

        assert!(
            result.is_err(),
            "required runtime evidence must fail closed"
        );
        assert!(
            !report.exists(),
            "missing nextest must not publish a report"
        );
    }

    #[test]
    fn postgres_feature_matrix_is_persistent_compile_gate_but_not_fast() -> anyhow::Result<()> {
        for (name, plan) in [
            ("verify", plan_for(PlanProjection::Verify)),
            ("release-check", plan_for(RELEASE_CHECK)),
            ("ci-core", plan_for(PlanProjection::Lane(GateGroup::Core))),
        ] {
            let step = plan
                .iter()
                .find(|step| step.id == GateId::PostgresFeatureMatrix)
                .ok_or_else(|| anyhow::anyhow!("{name} plan lacks postgres feature matrix"))?;
            assert!(
                step.needs_compile(),
                "{name} must classify matrix as compile"
            );
            assert_eq!(step.carrier_file(), None);
            assert!(matches!(
                step.kind,
                StepKind::Internal(InternalCheck::PostgresFeatureMatrix)
            ));
        }
        assert!(
            !verify_plan(&opts(true, false))
                .iter()
                .any(|step| step.id == GateId::PostgresFeatureMatrix),
            "verify --fast must skip compile gates"
        );
        Ok(())
    }

    #[test]
    fn shipped_feature_guard_is_shared_by_verify_and_ci() {
        for (lane, plan) in [
            ("verify", plan_for(PlanProjection::Verify)),
            ("ci", plan_for(RELEASE_CHECK)),
        ] {
            assert!(
                labels(&plan).contains(&"shipped-feature-guard"),
                "{lane} must check the actual server/rss feature graph"
            );
        }
    }

    fn runtime_env_guard_membership_is_exact(plan: &[Step]) -> bool {
        let members = plan
            .iter()
            .enumerate()
            .filter(|(_, step)| step.id == GateId::RuntimeEnvGuard)
            .collect::<Vec<_>>();
        let [(index, step)] = members.as_slice() else {
            return false;
        };
        step.label() == "runtime-env-guard"
            && !step.needs_compile()
            && step.carrier_file() == Some("xtask/src/runtime_env_guard.rs")
            && matches!(
                step.kind,
                StepKind::Internal(InternalCheck::RuntimeEnvGuard)
            )
            && index.checked_sub(1).is_some_and(|before| {
                plan[before].id == GateId::RuntimeRootGuard
                    && plan
                        .get(index + 1)
                        .is_some_and(|after| after.id == GateId::RuntimeDepsGuard)
            })
    }

    fn runtime_root_guard_membership_is_exact(plan: &[Step]) -> bool {
        let members = plan
            .iter()
            .enumerate()
            .filter(|(_, step)| step.id == GateId::RuntimeRootGuard)
            .collect::<Vec<_>>();
        let [(index, step)] = members.as_slice() else {
            return false;
        };
        step.label() == "runtime-root-guard"
            && !step.needs_compile()
            && step.carrier_file() == Some("xtask/src/runtime_root_guard.rs")
            && matches!(
                step.kind,
                StepKind::Internal(InternalCheck::RuntimeRootGuard)
            )
            && index.checked_sub(1).is_some_and(|before| {
                plan[before].id == GateId::RuntimeBaseline
                    && plan
                        .get(index + 1)
                        .is_some_and(|after| after.id == GateId::RuntimeEnvGuard)
            })
    }

    #[test]
    fn runtime_root_guard_is_typed_once_and_ordered_in_all_aggregate_plans() -> anyhow::Result<()> {
        for plan in [
            plan_for(PlanProjection::Verify),
            plan_for(PlanProjection::Lane(GateGroup::Meta)),
            plan_for(RELEASE_CHECK),
        ] {
            assert!(runtime_root_guard_membership_is_exact(&plan));
        }

        let real_plan = plan_for(PlanProjection::Verify);
        let mut omitted = real_plan.clone();
        omitted.retain(|step| step.id != GateId::RuntimeRootGuard);
        assert!(!runtime_root_guard_membership_is_exact(&omitted));

        let mut duplicated = real_plan.clone();
        duplicated.push(
            real_plan
                .iter()
                .find(|step| step.id == GateId::RuntimeRootGuard)
                .context("committed verify plan lacks runtime-root-guard")?
                .clone(),
        );
        assert!(!runtime_root_guard_membership_is_exact(&duplicated));

        let mut wrong_executor = real_plan;
        wrong_executor
            .iter_mut()
            .find(|step| step.id == GateId::RuntimeRootGuard)
            .context("committed verify plan lacks runtime-root-guard")?
            .kind = StepKind::Internal(InternalCheck::RuntimeBaseline);
        assert!(!runtime_root_guard_membership_is_exact(&wrong_executor));
        Ok(())
    }

    #[test]
    fn runtime_env_guard_is_typed_once_and_ordered_in_all_aggregate_plans() -> anyhow::Result<()> {
        for plan in [
            plan_for(PlanProjection::Verify),
            plan_for(PlanProjection::Lane(GateGroup::Meta)),
            plan_for(RELEASE_CHECK),
        ] {
            assert!(runtime_env_guard_membership_is_exact(&plan));
        }

        let real_plan = plan_for(PlanProjection::Verify);
        let mut omitted = real_plan.clone();
        omitted.retain(|step| step.id != GateId::RuntimeEnvGuard);
        assert!(!runtime_env_guard_membership_is_exact(&omitted));

        let mut duplicated = real_plan.clone();
        duplicated.push(
            real_plan
                .iter()
                .find(|step| step.id == GateId::RuntimeEnvGuard)
                .context("committed verify plan lacks runtime-env-guard")?
                .clone(),
        );
        assert!(!runtime_env_guard_membership_is_exact(&duplicated));

        let mut wrong_executor = real_plan;
        wrong_executor
            .iter_mut()
            .find(|step| step.id == GateId::RuntimeEnvGuard)
            .context("committed verify plan lacks runtime-env-guard")?
            .kind = StepKind::Internal(InternalCheck::RuntimeBaseline);
        assert!(!runtime_env_guard_membership_is_exact(&wrong_executor));
        Ok(())
    }

    /// `--fast` 精确投影 registry 的 Always 本地 meta 门。
    #[test]
    fn fast_plan_keeps_lightweight_meta_and_drops_external_or_compile_gates() -> anyhow::Result<()>
    {
        let plan = verify_plan(&opts(true, false));
        let expected = plan_for(PlanProjection::Verify)
            .into_iter()
            .filter(|step| matches!(step.id.local_meta_policy(), LocalMetaPolicy::Always))
            .map(|step| step.id);
        ensure_plan_has_exact_gate_ids(&plan, expected)?;
        assert!(!plan.is_empty(), "fast plan anti-vacuity");
        assert!(plan.iter().all(|step| !step.needs_compile()));
        for dropped in [
            "build",
            "clippy",
            "component-tests",
            "dylint",
            "dylint-test-no-bare-sleep",
            "promtool-rules",
            "deny",
        ] {
            assert!(!labels(&plan).contains(&dropped), "fast 不应含 {dropped}");
        }
        Ok(())
    }

    /// Always 本地 meta checks 在 fast/full 两种模式恒在。
    #[test]
    fn meta_checks_present_in_both_modes() {
        let expected = registry_gate_ids(|spec| {
            matches!(spec.id().local_meta_policy(), LocalMetaPolicy::Always)
        });
        let fast = verify_plan(&opts(true, false));
        assert_eq!(
            fast.iter()
                .map(|step| step.id)
                .collect::<std::collections::BTreeSet<_>>(),
            expected
        );
        let full = verify_plan(&opts(false, false));
        assert!(
            expected
                .iter()
                .all(|id| full.iter().any(|step| step.id == *id))
        );
    }

    #[test]
    fn archrules_matrix_is_full_only_no_compile_internal_gate() -> anyhow::Result<()> {
        assert!(
            !verify_plan(&opts(true, false))
                .iter()
                .any(|step| step.id == GateId::ArchRules)
        );
        for (name, plan) in [
            ("verify", plan_for(PlanProjection::Verify)),
            ("ci", plan_for(RELEASE_CHECK)),
        ] {
            let step = plan
                .iter()
                .find(|s| s.label() == "archrules")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 archrules 步"))?;
            assert!(!step.needs_compile(), "archrules 须是 no-compile gate");
            assert!(matches!(
                step.kind,
                StepKind::Internal(InternalCheck::ArchRules)
            ));
        }
        Ok(())
    }

    #[test]
    fn l0_l1_closeout_gates_have_typed_membership_and_order() -> anyhow::Result<()> {
        const GATES: [(GateId, InternalCheck); 7] = [
            (GateId::ContractValidate, InternalCheck::ContractValidate),
            (GateId::ContractBreaking, InternalCheck::ContractBreaking),
            (GateId::CodegenCheck, InternalCheck::CodegenCheck),
            (GateId::L2AssuranceCheck, InternalCheck::L2AssuranceCheck),
            (
                GateId::ProviderCapabilitiesCheck,
                InternalCheck::ProviderCapabilitiesCheck,
            ),
            (GateId::LocalTxCoverage, InternalCheck::LocalTxCoverage),
            (GateId::LocalOnlyEffects, InternalCheck::LocalOnlyEffects),
        ];

        for (id, expected_check) in GATES {
            let spec = id.spec();
            assert_eq!(spec.lanes(), [Some(GateGroup::Meta), None], "{id:?}");
            assert_eq!(spec.compile_kind(), CompileKind::NoCompile, "{id:?}");
            assert!(spec.included_in_verify(), "{id:?}");
            assert!(
                spec.included_in_profile(ExecutionProfile::ReleaseCheck),
                "{id:?}"
            );
            assert_eq!(spec.tool(), ToolRequirement::InProcess, "{id:?}");
            assert_eq!(
                step_for_id(id).kind,
                StepKind::Internal(expected_check),
                "{id:?} executor mapping drift"
            );
        }

        for (name, plan) in [
            ("full", plan_for(PlanProjection::Verify)),
            ("ci-meta", plan_for(PlanProjection::Lane(GateGroup::Meta))),
            ("release-check", plan_for(RELEASE_CHECK)),
        ] {
            let positions = GATES
                .map(|(id, _)| {
                    plan.iter()
                        .position(|step| step.id == id)
                        .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 {id:?}"))
                })
                .into_iter()
                .collect::<anyhow::Result<Vec<_>>>()?;

            assert!(
                positions.windows(2).all(|pair| pair[0] < pair[1]),
                "{name} contract/codegen/L2-assurance/L0/L1 order drift: {positions:?}"
            );
            assert_eq!(positions[5], positions[3] + 2, "{name} LocalTx order drift");
            assert_eq!(
                positions[6],
                positions[3] + 3,
                "{name} LocalOnly order drift"
            );
        }

        for lane in [GateGroup::Core, GateGroup::Security, GateGroup::Coverage] {
            let plan = plan_for(PlanProjection::Lane(lane));
            for (id, _) in GATES {
                assert!(
                    plan.iter().all(|step| step.id != id),
                    "{id:?} must not be duplicated into {lane:?}"
                );
            }
        }

        Ok(())
    }

    #[test]
    fn assembly_modules_codegen_is_no_compile_internal_gate_after_artifacts_in_all_lanes()
    -> anyhow::Result<()> {
        for (name, plan) in [
            ("full", plan_for(PlanProjection::Verify)),
            ("ci", plan_for(RELEASE_CHECK)),
        ] {
            let labels = labels(&plan);
            let validate = labels
                .iter()
                .position(|label| *label == "assembly-validate")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 assembly-validate"))?;
            let artifacts = labels
                .iter()
                .position(|label| *label == "assembly-artifacts-check")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 assembly-artifacts-check"))?;
            let codegen = labels
                .iter()
                .position(|label| *label == "assembly-modules-check")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 assembly-modules-check"))?;
            assert_eq!(artifacts, validate + 1, "{name} artifact order drift");
            assert_eq!(codegen, artifacts + 1, "{name} lane order drift");
            assert!(
                !plan[codegen].needs_compile(),
                "{name} gate must be no-compile"
            );
            assert_eq!(
                plan[codegen].carrier_file(),
                Some("xtask/src/assembly_codegen.rs")
            );
            assert!(matches!(
                plan[codegen].kind,
                StepKind::Internal(InternalCheck::AssemblyModulesCheck)
            ));
        }
        Ok(())
    }

    fn validate_assembly_artifacts_gate(plan: &[Step]) -> anyhow::Result<()> {
        let positions = [
            GateId::AssemblyValidate,
            GateId::AssemblyArtifactsCheck,
            GateId::AssemblyModulesCheck,
            GateId::AssemblyProvidersCheck,
            GateId::AssemblyLockCheck,
            GateId::AssemblyRuntimePlanCheck,
            GateId::AssemblyGraphCheck,
        ]
        .map(|id| {
            let members = plan
                .iter()
                .enumerate()
                .filter_map(|(index, step)| (step.id == id).then_some(index))
                .collect::<Vec<_>>();
            anyhow::ensure!(
                members.len() == 1,
                "expected exactly one {id:?}, got {members:?}"
            );
            Ok::<usize, anyhow::Error>(members[0])
        })
        .into_iter()
        .collect::<anyhow::Result<Vec<_>>>()?;
        anyhow::ensure!(
            positions.windows(2).all(|pair| pair[1] == pair[0] + 1),
            "assembly closure order drift: {positions:?}"
        );
        let artifact = &plan[positions[1]];
        anyhow::ensure!(!artifact.needs_compile(), "artifact gate compiled");
        anyhow::ensure!(
            artifact.carrier_file() == Some("xtask/src/assembly_artifacts.rs"),
            "artifact carrier drift"
        );
        anyhow::ensure!(
            matches!(
                artifact.kind,
                StepKind::Internal(InternalCheck::AssemblyArtifactsCheck)
            ),
            "artifact executor drift"
        );
        anyhow::ensure!(
            artifact.id.spec().lanes() == [Some(GateGroup::Meta), None]
                && artifact.id.spec().included_in_verify()
                && artifact
                    .id
                    .spec()
                    .included_in_profile(ExecutionProfile::ReleaseCheck)
                && artifact.id.spec().tool() == ToolRequirement::InProcess,
            "artifact typed membership drift"
        );
        Ok(())
    }

    #[test]
    fn assembly_artifacts_gate_is_typed_once_and_orders_the_assembly_closure() -> anyhow::Result<()>
    {
        for (name, plan) in [
            ("full", plan_for(PlanProjection::Verify)),
            ("ci-meta", plan_for(PlanProjection::Lane(GateGroup::Meta))),
            ("release-check", plan_for(RELEASE_CHECK)),
        ] {
            validate_assembly_artifacts_gate(&plan).with_context(|| format!("{name} plan"))?;
        }

        let real = plan_for(PlanProjection::Verify);
        let mut omitted = real.clone();
        omitted.retain(|step| step.id != GateId::AssemblyArtifactsCheck);
        assert!(validate_assembly_artifacts_gate(&omitted).is_err());

        let mut duplicated = real.clone();
        let duplicate = real
            .iter()
            .find(|step| step.id == GateId::AssemblyArtifactsCheck)
            .context("committed verify plan lacks artifact check")?
            .clone();
        duplicated.push(duplicate);
        assert!(validate_assembly_artifacts_gate(&duplicated).is_err());

        let mut wrong_executor = real;
        wrong_executor
            .iter_mut()
            .find(|step| step.id == GateId::AssemblyArtifactsCheck)
            .context("committed fast plan lacks artifact check")?
            .kind = StepKind::Internal(InternalCheck::AssemblyValidate);
        assert!(validate_assembly_artifacts_gate(&wrong_executor).is_err());
        Ok(())
    }

    fn validate_assembly_provider_codegen_gate(plan: &[Step]) -> anyhow::Result<()> {
        let members = plan
            .iter()
            .filter(|step| step.id == GateId::AssemblyProvidersCheck)
            .collect::<Vec<_>>();
        anyhow::ensure!(
            members.len() == 1,
            "expected exactly one assembly provider check"
        );
        let provider = members[0];
        anyhow::ensure!(
            !provider.needs_compile(),
            "provider check must be no-compile"
        );
        anyhow::ensure!(
            provider.carrier_file() == Some("xtask/src/assembly_codegen.rs"),
            "provider carrier drift"
        );
        anyhow::ensure!(
            matches!(
                provider.kind,
                StepKind::Internal(InternalCheck::AssemblyProvidersCheck)
            ),
            "provider executor drift"
        );
        anyhow::ensure!(
            provider.id.spec().lanes() == [Some(GateGroup::Meta), None]
                && provider.id.spec().included_in_verify()
                && provider
                    .id
                    .spec()
                    .included_in_profile(ExecutionProfile::ReleaseCheck)
                && provider.id.spec().tool() == ToolRequirement::InProcess,
            "provider typed membership drift"
        );
        let modules = plan
            .iter()
            .position(|step| step.id == GateId::AssemblyModulesCheck)
            .context("plan lacks modules check")?;
        let providers = plan
            .iter()
            .position(|step| step.id == GateId::AssemblyProvidersCheck)
            .context("plan lacks providers check")?;
        let lock = plan
            .iter()
            .position(|step| step.id == GateId::AssemblyLockCheck)
            .context("plan lacks lock check")?;
        anyhow::ensure!(
            providers == modules + 1 && lock == providers + 1,
            "assembly order must be modules -> providers -> lock"
        );
        Ok(())
    }

    #[test]
    fn assembly_provider_codegen_gate_is_typed_once_and_ordered_in_all_aggregate_plans()
    -> anyhow::Result<()> {
        for (name, plan) in [
            ("full", plan_for(PlanProjection::Verify)),
            ("ci-meta", plan_for(PlanProjection::Lane(GateGroup::Meta))),
            ("release-check", plan_for(RELEASE_CHECK)),
        ] {
            validate_assembly_provider_codegen_gate(&plan)
                .with_context(|| format!("{name} plan"))?;
        }

        let mut omitted = plan_for(PlanProjection::Verify);
        omitted.retain(|step| step.id != GateId::AssemblyProvidersCheck);
        assert!(validate_assembly_provider_codegen_gate(&omitted).is_err());

        let mut duplicated = plan_for(PlanProjection::Verify);
        let duplicate = duplicated
            .iter()
            .find(|step| step.id == GateId::AssemblyProvidersCheck)
            .context("committed verify plan lacks provider check")?
            .clone();
        duplicated.push(duplicate);
        assert!(validate_assembly_provider_codegen_gate(&duplicated).is_err());
        Ok(())
    }

    fn validate_assembly_lock_check(plan: &[Step]) -> anyhow::Result<()> {
        let members = plan
            .iter()
            .filter(|step| step.id == GateId::AssemblyLockCheck)
            .collect::<Vec<_>>();
        anyhow::ensure!(
            members.len() == 1,
            "expected exactly one assembly lock check"
        );
        let lock = members[0];
        anyhow::ensure!(!lock.needs_compile(), "lock check must be no-compile");
        anyhow::ensure!(
            lock.carrier_file() == Some("xtask/src/assembly_lock.rs"),
            "lock carrier drift"
        );
        anyhow::ensure!(
            matches!(
                lock.kind,
                StepKind::Internal(InternalCheck::AssemblyLockCheck)
            ),
            "lock executor drift"
        );
        anyhow::ensure!(
            lock.id.spec().lanes() == [Some(GateGroup::Meta), None]
                && lock.id.spec().included_in_verify()
                && lock
                    .id
                    .spec()
                    .included_in_profile(ExecutionProfile::ReleaseCheck)
                && lock.id.spec().tool() == ToolRequirement::InProcess,
            "lock typed membership drift"
        );
        let modules = plan
            .iter()
            .position(|step| step.id == GateId::AssemblyModulesCheck)
            .context("plan lacks modules check")?;
        let providers = plan
            .iter()
            .position(|step| step.id == GateId::AssemblyProvidersCheck)
            .context("plan lacks providers check")?;
        let lock = plan
            .iter()
            .position(|step| step.id == GateId::AssemblyLockCheck)
            .context("plan lacks lock check")?;
        let graph = plan
            .iter()
            .position(|step| step.id == GateId::AssemblyGraphCheck)
            .context("plan lacks graph check")?;
        let runtime_plan = plan
            .iter()
            .position(|step| step.id == GateId::AssemblyRuntimePlanCheck)
            .context("plan lacks runtime plan check")?;
        anyhow::ensure!(
            providers == modules + 1
                && lock == providers + 1
                && runtime_plan == lock + 1
                && graph == runtime_plan + 1,
            "assembly order must be modules -> providers -> lock -> runtime-plan -> graph"
        );
        Ok(())
    }

    #[test]
    fn assembly_lock_check_is_typed_once_and_ordered_in_all_aggregate_plans() -> anyhow::Result<()>
    {
        for (name, plan) in [
            ("full", plan_for(PlanProjection::Verify)),
            ("ci-meta", plan_for(PlanProjection::Lane(GateGroup::Meta))),
            ("release-check", plan_for(RELEASE_CHECK)),
        ] {
            validate_assembly_lock_check(&plan).with_context(|| format!("{name} plan"))?;
        }

        let mut omitted = plan_for(PlanProjection::Verify);
        omitted.retain(|step| step.id != GateId::AssemblyLockCheck);
        assert!(validate_assembly_lock_check(&omitted).is_err());

        let mut duplicated = plan_for(PlanProjection::Verify);
        let duplicate = duplicated
            .iter()
            .find(|step| step.id == GateId::AssemblyLockCheck)
            .context("committed verify plan lacks lock check")?
            .clone();
        duplicated.push(duplicate);
        assert!(validate_assembly_lock_check(&duplicated).is_err());
        Ok(())
    }

    fn validate_assembly_runtime_plan_gate(plan: &[Step]) -> anyhow::Result<()> {
        let registry = REGISTRY
            .iter()
            .filter(|spec| spec.id() == GateId::AssemblyRuntimePlanCheck)
            .collect::<Vec<_>>();
        anyhow::ensure!(
            registry.len() == 1,
            "expected exactly one assembly runtime plan registry entry"
        );
        let gates = plan
            .iter()
            .enumerate()
            .filter(|(_, step)| step.id == GateId::AssemblyRuntimePlanCheck)
            .collect::<Vec<_>>();
        anyhow::ensure!(
            gates.len() == 1,
            "expected exactly one assembly runtime plan gate"
        );
        let (runtime_plan, gate) = gates[0];
        anyhow::ensure!(
            !gate.needs_compile()
                && gate.carrier_file() == Some("xtask/src/assembly_runtime_plan.rs")
                && matches!(
                    gate.kind,
                    StepKind::Internal(InternalCheck::AssemblyRuntimePlanCheck)
                ),
            "assembly runtime plan executor drift"
        );
        anyhow::ensure!(
            gate.id.spec().lanes() == [Some(GateGroup::Meta), None]
                && gate.id.spec().included_in_verify()
                && gate
                    .id
                    .spec()
                    .included_in_profile(ExecutionProfile::ReleaseCheck)
                && gate.id.spec().tool() == ToolRequirement::InProcess,
            "assembly runtime plan typed membership drift"
        );
        let lock = plan
            .iter()
            .position(|step| step.id == GateId::AssemblyLockCheck)
            .context("plan lacks assembly lock check")?;
        let graph = plan
            .iter()
            .position(|step| step.id == GateId::AssemblyGraphCheck)
            .context("plan lacks assembly graph check")?;
        anyhow::ensure!(
            runtime_plan == lock + 1 && graph == runtime_plan + 1,
            "assembly runtime plan must be exactly between lock and graph"
        );
        Ok(())
    }

    #[test]
    fn assembly_runtime_plan_gate_is_typed_once_and_ordered_in_all_aggregate_plans()
    -> anyhow::Result<()> {
        for (name, plan) in [
            ("verify", plan_for(PlanProjection::Verify)),
            ("ci-meta", plan_for(PlanProjection::Lane(GateGroup::Meta))),
            ("release-check", plan_for(RELEASE_CHECK)),
        ] {
            validate_assembly_runtime_plan_gate(&plan).with_context(|| format!("{name} plan"))?;
        }

        let real = plan_for(PlanProjection::Verify);
        let mut omitted = real.clone();
        omitted.retain(|step| step.id != GateId::AssemblyRuntimePlanCheck);
        assert!(validate_assembly_runtime_plan_gate(&omitted).is_err());

        let mut duplicated = real.clone();
        duplicated.push(
            real.iter()
                .find(|step| step.id == GateId::AssemblyRuntimePlanCheck)
                .context("committed verify plan lacks runtime plan check")?
                .clone(),
        );
        assert!(validate_assembly_runtime_plan_gate(&duplicated).is_err());

        let mut wrong_executor = real;
        wrong_executor
            .iter_mut()
            .find(|step| step.id == GateId::AssemblyRuntimePlanCheck)
            .context("committed fast plan lacks runtime plan check")?
            .kind = StepKind::Internal(InternalCheck::AssemblyLockCheck);
        assert!(validate_assembly_runtime_plan_gate(&wrong_executor).is_err());
        Ok(())
    }

    fn validate_l2_assurance_gate(plan: &[Step]) -> anyhow::Result<()> {
        let registry = REGISTRY
            .iter()
            .filter(|spec| spec.id() == GateId::L2AssuranceCheck)
            .collect::<Vec<_>>();
        anyhow::ensure!(
            registry.len() == 1,
            "expected exactly one L2 assurance registry entry"
        );
        let spec = *registry[0];
        anyhow::ensure!(
            spec.label() == "l2-assurance-check"
                && spec.evidence() == crate::ci_lanes::EvidenceKind::Source,
            "L2 assurance registry binding drift"
        );
        anyhow::ensure!(
            matches!(
                step_for_id(GateId::L2AssuranceCheck).kind,
                StepKind::Internal(InternalCheck::L2AssuranceCheck)
            ),
            "L2 assurance catalog executor drift"
        );
        let gates = plan
            .iter()
            .filter(|step| step.id == GateId::L2AssuranceCheck)
            .collect::<Vec<_>>();
        anyhow::ensure!(gates.len() == 1, "expected exactly one L2 assurance gate");
        let gate = gates[0];
        anyhow::ensure!(!gate.needs_compile(), "L2 assurance must be no-compile");
        anyhow::ensure!(
            gate.carrier_file() == Some("xtask/src/l2_assurance.rs"),
            "L2 assurance carrier drift"
        );
        anyhow::ensure!(
            matches!(
                gate.kind,
                StepKind::Internal(InternalCheck::L2AssuranceCheck)
            ),
            "L2 assurance executor drift"
        );
        anyhow::ensure!(
            gate.id.spec().lanes() == [Some(GateGroup::Meta), None]
                && gate.id.spec().included_in_verify()
                && gate
                    .id
                    .spec()
                    .included_in_profile(ExecutionProfile::ReleaseCheck)
                && gate.id.spec().tool() == ToolRequirement::InProcess,
            "L2 assurance typed membership drift"
        );
        let codegen = plan
            .iter()
            .position(|step| step.id == GateId::CodegenCheck)
            .context("plan lacks codegen check")?;
        let assurance = plan
            .iter()
            .position(|step| step.id == GateId::L2AssuranceCheck)
            .context("plan lacks L2 assurance check")?;
        anyhow::ensure!(
            assurance == codegen + 1,
            "L2 assurance must immediately follow codegen"
        );
        Ok(())
    }

    #[test]
    fn l2_assurance_gate_is_typed_once_and_ordered_in_all_aggregate_plans() -> anyhow::Result<()> {
        for (name, plan) in [
            ("verify", plan_for(PlanProjection::Verify)),
            ("ci-meta", plan_for(PlanProjection::Lane(GateGroup::Meta))),
            ("release-check", plan_for(RELEASE_CHECK)),
        ] {
            validate_l2_assurance_gate(&plan).with_context(|| format!("{name} plan"))?;
        }

        let real_plan = plan_for(PlanProjection::Verify);

        let mut omitted = real_plan.clone();
        omitted.retain(|step| step.id != GateId::L2AssuranceCheck);
        assert!(validate_l2_assurance_gate(&omitted).is_err());

        let mut duplicated = real_plan.clone();
        let duplicate = real_plan
            .iter()
            .find(|step| step.id == GateId::L2AssuranceCheck)
            .context("committed fast plan lacks L2 assurance check")?
            .clone();
        duplicated.push(duplicate);
        assert!(validate_l2_assurance_gate(&duplicated).is_err());

        let mut wrong_executor = real_plan;
        wrong_executor
            .iter_mut()
            .find(|step| step.id == GateId::L2AssuranceCheck)
            .context("committed fast plan lacks L2 assurance check")?
            .kind = StepKind::Internal(InternalCheck::CodegenCheck);
        assert!(validate_l2_assurance_gate(&wrong_executor).is_err());
        Ok(())
    }

    fn validate_provider_capabilities_gate(plan: &[Step]) -> anyhow::Result<()> {
        let registry = REGISTRY
            .iter()
            .filter(|spec| spec.id() == GateId::ProviderCapabilitiesCheck)
            .collect::<Vec<_>>();
        anyhow::ensure!(
            registry.len() == 1,
            "expected exactly one provider capabilities registry entry"
        );
        let spec = *registry[0];
        anyhow::ensure!(
            spec.label() == "provider-capabilities-check"
                && spec.id().carrier_file() == Some("xtask/src/provider_capabilities.rs")
                && spec.evidence() == crate::ci_lanes::EvidenceKind::Source,
            "provider capabilities registry binding drift"
        );
        anyhow::ensure!(
            matches!(
                step_for_id(GateId::ProviderCapabilitiesCheck).kind,
                StepKind::Internal(InternalCheck::ProviderCapabilitiesCheck)
            ),
            "provider capabilities catalog executor drift"
        );
        let gates = plan
            .iter()
            .filter(|step| step.id == GateId::ProviderCapabilitiesCheck)
            .collect::<Vec<_>>();
        anyhow::ensure!(
            gates.len() == 1,
            "expected exactly one provider capabilities gate"
        );
        let gate = gates[0];
        anyhow::ensure!(
            !gate.needs_compile()
                && matches!(
                    gate.kind,
                    StepKind::Internal(InternalCheck::ProviderCapabilitiesCheck)
                ),
            "provider capabilities executor drift"
        );
        let assurance = plan
            .iter()
            .position(|step| step.id == GateId::L2AssuranceCheck)
            .context("plan lacks L2 assurance check")?;
        let provider = plan
            .iter()
            .position(|step| step.id == GateId::ProviderCapabilitiesCheck)
            .context("plan lacks provider capabilities check")?;
        anyhow::ensure!(
            provider == assurance + 1,
            "provider capabilities must immediately follow L2 assurance"
        );
        Ok(())
    }

    #[test]
    fn provider_capabilities_gate_is_typed_once_and_ordered_in_all_aggregate_plans()
    -> anyhow::Result<()> {
        for (name, plan) in [
            ("verify", plan_for(PlanProjection::Verify)),
            ("ci-meta", plan_for(PlanProjection::Lane(GateGroup::Meta))),
            ("release-check", plan_for(RELEASE_CHECK)),
        ] {
            validate_provider_capabilities_gate(&plan).with_context(|| format!("{name} plan"))?;
        }

        let real_plan = plan_for(PlanProjection::Verify);
        let mut omitted = real_plan.clone();
        omitted.retain(|step| step.id != GateId::ProviderCapabilitiesCheck);
        assert!(validate_provider_capabilities_gate(&omitted).is_err());

        let mut duplicated = real_plan.clone();
        let duplicate = real_plan
            .iter()
            .find(|step| step.id == GateId::ProviderCapabilitiesCheck)
            .context("committed verify plan lacks provider capabilities check")?
            .clone();
        duplicated.push(duplicate);
        assert!(validate_provider_capabilities_gate(&duplicated).is_err());

        let mut wrong_executor = real_plan;
        wrong_executor
            .iter_mut()
            .find(|step| step.id == GateId::ProviderCapabilitiesCheck)
            .context("committed verify plan lacks provider capabilities check")?
            .kind = StepKind::Internal(InternalCheck::CodegenCheck);
        assert!(validate_provider_capabilities_gate(&wrong_executor).is_err());
        Ok(())
    }

    #[test]
    fn assembly_graph_is_no_compile_internal_gate_after_modules_in_all_lanes() -> anyhow::Result<()>
    {
        for (name, plan) in [
            ("full", plan_for(PlanProjection::Verify)),
            ("ci", plan_for(RELEASE_CHECK)),
        ] {
            let labels = labels(&plan);
            let modules = labels
                .iter()
                .position(|label| *label == "assembly-modules-check")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 assembly-modules-check"))?;
            let graph = labels
                .iter()
                .position(|label| *label == "assembly-graph-check")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 assembly-graph-check"))?;
            let providers = labels
                .iter()
                .position(|label| *label == "assembly-providers-check")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 assembly-providers-check"))?;
            let lock = labels
                .iter()
                .position(|label| *label == "assembly-lock-check")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 assembly-lock-check"))?;
            let runtime_plan = labels
                .iter()
                .position(|label| *label == "assembly-runtime-plan-check")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 assembly-runtime-plan-check"))?;
            assert_eq!(providers, modules + 1, "{name} providers lane order drift");
            assert_eq!(lock, providers + 1, "{name} lock lane order drift");
            assert_eq!(runtime_plan, lock + 1, "{name} runtime plan order drift");
            assert_eq!(graph, runtime_plan + 1, "{name} graph lane order drift");
            assert!(!plan[graph].needs_compile());
            assert_eq!(plan[graph].carrier_file(), Some("xtask/src/graph.rs"));
            assert!(matches!(
                plan[graph].kind,
                StepKind::Internal(InternalCheck::AssemblyGraphCheck)
            ));
        }
        Ok(())
    }

    #[test]
    fn runtime_deps_guard_is_no_compile_internal_gate_between_baseline_and_archrules()
    -> anyhow::Result<()> {
        for (name, plan) in [("ci", plan_for(RELEASE_CHECK))] {
            let labels = labels(&plan);
            let baseline_pos = labels
                .iter()
                .position(|label| *label == "runtime-baseline")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 runtime-baseline 步"))?;
            let guard_pos = labels
                .iter()
                .position(|label| *label == "runtime-deps-guard")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 runtime-deps-guard 步"))?;
            let archrules_pos = labels
                .iter()
                .position(|label| *label == "archrules")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 archrules 步"))?;
            assert!(
                baseline_pos < guard_pos && guard_pos < archrules_pos,
                "runtime-deps-guard 必须位于 runtime-baseline 之后、archrules 之前，确保 archrules 能索引 guard carrier"
            );
            let step = &plan[guard_pos];
            assert!(
                !step.needs_compile(),
                "runtime-deps-guard 须是 no-compile gate"
            );
            assert!(matches!(
                step.kind,
                StepKind::Internal(InternalCheck::RuntimeDepsGuard)
            ));
        }
        Ok(())
    }

    /// 决策真值表（INVARIANT VERIFY-TOOL-GATE-01）：缺工具默认 fail-closed，豁免仅经显式 flag。
    #[test]
    fn resolve_tool_truth_table() {
        assert_eq!(resolve_tool(true, false), ToolAction::Run);
        assert_eq!(resolve_tool(true, true), ToolAction::Run);
        assert_eq!(resolve_tool(false, true), ToolAction::SkipWarn);
        assert_eq!(resolve_tool(false, false), ToolAction::Fail);
    }

    fn assert_integration_batch_argv(
        selection: &IntegrationSelection,
        shard: IntegrationShard,
        batch: &integration_shards::ShardBatch,
        partition: crate::nextest::HashPartition,
    ) -> anyhow::Result<()> {
        let args =
            crate::nextest::NextestInvocation::for_integration_batch(selection, batch, None)?
                .execution_argv();
        assert!(args.iter().any(|arg| arg == "--no-tests=fail"));
        assert_eq!(
            args.windows(2)
                .filter(|pair| pair[0] == "--test-threads" && pair[1] == "1")
                .count(),
            usize::from(batch.scheduling == Scheduling::Serial)
        );
        let selected_packages = args
            .windows(2)
            .filter(|pair| pair[0] == "-p")
            .map(|pair| pair[1].as_str())
            .collect::<Vec<_>>();
        assert_eq!(selected_packages, [batch.package]);
        assert_integration_batch_feature_and_target(batch, &args)?;
        assert!(
            args.windows(2)
                .any(|pair| pair[0] == "-E" && pair[1].as_str() == batch.filter.as_str())
        );
        if shard.validate_partition(Some(partition)).is_ok() {
            let partitioned = crate::nextest::NextestInvocation::for_integration_batch(
                selection,
                batch,
                Some(partition),
            )?
            .execution_argv();
            assert!(partitioned.iter().any(|arg| arg == "--no-tests=pass"));
        }
        Ok(())
    }

    fn assert_integration_batch_feature_and_target(
        batch: &integration_shards::ShardBatch,
        args: &[String],
    ) -> anyhow::Result<()> {
        let expected_feature = integration_shards::LocalFeatureScope::for_package(batch.package)
            .context("batch package must map to LocalFeatureScope")?
            .feature();
        assert_eq!(batch.feature, expected_feature);
        assert!(
            args.windows(2)
                .any(|pair| pair[0] == "--features" && pair[1] == expected_feature),
            "package {} must enable feature {expected_feature}, args={args:?}",
            batch.package
        );
        if batch.package == integration_shards::LocalFeatureScope::Mqtt.package() {
            assert_eq!(expected_feature, "broker-tests");
        }
        match batch.kind {
            integration_shards::TargetKind::Lib => {
                assert!(args.iter().any(|arg| arg == "--lib"));
                assert!(!args.iter().any(|arg| arg == "--test"));
            }
            integration_shards::TargetKind::Test => {
                assert!(!args.iter().any(|arg| arg == "--lib"));
                let selected = args
                    .windows(2)
                    .filter(|pair| pair[0] == "--test")
                    .map(|pair| pair[1].as_str())
                    .collect::<Vec<_>>();
                assert_eq!(selected, batch.targets);
            }
        }
        Ok(())
    }

    #[test]
    fn integration_batch_args_scope_targets_and_threads() -> anyhow::Result<()> {
        let partition = crate::nextest::HashPartition::new(1, 2)?;
        let selection = IntegrationSelection::for_profile(ExecutionProfile::ReleaseCheck)?;
        for shard in IntegrationShard::ALL {
            let batches = integration_shards::batches(&selection, *shard);
            let selected_units = batches
                .iter()
                .flat_map(|batch| batch.unit_ids.iter().copied())
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(selected_units, selection.unit_ids_for_shard(*shard));
            for batch in &batches {
                assert_integration_batch_argv(&selection, *shard, batch, partition)?;
            }
        }
        Ok(())
    }

    #[test]
    fn critical_integration_selection_has_exact_argv_and_rejects_batch_drift() -> anyhow::Result<()>
    {
        let selection = IntegrationSelection::critical([IntegrationUnitId::AmqpLib])?;
        let batches = integration_shards::batches(&selection, IntegrationShard::EventTransport);
        let [batch] = batches.as_slice() else {
            bail!("single amqp-lib selection must derive one batch");
        };
        let invocation = crate::nextest::NextestInvocation::for_integration_batch(
            &selection,
            batch,
            Some("1/2".parse()?),
        )?;
        assert_eq!(
            invocation.execution_argv(),
            [
                "cargo",
                "nextest",
                "run",
                "--profile",
                "integration",
                "--features",
                "integration",
                "--no-tests=pass",
                "-p",
                "amqp",
                "--lib",
                "-E",
                "(package(=amqp) and binary(=amqp) and kind(=lib))",
                "--partition",
                "hash:1/2",
            ]
            .map(str::to_owned)
        );

        let mut drifted = batch.clone();
        drifted.filter = "all()".to_owned();
        assert!(
            crate::nextest::NextestInvocation::for_integration_batch(
                &selection,
                &drifted,
                Some("1/2".parse()?)
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn nextest_probe_registry_is_bidirectionally_bound_to_step_kind() {
        fn binding_is_valid(requirement: ToolRequirement, is_nextest: bool) -> bool {
            matches!(requirement, ToolRequirement::Nextest) == is_nextest
        }
        for spec in REGISTRY {
            let step = step_for_id(spec.id());
            assert!(
                binding_is_valid(
                    spec.tool(),
                    matches!(step.kind, StepKind::Nextest | StepKind::LocalOnlyExecution)
                ),
                "gate {} nextest probe/StepKind 漂移",
                step.label()
            );
        }
        assert!(!binding_is_valid(ToolRequirement::Nextest, false));
        assert!(!binding_is_valid(
            ToolRequirement::CargoBuiltin(crate::cmd::CargoSubcommand::Build),
            true
        ));
    }

    #[test]
    fn cargo_builtin_registry_has_exact_typed_prefixes() {
        let mut observed = std::collections::BTreeSet::new();
        for spec in REGISTRY {
            if let ToolRequirement::CargoBuiltin(subcommand) = spec.tool() {
                let step = step_for_id(spec.id());
                assert_eq!(
                    step.args.first().copied(),
                    Some(subcommand.as_str()),
                    "gate {} typed cargo builtin/argv 漂移",
                    step.label()
                );
                observed.insert(subcommand.as_str());
            }
        }
        assert_eq!(observed, ["build", "clippy", "fmt", "test"].into());
    }

    #[test]
    fn integration_replay_route_is_closed_and_exact() -> anyhow::Result<()> {
        let selection = IntegrationSelection::critical([
            IntegrationUnitId::AmqpLib,
            IntegrationUnitId::AmqpIntegration,
        ])?;
        let batch = integration_shards::batches(&selection, IntegrationShard::EventTransport)
            .into_iter()
            .find(|batch| batch.unit_ids.contains(&IntegrationUnitId::AmqpLib))
            .context("amqp-lib critical batch")?;
        let invocation = crate::nextest::NextestInvocation::for_integration_batch(
            &selection,
            &batch,
            Some("2/2".parse()?),
        )?;
        assert_eq!(
            invocation.replay_spec(),
            &crate::nextest::ReplaySpec::Integration {
                profile: crate::nextest::NextestProfile::Integration,
                shard: IntegrationShard::EventTransport,
                selection,
                unit_ids: crate::nextest::IntegrationReplayUnitIds::new(
                    [IntegrationUnitId::AmqpLib].into_iter().collect(),
                )?,
                partition: Some("2/2".parse()?),
            }
        );
        Ok(())
    }

    /// anti-vacuity 红例（INVARIANT VERIFY-AGGREGATE-01）：门步非零退出 ⇒ `Err`，证明门真会 fail。
    #[test]
    fn run_step_nonzero_is_err() -> anyhow::Result<()> {
        let root = workspace_root()?;
        assert!(
            run_step(
                "verify",
                "redcase",
                crate::cmd::CargoSubcommand::Fmt,
                &["--zzz-not-a-cargo-flag"],
                &[],
                &root,
                crate::cmd::ExecutionPolicy::FailFast,
            )
            .is_err()
        );
        Ok(())
    }

    /// 对照绿例：成功步 ⇒ `Ok`。
    #[test]
    fn run_step_success_is_ok() -> anyhow::Result<()> {
        let root = workspace_root()?;
        assert!(
            run_step(
                "verify",
                "greencase",
                crate::cmd::CargoSubcommand::Fmt,
                &["--version"],
                &[],
                &root,
                crate::cmd::ExecutionPolicy::FailFast,
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn run_labeled_plan_executes_small_plan_with_lane_prefix() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let plan = [Step {
            id: GateId::Fmt,
            args: &["fmt", "--version"],
            kind: StepKind::Cargo,
            env: &[],
        }];
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        run_labeled_plan("ci", &plan, &opts(false, false), &root, &command_facts)
    }

    #[test]
    fn command_scope_non_facts_plan_is_zero_load() -> anyhow::Result<()> {
        use std::cell::Cell;
        use std::rc::Rc;

        let root = workspace_root()?;
        let calls = Rc::new(Cell::new(0));
        let counter = Rc::clone(&calls);
        let command_facts =
            crate::workspace_facts::CommandWorkspaceFacts::with_metadata_loader(&root, move |_| {
                counter.set(counter.get() + 1);
                Err("non-facts plan must not load workspace facts".to_owned())
            });
        let plan = [Step {
            id: GateId::Fmt,
            args: &["fmt", "--version"],
            kind: StepKind::Cargo,
            env: &[],
        }];
        run_labeled_plan("ci", &plan, &opts(false, false), &root, &command_facts)?;
        assert_eq!(
            calls.get(),
            0,
            "non-facts labeled plan must keep CommandWorkspaceFacts zero-load"
        );
        Ok(())
    }

    #[test]
    fn command_scope_one_load_across_assembly_consumers() -> anyhow::Result<()> {
        use std::cell::Cell;
        use std::rc::Rc;

        let root = workspace_root()?;
        let output = crate::cmd::cargo_cmd(
            crate::cmd::CargoSubcommand::Metadata,
            &["--locked", "--all-features", "--format-version", "1"],
            &[],
            Some(&root),
        )
        .output()?;
        anyhow::ensure!(output.status.success(), "prepare metadata fixture");
        let metadata = output.stdout;
        let calls = Rc::new(Cell::new(0));
        let counter = Rc::clone(&calls);
        let command_facts =
            crate::workspace_facts::CommandWorkspaceFacts::with_metadata_loader(&root, move |_| {
                counter.set(counter.get() + 1);
                Ok(metadata.clone())
            });

        for check in [
            InternalCheck::AssemblyValidate,
            InternalCheck::AssemblyArtifactsCheck,
            InternalCheck::AssemblyLockCheck,
            InternalCheck::AssemblyGraphCheck,
        ] {
            run_internal(check, &opts(false, false), &root, &command_facts)?;
        }
        assert_eq!(calls.get(), 1);
        Ok(())
    }

    #[test]
    fn assembly_artifacts_metadata_failure_runs_stable_failure_reporter() -> anyhow::Result<()> {
        use std::cell::Cell;

        let root = workspace_root()?;
        let command_facts =
            crate::workspace_facts::CommandWorkspaceFacts::with_metadata_loader(&root, |_| {
                Err("synthetic metadata failure".to_owned())
            });
        let reported = Cell::new(false);
        let error = run_assembly_artifacts_check(&root, &command_facts, || reported.set(true))
            .expect_err("metadata failure must fail the aggregate artifact check");
        assert!(
            reported.get(),
            "metadata failure must emit the stable FAILED view"
        );
        assert!(
            error
                .to_string()
                .contains("assembly-artifacts-check: load command-scoped workspace facts")
        );
        Ok(())
    }

    #[test]
    fn command_scope_one_load_across_nextest_shipped_and_contract_consumers() -> anyhow::Result<()>
    {
        use std::cell::Cell;
        use std::rc::Rc;

        let root = workspace_root()?;
        let metadata_bytes = {
            let output = crate::cmd::cargo_cmd(
                crate::cmd::CargoSubcommand::Metadata,
                &["--locked", "--all-features", "--format-version", "1"],
                &[],
                Some(&root),
            )
            .output()
            .context("execute cargo metadata for one-load fixture bytes")?;
            anyhow::ensure!(
                output.status.success(),
                "cargo metadata failed while preparing one-load fixture bytes (status={}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            output.stdout
        };
        let calls = Rc::new(Cell::new(0));
        let counter = Rc::clone(&calls);
        let injected = metadata_bytes.clone();
        let command_facts =
            crate::workspace_facts::CommandWorkspaceFacts::with_metadata_loader(&root, move |_| {
                counter.set(counter.get() + 1);
                Ok(injected.clone())
            });

        crate::nextest::validate_workspace(&root, command_facts.get()?)?;
        run_internal(
            InternalCheck::ShippedFeatureGuard,
            &opts(false, false),
            &root,
            &command_facts,
        )?;
        run_internal(
            InternalCheck::ContractBindingGuard,
            &opts(false, false),
            &root,
            &command_facts,
        )?;
        assert_eq!(
            calls.get(),
            1,
            "nextest / shipped-feature / contract-binding consumers must share one metadata load"
        );
        Ok(())
    }

    #[test]
    fn command_scope_one_load_across_l2_localtx_and_localonly_consumers() -> anyhow::Result<()> {
        use std::cell::Cell;
        use std::rc::Rc;

        let root = workspace_root()?;
        let metadata_bytes = {
            let output = crate::cmd::cargo_cmd(
                crate::cmd::CargoSubcommand::Metadata,
                &["--locked", "--all-features", "--format-version", "1"],
                &[],
                Some(&root),
            )
            .output()
            .context("execute cargo metadata for L2/LocalTx/LocalOnly one-load fixture bytes")?;
            anyhow::ensure!(
                output.status.success(),
                "cargo metadata failed while preparing one-load fixture bytes (status={}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            output.stdout
        };
        let calls = Rc::new(Cell::new(0));
        let counter = Rc::clone(&calls);
        let injected = metadata_bytes.clone();
        let command_facts =
            crate::workspace_facts::CommandWorkspaceFacts::with_metadata_loader(&root, move |_| {
                counter.set(counter.get() + 1);
                Ok(injected.clone())
            });

        // Success or early governance error still counts as a consumer invocation; the plan-level
        // invariant is that CommandWorkspaceFacts loads metadata at most once across consumers.
        let _ = run_internal(
            InternalCheck::L2AssuranceCheck,
            &opts(false, false),
            &root,
            &command_facts,
        );
        let _ = run_internal(
            InternalCheck::LocalTxCoverage,
            &opts(false, false),
            &root,
            &command_facts,
        );
        let _ = run_internal(
            InternalCheck::LocalOnlyEffects,
            &opts(false, false),
            &root,
            &command_facts,
        );
        assert_eq!(
            calls.get(),
            1,
            "L2 / LocalTx / LocalOnly consumers must share one metadata load"
        );
        Ok(())
    }

    /// dylint 步必须带 `DYLINT_RUSTFLAGS=-D warnings`——否则默认 `Warn` 的 `rss_domain_no_serialize`
    /// 不会让 verify 非零，门退化为非 fail-closed（#1023 的核心诉求落空）。
    ///
    /// 注：本测试只断言 **plan 配置**带该 env（无 spawn）；运行时端到端 fail-closed（违例真让 dylint
    /// 非零）经手跑 `cargo xtask verify` 验证——xtask 测试策略不含跑 nightly dylint 的集成测试。
    #[test]
    fn dylint_step_is_fail_closed_via_deny_warnings() -> anyhow::Result<()> {
        let plan = plan_for(PlanProjection::Verify);
        let dylint = plan
            .iter()
            .find(|s| s.label() == "dylint")
            .ok_or_else(|| anyhow::anyhow!("plan 缺 dylint 步"))?;
        assert!(
            dylint
                .env
                .iter()
                .any(|(k, v)| *k == "DYLINT_RUSTFLAGS" && v.contains("-D warnings")),
            "dylint 步须 -D warnings 才 fail-closed"
        );
        Ok(())
    }

    /// #1495：`rss_test_no_bare_sleep` 专用步须 `-D rss_test_no_bare_sleep` +
    /// `--all-features --all-targets`（扫测试目标面；勿用全局 `-D warnings`）。
    #[test]
    fn dylint_test_no_bare_sleep_step_is_fail_closed_with_all_targets() -> anyhow::Result<()> {
        let plan = plan_for(PlanProjection::Verify);
        let step = plan
            .iter()
            .find(|s| s.label() == "dylint-test-no-bare-sleep")
            .ok_or_else(|| anyhow::anyhow!("plan 缺 dylint-test-no-bare-sleep 步"))?;
        assert!(
            step.env
                .iter()
                .any(|(k, v)| *k == "DYLINT_RUSTFLAGS" && v.contains("-D rss_test_no_bare_sleep")),
            "dylint-test-no-bare-sleep 步须 -D rss_test_no_bare_sleep 才 fail-closed"
        );
        assert!(
            step.args.contains(&"--all-features") && step.args.contains(&"--all-targets"),
            "dylint-test-no-bare-sleep 须 --all-features --all-targets，实际 {:?}",
            step.args
        );
        assert!(
            step.args.contains(&"--lib") && step.args.contains(&"rss_test_no_bare_sleep"),
            "dylint-test-no-bare-sleep 须 --lib rss_test_no_bare_sleep，实际 {:?}",
            step.args
        );
        Ok(())
    }

    /// 缺工具 + 不宽限 ⇒ `run_one` 返回 `Err`（executor 层 anti-vacuity 红例，INVARIANT VERIFY-TOOL-GATE-01）。
    #[test]
    fn run_one_missing_tool_fail_closed_is_err() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let step = missing_coverage_tool_step();
        let probed = std::cell::Cell::new(false);
        let command_facts =
            crate::workspace_facts::CommandWorkspaceFacts::with_metadata_loader(&root, |_| {
                Err("tool-gate path must not load workspace facts".to_owned())
            });
        assert!(
            run_one(
                "verify",
                &step,
                &opts(false, false),
                &root,
                &command_facts,
                |probe| {
                    assert_eq!(probe, crate::cmd::CargoSubcommand::LlvmCovReport);
                    probed.set(true);
                    false
                }
            )
            .is_err()
        );
        assert!(probed.get(), "run_one must query registry tool metadata");
        Ok(())
    }

    /// 缺工具 + 显式宽限 ⇒ `run_one` 警告跳过、返回 `Ok`（`--allow-missing-tools` 路径）。
    #[test]
    fn run_one_missing_tool_skipwarn_does_not_touch_executor() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let step = missing_coverage_tool_step();
        let command_facts =
            crate::workspace_facts::CommandWorkspaceFacts::with_metadata_loader(&root, |_| {
                Err("tool-gate path must not load workspace facts".to_owned())
            });
        assert!(
            run_one(
                "verify",
                &step,
                &opts(false, true),
                &root,
                &command_facts,
                |_| false
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn coverage_tools_require_both_typed_capabilities_before_execution() {
        for (llvm_cov, nextest, should_run) in [
            (false, false, false),
            (false, true, false),
            (true, false, false),
            (true, true, true),
        ] {
            let executed = std::cell::Cell::new(false);
            let result = run_coverage_tools_gated(
                "ci-coverage",
                false,
                "coverage",
                llvm_cov,
                || nextest,
                || {
                    executed.set(true);
                    Ok(())
                },
            );
            assert_eq!(result.is_ok(), should_run);
            assert_eq!(executed.get(), should_run);
        }
    }

    fn missing_coverage_tool_step() -> Step {
        Step {
            id: GateId::Coverage,
            args: &["zzz-executor-must-not-run"],
            kind: StepKind::Cargo,
            env: &[],
        }
    }

    // ---- ci 超集计划（issue #1132）----

    /// ci 的 build/clippy 升 `--all-features --all-targets`（issue 验收：编译态全覆盖）。
    #[test]
    fn ci_build_clippy_use_all_features_all_targets() -> anyhow::Result<()> {
        let plan = plan_for(RELEASE_CHECK);
        for label in ["build", "clippy"] {
            let step = plan
                .iter()
                .find(|s| s.label() == label)
                .ok_or_else(|| anyhow::anyhow!("release-check 缺 `{label}` 步"))?;
            assert!(
                step.args.contains(&"--all-features") && step.args.contains(&"--all-targets"),
                "ci `{label}` 须 --all-features --all-targets，实际 {:?}",
                step.args
            );
        }
        Ok(())
    }

    /// ci 用覆盖率门**替** nextest（同跑兼测试），并尾追 public-api（轴 A）；二者皆 ToolGatedInternal。
    #[test]
    fn ci_replaces_nextest_with_coverage_and_adds_public_api() -> anyhow::Result<()> {
        let plan = plan_for(RELEASE_CHECK);
        assert!(
            !labels(&plan).contains(&"component-tests"),
            "ci 不应有独立 nextest 步（已并入 coverage）"
        );
        let cov = plan
            .iter()
            .find(|s| s.label() == "coverage")
            .ok_or_else(|| anyhow::anyhow!("release-check 缺 coverage 步"))?;
        assert!(matches!(
            cov.kind,
            StepKind::Internal(InternalCheck::Coverage)
        ));
        assert!(matches!(
            cov.id.spec().tool(),
            ToolRequirement::CoverageTools
        ));
        let pa = plan
            .iter()
            .find(|s| s.label() == "public-api")
            .ok_or_else(|| anyhow::anyhow!("release-check 缺 public-api 步"))?;
        assert!(matches!(
            pa.kind,
            StepKind::Internal(InternalCheck::PublicApiCheck)
        ));
        assert!(matches!(
            pa.id.spec().tool(),
            ToolRequirement::CargoTool {
                tool: crate::cmd::CargoSubcommand::PublicApi,
                ..
            }
        ));
        Ok(())
    }

    /// 共享门步在 verify 与 ci 里**逐字相同**（同一构造，不漂移）。Step 派生 PartialEq ⇒ 直接比对。
    #[test]
    fn ci_shares_meta_deny_dylint_with_verify_verbatim() {
        let v = plan_for(PlanProjection::Verify);
        let c = plan_for(RELEASE_CHECK);
        let find = |plan: &[Step], id: GateId| plan.iter().find(|s| s.id == id).cloned();
        let shared = registry_gate_ids(|spec| {
            selected_for(PlanProjection::Verify, spec.id())
                && selected_for(RELEASE_CHECK, spec.id())
        });
        assert!(
            shared.contains(&GateId::CiEntryGuard),
            "shared-set anti-vacuity"
        );
        for id in shared {
            assert_eq!(
                find(&v, id),
                find(&c, id),
                "共享门步 `{id:?}` 在 verify/ci 不一致（漂移）"
            );
        }
    }

    // ---- audit 精简供应链 lane（issue #1133；每日 cron advisory 刷新）----

    /// audit_plan 顺序与门集（单一事实源；scheduled lane 实跑顺序）：advisory-scoped deny + cargo-audit。
    /// 不含 licenses/bans——它们只随 Cargo.lock 变（= 随 PR 变），定时跑无增益；release-check 已全查。
    #[test]
    fn audit_plan_keeps_local_supply_chain_order() {
        assert_eq!(labels(&audit_plan()), vec!["deny-advisories", "audit"]);
    }

    /// integration-compile（默认 verify 抓编译漂移）`--no-run` 覆盖各 adapter + journeys durable journey
    /// （F7 + #1137：原仅 postgres；#1010 加 mqtt；#1298 加 runtime assembly integration 测试）。
    #[test]
    fn integration_compile_covers_adapters_and_journeys_no_run() {
        let step = step_integration_compile();
        assert_eq!(step.label(), "integration-compile");
        assert_eq!(
            step.id.spec().tool(),
            ToolRequirement::CargoBuiltin(crate::cmd::CargoSubcommand::Test)
        );
        assert!(step.args.contains(&"--no-run"), "默认门只编译不实跑");
        for p in [
            "postgres",
            "redis-adapter",
            "amqp",
            "mqtt",
            "journeys",
            "runtime",
        ] {
            assert!(step.args.contains(&p), "integration-compile 须覆盖 {p}");
        }
    }

    /// audit lane 的 deny 步是 **advisory-scoped**（`deny check advisories`），非裸 `deny check`——
    /// 定时刷新只查漏洞库，licenses/bans 留给 PR-triggered adaptive plan 的 `deny check`。
    #[test]
    fn audit_plan_deny_is_advisories_scoped() -> anyhow::Result<()> {
        let plan = audit_plan();
        let deny = plan
            .iter()
            .find(|s| s.label() == "deny-advisories")
            .ok_or_else(|| anyhow::anyhow!("audit_plan 缺 deny-advisories 步"))?;
        assert_eq!(deny.args, &["deny", "check", "advisories"]);
        assert!(matches!(
            deny.id.spec().tool(),
            ToolRequirement::CargoTool {
                tool: crate::cmd::CargoSubcommand::Deny,
                ..
            }
        ));
        Ok(())
    }

    /// cargo-audit 步是 Tool gate、probe `audit`（缺工具 fail-closed，复用 VERIFY-TOOL-GATE-01）；
    /// 首 arg 是 `audit` 子命令，no-compile。
    #[test]
    fn cargo_audit_step_is_tool_gate_probe_audit() {
        let step = step_cargo_audit();
        assert_eq!(step.label(), "audit");
        assert_eq!(step.args.first(), Some(&"audit"));
        assert!(matches!(
            step.id.spec().tool(),
            ToolRequirement::CargoTool {
                tool: crate::cmd::CargoSubcommand::Audit,
                ..
            }
        ));
        assert!(
            !step.needs_compile(),
            "cargo audit 只读 Cargo.lock，无需编译"
        );
        // phantom rsa 豁免须在 args（唯一 cargo-audit ignore 单源）；删掉它定时 lane 会在 phantom 条目上误红。
        assert!(
            step.args
                .windows(2)
                .any(|w| w[0] == "--ignore" && w[1] == "RUSTSEC-2023-0071"),
            "cargo audit 步须 --ignore phantom rsa RUSTSEC-2023-0071，实际 {:?}",
            step.args
        );
    }

    /// cargo-audit 步在 release-check 与 audit（定时 lane）里**逐字相同**（同一构造，不漂移）。
    #[test]
    fn cargo_audit_step_shared_between_ci_and_audit_verbatim() {
        let find = |plan: &[Step]| plan.iter().find(|s| s.label() == "audit").cloned();
        assert_eq!(find(&plan_for(RELEASE_CHECK)), find(&audit_plan()));
        assert!(
            find(&plan_for(RELEASE_CHECK)).is_some(),
            "release-check 须含 audit 步"
        );
    }

    /// ToolGatedInternal 缺工具 + 不宽限 ⇒ `Err`（fail-closed；不执行内部逻辑）。INVARIANT VERIFY-TOOL-GATE-01。
    #[test]
    fn run_one_toolgated_missing_fail_closed_is_err() -> anyhow::Result<()> {
        assert!(
            run_tool_gated("verify", false, false, "missing", "install", "red", || Ok(
                ()
            ))
            .is_err()
        );
        Ok(())
    }

    /// ToolGatedInternal 缺工具 + 宽限 ⇒ `Ok`（SkipWarn；不执行内部逻辑）。
    #[test]
    fn run_one_toolgated_missing_skipwarn_is_ok() -> anyhow::Result<()> {
        assert!(
            run_tool_gated(
                "verify",
                false,
                true,
                "missing",
                "install",
                "red",
                || Ok(())
            )
            .is_ok()
        );
        Ok(())
    }

    // ---- CI-FIXED-WORKFLOW-01：GitHub workflow 委托三个固定 Job ----

    /// 剥 `#` 注释 + 去缩进后的 YAML「代码行」（注释行 → 空串）。委托守卫据此**绑定结构**而非裸全文匹配——
    /// 散文注释（已剥）与 displayName/name 等字符串字段值都不能满足守卫（fail-closed，对标 codex F1：
    /// 守卫不可被注释 / displayName 文本误满足）。
    fn yaml_code_lines(yaml: &str) -> Vec<&str> {
        yaml.lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .collect()
    }

    /// 保留缩进的 YAML code 行，用于把 `pull_request:` / `push:` 与其 `branches:` 子块结构绑定。
    fn yaml_indented_code_lines(yaml: &str) -> Vec<(usize, &str)> {
        yaml.lines()
            .filter_map(|line| {
                let code = line.split('#').next().unwrap_or("").trim_end();
                let text = code.trim();
                if text.is_empty() {
                    return None;
                }
                let indent = code.len() - code.trim_start().len();
                Some((indent, text))
            })
            .collect()
    }

    fn yaml_scalar_eq(raw: &str, expected: &str) -> bool {
        let scalar = raw.trim().trim_matches(|c| c == '"' || c == '\'');
        scalar == expected
    }

    fn yaml_value_contains_scalar(raw: &str, expected: &str) -> bool {
        let value = raw.trim();
        if value.is_empty() {
            return false;
        }
        if let Some(list) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
            return list.split(',').any(|item| yaml_scalar_eq(item, expected));
        }
        yaml_scalar_eq(value, expected)
    }

    fn is_yaml_block_scalar_marker(value: &str) -> bool {
        matches!(value, "|" | "|-" | "|+" | ">" | ">-" | ">+")
    }

    /// 只承认顶层 `on:` 下的直接 event 键，避免 jobs/env/name 中的同名字段凑出假阳性。
    fn workflow_has_top_level_on_event(yaml: &str, event: &str) -> bool {
        let lines = yaml_indented_code_lines(yaml);
        let event_key = format!("{event}:");
        for (idx, (on_indent, text)) in lines.iter().enumerate() {
            if *on_indent != 0 || *text != "on:" {
                continue;
            }
            for (indent, child) in lines.iter().skip(idx + 1) {
                if *indent <= *on_indent {
                    break;
                }
                if *indent == *on_indent + 2 && *child == event_key {
                    return true;
                }
            }
        }
        false
    }

    /// GitHub Actions event 必须绑定 develop 分支，而不是只有裸 `pull_request:` / `push:`。
    fn workflow_event_has_develop_branch(yaml: &str, event: &str) -> bool {
        let lines = yaml_indented_code_lines(yaml);
        let event_key = format!("{event}:");
        for (on_idx, (on_indent, text)) in lines.iter().enumerate() {
            if *on_indent != 0 || *text != "on:" {
                continue;
            }
            let mut event_idx = None;
            let mut i = on_idx + 1;
            while i < lines.len() {
                let (indent, child) = lines[i];
                if indent <= *on_indent {
                    break;
                }
                if indent == *on_indent + 2 && child == event_key {
                    event_idx = Some((i, indent));
                    break;
                }
                i += 1;
            }

            let Some((idx, event_indent)) = event_idx else {
                continue;
            };
            let mut i = idx + 1;
            while i < lines.len() {
                let (indent, child) = lines[i];
                if indent <= event_indent {
                    break;
                }
                if let Some(rest) = child.strip_prefix("branches:") {
                    if yaml_value_contains_scalar(rest, "develop") {
                        return true;
                    }
                    let branch_indent = indent;
                    let mut j = i + 1;
                    while j < lines.len() {
                        let (nested_indent, nested) = lines[j];
                        if nested_indent <= branch_indent {
                            break;
                        }
                        if nested_indent == branch_indent + 2
                            && nested
                                .strip_prefix("- ")
                                .map(|item| yaml_scalar_eq(item, "develop"))
                                == Some(true)
                        {
                            return true;
                        }
                        j += 1;
                    }
                }
                i += 1;
            }
        }
        false
    }

    /// 把去注释 / 去缩进的 code 行按 step 边界（`- ` 起头）切块——每块 = 一个 step 的全部字段行（首个 `- ` 前的
    /// preamble 丢弃）。供「把 condition 等字段**绑定到承载某命令形的那个 step**」用（避免全文任意行匹配的假阳性，
    /// review #281 F1）。
    fn yaml_step_blocks(yaml: &str) -> Vec<Vec<&str>> {
        let mut blocks: Vec<Vec<&str>> = Vec::new();
        for line in yaml_code_lines(yaml) {
            if line.starts_with("- ") {
                blocks.push(Vec::new());
            }
            if let Some(block) = blocks.last_mut() {
                block.push(line);
            }
        }
        blocks
    }

    /// step 块内是否有**真实 `uses:` 键**精确引用某 action。解析键后的值再比较，排除
    /// `name:` / `displayName:`、注释及 action 前后缀伪造（结构绑定，review #281 F2 / #469）。
    fn block_uses_action(block: &[&str], action: &str) -> bool {
        block.iter().any(|raw| {
            let line = raw.strip_prefix("- ").map(str::trim).unwrap_or(raw);
            line.strip_prefix("uses:")
                .is_some_and(|value| value.trim() == action)
        })
    }

    #[derive(Debug, Default)]
    struct TypedStep {
        fields: Vec<String>,
        id: Option<String>,
        name: Option<String>,
        display_name: Option<String>,
        uses: Option<String>,
        checkout: Option<String>,
        task: Option<String>,
        if_expr: Option<String>,
        condition: Option<String>,
        fetch_depth: Option<String>,
        continue_on_error: Option<String>,
        timeout_minutes: Option<String>,
        with: Vec<(String, Vec<String>)>,
        env: Vec<(String, Vec<String>)>,
        inputs: Vec<(String, Vec<String>)>,
        run: Vec<String>,
    }

    impl TypedStep {
        fn fields_exact(&self, expected: &[&str]) -> bool {
            self.fields
                .iter()
                .map(String::as_str)
                .eq(expected.iter().copied())
        }

        fn inputs_exact(&self, expected: &[(&str, &str)]) -> bool {
            self.inputs
                .iter()
                .filter_map(|(key, values)| {
                    let [value] = values.as_slice() else {
                        return None;
                    };
                    Some((key.as_str(), value.as_str()))
                })
                .eq(expected.iter().copied())
                && self.inputs.len() == expected.len()
        }

        fn run_exact(&self, expected: &[&str]) -> bool {
            self.run
                .iter()
                .map(String::as_str)
                .eq(expected.iter().copied())
        }
    }

    fn typed_steps_in_lines(lines: &[(usize, &str)]) -> Vec<TypedStep> {
        let mut steps = Vec::new();
        for (steps_index, (steps_indent, text)) in lines.iter().enumerate() {
            if *text != "steps:" || !matches!(*steps_indent, 0 | 2 | 4) {
                continue;
            }
            let item_indent = steps_indent + 2;
            let mut index = steps_index + 1;
            while index < lines.len() && lines[index].0 > *steps_indent {
                if lines[index].0 != item_indent || !lines[index].1.starts_with("- ") {
                    index += 1;
                    continue;
                }
                let end = lines[index + 1..]
                    .iter()
                    .position(|(indent, text)| {
                        *indent <= *steps_indent
                            || (*indent == item_indent && text.starts_with("- "))
                    })
                    .map_or(lines.len(), |offset| index + 1 + offset);
                steps.push(parse_typed_step(&lines[index..end], item_indent));
                index = end;
            }
        }
        steps
    }

    fn yaml_typed_steps(yaml: &str) -> Vec<TypedStep> {
        let lines = yaml_indented_code_lines(yaml);
        typed_steps_in_lines(&lines)
    }

    fn parse_typed_step(lines: &[(usize, &str)], item_indent: usize) -> TypedStep {
        let mut step = TypedStep::default();
        let field_indent = item_indent + 2;
        let mut index = 0;
        while index < lines.len() {
            let (indent, raw) = lines[index];
            let text = if index == 0 {
                raw.strip_prefix("- ").map(str::trim).unwrap_or(raw)
            } else {
                raw
            };
            let effective_indent = if index == 0 { field_indent } else { indent };
            if effective_indent != field_indent {
                index += 1;
                continue;
            }
            let Some((key, value)) = text.split_once(':') else {
                index += 1;
                continue;
            };
            let value = value.trim();
            step.fields.push(key.to_owned());
            match key {
                "id" => step.id = Some(value.to_owned()),
                "name" => step.name = Some(value.to_owned()),
                "displayName" => step.display_name = Some(value.to_owned()),
                "uses" => step.uses = Some(value.to_owned()),
                "checkout" => step.checkout = Some(value.to_owned()),
                "task" => step.task = Some(value.to_owned()),
                "if" => step.if_expr = Some(value.to_owned()),
                "condition" => step.condition = Some(value.to_owned()),
                "fetchDepth" => step.fetch_depth = Some(value.to_owned()),
                "continue-on-error" => step.continue_on_error = Some(value.to_owned()),
                "timeout-minutes" => step.timeout_minutes = Some(value.to_owned()),
                "run" | "bash" => {
                    if is_yaml_block_scalar_marker(value) {
                        let mut body = index + 1;
                        while body < lines.len() && lines[body].0 > field_indent {
                            step.run.push(lines[body].1.to_owned());
                            body += 1;
                        }
                        index = body;
                        continue;
                    }
                    step.run.push(value.to_owned());
                }
                "with" | "env" | "inputs" => {
                    let target = match key {
                        "with" => &mut step.with,
                        "env" => &mut step.env,
                        "inputs" => &mut step.inputs,
                        _ => unreachable!("closed mapping key"),
                    };
                    let mapping_indent = field_indent + 2;
                    let mut child = index + 1;
                    while child < lines.len() && lines[child].0 > field_indent {
                        if lines[child].0 != mapping_indent {
                            child += 1;
                            continue;
                        }
                        let Some((child_key, child_value)) = lines[child].1.split_once(':') else {
                            child += 1;
                            continue;
                        };
                        let child_value = child_value.trim();
                        let mut values = Vec::new();
                        if is_yaml_block_scalar_marker(child_value) {
                            let mut body = child + 1;
                            while body < lines.len() && lines[body].0 > mapping_indent {
                                values.push(lines[body].1.to_owned());
                                body += 1;
                            }
                            child = body;
                        } else {
                            values.push(child_value.to_owned());
                            child += 1;
                        }
                        target.push((child_key.to_owned(), values));
                    }
                    index = child;
                    continue;
                }
                _ => {}
            }
            index += 1;
        }
        step
    }

    fn azure_top_level_scalar_exact(yaml: &str, key: &str, expected: &str) -> bool {
        let matches = yaml_indented_code_lines(yaml)
            .into_iter()
            .filter_map(|(indent, text)| {
                if indent != 0 {
                    return None;
                }
                let (candidate, value) = text.split_once(':')?;
                (candidate == key).then_some(value.trim())
            })
            .collect::<Vec<_>>();
        matches.len() == 1 && yaml_scalar_eq(matches[0], expected)
    }

    fn azure_localonly_pipeline_is_hardened(yaml: &str) -> bool {
        const OUTPUT: &str = "$(Agent.TempDirectory)/localonly-execution.json";
        const TYPED_COMMAND: &str = "cargo run --locked -p xtask -- ci localonly-evidence --output \"$(Agent.TempDirectory)/localonly-execution.json\"";

        let top_level_steps = yaml_indented_code_lines(yaml)
            .into_iter()
            .filter(|(indent, text)| *indent == 0 && *text == "steps:")
            .count();
        if top_level_steps != 1
            || !azure_top_level_scalar_exact(yaml, "trigger", "none")
            || !azure_top_level_scalar_exact(yaml, "pr", "none")
        {
            return false;
        }
        let steps = yaml_typed_steps(yaml);
        let [checkout, install, execute, publish] = steps.as_slice() else {
            return false;
        };

        checkout.fields_exact(&["checkout", "fetchDepth"])
            && checkout.checkout.as_deref() == Some("self")
            && checkout.fetch_depth.as_deref() == Some("0")
            && install.fields_exact(&["bash", "displayName"])
            && install.run_exact(&[
                "set -euo pipefail",
                "cargo install --locked --version 0.9.137 cargo-nextest",
            ])
            && install.display_name.as_deref() == Some("Install pinned test runner")
            && execute.fields_exact(&["bash", "displayName"])
            && execute.run_exact(&["set -euo pipefail", TYPED_COMMAND])
            && execute.display_name.as_deref() == Some("Run typed LocalOnly evidence job")
            && publish.fields_exact(&["task", "displayName", "condition", "inputs"])
            && publish.task.as_deref() == Some("PublishPipelineArtifact@1")
            && publish.display_name.as_deref() == Some("Publish LocalOnly execution report")
            && publish.condition.as_deref() == Some("succeeded()")
            && publish.inputs_exact(&[("targetPath", OUTPUT), ("artifact", "localonly-execution")])
    }

    #[test]
    fn azure_localonly_pipeline_committed_guard_rejects_structural_camouflage() -> anyhow::Result<()>
    {
        const COMMAND: &str = "cargo run --locked -p xtask -- ci localonly-evidence --output \"$(Agent.TempDirectory)/localonly-execution.json\"";
        let green = std::fs::read_to_string(workspace_root()?.join("azure-pipelines.yml"))?;
        assert!(
            azure_localonly_pipeline_is_hardened(&green),
            "committed Azure validation must preserve the typed LocalOnly topology"
        );

        let no_execute = green.replacen(COMMAND, "true", 1);
        let display_name_camouflage = no_execute.replacen(
            "displayName: Run typed LocalOnly evidence job",
            &format!("displayName: {COMMAND}"),
            1,
        );
        let env_camouflage = green.replacen(
            COMMAND,
            &format!("true\n    env:\n      CAMOUFLAGE: {COMMAND}"),
            1,
        );
        let comment_camouflage = green.replacen(COMMAND, &format!("# {COMMAND}\n      true"), 1);
        let reds = [
            (
                "trigger",
                green.replacen("trigger: none", "trigger: develop", 1),
            ),
            ("pr", green.replacen("pr: none", "pr: develop", 1)),
            (
                "nextest pin",
                green.replacen("--version 0.9.137", "--version 0.9.138", 1),
            ),
            ("typed command missing", no_execute),
            ("comment camouflage", comment_camouflage),
            ("env camouflage", env_camouflage),
            ("displayName camouflage", display_name_camouflage),
            (
                "wrong typed command",
                green.replacen("ci localonly-evidence", "ci audit", 1),
            ),
            (
                "wrong evidence output",
                green.replacen("localonly-execution.json", "other.json", 1),
            ),
            (
                "non-success publication",
                green.replacen("condition: succeeded()", "condition: always()", 1),
            ),
            (
                "wrong publication target",
                green.replacen(
                    "targetPath: $(Agent.TempDirectory)",
                    "targetPath: target",
                    1,
                ),
            ),
            (
                "extra executable step",
                format!("{green}\n  - bash: |\n      true\n    displayName: Extra executable\n"),
            ),
            ("duplicate steps root", format!("{green}\nsteps:\n")),
        ];
        for (label, red) in reds {
            assert_ne!(
                red, green,
                "synthetic red `{label}` must mutate the fixture"
            );
            assert!(
                !azure_localonly_pipeline_is_hardened(&red),
                "Azure structural guard accepted `{label}`"
            );
        }
        Ok(())
    }

    fn yaml_map(value: &serde_yaml_ng::Value) -> Option<&serde_yaml_ng::Mapping> {
        value.as_mapping()
    }

    fn yaml_field<'a>(
        mapping: &'a serde_yaml_ng::Mapping,
        key: &str,
    ) -> Option<&'a serde_yaml_ng::Value> {
        mapping.get(serde_yaml_ng::Value::String(key.to_owned()))
    }

    fn yaml_scalar<'a>(mapping: &'a serde_yaml_ng::Mapping, key: &str) -> Option<&'a str> {
        yaml_field(mapping, key).and_then(serde_yaml_ng::Value::as_str)
    }

    fn yaml_keys_exact(mapping: &serde_yaml_ng::Mapping, expected: &[&str]) -> bool {
        mapping
            .keys()
            .filter_map(serde_yaml_ng::Value::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            == expected
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
            && mapping.len() == expected.len()
    }

    fn yaml_sequence_exact(value: &serde_yaml_ng::Value, expected: &[&str]) -> bool {
        value.as_sequence().is_some_and(|items| {
            items
                .iter()
                .filter_map(serde_yaml_ng::Value::as_str)
                .eq(expected.iter().copied())
                && items.len() == expected.len()
        })
    }

    fn exact_read_permissions(root: &serde_yaml_ng::Mapping) -> bool {
        yaml_field(root, "permissions")
            .and_then(yaml_map)
            .is_some_and(|permissions| {
                yaml_keys_exact(permissions, &["contents"])
                    && yaml_scalar(permissions, "contents") == Some("read")
            })
    }

    fn jobs_have_no_permission_override(jobs: &serde_yaml_ng::Mapping) -> bool {
        jobs.values().all(|job| {
            job.as_mapping()
                .is_some_and(|mapping| yaml_field(mapping, "permissions").is_none())
        })
    }

    fn fixed_caller_job_is_exact(jobs: &serde_yaml_ng::Mapping, identity: &str) -> bool {
        let Some(job) = yaml_field(jobs, identity).and_then(yaml_map) else {
            return false;
        };
        let Some(with) = yaml_field(job, "with").and_then(yaml_map) else {
            return false;
        };
        yaml_keys_exact(job, &["name", "needs", "uses", "with"])
            && yaml_scalar(job, "name") == Some(identity)
            && yaml_scalar(job, "needs") == Some("selector")
            && yaml_scalar(job, "uses") == Some("./.github/workflows/rss-rust-job.yml")
            && yaml_keys_exact(with, &["job", "selection", "source-revision"])
            && yaml_scalar(with, "job") == Some(identity)
            && yaml_scalar(with, "selection") == Some("${{ needs.selector.outputs.selection }}")
            && yaml_scalar(with, "source-revision") == Some("${{ github.sha }}")
    }

    fn step_by_id<'a>(
        job: &'a serde_yaml_ng::Mapping,
        id: &str,
    ) -> Option<&'a serde_yaml_ng::Mapping> {
        yaml_field(job, "steps")?
            .as_sequence()?
            .iter()
            .filter_map(serde_yaml_ng::Value::as_mapping)
            .find(|step| yaml_scalar(step, "id") == Some(id))
    }

    fn step_ids_are_ordered(job: &serde_yaml_ng::Mapping, expected: &[&str]) -> bool {
        let Some(steps) = yaml_field(job, "steps").and_then(serde_yaml_ng::Value::as_sequence)
        else {
            return false;
        };
        expected
            .iter()
            .try_fold(0usize, |after, expected_id| {
                steps[after..]
                    .iter()
                    .position(|step| {
                        step.as_mapping().and_then(|step| yaml_scalar(step, "id"))
                            == Some(*expected_id)
                    })
                    .map(|offset| after + offset + 1)
            })
            .is_some()
    }

    fn scheduled_audit_is_exact(
        root: &serde_yaml_ng::Mapping,
        jobs: &serde_yaml_ng::Mapping,
    ) -> bool {
        let schedule_is_utc = yaml_field(root, "on")
            .and_then(yaml_map)
            .and_then(|on| yaml_field(on, "schedule"))
            .and_then(serde_yaml_ng::Value::as_sequence)
            .is_some_and(|entries| {
                entries.len() == 1
                    && entries[0].as_mapping().is_some_and(|entry| {
                        yaml_keys_exact(entry, &["cron"])
                            && yaml_scalar(entry, "cron") == Some("0 6 * * *")
                    })
            });
        let Some(job) = yaml_field(jobs, "scheduled-audit-fallback").and_then(yaml_map) else {
            return false;
        };
        let checkout = step_by_id(job, "audit-checkout");
        let setup = step_by_id(job, "audit-setup");
        let audit = step_by_id(job, "audit-run");
        schedule_is_utc
            && yaml_scalar(job, "if")
                == Some(
                    "${{ always() && github.event_name == 'schedule' && needs.selector.result != 'success' }}",
                )
            && yaml_scalar(job, "needs") == Some("selector")
            && checkout.is_some_and(|step| {
                yaml_scalar(step, "uses") == Some("actions/checkout@v4")
                    && yaml_field(step, "with")
                        .and_then(yaml_map)
                        .is_some_and(|with| {
                            yaml_field(with, "persist-credentials")
                                .and_then(serde_yaml_ng::Value::as_bool)
                                == Some(false)
                                && yaml_scalar(with, "ref") == Some("${{ github.sha }}")
                        })
            })
            && setup.is_some_and(|step| {
                yaml_scalar(step, "uses") == Some("./.github/actions/setup-rss-ci")
                    && yaml_field(step, "with")
                        .and_then(yaml_map)
                        .is_some_and(|with| {
                            yaml_scalar(with, "lane") == Some("audit")
                                && yaml_scalar(with, "profile") == Some("audit")
                        })
            })
            && audit.and_then(|step| yaml_scalar(step, "run"))
                == Some("cargo run --locked -p xtask -- ci audit")
    }

    fn artifact_step_is_exact(
        job: &serde_yaml_ng::Mapping,
        id: &str,
        condition: &str,
        name: &str,
        path: &str,
        missing: &str,
    ) -> bool {
        step_by_id(job, id).is_some_and(|step| {
            yaml_scalar(step, "if") == Some(condition)
                && yaml_scalar(step, "uses") == Some("actions/upload-artifact@v4")
                && yaml_field(step, "with")
                    .and_then(yaml_map)
                    .is_some_and(|with| {
                        yaml_scalar(with, "name") == Some(name)
                            && yaml_scalar(with, "path") == Some(path)
                            && yaml_scalar(with, "if-no-files-found") == Some(missing)
                    })
        })
    }

    /// INVARIANT: CI-FIXED-WORKFLOW-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "fixed_ci_workflow_guard_rejects_structural_weakening", anti_vacuity = "committed_fixed_ci_workflow_is_closed" }.
    fn fixed_ci_workflow_is_closed(caller: &str, reusable: &str) -> bool {
        let Ok(caller_value) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(caller) else {
            return false;
        };
        let Ok(reusable_value) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(reusable) else {
            return false;
        };
        let Some(caller_root) = yaml_map(&caller_value) else {
            return false;
        };
        let Some(reusable_root) = yaml_map(&reusable_value) else {
            return false;
        };
        let Some(jobs) = yaml_field(caller_root, "jobs").and_then(yaml_map) else {
            return false;
        };
        let expected_jobs = [
            "selector",
            "check",
            "test-affected",
            "integration-critical",
            "scheduled-audit-fallback",
            "ci-gate",
        ];
        let Some(reusable_jobs) = yaml_field(reusable_root, "jobs").and_then(yaml_map) else {
            return false;
        };
        let Some(execute) = yaml_field(reusable_jobs, "execute").and_then(yaml_map) else {
            return false;
        };
        let exact_permissions = exact_read_permissions(caller_root)
            && exact_read_permissions(reusable_root)
            && jobs_have_no_permission_override(jobs)
            && jobs_have_no_permission_override(reusable_jobs);
        let exact_inputs = yaml_field(reusable_root, "on")
            .and_then(yaml_map)
            .and_then(|on| yaml_field(on, "workflow_call"))
            .and_then(yaml_map)
            .and_then(|call| yaml_field(call, "inputs"))
            .and_then(yaml_map)
            .is_some_and(|inputs| {
                inputs
                    .keys()
                    .filter_map(serde_yaml_ng::Value::as_str)
                    .collect::<std::collections::BTreeSet<_>>()
                    == ["job", "selection", "source-revision"]
                        .into_iter()
                        .collect()
            });
        let banned = [
            "matrix:",
            "fromJSON(",
            "plan-digest",
            "ci-job-key",
            "generic-success-artifact",
            "/usr/bin/time",
        ];
        let fixed_calls = ["check", "test-affected", "integration-critical"]
            .into_iter()
            .all(|job| fixed_caller_job_is_exact(jobs, job));
        let push_is_develop_only = yaml_field(caller_root, "on")
            .and_then(yaml_map)
            .and_then(|on| yaml_field(on, "push"))
            .and_then(yaml_map)
            .and_then(|push| yaml_field(push, "branches"))
            .is_some_and(|branches| yaml_sequence_exact(branches, &["develop"]));
        let gate = yaml_field(jobs, "ci-gate").and_then(yaml_map);
        let exact_gate = gate.is_some_and(|gate| {
            yaml_scalar(gate, "if") == Some("${{ always() }}")
                && yaml_field(gate, "needs").is_some_and(|needs| {
                    yaml_sequence_exact(
                        needs,
                        &["selector", "check", "test-affected", "integration-critical"],
                    )
                })
                && step_by_id(gate, "fixed-job-gate")
                    .and_then(|step| yaml_scalar(step, "run"))
                    .is_some_and(|run| {
                        [
                            "--selector-result \"${{ needs.selector.result }}\"",
                            "--check-result \"${{ needs.check.result }}\"",
                            "--test-affected-result \"${{ needs.test-affected.result }}\"",
                            "--integration-critical-result \"${{ needs.integration-critical.result }}\"",
                        ]
                        .into_iter()
                        .all(|binding| run.contains(binding))
                    })
        });
        let cleanup_is_always = step_by_id(execute, "integration-cleanup")
            .is_some_and(|step| {
                yaml_scalar(step, "if")
                    == Some("${{ always() && inputs.job == 'integration-critical' && steps.integration-prepare.outcome == 'success' }}")
            });
        let lifecycle = step_ids_are_ordered(
            execute,
            &[
                "integration-prepare",
                "xtask",
                "integration-collect",
                "integration-snapshot",
                "integration-cleanup",
                "upload-localonly",
                "upload-localtx",
                "upload-integration-failure",
            ],
        ) && step_by_id(execute, "xtask")
            .and_then(|step| yaml_scalar(step, "run"))
            .is_some_and(|run| {
                run.contains("ci run --job \"$RSS_FIXED_JOB\" --selection \"$RSS_SELECTION\"")
            })
            && artifact_step_is_exact(
                execute,
                "upload-localonly",
                "${{ always() && inputs.job == 'test-affected' }}",
                "localonly-execution-${{ github.run_id }}-${{ github.run_attempt }}",
                "target/localonly-execution/localonly-execution.json",
                "error",
            )
            && artifact_step_is_exact(
                execute,
                "upload-localtx",
                "${{ always() && inputs.job == 'integration-critical' }}",
                "localtx-required-${{ github.run_id }}-${{ github.run_attempt }}",
                "target/required-evidence/localtx-required.json",
                "error",
            )
            && artifact_step_is_exact(
                execute,
                "upload-integration-failure",
                "${{ failure() && inputs.job == 'integration-critical' }}",
                "integration-failure-${{ github.run_id }}-${{ github.run_attempt }}",
                "${{ runner.temp }}/integration-lifecycle.json\n${{ runner.temp }}/integration-service-logs.tar.gz\n",
                "warn",
            );
        yaml_keys_exact(jobs, &expected_jobs)
            && yaml_keys_exact(reusable_jobs, &["execute"])
            && exact_permissions
            && exact_inputs
            && fixed_calls
            && push_is_develop_only
            && scheduled_audit_is_exact(caller_root, jobs)
            && exact_gate
            && cleanup_is_always
            && lifecycle
            && banned
                .into_iter()
                .all(|needle| !caller.contains(needle) && !reusable.contains(needle))
    }

    #[test]
    fn committed_fixed_ci_workflow_is_closed() {
        assert!(fixed_ci_workflow_is_closed(
            include_str!("../../.github/workflows/ci.yml"),
            include_str!("../../.github/workflows/rss-rust-job.yml"),
        ));
    }

    #[test]
    fn fixed_ci_workflow_guard_rejects_structural_weakening() {
        let caller = include_str!("../../.github/workflows/ci.yml");
        let reusable = include_str!("../../.github/workflows/rss-rust-job.yml");
        let reds = [
            (caller.replacen("  check:\n", "  check-removed:\n", 1), reusable.to_owned()),
            (caller.replacen("  check:\n", "  check:\n    strategy:\n      matrix: { shard: [one] }\n", 1), reusable.to_owned()),
            (caller.replacen("contents: read", "contents: write", 1), reusable.to_owned()),
            (caller.replacen("  check:\n", "  check:\n    permissions:\n      contents: write\n", 1), reusable.to_owned()),
            (caller.to_owned(), reusable.replacen("  execute:\n", "  execute:\n    permissions:\n      contents: write\n", 1)),
            (caller.replacen("if: ${{ always() }}", "if: ${{ success() }}", 1), reusable.to_owned()),
            (caller.replacen("      job: check\n", "      job: test-affected\n", 1), reusable.to_owned()),
            (caller.replacen("    uses: ./.github/workflows/rss-rust-job.yml\n", "    runs-on: ubuntu-latest\n", 1), reusable.to_owned()),
            (caller.replacen("--check-result \"${{ needs.check.result }}\"", "--check-result \"${{ needs.test-affected.result }}\"", 1), reusable.to_owned()),
            (caller.replace("    branches: [develop]\n", "    branches: [develop, refactor/**]\n"), reusable.to_owned()),
            (caller.to_owned(), reusable.replacen("      source-revision:\n", "      legacy-lane:\n        required: false\n        type: string\n      source-revision:\n", 1)),
            (caller.replacen("  schedule:\n    - cron: \"0 6 * * *\"\n", "", 1), reusable.to_owned()),
            (caller.replacen("always() && github.event_name == 'schedule' && needs.selector.result != 'success'", "false", 1), reusable.to_owned()),
            (caller.replacen("cargo run --locked -p xtask -- ci audit", "cargo run --locked -p xtask -- ci plan", 1), reusable.to_owned()),
            (caller.to_owned(), reusable.replacen("        id: integration-cleanup\n", "        id: integration-cleanup-removed\n", 1)),
            (caller.to_owned(), reusable.replacen("        id: integration-cleanup\n        if: ${{ always() && inputs.job == 'integration-critical' && steps.integration-prepare.outcome == 'success' }}", "        id: integration-cleanup\n        if: ${{ success() && inputs.job == 'integration-critical' }}", 1)),
            (caller.to_owned(), reusable.replacen("name: integration-failure-${{ github.run_id }}-${{ github.run_attempt }}", "name: generic-success-artifact", 1)),
        ];
        for (index, (red_caller, red_reusable)) in reds.into_iter().enumerate() {
            assert!(red_caller != caller || red_reusable != reusable);
            assert!(
                !fixed_ci_workflow_is_closed(&red_caller, &red_reusable),
                "fixed workflow synthetic red {index} was accepted"
            );
        }
    }

    /// INVARIANT: CI-TOOL-ADAPTER-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "fixed_tool_adapter_rejects_policy_weakening", anti_vacuity = "committed_fixed_tool_adapter_is_closed" }.
    fn fixed_tool_adapter_is_closed(action: &str, adapter: &str) -> bool {
        let Ok(action_value) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(action) else {
            return false;
        };
        let Some(action_root) = yaml_map(&action_value) else {
            return false;
        };
        let Some(runs) = yaml_field(action_root, "runs").and_then(yaml_map) else {
            return false;
        };
        let restore = step_by_id(runs, "tools-cache");
        let verify = step_by_id(runs, "tools-verify");
        let save = step_by_id(runs, "tools-save");
        let sealed_cache = step_ids_are_ordered(runs, &["tools-cache", "tools-verify", "tools-save"])
            && restore.is_some_and(|step| {
                yaml_scalar(step, "uses") == Some("actions/cache/restore@v4")
            })
            && verify.and_then(|step| yaml_scalar(step, "run")).is_some_and(|run| {
                run.contains(".github/scripts/ci-tool-adapters.sh verify --mode \"$mode\" --lane \"$RSS_LANE\"")
            })
            && save.is_some_and(|step| {
                yaml_scalar(step, "if") == Some("${{ steps.tools-cache.outputs.cache-hit != 'true' && ((github.event_name == 'push' && github.ref == 'refs/heads/develop') || github.event_name == 'schedule') }}")
                    && yaml_scalar(step, "uses") == Some("actions/cache/save@v4")
                    && yaml_field(step, "with").and_then(yaml_map).is_some_and(|with| {
                        yaml_scalar(with, "path") == Some(".cache/ci-tools/${{ inputs.profile }}")
                            && yaml_scalar(with, "key") == Some("${{ steps.cache-keys.outputs.tools-primary-key }}")
                    })
            });
        adapter.contains("all|check|test-affected|integration-critical|audit)")
            && action
                .contains("case \"$RSS_LANE\" in check|test-affected|integration-critical|audit)")
            && action.contains("compiler-cache-identity:")
            && action.contains(".github/scripts/ci-tool-adapters.sh specs --lane \"$RSS_LANE\"")
            && sealed_cache
    }

    #[test]
    fn committed_fixed_tool_adapter_is_closed() {
        assert!(fixed_tool_adapter_is_closed(
            include_str!("../../.github/actions/setup-rss-ci/action.yml"),
            include_str!("../../.github/scripts/ci-tool-adapters.sh"),
        ));
    }

    #[test]
    fn fixed_tool_adapter_rejects_policy_weakening() {
        let action = include_str!("../../.github/actions/setup-rss-ci/action.yml");
        let adapter = include_str!("../../.github/scripts/ci-tool-adapters.sh");
        for (label, red_action, red_adapter) in [
            (
                "lane closure",
                action.replacen("|audit)", "|legacy)", 1),
                adapter.to_owned(),
            ),
            (
                "restore-only tool cache",
                action.replacen("actions/cache/restore@v4", "actions/cache@v4", 1),
                adapter.to_owned(),
            ),
            (
                "trusted develop writer",
                action.replacen(
                    "github.ref == 'refs/heads/develop'",
                    "github.ref != 'refs/heads/develop'",
                    1,
                ),
                adapter.to_owned(),
            ),
            (
                "save after verification",
                action.replacen(
                    "      id: tools-save\n",
                    "      id: tools-save-before-verify\n",
                    1,
                ),
                adapter.to_owned(),
            ),
            (
                "adapter lane closure",
                action.to_owned(),
                adapter.replacen("|audit)", "|legacy)", 1),
            ),
        ] {
            assert!(
                red_action != action || red_adapter != adapter,
                "tool adapter synthetic red `{label}` must mutate its fixture"
            );
            assert!(
                !fixed_tool_adapter_is_closed(&red_action, &red_adapter),
                "tool adapter synthetic red `{label}` was accepted"
            );
        }
    }

    fn codeql_workflow_well_formed(yaml: &str) -> bool {
        let code = yaml_code_lines(yaml);
        let blocks = yaml_step_blocks(yaml);
        let triggers = workflow_event_has_develop_branch(yaml, "push")
            && workflow_has_top_level_on_event(yaml, "schedule");
        let init_bound = blocks.iter().any(|b| {
            block_uses_action(b, "github/codeql-action/init@v4")
                && b.iter().any(|l| l.contains("languages: rust"))
                && b.iter().any(|l| l.contains("build-mode: none"))
        });
        let analyze = blocks
            .iter()
            .any(|b| block_uses_action(b, "github/codeql-action/analyze@v4"));
        let perm = code.iter().any(|l| l.contains("security-events: write"));
        triggers && init_bound && analyze && perm
    }

    /// 谓词绿/红例（anti-vacuity）：逐一抽掉每个必需要素都使谓词变假（守卫非恒真）。
    #[test]
    fn codeql_workflow_predicate_green_and_red() {
        let green = "on:\n  push:\n    branches: [develop]\n  schedule:\n    - cron: \"0 7 * * 1\"\n  workflow_dispatch:\npermissions:\n  security-events: write\njobs:\n  analyze:\n    steps:\n      - uses: github/codeql-action/init@v4\n        with:\n          languages: rust\n          build-mode: none\n      - uses: github/codeql-action/analyze@v4\n";
        assert!(
            codeql_workflow_well_formed(green),
            "完整 CodeQL workflow 应为真"
        );
        // 红（review #281 F2）：触发器退化——缺 push（仅 schedule/workflow_dispatch）或缺 schedule。SAST 不随
        // 镜像 push / 定时跑即静默失效。
        assert!(
            !codeql_workflow_well_formed(&green.replace("push:", "pull_request:")),
            "缺 push 触发器（SAST 不随镜像 push 跑）"
        );
        assert!(
            !codeql_workflow_well_formed(&green.replace("schedule:", "x_schedule:")),
            "缺 schedule 触发器（无定时 backstop）"
        );
        // 红：缺真实 analyze step（不产 code-scanning alert）。
        assert!(
            !codeql_workflow_well_formed(
                &green.replace("      - uses: github/codeql-action/analyze@v4\n", "")
            ),
            "缺 analyze step"
        );
        // 红：缺写权限。
        assert!(
            !codeql_workflow_well_formed(
                &green.replace("security-events: write", "contents: read")
            ),
            "缺 security-events:write"
        );
        // 红（codex review #281 第2轮 F2）：init 关键字仅在 **name** 值里、无真实 `uses: …/init` step →
        // [`block_uses_action`] 不认（displayName/name 假阳性 fail-closed）。
        assert!(
            !codeql_workflow_well_formed(
                "on:\n  push:\n    branches: [develop]\n  schedule:\n    - cron: \"0 7 * * 1\"\npermissions:\n  security-events: write\njobs:\n  analyze:\n    steps:\n      - name: \"github/codeql-action/init languages: rust build-mode: none\"\n      - uses: github/codeql-action/analyze@v4\n"
            ),
            "init 关键字仅在 name 值、无真实 uses（fail-closed）"
        );
        // 红（codex review #281 第2轮 F2）：languages/build-mode 与 init `uses:` 不在**同一 step 块** →
        // 同块绑定不满足（避免散落各处的关键字凑齐误判通过）。
        assert!(
            !codeql_workflow_well_formed(
                "on:\n  push:\n    branches: [develop]\n  schedule:\n    - cron: \"0 7 * * 1\"\npermissions:\n  security-events: write\njobs:\n  analyze:\n    steps:\n      - uses: github/codeql-action/init@v4\n      - name: stray\n        languages: rust\n        build-mode: none\n      - uses: github/codeql-action/analyze@v4\n"
            ),
            "languages/build-mode 不在 init step 块内（同块绑定不满足）"
        );
        // 红：全部要素仅在**注释**里（每行前缀 `# `）→ 剥注释后不满足（fail-closed）。
        let commented = green
            .lines()
            .map(|l| format!("# {l}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !codeql_workflow_well_formed(&commented),
            "要素仅在注释里不应满足守卫（fail-closed）"
        );
    }

    /// 真实 committed 文件：.github/workflows/codeql.yml 存在且形态良好（防 SAST workflow 被静默删除 / 禁用）。
    #[test]
    fn github_codeql_workflow_present() -> anyhow::Result<()> {
        let path = workspace_root()?
            .join(".github")
            .join("workflows")
            .join("codeql.yml");
        let yaml = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))?;
        assert!(
            codeql_workflow_well_formed(&yaml),
            ".github/workflows/codeql.yml 须声明 Rust + build-mode none + analyze + security-events:write"
        );
        Ok(())
    }

    /// 双工具 advisory ignore 对账守卫（issue #1133）。deny 与 cargo-audit 同查 RustSec、各有独立 ignore
    /// 机制（deny.toml `[advisories].ignore` vs cargo-audit `--ignore`），且 cargo-audit 扫 Cargo.lock 全量、
    /// deny 按 feature-resolved 图——cargo-audit 会多报 phantom 条目（如 rsa RUSTSEC-2023-0071）。
    ///
    /// 正确不变式 = **非对称包含**：`deny.toml.ignore ⊆ cargo-audit.ignore`。即任何 deny 接受（ignore）的
    /// **图内** advisory 必须也被 cargo-audit 接受——否则 deny 绿而 audit 红（一过一红、阻断合入）。反向 audit
    /// 可多 ignore（phantom-only，deny 图里根本没有，无需 deny 侧 ignore）。两门互为 in-graph 漏洞的 backstop：
    /// 谁单边 ignore 一个**真·图内**漏洞，另一门仍会红，故无静默架空。本守卫把「deny 接受却忘了同步 audit」
    /// 这一会导致 audit 误红的漂移从 Soft 升为 Medium tripwire。
    /// anti-vacuity：构造 deny ⊄ audit 的反例 → 判定返回 false（守卫非恒真）。
    #[test]
    fn deny_audit_ignore_lists_reconciled() -> anyhow::Result<()> {
        // 解析 deny.toml `[advisories].ignore`：兼容裸字符串形 `"RUSTSEC-..."` 与结构化形
        // `{ id = "RUSTSEC-...", reason = "..." }`（cargo-deny 0.16+）——否则对结构化条目静默返回空、守卫恒真。
        fn deny_advisory_ignores(toml_src: &str) -> Result<Vec<String>> {
            let v: toml::Value = toml::from_str(toml_src)?;
            Ok(v.get("advisories")
                .and_then(|a| a.get("ignore"))
                .and_then(|i| i.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|e| {
                            e.as_str().map(str::to_owned).or_else(|| {
                                e.get("id").and_then(toml::Value::as_str).map(str::to_owned)
                            })
                        })
                        .collect()
                })
                .unwrap_or_default())
        }
        // 子集判定：deny.ignore ⊆ audit.ignore。
        fn deny_subset_audit(deny: &[String], audit: &[&str]) -> bool {
            deny.iter().all(|d| audit.contains(&d.as_str()))
        }
        // anti-vacuity ①：deny ignore 某 ID 但 audit 没有 → 非对账（子集判定非恒真）。
        assert!(!deny_subset_audit(
            &["RUSTSEC-2099-9999".to_owned()],
            &["RUSTSEC-2023-0071"]
        ));
        assert!(deny_subset_audit(&[], &["RUSTSEC-2023-0071"])); // 空 ⊆ 任意
        // anti-vacuity ②：结构化 ignore 形 `{ id = ... }` 也被解析（防解析器对结构化条目静默丢、守卫恒真）。
        assert_eq!(
            deny_advisory_ignores(
                "[advisories]\nignore = [{ id = \"RUSTSEC-2023-0071\", reason = \"x\" }]\n"
            )?,
            vec!["RUSTSEC-2023-0071".to_owned()]
        );
        let path = workspace_root()?.join("deny.toml");
        let toml_src = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))?;
        let deny = deny_advisory_ignores(&toml_src)?;
        let audit = cargo_audit_ignored_ids();
        // anti-vacuity ③：args 解析必须真解析出 cargo-audit 侧 ignore（含已知 phantom rsa）——否则 args 解析
        // 静默失效时 audit=[] 会让「空 deny ⊆ 空 audit」恒真，对账失去意义。锁住 parser 有效。
        assert!(
            audit.contains(&"RUSTSEC-2023-0071"),
            "cargo_audit_ignored_ids 未解析出 phantom rsa ignore（step_cargo_audit args 解析失效？）：{audit:?}"
        );
        assert!(
            deny_subset_audit(&deny, &audit),
            "deny.toml [advisories].ignore ⊄ cargo-audit --ignore：deny 接受的图内 advisory 须同步到 \
             step_cargo_audit 的 --ignore，否则 cargo-audit 仍报、一过一红。deny={deny:?} audit={audit:?}"
        );
        Ok(())
    }

    /// 反向守卫（issue #1133）：workspace root 不得有 `audit.toml`。cargo-audit ignore 单源 = `step_cargo_audit`
    /// 的 `--ignore`（已实测 0.22.2 不从 cwd 自动加载 audit.toml）；若有人放 audit.toml 会引入第三套 ignore 源、
    /// 绕过 `deny_audit_ignore_lists_reconciled` 对账。本守卫确保该文件不存在（anti-vacuity：文件在即红）。
    #[test]
    fn no_audit_toml_at_workspace_root() -> anyhow::Result<()> {
        let path = workspace_root()?.join("audit.toml");
        assert!(
            !path.exists(),
            "workspace root 不应有 audit.toml（cargo-audit ignore 单源 = step_cargo_audit --ignore，见其 rustdoc）"
        );
        Ok(())
    }

    /// NIGHTLY-PIN-01 第四处镜像：public-api 门步的 `install_hint` 字面量（`&'static str` 字段无法引 const，
    /// 故内嵌 nightly 版本）须含钉版 nightly `publicapi::PINNED_NIGHTLY`——**绑 `step_public_api()` 返回的真实
    /// install_hint 字段值**（非 verify.rs 源码全文）：install_hint 回退 rolling `nightly`（或漏随 const bump）
    /// 即 fail，且注释/其它字符串含 pin **不能**误满足（修复源码全文扫描的 anti-vacuity 盲区）。
    /// INVARIANT: NIGHTLY-PIN-01 { level = "Medium", exec = "check", source = "code" }.
    #[test]
    fn public_api_install_hint_pins_nightly() {
        let pin = crate::publicapi::PINNED_NIGHTLY;
        // reason: 非 ToolGatedInternal 变体回退空串（必不含 pin），令下面 assert 以失败信息暴露形态变化，
        // 而非 panic（生产代码禁 panic，clippy Medium）。
        let install_hint = match step_public_api().id.spec().tool() {
            ToolRequirement::CargoTool { install_hint, .. } => install_hint,
            _ => "",
        };
        assert!(
            install_hint.contains(pin),
            "public-api install_hint 须为 ToolGatedInternal 且含钉版 nightly {pin}\
             （NIGHTLY-PIN-01，与 publicapi::PINNED_NIGHTLY 同步）；当前: {install_hint:?}"
        );
    }
}
