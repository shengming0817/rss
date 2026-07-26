//! `cargo xtask verify` —— 本地全量治理门聚合入口。
//!
//! RSS 本地全量治理门。Azure 是 active PR forge；GitHub typed lanes 当前用于 Shadow 取证，
//! `ci-gate` 尚不是 required check。完整门集与顺序只由 typed registry 派生，本说明不复制 gate inventory。
//! 聚合按 fail-fast 执行：no-compile Meta 证明优先，随后是 workspace/feature 编译、lint、默认与
//! feature-gated 行为测试、供应链检查和注册 lint。
//!
//! `--fast` 的 inner typed plan 只跑不依赖 Docker、额外 Cargo 工具或 crate 编译的轻量
//! `CompileKind::NoCompile` gate（fmt + repository meta），
//! 供快速迭代；冷缓存或 xtask 变更时，外层 Cargo 仍会构建 xtask 启动器。`--allow-missing-tools`
//! 在缺外部工具时显式宽限（默认 fail-closed）。
//!
//! **`cargo xtask ci full`（[`run_ci`]）= 本地完整 CI 聚合**（issue #1132）：
//! verify 全门 + build/clippy 升 `--all-features --all-targets` + 覆盖率门（`cargo llvm-cov nextest` 替
//! nextest，强制 basis/engine ≥90%，见 `coverage.rs`）+ `public-api --check`（轴 A，见 `publicapi.rs`）。
//! `verify` 仍是 **stable-only 本地快门**（不需 nightly / llvm-cov）；`ci full` 只供本地一次性跑全部
//! CI 门。二者与 GitHub typed 16-job catalog 均经 [`plan_for`] 与 `CiJobKey` Hard 闭集派生，杜绝门集漂移。
//!
//! **`cargo xtask ci run --job audit`（[`run_audit`]）= 供应链漏洞定时刷新 lane**（issue #1133，GitHub Actions
//! `schedule:` 调用入口）：advisory-scoped `cargo deny check advisories` + `cargo audit` 两门
//! （皆 no-compile、快）。PR-triggered Shadow plan 含全量 `deny check`
//! （advisories+licenses+bans+sources）+ cargo-audit；scheduled audit 专攻**时间维度**，捕获未改依赖的新披露
//! CVE。两者在各自 run 内 fail-closed；`ci-gate` 激活为 required check 或建立 forge bridge 前均不阻断 Azure 合入。
//!
//! **`cargo-udeps` 仍不入三者**（多余/未声明依赖，需 nightly `-Z`，与根 stable 1.96 冲突）——独立可选门。
//! `cargo-semver-checks`（轴 A 语义破坏检测）当前所有 crate `publish = false` ⇒ `--workspace` 选 0 包、门
//! 空转，故本轮不入 ci（public-api --check 已非空转兜轴 A）；待 crate 可发布后 follow-up 接入（见 PR body）。
//!
//! INVARIANT: VERIFY-AGGREGATE-01 { level = "Medium", exec = "verify", source = "code" }—— 任一门步失败 ⇒ verify/ci/audit 非零退出（聚合 fail-fast，不吞错）。
//! INVARIANT: VERIFY-TOOL-GATE-01 { level = "Medium", exec = "verify", source = "code" }—— 缺外部工具默认 fail-closed；豁免仅经显式 `--allow-missing-tools`。
//! INVARIANT: ASSEMBLY-PROVIDERS-VERIFY-GATE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "assembly_provider_codegen_gate_is_typed_once_and_ordered_in_all_aggregate_plans", anti_vacuity = "assembly_codegen::tests::assembly_provider_codegen_generated_provider_catalogs_are_non_empty_and_check_clean" }—— provider catalog drift is an independent typed no-compile gate exactly once between modules drift and AssemblyLock in every aggregate plan.
//! INVARIANT: RUNTIME-DYLINT-UI-GATE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "runtime_dylint_ui_gate_is_typed_closed_and_in_aggregate_plans", anti_vacuity = "runtime_dylint_ui_gate_is_typed_closed_and_in_aggregate_plans" }—— the three runtime Dylint UI carriers run as one typed `cargo test --locked` gate from the fixed `lints` workspace in full verify, compatibility CI, and core prerequisites, while fast remains no-compile.
//! INVARIANT: L2-ASSURANCE-VERIFY-GATE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "l2_assurance_gate_is_typed_once_and_ordered_in_all_aggregate_plans", anti_vacuity = "l2_assurance::tests::workspace_inventory_is_exact_and_deterministic" }—— L2 assurance drift check is a typed, in-process, no-compile gate present exactly once immediately after codegen in every aggregate plan.
//! INVARIANT: CI-ADAPTIVE-WORKFLOW-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "split_ci_caller_predicate_green_and_synthetic_red", anti_vacuity = "github_ci_workflow_delegates_to_split_xtask_lanes" }—— GitHub CI workflow
//!   精确委托闭合 xtask job，Meta/Security 并行，Core tests 仅依赖单次 prerequisites；门归属由
//!   Hard registry 闭集与穷举 dispatch 强制，YAML 拓扑、权限和 literal 委托由 Medium 结构化守卫
//!   `github_ci_workflow_delegates_to_split_xtask_lanes` 强制。
//! INVARIANT: CI-RESOURCE-EVIDENCE-01 { level = "Medium", exec = "verify", source = "code" }—— CI / Integration workflow
//!   须按 checkout → start → cache/after-cache → xtask → after-build → cleanup/measure → before-save → explicit save → after-save → artifact 的唯一有序生命周期
//!   采集资源证据，且在昂贵构建前 fail-closed 检查磁盘预算。该约束无法用 Rust 类型系统
//!   表达，由结构化 YAML 谓词、synthetic red / anti-vacuity 与脚本 selftest 联合承载。
//! INVARIANT: CI-CACHE-WRITER-01 { level = "Medium", exec = "verify", source = "code" }—— cache writer 资格必须由
//!   workflow 顶层唯一的受保护 trigger 表达式决定，setup、cleanup 与 save 只能消费该单一 env；
//!   restore/key/evidence/save 顺序由结构谓词、synthetic red 与 committed-file gate fail-closed 承载。
//! INVARIANT: CI-TOOL-ADAPTER-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "ci_tool_adapter_contract_green_and_synthetic_red", anti_vacuity = "github_ci_tool_adapter_contract_is_closed" }—— lane 工具集只能由机器 catalog 经 adapter 派生；workflow/action 不得复制清单或接收任意工具 input，installer immutable SHA 必须同时绑定 uses 与 cache identity，adapter 与 catalog 内容必须绑定 cache key 与 seal，fresh/cache verify 必须先于 PATH 暴露和 cache save，tool-cache epoch 必须为 v4。
//! INVARIANT: CI-TEST-PARTITION-MATRIX-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "split_ci_caller_predicate_green_and_synthetic_red", anti_vacuity = "github_ci_workflow_delegates_to_split_xtask_lanes" }—— Core 与 integration partition topology 必须只由 typed planner 的动态 matrix 派生。
//! INVARIANT: LOCALTX-PROOF-CI-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "split_ci_caller_predicate_green_and_synthetic_red", anti_vacuity = "github_ci_workflow_delegates_to_split_xtask_lanes" }—— same-head planner job 必须原子生成并上传 JSON/Markdown LocalTx proof artifact。
//! INVARIANT: CI-TEST-EVIDENCE-UPLOAD-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "reusable_rust_lane_guard_rejects_semantic_weakening", anti_vacuity = "github_resource_evidence_workflows_have_lifecycle" }—— evidence 必须 always 上传、唯一命名、精确路径且只保留七天。
//! INVARIANT: CI-SLO-WORKFLOW-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "reusable_rust_lane_slo_contract_rejects_semantic_weakening", anti_vacuity = "reusable_rust_lane_slo_contract_accepts_committed_workflow" }—— SLO 证据必须先 stage 再 always 上传，最后 always 评估并写入 Job Summary；四个 live disk guard 必须从固定 SLO config 读取阈值并 fail-closed。
//! INVARIANT: CI-INTEGRATION-SERVICE-LIFECYCLE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "integration_service_lifecycle_predicate_green_and_synthetic_red", anti_vacuity = "github_resource_evidence_workflows_have_lifecycle" }—— Integration lane 必须在 xtask 前建立 exact scope，在失败后有界取证并 always 精确清理；生命周期证据始终归档，服务日志仅失败时归档，且 workflow 禁止任何全局 Docker prune。
//! INVARIANT: INTEGRATION-CONTAINER-OWNERSHIP-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "integration_container_source_contract_synthetic_red", anti_vacuity = "integration_container_source_contract_accepts_committed_sources" }—— testkit 只能在 owned 模块导入 AsyncRunner/调用 start，四类 fixture、四个 context env、四种 service、五个 ownership label 与精确 partition 闭集须和 shell/workflow 同步。
//! INVARIANT: CI-SELFTEST-TEMP-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "ci_selftest_temp_root_guard_rejects_unsafe_fixtures", anti_vacuity = "committed_ci_selftest_temp_roots_are_atomic" }—— 所有 GitHub shell selftest 必须递归自动发现；可执行源码中的 PID 临时路径与非原子 TMP_ROOT 均 fail-closed，实际 TMP_ROOT 必须以带 `.XXXXXX` 模板的原子 `mktemp -d` 创建独占根目录；注释不能充当合规证据或触发误报。

use crate::ci_lanes::CiJobKey;
use crate::ci_lanes::{
    CiLane, CompatMembership, CompileKind, GateId, REGISTRY, StandaloneReason, ToolRequirement,
    VerifyMembership,
};
use crate::diagnostic::run_check;
use crate::integration_shards::{self, IntegrationShard, Scheduling};
use crate::workspace_root;
use crate::{
    archrules, assembly, assembly_lock, codegen, consistency_effects, consistency_fixtures,
    contract, layerdeps, reconcile_outbox_command_guard, repo_scope_guard, runtime_baseline,
    runtime_deps_guard, runtime_env_guard, runtime_root_guard, shipped_feature_guard, wsdeps,
};
use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Stdio;

/// verify 选项。
#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifyOpts {
    /// Inner typed plan 只跑不依赖 Docker、额外 Cargo 工具或 crate 编译的轻量
    /// `CompileKind::NoCompile` gate；外层 Cargo 仍可能构建 xtask 启动器。
    fast: bool,
    /// 缺外部工具时显式宽限（默认 fail-closed，唯一门不建议）。
    allow_missing_tools: bool,
    partition: Option<crate::nextest::HashPartition>,
    nextest_lane: crate::nextest::NextestLane,
    contract_against: String,
    /// `ci run --job ci-coverage`：用与 plan 同 base 的 CoverageProjection。
    /// `ci full` / CompatibilityCi：恒 Workspace。
    coverage_typed_job: bool,
}

/// in-process Rust 门（无外部进程 / 自管子进程）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InternalCheck {
    ContractValidate,
    /// assembly-level DI provider 声明校验（RevocationStore active provider 必须持久）。
    AssemblyValidate,
    /// assembly lifecycle 与部署 artifact exact closure 门（#1798）。
    AssemblyArtifactsCheck,
    /// assembly.toml domains → committed modules_gen.rs 漂移门（ASSEMBLY-MODULES-CODEGEN-01）。
    AssemblyModulesCheck,
    /// assembly.toml providers → committed providers_gen.rs 漂移门（ASSEMBLY-PROVIDERS-CODEGEN-01）。
    AssemblyProvidersCheck,
    /// repository-verified committed assembly.lock.json raw-byte 漂移门（#1781）。
    AssemblyLockCheck,
    /// RuntimePlan-bound DeploymentPlan exact generated-set raw-byte 漂移门（#1802）。
    DeploymentPlanCheck,
    /// committed runtime assembly Mermaid/JSON graph 漂移与 source closure 门。
    AssemblyGraphCheck,
    /// wire JSON-Schema/manifest 跨版本破坏检测门（ADR-008，WIRE-BREAKING-01）。
    /// active 默认 deny；三个固定 review rules 为 warn，但未确认 fail-closed；against = origin/develop。
    ContractBreaking,
    LayerDeps,
    /// server/rss 实际 Cargo feature graph 禁止通过 feature unification 启用 httpserve/test-util。
    ShippedFeatureGuard,
    WsDepsDrift,
    /// Production Rustdoc semantic and token-profile trust-chain source guard.
    SourceSemanticGuard,
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
    /// Runtime Deployment SpecKit schemas/tasks/fingerprints + synthetic-red closure（#1779）。
    RuntimeDeploymentSpec,
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
    /// tenant 表 RLS 三件套守卫（TENANCY-RLS-FORCE-01；内容扫描迁移 SQL，no-compile）。
    SchemaRlsGuard,
    /// tenant-scope SET-LOCAL 单漏斗守卫（TENANCY-SETLOCAL-FUNNEL-01；内容扫描 Rust 源，no-compile）。
    SetLocalFunnel,
    /// Postgres tenant-table raw-pool / TxManager bypass guard（TENANCY-PG-TX-FUNNEL-01；no-compile）。
    PgTenantTxGuard,
    /// domain repo port 禁裸 TenantId / RowVisibility / RowScope 签名守卫（TENANCY-REPO-SCOPE-SIGNATURE-01）。
    RepoScopeGuard,
    /// tenancy/AuthZ/projection closeout reverse self-check（TENANCY-CLOSEOUT-REVERSE-01；no-compile）。
    TenancyCloseout,
    /// migration 文件序号唯一性 + 连续性守卫（MIGRATION-SERIAL-UNIQUE-01；内容扫描文件名，no-compile）。
    MigrationsSerial,
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
    Nextest(crate::nextest::CoreTestScope),
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

    fn needs_compile(&self) -> bool {
        self.id.spec().compile_kind() != CompileKind::NoCompile
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
fn step_deployment_plan_check() -> Step {
    Step {
        id: GateId::DeploymentPlanCheck,
        args: &[],
        kind: StepKind::Internal(InternalCheck::DeploymentPlanCheck),
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
fn step_runtime_deployment_spec() -> Step {
    Step {
        id: GateId::RuntimeDeploymentSpec,
        args: &[],
        kind: StepKind::Internal(InternalCheck::RuntimeDeploymentSpec),
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
fn step_setlocal_funnel() -> Step {
    Step {
        id: GateId::SetLocalFunnel,
        args: &[],
        kind: StepKind::Internal(InternalCheck::SetLocalFunnel),
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
fn step_migrations_serial() -> Step {
    Step {
        id: GateId::MigrationsSerial,
        args: &[],
        kind: StepKind::Internal(InternalCheck::MigrationsSerial),
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
/// licenses/bans 留给 PR-triggered Shadow plan 的全量 [`step_deny`]）。issue #1133 每日 cron 只刷新漏洞维度。
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

fn step_runtime_dylint_ui_tests() -> Step {
    Step {
        id: GateId::RuntimeDylintUiTests,
        args: &[
            "test",
            "--locked",
            "-p",
            "rss_runtime_env_funnel",
            "-p",
            "rss_dlq_operator_callsite",
            "-p",
            "rss_authenticated_callsite",
        ],
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
fn step_assembly_lock_protocol_tests() -> Step {
    Step {
        id: GateId::AssemblyLockProtocolTests,
        args: &["test", "-p", "assembly-schema"],
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
/// F7 + #1137：postgres/redis/amqp 集成测试由 `#[cfg(feature = "integration")]` gate，verify 的
/// build/clippy/nextest 仅 workspace 默认 feature ⇒ 关键状态机测试（崩溃重投 / CAS fencing / DLX / sweep /
/// redis 幂等 / amqp pub-sub + 跨 vhost / durable journey）默认门外、回归漏网。本步 `--no-run` 仅编译（不跑、
/// 无需真实后端 / docker）纳入默认 verify 抓**编译漂移**；有 docker / env URL 时经
/// `cargo xtask ci run --job integration/<shard>` 按 target 实跑。ci lane 经 `--all-features --all-targets`
/// 已覆盖该编译面，故仅入
/// `Verify` 计划、不入 `CompatibilityCi` 计划。
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
            "integration",
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
fn step_nextest() -> Step {
    Step {
        id: GateId::DefaultNextest,
        args: &[],
        kind: StepKind::Nextest(crate::nextest::CoreTestScope::Workspace),
        env: &[],
    }
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

// ---- feature-gated 行为测试门（确定性 mock / lazy 构造，无需 live 后端）----
//
// 默认 feature 的 workspace nextest（[`step_nextest`] / coverage）**不编入** adapter 的
// `#[cfg(all(test, feature = "..."))]` 行为测试模块，故按包显式补跑——否则 backend 真身行为只靠人工命令记忆、
// 不在机器门内（azure 无 CI ⇒ verify 是唯一 gate，缺这步等于 S3/redis backend 行为无门）。**不**用
// `--all-features --workspace` nextest：会误触 postgres `integration` / redis `integration` 等需 live 后端的
// 门（s3 / redis 的 `backend` 是 aws-smithy-mocks / deadpool lazy-pool 确定性测试，postgres `integration` 需
// 真实 DB）。**不**带 `--no-tests=pass`：targeted 包必有该 feature 行为测试，0 选中即 feature gate 漂移 ⇒ 须
// fail-loud（不可空转）。新增确定性 feature 行为测试的 adapter 在 [`feature_test_steps`] 追加一条（显式清单，
// 与 coverage STRICT_CRATES 同款机制）。
fn step_s3_backend_tests() -> Step {
    Step {
        id: GateId::S3BackendTests,
        args: &[],
        kind: StepKind::Nextest(crate::nextest::CoreTestScope::S3Backend),
        env: &[],
    }
}
fn step_redis_backend_tests() -> Step {
    Step {
        id: GateId::RedisBackendTests,
        args: &[],
        kind: StepKind::Nextest(crate::nextest::CoreTestScope::RedisBackend),
        env: &[],
    }
}
fn step_oidc_backend_tests() -> Step {
    Step {
        id: GateId::OidcBackendTests,
        args: &[],
        kind: StepKind::Nextest(crate::nextest::CoreTestScope::OidcBackend),
        env: &[],
    }
}
fn step_prometheus_backend_tests() -> Step {
    Step {
        id: GateId::PrometheusBackendTests,
        args: &[],
        kind: StepKind::Nextest(crate::nextest::CoreTestScope::PrometheusBackend),
        env: &[],
    }
}
fn step_otel_backend_tests() -> Step {
    // otel OTLP/gRPC trace 导出确定性单测（#1011：InMemorySpanExporter round-trip + observ::MetricLabel→KeyValue
    // 映射 + OtelEndpoint typed 安全边界 + 导出边界脱敏）。`backend` feature 的 `#[cfg(feature)]` 测试模块默认
    // workspace nextest 不编入，按包显式补跑——#1253 让 otel 成为 runtime 生产依赖后，确定性测试须入机器门（同 prometheus 范式）。
    Step {
        id: GateId::OtelBackendTests,
        args: &[],
        kind: StepKind::Nextest(crate::nextest::CoreTestScope::OtelBackend),
        env: &[],
    }
}
fn step_grpc_backend_tests() -> Step {
    Step {
        id: GateId::GrpcBackendTests,
        args: &[],
        kind: StepKind::Nextest(crate::nextest::CoreTestScope::GrpcBackend),
        env: &[],
    }
}
fn step_vault_backend_tests() -> Step {
    // vault Transit `sign_impl` HTTP 编排层确定性单测（#1179：wiremock loopback mock，4 分支 + percent-encode/
    // header）+ 非 2xx 状态分级（#1180：classify_status 表驱动）。`backend` feature 的 `#[cfg(feature)]` 测试模块
    // 默认 workspace nextest 不编入，按包显式补跑——否则 azure 无 CI 下这些确定性测试不被任何 gate 实跑。
    Step {
        id: GateId::VaultBackendTests,
        args: &[],
        kind: StepKind::Nextest(crate::nextest::CoreTestScope::VaultBackend),
        env: &[],
    }
}
fn step_settingsonly_tests() -> Step {
    // settingsonly 精确 package smoke：workspace / all-features 联合编译不能证明该 assembly 自身的
    // feature 选择图（postgres domain-settings only）。按包显式 nextest，不带 `--no-tests=pass`——
    // 0 选中即漂移 fail-loud。
    Step {
        id: GateId::SettingsOnlyTests,
        args: &[],
        kind: StepKind::Nextest(crate::nextest::CoreTestScope::SettingsOnly),
        env: &[],
    }
}
fn step_testkit_container_tests() -> Step {
    Step {
        id: GateId::TestkitContainerTests,
        args: &[],
        kind: StepKind::Nextest(crate::nextest::CoreTestScope::TestkitContainers),
        env: &[],
    }
}
fn step_identityaudit_tests() -> Step {
    // identityaudit 精确 package smoke：workspace / all-features 联合编译不能证明该 assembly
    // 只组合 identity + audit。非分片执行保持 0 选中 fail-loud；PR hash 分片允许某一半为空。
    Step {
        id: GateId::IdentityAuditTests,
        args: &[],
        kind: StepKind::Nextest(crate::nextest::CoreTestScope::IdentityAudit),
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
pub(crate) enum PlanTarget {
    Verify,
    CompatibilityCi,
    Lane(CiLane),
    Core(CoreExecution),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoreExecution {
    Full,
    Prerequisites,
    Tests,
}

fn selected_for(target: PlanTarget, id: GateId) -> bool {
    let spec = id.spec();
    match target {
        PlanTarget::CompatibilityCi => spec.compat() == CompatMembership::Included,
        PlanTarget::Core(CoreExecution::Full) | PlanTarget::Lane(CiLane::Core) => {
            spec.belongs_to(CiLane::Core)
                && spec.compat() != CompatMembership::Standalone(StandaloneReason::VerifyOnly)
        }
        PlanTarget::Core(CoreExecution::Prerequisites) => matches!(
            id,
            GateId::BuildAllFeatures
                | GateId::ClippyAllFeatures
                | GateId::Dylint
                | GateId::RuntimeDylintUiTests
                | GateId::PostgresFeatureMatrix
                | GateId::SecureProductionTrybuild
        ),
        PlanTarget::Core(CoreExecution::Tests) => matches!(
            id,
            GateId::DefaultNextest
                | GateId::S3BackendTests
                | GateId::RedisBackendTests
                | GateId::OidcBackendTests
                | GateId::PrometheusBackendTests
                | GateId::OtelBackendTests
                | GateId::GrpcBackendTests
                | GateId::VaultBackendTests
                | GateId::SettingsOnlyTests
                | GateId::TestkitContainerTests
                | GateId::IdentityAuditTests
        ),
        PlanTarget::Lane(lane) => spec.belongs_to(lane),
        PlanTarget::Verify => spec.verify_membership() == VerifyMembership::Included,
    }
}

pub(crate) fn plan_for(target: PlanTarget) -> Vec<Step> {
    let mut plan: Vec<_> = REGISTRY
        .iter()
        .filter(|spec| selected_for(target, spec.id()))
        .map(|spec| step_for_id(spec.id()))
        .collect();
    if target == PlanTarget::Lane(CiLane::Nightly) {
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
/// `CompatibilityCi` 计划已用全量 `deny check` + cargo-audit 覆盖。audit 步与 ci 共享同一
/// [`step_cargo_audit`] 构造。
///
/// Audit 亦经统一动态 executor 委托（不内联门命令），由 `CI-ADAPTIVE-WORKFLOW-01` 守。
fn audit_plan() -> Vec<Step> {
    plan_for(PlanTarget::Lane(CiLane::Nightly))
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
    shard: IntegrationShard,
    partition: Option<crate::nextest::HashPartition>,
    root: &Path,
) -> Result<()> {
    let lane = shard.as_str();
    let batches = integration_shards::batches(shard);
    for (index, batch) in batches.iter().enumerate() {
        let mode = match batch.scheduling {
            Scheduling::Serial => "serial",
            Scheduling::Parallel => "parallel",
        };
        eprintln!(
            "ci-integration/{lane}: [{}/{}] {mode}",
            index + 1,
            batches.len()
        );
        let batch_id = crate::nextest::IntegrationBatchId::new(shard, index + 1)?;
        crate::nextest::NextestInvocation::for_integration_batch(batch_id, partition)?
            .run(root, INTEGRATION_ENV)?;
    }
    Ok(())
}

/// Capability-sharded integration entrypoint. Target coverage is checked from Cargo metadata
/// before execution; resource requirements and serial/parallel batches come from the same typed
/// registry. Missing tools and Docker fail closed unless the local-only allowance is explicit.
pub(crate) fn run_ci_integration(
    shard: IntegrationShard,
    allow_missing_tools: bool,
    partition: Option<crate::nextest::HashPartition>,
) -> Result<()> {
    shard.validate_partition(partition)?;
    let root = workspace_root()?;
    integration_shards::validate_workspace(&root)?;
    let missing = integration_shards::missing_external_resources(shard);
    if !missing.is_empty() && !docker_available() {
        let labels = missing
            .iter()
            .map(|resource| resource.label())
            .collect::<Vec<_>>()
            .join(", ");
        if allow_missing_tools {
            eprintln!(
                "ci-integration/{shard}: [跳过] docker daemon 不可达，且缺少外部资源: {labels}"
            );
            return Ok(());
        }
        bail!(
            "ci-integration/{shard}: docker daemon 不可达，且缺少 shard 所需外部资源: {labels}; \
             启动 Docker、提供该 shard 的外部测试资源，或本地显式使用 --allow-missing-tools"
        );
    }
    let ran = crate::nextest::run_gated(
        &format!("ci-integration/{shard}"),
        allow_missing_tools,
        "integration shard",
        || run_integration_batches(shard, partition, &root),
    )?;
    if ran.is_some() {
        eprintln!("ci-integration/{shard}: 全部通过");
    } else {
        eprintln!("ci-integration/{shard}: 执行完成（缺 nextest，shard 已跳过）");
    }
    Ok(())
}

pub(crate) fn run_nextest_replay(
    shard: IntegrationShard,
    batch_number: usize,
    partition: Option<crate::nextest::HashPartition>,
) -> Result<()> {
    shard.validate_partition(partition)?;
    let root = workspace_root()?;
    integration_shards::validate_workspace(&root)?;
    let batch_id = crate::nextest::IntegrationBatchId::new(shard, batch_number)?;
    crate::nextest::NextestInvocation::for_integration_batch(batch_id, partition)?
        .run(&root, INTEGRATION_ENV)
}

/// 纯函数：`--fast` 只保留轻量的 repository meta / Cargo builtin metadata gate。
fn verify_plan(opts: &VerifyOpts) -> Vec<Step> {
    let plan = plan_for(PlanTarget::Verify);
    if opts.fast {
        plan.into_iter()
            .filter(|step| {
                !step.needs_compile()
                    && !matches!(
                        step.id,
                        GateId::PromtoolRules | GateId::Deny | GateId::AssemblyLockProtocolTests
                    )
            })
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
) -> Result<()> {
    let rendered = std::iter::once(subcommand.as_str())
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    let status = crate::cmd::cargo_cmd(subcommand, args, env, Some(cwd))
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

/// 跑单步：Internal 进程内执行；CargoBuiltin 直接 spawn；Tool 先探测再按决策分派。
fn run_one(
    lane: &str,
    step: &Step,
    opts: &VerifyOpts,
    root: &Path,
    tool_available: impl Fn(crate::cmd::CargoSubcommand) -> bool,
) -> Result<()> {
    let execute = || match step.kind {
        StepKind::Internal(check) => run_internal(check, opts, root),
        StepKind::LocalOnlyExecution => {
            let request = crate::localonly_evidence::prepare_request(
                crate::localonly_evidence::OWNER,
                None,
                root,
            )?
            .context("verify must prepare LocalOnly execution evidence")?;
            crate::localonly_evidence::execute(root, request).map(|_| ())
        }
        StepKind::Nextest(scope) => {
            crate::nextest::NextestInvocation::for_core(scope, opts.nextest_lane, opts.partition)
                .run(root, step.env)
        }
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
            run_step(lane, step.label(), subcommand, args, step.env, root)
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

fn run_internal(check: InternalCheck, opts: &VerifyOpts, root: &Path) -> Result<()> {
    match check {
        InternalCheck::ContractValidate => run_check(&contract::validate::ContractValidate),
        InternalCheck::AssemblyValidate => run_check(&assembly::AssemblyValidate),
        InternalCheck::AssemblyArtifactsCheck => crate::assembly_artifacts::run(),
        InternalCheck::AssemblyModulesCheck => crate::assembly_codegen::run(true),
        InternalCheck::AssemblyProvidersCheck => crate::assembly_codegen::run_providers(true),
        InternalCheck::AssemblyLockCheck => {
            assembly_lock::run(assembly_lock::AssemblyLockAction::Check)
        }
        InternalCheck::DeploymentPlanCheck => {
            crate::deployment_plan::run(crate::deployment_plan::Action::Check)
        }
        InternalCheck::AssemblyGraphCheck => {
            crate::graph::run(&crate::graph::Options::check_runtime())
        }
        // active 默认 deny；固定 review rules 为 warn，但未确认 fail-closed。
        InternalCheck::ContractBreaking => contract::breaking::run(&opts.contract_against),
        InternalCheck::LayerDeps => run_check(&layerdeps::LayerDeps),
        InternalCheck::ShippedFeatureGuard => {
            run_check(&shipped_feature_guard::ShippedFeatureGuard)
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
        InternalCheck::RuntimeDeploymentSpec => crate::runtime_deployment_spec::run_selftest_gate(),
        InternalCheck::RuntimeDepsGuard => run_check(&runtime_deps_guard::RuntimeDepsGuard),
        InternalCheck::SourceSemanticGuard => {
            run_check(&crate::source_semantic_guard::SourceSemanticGuard)
        }
        InternalCheck::ArchRules => run_check(&archrules::ArchRules),
        InternalCheck::CodegenCheck => codegen::run(true),
        InternalCheck::L2AssuranceCheck => crate::l2_assurance::run(true),
        InternalCheck::ProviderCapabilitiesCheck => crate::provider_capabilities::run(true),
        InternalCheck::LocalTxCoverage => run_check(&crate::localtx_coverage::LocalTxCoverage),
        InternalCheck::LocalOnlyEffects => run_check(&consistency_effects::LocalOnlyEffects),
        InternalCheck::PdpAllowGuard => run_check(&crate::pdpallow::PdpAllowGuard),
        InternalCheck::ContractBindingGuard => {
            run_check(&crate::contract_binding_guard::ContractBindingGuard)
        }
        InternalCheck::SchemaRlsGuard => run_check(&crate::schema_rls::SchemaRlsGuard),
        InternalCheck::SetLocalFunnel => run_check(&crate::setlocal_funnel::SetLocalFunnelGuard),
        InternalCheck::PgTenantTxGuard => run_check(&crate::pg_tenant_tx_guard::PgTenantTxGuard),
        InternalCheck::RepoScopeGuard => run_check(&repo_scope_guard::RepoScopeGuard),
        InternalCheck::TenancyCloseout => run_check(&crate::tenancy_closeout::TenancyCloseout),
        InternalCheck::MigrationsSerial => run_check(&crate::migrations::MigrationSerialGuard),
        InternalCheck::CommandSymmetry => run_check(&crate::command_symmetry::CommandSymmetry),
        InternalCheck::CiEntryGuard => crate::ci_entry_guard::run(),
        InternalCheck::ReconcileOutboxCommandGuard => {
            run_check(&reconcile_outbox_command_guard::ReconcileOutboxCommandGuard)
        }
        InternalCheck::DeferGate => run_check(&crate::defergate::DeferGate),
        InternalCheck::PostgresFeatureMatrix => crate::postgres_feature_matrix::run(),
        InternalCheck::Coverage => {
            let scope = if opts.coverage_typed_job {
                crate::ci_impact::coverage_scope_for_typed_job(root)?
            } else {
                crate::ci_impact::coverage_scope_for_full_ci()
            };
            crate::coverage::run(scope)
        }
        // 轴 A 封装面：basis+engine+curated extras 全集（layer=None）；check=true 漂移门 fail-closed（PUBLICAPI-DRIFT-GATE-01）。
        InternalCheck::PublicApiCheck => crate::publicapi::run(true, false, None),
    }
}

fn run_labeled_plan(lane: &str, plan: &[Step], opts: &VerifyOpts, root: &Path) -> Result<()> {
    crate::nextest::validate_workspace(root)?;
    for (i, step) in plan.iter().enumerate() {
        eprintln!("{lane}: [{}/{}] {}", i + 1, plan.len(), step.label());
        run_one(lane, step, opts, root, crate::cmd::tool_available)?;
    }
    Ok(())
}

/// verify 入口：按 plan 顺序跑每步，fail-fast。
pub(crate) fn run(
    fast: bool,
    allow_missing_tools: bool,
    contract_against: Option<&str>,
) -> Result<()> {
    let opts = VerifyOpts {
        fast,
        allow_missing_tools,
        partition: None,
        nextest_lane: crate::nextest::NextestLane::Verify,
        contract_against: contract_against
            .unwrap_or(contract::breaking::DEFAULT_AGAINST)
            .to_owned(),
        coverage_typed_job: false,
    };
    let root = workspace_root()?;
    let plan = verify_plan(&opts);
    let mode = if fast { "fast" } else { "full" };
    eprintln!("verify（{mode}）：{} 步", plan.len());
    // 每步开始打 label——build/clippy/nextest 各数分钟，让操作者实时知道卡在哪步。
    run_labeled_plan("verify", &plan, &opts, &root)?;
    eprintln!("verify（{mode}）：全部通过");
    Ok(())
}

/// `ci full` 本地兼容聚合入口（issue #1132）：按 [`plan_for`] 的兼容计划顺序跑每步，
/// fail-fast。GitHub Actions 不调此聚合，而是分别调用四条 [`CiLane`]。本地完整
/// canonical 入口是 `make ci-full`；`make ci` 仅执行 10 分钟有界 adaptive preflight，不调用本聚合。
/// `allow_missing_tools` 仅本地便利——CI 不传 = 缺工具 fail-closed。
pub(crate) fn run_ci(allow_missing_tools: bool) -> Result<()> {
    let opts = VerifyOpts {
        fast: false,
        allow_missing_tools,
        partition: None,
        nextest_lane: crate::nextest::NextestLane::CiCore,
        contract_against: contract::breaking::DEFAULT_AGAINST.to_owned(),
        coverage_typed_job: false,
    };
    let root = workspace_root()?;
    let plan = plan_for(PlanTarget::CompatibilityCi);
    eprintln!("ci：{} 步（CI lane 超集）", plan.len());
    run_labeled_plan("ci", &plan, &opts, &root)?;
    eprintln!("ci：全部通过");
    Ok(())
}

pub(crate) fn run_lane(
    lane: CiLane,
    allow_missing_tools: bool,
    partition: Option<crate::nextest::HashPartition>,
) -> Result<()> {
    if partition.is_some() {
        bail!("ci-core 不接受 partition；PR tests 使用 ci-core-tests --partition M/N");
    }
    let opts = VerifyOpts {
        fast: false,
        allow_missing_tools,
        partition,
        nextest_lane: crate::nextest::NextestLane::CiCore,
        contract_against: contract::breaking::DEFAULT_AGAINST.to_owned(),
        coverage_typed_job: lane == CiLane::Coverage,
    };
    let root = workspace_root()?;
    let plan = if lane == CiLane::Core {
        plan_for(PlanTarget::Core(CoreExecution::Full))
    } else {
        plan_for(PlanTarget::Lane(lane))
    };
    let name = lane.command_name();
    eprintln!("{name}：{} 步", plan.len());
    run_labeled_plan(name, &plan, &opts, &root)?;
    eprintln!("{name}：全部通过");
    Ok(())
}

pub(crate) fn run_core_execution(
    execution: CoreExecution,
    allow_missing_tools: bool,
    partition: Option<crate::nextest::HashPartition>,
) -> Result<()> {
    match (execution, partition) {
        (CoreExecution::Prerequisites, None) => {}
        (CoreExecution::Tests, Some(value)) if value.is_two_way() => {}
        _ => bail!("ci-core-prerequisites 禁止 partition；ci-core-tests 必须传 1/2 或 2/2"),
    }
    let opts = VerifyOpts {
        fast: false,
        allow_missing_tools,
        partition,
        nextest_lane: crate::nextest::NextestLane::CiCore,
        contract_against: contract::breaking::DEFAULT_AGAINST.to_owned(),
        coverage_typed_job: false,
    };
    let root = workspace_root()?;
    let plan = plan_for(PlanTarget::Core(execution));
    let name = match execution {
        CoreExecution::Prerequisites => "ci-core-prerequisites",
        CoreExecution::Tests => "ci-core-tests",
        CoreExecution::Full => "ci-core",
    };
    run_labeled_plan(name, &plan, &opts, &root)
}

/// The sole executable meaning of a closed [`CiJobKey`]. Keeping this enum private prevents
/// workflows or callers from rebuilding lane/shard/partition command strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobExecution {
    Lane(CiLane),
    Core {
        execution: CoreExecution,
        partition: Option<crate::nextest::HashPartition>,
    },
    Integration {
        shard: IntegrationShard,
        partition: Option<crate::nextest::HashPartition>,
    },
    LocalTxRequired,
    LocalOnlyRequired,
    Audit,
}

/// Unforgeable proof that the complete, unpartitioned postgres-domain execution returned success.
/// The private field keeps construction inside this execution module; the receipt minter can only
/// consume the capability after the typed runner has completed.
pub(crate) struct PostgresDomainPassed(());

#[cfg(test)]
impl PostgresDomainPassed {
    pub(crate) const fn for_test() -> Self {
        Self(())
    }
}

fn run_required_postgres_domain() -> Result<PostgresDomainPassed> {
    run_ci_integration(IntegrationShard::PostgresDomain, false, None)?;
    Ok(PostgresDomainPassed(()))
}

fn execution_for_job(job: CiJobKey) -> Result<JobExecution> {
    let one_of_two = || crate::nextest::HashPartition::new(1, 2);
    let two_of_two = || crate::nextest::HashPartition::new(2, 2);
    Ok(match job {
        CiJobKey::CiMeta => JobExecution::Lane(CiLane::Meta),
        CiJobKey::CiCorePrerequisites => JobExecution::Core {
            execution: CoreExecution::Prerequisites,
            partition: None,
        },
        CiJobKey::CiCoreTests1Of2 => JobExecution::Core {
            execution: CoreExecution::Tests,
            partition: Some(one_of_two()?),
        },
        CiJobKey::CiCoreTests2Of2 => JobExecution::Core {
            execution: CoreExecution::Tests,
            partition: Some(two_of_two()?),
        },
        CiJobKey::CiSecurity => JobExecution::Lane(CiLane::Security),
        CiJobKey::CiCoverage => JobExecution::Lane(CiLane::Coverage),
        CiJobKey::CiLocalOnly => JobExecution::LocalOnlyRequired,
        CiJobKey::IntegrationPostgresDomain => JobExecution::LocalTxRequired,
        CiJobKey::IntegrationEventTransport1Of2 => JobExecution::Integration {
            shard: IntegrationShard::EventTransport,
            partition: Some(one_of_two()?),
        },
        CiJobKey::IntegrationEventTransport2Of2 => JobExecution::Integration {
            shard: IntegrationShard::EventTransport,
            partition: Some(two_of_two()?),
        },
        CiJobKey::IntegrationRuntimeHttpAuth1Of2 => JobExecution::Integration {
            shard: IntegrationShard::RuntimeHttpAuth,
            partition: Some(one_of_two()?),
        },
        CiJobKey::IntegrationRuntimeHttpAuth2Of2 => JobExecution::Integration {
            shard: IntegrationShard::RuntimeHttpAuth,
            partition: Some(two_of_two()?),
        },
        CiJobKey::IntegrationConsistencyFault => JobExecution::Integration {
            shard: IntegrationShard::ConsistencyFault,
            partition: None,
        },
        CiJobKey::IntegrationCdcProjectionSaga => JobExecution::Integration {
            shard: IntegrationShard::CdcProjectionSaga,
            partition: None,
        },
        CiJobKey::IntegrationObjectStorage => JobExecution::Integration {
            shard: IntegrationShard::ObjectStorage,
            partition: None,
        },
        CiJobKey::Audit => JobExecution::Audit,
    })
}

/// Execute exactly one typed CI job. CI is fail-closed, so this carrier intentionally has no
/// local missing-tool allowance.
fn required_evidence_request_kind(
    job: CiJobKey,
    output: Option<&Path>,
) -> Result<Option<crate::ci_lanes::RequiredEvidenceKind>> {
    match (job.required_evidence(), output) {
        (None, Some(_)) => {
            bail!("non-owner CI job {job} may not request --required-evidence-output")
        }
        (required, _) => Ok(required),
    }
}

pub(crate) fn run_job(job: CiJobKey, required_evidence_output: Option<&Path>) -> Result<()> {
    let root = workspace_root()?;
    let required_evidence = required_evidence_request_kind(job, required_evidence_output)?;
    let (localtx_evidence, localonly_evidence) = match required_evidence {
        None => (None, None),
        Some(crate::ci_lanes::RequiredEvidenceKind::LocalTx) => (
            crate::localtx_evidence::prepare_request(job, required_evidence_output)?,
            None,
        ),
        Some(crate::ci_lanes::RequiredEvidenceKind::LocalOnly) => (
            None,
            crate::localonly_evidence::prepare_request(job, required_evidence_output, &root)?,
        ),
    };
    match execution_for_job(job)? {
        JobExecution::Lane(lane) => run_lane(lane, false, None),
        JobExecution::Core {
            execution,
            partition,
        } => run_core_execution(execution, false, partition),
        JobExecution::Integration { shard, partition } => {
            run_ci_integration(shard, false, partition)
        }
        JobExecution::LocalTxRequired => {
            let passed = run_required_postgres_domain()?;
            if let Some(request) = localtx_evidence {
                let counts = crate::localtx_coverage::verify_required_evidence_counts(&root)?;
                request.publish(passed, counts)?;
            }
            Ok(())
        }
        JobExecution::LocalOnlyRequired => {
            let request = localonly_evidence
                .context("ci-local-only must prepare its required execution evidence")?;
            crate::localonly_evidence::execute(&root, request)?;
            Ok(())
        }
        JobExecution::Audit => run_audit(false),
    }
}

/// audit 入口（issue #1133 供应链定时刷新 lane）：按 [`audit_plan`] 顺序跑每步，fail-fast。
/// GitHub Actions schedule 由 `ci run --job audit` 调用（CI-ADAPTIVE-WORKFLOW-01）。
/// `allow_missing_tools` 仅本地便利——CI 不传 = 缺 deny/audit 工具 fail-closed。
pub(crate) fn run_audit(allow_missing_tools: bool) -> Result<()> {
    let opts = VerifyOpts {
        fast: false,
        allow_missing_tools,
        partition: None,
        nextest_lane: crate::nextest::NextestLane::Verify,
        contract_against: contract::breaking::DEFAULT_AGAINST.to_owned(),
        coverage_typed_job: false,
    };
    let root = workspace_root()?;
    let plan = audit_plan();
    eprintln!("audit：{} 步（供应链漏洞刷新 lane）", plan.len());
    run_labeled_plan("audit", &plan, &opts, &root)?;
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
    fn every_ci_job_has_one_typed_executor() -> anyhow::Result<()> {
        assert_eq!(CiJobKey::ALL.len(), CiJobKey::COUNT);
        for job in CiJobKey::ALL {
            assert_executor_matches_job(job, execution_for_job(job)?)?;
        }
        Ok(())
    }

    #[test]
    fn required_evidence_output_is_validated_before_job_dispatch_red() -> anyhow::Result<()> {
        let output = Path::new("target/required-evidence.json");
        for job in CiJobKey::ALL {
            let actual = required_evidence_request_kind(job, Some(output));
            match job.required_evidence() {
                Some(expected) => assert_eq!(actual?, Some(expected), "{job}"),
                None => assert!(
                    actual.is_err(),
                    "non-owner {job} must reject --required-evidence-output"
                ),
            }
        }
        assert_eq!(
            required_evidence_request_kind(CiJobKey::CiMeta, None)?,
            None
        );
        Ok(())
    }

    fn assert_executor_matches_job(job: CiJobKey, execution: JobExecution) -> anyhow::Result<()> {
        match execution {
            JobExecution::Lane(lane) => assert_lane_executor(job, lane),
            JobExecution::Core {
                execution,
                partition,
            } => assert_core_executor(job, execution, partition)?,
            JobExecution::Integration { shard, partition } => {
                assert_integration_executor(job, shard, partition);
            }
            JobExecution::LocalTxRequired => assert_localtx_executor(job),
            JobExecution::LocalOnlyRequired => assert_localonly_executor(job),
            JobExecution::Audit => assert_eq!(job, CiJobKey::Audit),
        }
        Ok(())
    }

    fn assert_lane_executor(job: CiJobKey, lane: CiLane) {
        assert_eq!(job.lane_kind(), lane);
        assert!(job.shard().is_none());
        assert!(job.partition().is_none());
    }

    fn assert_core_executor(
        job: CiJobKey,
        execution: CoreExecution,
        partition: Option<crate::nextest::HashPartition>,
    ) -> anyhow::Result<()> {
        assert_eq!(job.lane_kind(), expected_core_lane(execution)?);
        let partition = partition.map(|value| value.to_string());
        assert_eq!(job.partition(), partition.as_deref());
        Ok(())
    }

    fn assert_integration_executor(
        job: CiJobKey,
        shard: IntegrationShard,
        partition: Option<crate::nextest::HashPartition>,
    ) {
        assert_eq!(job.lane_kind(), CiLane::Integration);
        assert_eq!(job.shard(), Some(shard.as_str()));
        assert_eq!(
            job.partition(),
            partition.as_ref().map(ToString::to_string).as_deref()
        );
    }

    fn assert_localtx_executor(job: CiJobKey) {
        assert_eq!(job, CiJobKey::IntegrationPostgresDomain);
        assert_eq!(job.lane_kind(), CiLane::Integration);
        assert_eq!(job.shard(), Some("postgres-domain"));
        assert!(job.partition().is_none());
    }

    fn assert_localonly_executor(job: CiJobKey) {
        assert_eq!(job, CiJobKey::CiLocalOnly);
        assert_eq!(job.lane_kind(), CiLane::LocalOnly);
        assert!(job.shard().is_none());
        assert!(job.partition().is_none());
    }

    fn expected_core_lane(execution: CoreExecution) -> anyhow::Result<CiLane> {
        match execution {
            CoreExecution::Prerequisites => Ok(CiLane::CorePrerequisites),
            CoreExecution::Tests => Ok(CiLane::CoreTests),
            CoreExecution::Full => bail!("full core is not a matrix job"),
        }
    }

    fn opts(fast: bool, allow_missing_tools: bool) -> VerifyOpts {
        VerifyOpts {
            fast,
            allow_missing_tools,
            partition: None,
            nextest_lane: crate::nextest::NextestLane::Verify,
            contract_against: contract::breaking::DEFAULT_AGAINST.to_owned(),
            coverage_typed_job: false,
        }
    }

    fn labels(plan: &[Step]) -> Vec<&'static str> {
        plan.iter().map(|s| s.label()).collect()
    }

    #[test]
    fn ci_lane_plans_are_registry_derived_and_partitioned() {
        assert_eq!(labels(&plan_for(PlanTarget::Lane(CiLane::Meta))).len(), 43);
        assert_eq!(
            labels(&plan_for(PlanTarget::Lane(CiLane::Security))),
            vec!["deny", "audit"]
        );
        assert_eq!(
            labels(&plan_for(PlanTarget::Lane(CiLane::Coverage))),
            vec!["coverage", "public-api"]
        );
        let core = labels(&plan_for(PlanTarget::Lane(CiLane::Core)));
        assert!(core.contains(&"build"));
        assert_eq!(core.first(), Some(&"postgres-feature-matrix"));
        assert!(core.contains(&"default-test-runner"));
        assert!(core.contains(&"settingsonly-tests"));
        assert!(core.contains(&"identityaudit-tests"));
        assert!(!core.contains(&"coverage"));
        assert!(!core.contains(&"integration-compile"));

        let compatibility: std::collections::BTreeSet<_> = plan_for(PlanTarget::CompatibilityCi)
            .into_iter()
            .map(|step| step.id as usize)
            .collect();
        let split: Vec<std::collections::BTreeSet<_>> = [
            CiLane::Meta,
            CiLane::Core,
            CiLane::Security,
            CiLane::Coverage,
        ]
        .into_iter()
        .map(|lane| {
            plan_for(PlanTarget::Lane(lane))
                .into_iter()
                .filter(|step| step.id.spec().compat() == CompatMembership::Included)
                .map(|step| step.id as usize)
                .collect()
        })
        .collect();
        for (index, lane) in split.iter().enumerate() {
            for other in &split[index + 1..] {
                assert!(lane.is_disjoint(other), "split CI lanes must be disjoint");
            }
        }
        let union: std::collections::BTreeSet<_> = split.into_iter().flatten().collect();
        assert_eq!(
            union, compatibility,
            "split CI lanes must cover compatibility CI"
        );
    }

    #[test]
    fn core_execution_plans_are_disjoint_and_cover_full_core() {
        let full = plan_for(PlanTarget::Core(CoreExecution::Full));
        let prerequisites = plan_for(PlanTarget::Core(CoreExecution::Prerequisites));
        let tests = plan_for(PlanTarget::Core(CoreExecution::Tests));
        assert_eq!(prerequisites.len(), 6);
        assert_eq!(tests.len(), 11);
        let prereq_ids = prerequisites
            .iter()
            .map(|step| step.id as usize)
            .collect::<std::collections::BTreeSet<_>>();
        let test_ids = tests
            .iter()
            .map(|step| step.id as usize)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(prereq_ids.is_disjoint(&test_ids));
        let union = prereq_ids
            .union(&test_ids)
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(union, full.iter().map(|step| step.id as usize).collect());
        let scopes = tests
            .iter()
            .filter_map(|step| match step.kind {
                StepKind::Nextest(scope) => Some(scope),
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            scopes,
            crate::nextest::CoreTestScope::ALL.into_iter().collect()
        );
    }

    #[test]
    fn runtime_dylint_ui_gate_is_typed_closed_and_in_aggregate_plans() -> anyhow::Result<()> {
        let validate = |plan: &[Step]| -> anyhow::Result<()> {
            let gates = plan
                .iter()
                .filter(|step| step.id == GateId::RuntimeDylintUiTests)
                .collect::<Vec<_>>();
            anyhow::ensure!(gates.len() == 1, "expected one runtime Dylint UI gate");
            let gate = gates[0];
            anyhow::ensure!(gate.label() == "runtime-dylint-ui-tests");
            anyhow::ensure!(matches!(gate.kind, StepKind::LintWorkspaceTests));
            anyhow::ensure!(
                gate.args
                    == [
                        "test",
                        "--locked",
                        "-p",
                        "rss_runtime_env_funnel",
                        "-p",
                        "rss_dlq_operator_callsite",
                        "-p",
                        "rss_authenticated_callsite",
                    ]
            );
            Ok(())
        };

        validate(&plan_for(PlanTarget::Verify))?;
        validate(&plan_for(PlanTarget::CompatibilityCi))?;
        validate(&plan_for(PlanTarget::Lane(CiLane::Core)))?;
        validate(&plan_for(PlanTarget::Core(CoreExecution::Prerequisites)))?;
        assert!(
            verify_plan(&opts(true, false))
                .iter()
                .all(|step| step.id != GateId::RuntimeDylintUiTests)
        );

        let mut omitted = plan_for(PlanTarget::Verify);
        omitted.retain(|step| step.id != GateId::RuntimeDylintUiTests);
        assert!(validate(&omitted).is_err());
        let mut weakened = plan_for(PlanTarget::Verify);
        weakened
            .iter_mut()
            .find(|step| step.id == GateId::RuntimeDylintUiTests)
            .context("runtime Dylint UI gate")?
            .args = &["test", "-p", "rss_runtime_env_funnel"];
        assert!(validate(&weakened).is_err());
        Ok(())
    }

    #[test]
    fn secure_production_trybuild_gate_is_feature_isolated() -> anyhow::Result<()> {
        let prerequisites = plan_for(PlanTarget::Core(CoreExecution::Prerequisites));
        let production = prerequisites
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
    fn ci_lane_compatibility_plan_keeps_63_unique_gates_and_supersedes_nextest() {
        let plan = plan_for(PlanTarget::CompatibilityCi);
        assert_eq!(plan.len(), 63);
        assert!(!labels(&plan).contains(&"default-test-runner"));
        let mut ids: Vec<_> = plan.iter().map(|step| step.id as usize).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 63);
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
            verify_plan(&opts(true, false)),
            plan_for(PlanTarget::CompatibilityCi),
            plan_for(PlanTarget::Lane(CiLane::Meta)),
        ] {
            assert!(!labels(&plan).contains(&"doc-contracts"));
            assert!(labels(&plan).contains(&"source-semantic-guard"));
        }
    }

    #[test]
    fn verify_plan_order_and_count() {
        let plan = verify_plan(&opts(false, false));
        assert_eq!(
            labels(&plan),
            vec![
                "fmt",
                "contract-validate",
                "assembly-validate",
                "assembly-artifacts-check",
                "assembly-modules-check",
                "assembly-providers-check",
                "assembly-lock-check",
                "deployment-plan-check",
                "assembly-graph-check",
                "contract-breaking",
                "layer-deps",
                "shipped-feature-guard",
                "wsdeps-drift",
                "source-semantic-guard",
                "promtool-rules",
                "outbox-same-id-guard",
                "consistency-fixtures",
                "event-transport-guard",
                "inbox-cutover-guard",
                "dlx-lifecycle-funnel",
                "runtime-baseline",
                "runtime-root-guard",
                "runtime-env-guard",
                "runtime-deployment-spec",
                "runtime-deps-guard",
                "archrules",
                "codegen-check",
                "l2-assurance-check",
                "provider-capabilities-check",
                "localtx-coverage",
                "local-only-effects",
                "local-only-execution",
                "pdp-allow-guard",
                "contract-binding-guard",
                "schema-rls",
                "setlocal-funnel",
                "pg-tenant-tx-guard",
                "repo-scope-guard",
                "tenancy-closeout",
                "migrations-serial",
                "command-symmetry",
                "ci-entry-guard",
                "reconcile-outbox-command-guard",
                "defer-gate",
                "assembly-lock-protocol-tests",
                "build",
                "postgres-feature-matrix",
                "integration-compile",
                "clippy",
                "default-test-runner",
                "secure-production-trybuild",
                "s3-backend-tests",
                "redis-backend-tests",
                "oidc-backend-tests",
                "prometheus-backend-tests",
                "otel-backend-tests",
                "grpc-backend-tests",
                "vault-backend-tests",
                "settingsonly-tests",
                "identityaudit-tests",
                "testkit-container-tests",
                "deny",
                "dylint",
                "runtime-dylint-ui-tests",
            ]
        );
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
        assert_eq!(gate.id.spec().lanes(), [Some(CiLane::LocalOnly), None]);
        assert_eq!(gate.id.spec().tool(), ToolRequirement::Nextest);
        assert_eq!(
            gate.id.spec().compat(),
            CompatMembership::Standalone(StandaloneReason::VerifyOnly)
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
            ("verify", plan_for(PlanTarget::Verify)),
            ("compatibility-ci", plan_for(PlanTarget::CompatibilityCi)),
            ("ci-core", plan_for(PlanTarget::Lane(CiLane::Core))),
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
            ("verify", plan_for(PlanTarget::Verify)),
            ("ci", plan_for(PlanTarget::CompatibilityCi)),
        ] {
            assert!(
                labels(&plan).contains(&"shipped-feature-guard"),
                "{lane} must check the actual server/rss feature graph"
            );
        }
    }

    fn validate_runtime_deployment_spec_membership(plan: &[Step]) -> anyhow::Result<()> {
        let members = plan
            .iter()
            .filter(|step| step.id == GateId::RuntimeDeploymentSpec)
            .collect::<Vec<_>>();
        anyhow::ensure!(
            members.len() == 1,
            "aggregate plan must contain exactly one gate"
        );
        let step = members[0];
        anyhow::ensure!(
            step.label() == "runtime-deployment-spec",
            "aggregate gate label drift"
        );
        anyhow::ensure!(!step.needs_compile(), "aggregate gate must be no-compile");
        anyhow::ensure!(
            step.carrier_file() == Some("xtask/src/runtime_deployment_spec.rs"),
            "aggregate gate carrier drift"
        );
        anyhow::ensure!(
            matches!(
                step.kind,
                StepKind::Internal(InternalCheck::RuntimeDeploymentSpec)
            ),
            "aggregate gate executor drift"
        );
        Ok(())
    }

    #[test]
    fn runtime_deployment_spec_membership_predicate_green_and_synthetic_red() -> anyhow::Result<()>
    {
        for (name, plan) in [
            ("fast", verify_plan(&opts(true, false))),
            ("ci-meta", plan_for(PlanTarget::Lane(CiLane::Meta))),
            ("compatibility", plan_for(PlanTarget::CompatibilityCi)),
        ] {
            validate_runtime_deployment_spec_membership(&plan)
                .with_context(|| format!("{name} membership"))?;
        }

        let mut mutant = verify_plan(&opts(true, false));
        mutant.retain(|step| step.id != GateId::RuntimeDeploymentSpec);
        assert!(
            validate_runtime_deployment_spec_membership(&mutant).is_err(),
            "omission synthetic red must fail"
        );

        let mut mutant = verify_plan(&opts(true, false));
        let mutant_step = mutant
            .iter_mut()
            .find(|step| step.id == GateId::RuntimeDeploymentSpec)
            .context("committed fast plan lacks runtime-deployment-spec")?;
        mutant_step.kind = StepKind::Internal(InternalCheck::RuntimeBaseline);
        assert!(
            validate_runtime_deployment_spec_membership(&mutant).is_err(),
            "executor synthetic red must fail"
        );
        Ok(())
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
                        .is_some_and(|after| after.id == GateId::RuntimeDeploymentSpec)
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
            plan_for(PlanTarget::Verify),
            verify_plan(&opts(true, false)),
            plan_for(PlanTarget::Lane(CiLane::Meta)),
            plan_for(PlanTarget::CompatibilityCi),
        ] {
            assert!(runtime_root_guard_membership_is_exact(&plan));
        }

        let real_plan = verify_plan(&opts(true, false));
        let mut omitted = real_plan.clone();
        omitted.retain(|step| step.id != GateId::RuntimeRootGuard);
        assert!(!runtime_root_guard_membership_is_exact(&omitted));

        let mut duplicated = real_plan.clone();
        duplicated.push(
            real_plan
                .iter()
                .find(|step| step.id == GateId::RuntimeRootGuard)
                .context("committed fast plan lacks runtime-root-guard")?
                .clone(),
        );
        assert!(!runtime_root_guard_membership_is_exact(&duplicated));

        let mut wrong_executor = real_plan;
        wrong_executor
            .iter_mut()
            .find(|step| step.id == GateId::RuntimeRootGuard)
            .context("committed fast plan lacks runtime-root-guard")?
            .kind = StepKind::Internal(InternalCheck::RuntimeBaseline);
        assert!(!runtime_root_guard_membership_is_exact(&wrong_executor));
        Ok(())
    }

    #[test]
    fn runtime_env_guard_is_typed_once_and_ordered_in_all_aggregate_plans() -> anyhow::Result<()> {
        for plan in [
            plan_for(PlanTarget::Verify),
            verify_plan(&opts(true, false)),
            plan_for(PlanTarget::Lane(CiLane::Meta)),
            plan_for(PlanTarget::CompatibilityCi),
        ] {
            assert!(runtime_env_guard_membership_is_exact(&plan));
        }

        let real_plan = verify_plan(&opts(true, false));
        let mut omitted = real_plan.clone();
        omitted.retain(|step| step.id != GateId::RuntimeEnvGuard);
        assert!(!runtime_env_guard_membership_is_exact(&omitted));

        let mut duplicated = real_plan.clone();
        duplicated.push(
            real_plan
                .iter()
                .find(|step| step.id == GateId::RuntimeEnvGuard)
                .context("committed fast plan lacks runtime-env-guard")?
                .clone(),
        );
        assert!(!runtime_env_guard_membership_is_exact(&duplicated));

        let mut wrong_executor = real_plan;
        wrong_executor
            .iter_mut()
            .find(|step| step.id == GateId::RuntimeEnvGuard)
            .context("committed fast plan lacks runtime-env-guard")?
            .kind = StepKind::Internal(InternalCheck::RuntimeBaseline);
        assert!(!runtime_env_guard_membership_is_exact(&wrong_executor));
        Ok(())
    }

    #[test]
    fn assembly_lock_protocol_tests_remain_full_verify_only() {
        let fast = verify_plan(&opts(true, false));
        assert!(
            !fast
                .iter()
                .any(|step| step.id == GateId::AssemblyLockProtocolTests)
        );

        let full = verify_plan(&opts(false, false));
        let gates = full
            .iter()
            .filter(|step| step.id == GateId::AssemblyLockProtocolTests)
            .collect::<Vec<_>>();
        assert_eq!(gates.len(), 1);
        let gate = gates[0];
        assert!(gate.needs_compile());
        assert!(matches!(gate.kind, StepKind::Cargo));
        assert_eq!(gate.args, ["test", "-p", "assembly-schema"]);
        assert_eq!(gate.id.spec().compile_kind(), CompileKind::Workspace);
        assert!(matches!(
            gate.id.spec().tool(),
            ToolRequirement::CargoBuiltin(crate::cmd::CargoSubcommand::Test)
        ));
    }

    /// `--fast` 只保留轻量 no-compile 步，不接 Docker、额外 Cargo 工具或 crate 测试。
    #[test]
    fn fast_plan_keeps_lightweight_meta_and_drops_external_or_compile_gates() {
        let plan = verify_plan(&opts(true, false));
        assert_eq!(
            labels(&plan),
            vec![
                "fmt",
                "contract-validate",
                "assembly-validate",
                "assembly-artifacts-check",
                "assembly-modules-check",
                "assembly-providers-check",
                "assembly-lock-check",
                "deployment-plan-check",
                "assembly-graph-check",
                "contract-breaking",
                "layer-deps",
                "shipped-feature-guard",
                "wsdeps-drift",
                "source-semantic-guard",
                "outbox-same-id-guard",
                "consistency-fixtures",
                "event-transport-guard",
                "inbox-cutover-guard",
                "dlx-lifecycle-funnel",
                "runtime-baseline",
                "runtime-root-guard",
                "runtime-env-guard",
                "runtime-deployment-spec",
                "runtime-deps-guard",
                "archrules",
                "codegen-check",
                "l2-assurance-check",
                "provider-capabilities-check",
                "localtx-coverage",
                "local-only-effects",
                "pdp-allow-guard",
                "contract-binding-guard",
                "schema-rls",
                "setlocal-funnel",
                "pg-tenant-tx-guard",
                "repo-scope-guard",
                "tenancy-closeout",
                "migrations-serial",
                "command-symmetry",
                "ci-entry-guard",
                "reconcile-outbox-command-guard",
                "defer-gate"
            ]
        );
        for dropped in [
            "build",
            "clippy",
            "default-test-runner",
            "dylint",
            "promtool-rules",
            "assembly-lock-protocol-tests",
            "deny",
        ] {
            assert!(!labels(&plan).contains(&dropped), "fast 不应含 {dropped}");
        }
    }

    /// 两种模式共享的轻量 repository meta checks（contract validate / assembly validate / assembly artifacts / contract breaking / layer-deps / wsdeps-drift /
    /// consistency-fixtures / event-transport-guard / inbox-cutover-guard /
    /// runtime-baseline / runtime-root-guard / runtime-env-guard / runtime-deployment-spec / runtime-deps-guard / archrules / codegen / L2 assurance / pdp-allow-guard / contract-binding-guard /
    /// schema-rls / setlocal-funnel / pg-tenant-tx-guard / repo-scope-guard / tenancy-closeout / migrations-serial / command-symmetry /
    /// reconcile-outbox-command-guard / defer-gate）在两种模式恒在。
    #[test]
    fn meta_checks_present_in_both_modes() {
        for fast in [true, false] {
            let plan = verify_plan(&opts(fast, false));
            let internals: Vec<_> = plan
                .iter()
                .filter(|s| {
                    matches!(s.kind, StepKind::Internal(_))
                        && !s.needs_compile()
                        && s.id != GateId::PromtoolRules
                })
                .map(|s| s.label())
                .collect();
            assert_eq!(
                internals,
                vec![
                    "contract-validate",
                    "assembly-validate",
                    "assembly-artifacts-check",
                    "assembly-modules-check",
                    "assembly-providers-check",
                    "assembly-lock-check",
                    "deployment-plan-check",
                    "assembly-graph-check",
                    "contract-breaking",
                    "layer-deps",
                    "shipped-feature-guard",
                    "wsdeps-drift",
                    "source-semantic-guard",
                    "outbox-same-id-guard",
                    "consistency-fixtures",
                    "event-transport-guard",
                    "inbox-cutover-guard",
                    "dlx-lifecycle-funnel",
                    "runtime-baseline",
                    "runtime-root-guard",
                    "runtime-env-guard",
                    "runtime-deployment-spec",
                    "runtime-deps-guard",
                    "archrules",
                    "codegen-check",
                    "l2-assurance-check",
                    "provider-capabilities-check",
                    "localtx-coverage",
                    "local-only-effects",
                    "pdp-allow-guard",
                    "contract-binding-guard",
                    "schema-rls",
                    "setlocal-funnel",
                    "pg-tenant-tx-guard",
                    "repo-scope-guard",
                    "tenancy-closeout",
                    "migrations-serial",
                    "command-symmetry",
                    "ci-entry-guard",
                    "reconcile-outbox-command-guard",
                    "defer-gate"
                ],
                "fast={fast}"
            );
        }
    }

    #[test]
    fn archrules_matrix_is_no_compile_internal_gate_in_fast_and_ci() -> anyhow::Result<()> {
        for (name, plan) in [
            ("fast", verify_plan(&opts(true, false))),
            ("ci", plan_for(PlanTarget::CompatibilityCi)),
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
            assert_eq!(spec.lanes(), [Some(CiLane::Meta), None], "{id:?}");
            assert_eq!(spec.compile_kind(), CompileKind::NoCompile, "{id:?}");
            assert_eq!(
                spec.verify_membership(),
                VerifyMembership::Included,
                "{id:?}"
            );
            assert_eq!(spec.compat(), CompatMembership::Included, "{id:?}");
            assert_eq!(spec.tool(), ToolRequirement::InProcess, "{id:?}");
            assert_eq!(
                step_for_id(id).kind,
                StepKind::Internal(expected_check),
                "{id:?} executor mapping drift"
            );
        }

        for (name, plan) in [
            ("full", plan_for(PlanTarget::Verify)),
            ("fast", verify_plan(&opts(true, false))),
            ("ci-meta", plan_for(PlanTarget::Lane(CiLane::Meta))),
            ("compatibility", plan_for(PlanTarget::CompatibilityCi)),
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

        for lane in [CiLane::Core, CiLane::Security, CiLane::Coverage] {
            let plan = plan_for(PlanTarget::Lane(lane));
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
            ("full", plan_for(PlanTarget::Verify)),
            ("fast", verify_plan(&opts(true, false))),
            ("ci", plan_for(PlanTarget::CompatibilityCi)),
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
            GateId::DeploymentPlanCheck,
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
            artifact.id.spec().lanes() == [Some(CiLane::Meta), None]
                && artifact.id.spec().verify_membership() == VerifyMembership::Included
                && artifact.id.spec().compat() == CompatMembership::Included
                && artifact.id.spec().tool() == ToolRequirement::InProcess,
            "artifact typed membership drift"
        );
        Ok(())
    }

    #[test]
    fn assembly_artifacts_gate_is_typed_once_and_orders_the_assembly_closure() -> anyhow::Result<()>
    {
        for (name, plan) in [
            ("full", plan_for(PlanTarget::Verify)),
            ("fast", verify_plan(&opts(true, false))),
            ("ci-meta", plan_for(PlanTarget::Lane(CiLane::Meta))),
            ("compatibility", plan_for(PlanTarget::CompatibilityCi)),
        ] {
            validate_assembly_artifacts_gate(&plan).with_context(|| format!("{name} plan"))?;
        }

        let real = verify_plan(&opts(true, false));
        let mut omitted = real.clone();
        omitted.retain(|step| step.id != GateId::AssemblyArtifactsCheck);
        assert!(validate_assembly_artifacts_gate(&omitted).is_err());

        let mut duplicated = real.clone();
        let duplicate = real
            .iter()
            .find(|step| step.id == GateId::AssemblyArtifactsCheck)
            .context("committed fast plan lacks artifact check")?
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
            provider.id.spec().lanes() == [Some(CiLane::Meta), None]
                && provider.id.spec().verify_membership() == VerifyMembership::Included
                && provider.id.spec().compat() == CompatMembership::Included
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
            ("full", plan_for(PlanTarget::Verify)),
            ("fast", verify_plan(&opts(true, false))),
            ("ci-meta", plan_for(PlanTarget::Lane(CiLane::Meta))),
            ("compatibility", plan_for(PlanTarget::CompatibilityCi)),
        ] {
            validate_assembly_provider_codegen_gate(&plan)
                .with_context(|| format!("{name} plan"))?;
        }

        let mut omitted = verify_plan(&opts(true, false));
        omitted.retain(|step| step.id != GateId::AssemblyProvidersCheck);
        assert!(validate_assembly_provider_codegen_gate(&omitted).is_err());

        let mut duplicated = verify_plan(&opts(true, false));
        let duplicate = duplicated
            .iter()
            .find(|step| step.id == GateId::AssemblyProvidersCheck)
            .context("committed fast plan lacks provider check")?
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
            lock.id.spec().lanes() == [Some(CiLane::Meta), None]
                && lock.id.spec().verify_membership() == VerifyMembership::Included
                && lock.id.spec().compat() == CompatMembership::Included
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
        let deployment = plan
            .iter()
            .position(|step| step.id == GateId::DeploymentPlanCheck)
            .context("plan lacks deployment plan check")?;
        let graph = plan
            .iter()
            .position(|step| step.id == GateId::AssemblyGraphCheck)
            .context("plan lacks graph check")?;
        anyhow::ensure!(
            providers == modules + 1
                && lock == providers + 1
                && deployment == lock + 1
                && graph == deployment + 1,
            "assembly order must be modules -> providers -> lock -> deployment -> graph"
        );
        Ok(())
    }

    #[test]
    fn assembly_lock_check_is_typed_once_and_ordered_in_all_aggregate_plans() -> anyhow::Result<()>
    {
        for (name, plan) in [
            ("full", plan_for(PlanTarget::Verify)),
            ("fast", verify_plan(&opts(true, false))),
            ("ci-meta", plan_for(PlanTarget::Lane(CiLane::Meta))),
            ("compatibility", plan_for(PlanTarget::CompatibilityCi)),
        ] {
            validate_assembly_lock_check(&plan).with_context(|| format!("{name} plan"))?;
        }

        let mut omitted = verify_plan(&opts(true, false));
        omitted.retain(|step| step.id != GateId::AssemblyLockCheck);
        assert!(validate_assembly_lock_check(&omitted).is_err());

        let mut duplicated = verify_plan(&opts(true, false));
        let duplicate = duplicated
            .iter()
            .find(|step| step.id == GateId::AssemblyLockCheck)
            .context("committed fast plan lacks lock check")?
            .clone();
        duplicated.push(duplicate);
        assert!(validate_assembly_lock_check(&duplicated).is_err());
        Ok(())
    }

    fn validate_deployment_plan_check(plan: &[Step]) -> anyhow::Result<()> {
        let members = plan
            .iter()
            .filter(|step| step.id == GateId::DeploymentPlanCheck)
            .collect::<Vec<_>>();
        anyhow::ensure!(members.len() == 1, "expected one deployment plan check");
        let step = members[0];
        anyhow::ensure!(
            step.label() == "deployment-plan-check"
                && !step.needs_compile()
                && step.carrier_file() == Some("xtask/src/deployment_plan.rs")
                && matches!(
                    step.kind,
                    StepKind::Internal(InternalCheck::DeploymentPlanCheck)
                ),
            "deployment plan gate binding drift"
        );
        anyhow::ensure!(
            step.id.spec().lanes() == [Some(CiLane::Meta), None]
                && step.id.spec().verify_membership() == VerifyMembership::Included
                && step.id.spec().compat() == CompatMembership::Included,
            "deployment plan gate membership drift"
        );
        Ok(())
    }

    #[test]
    fn deployment_plan_check_is_typed_once_in_all_aggregate_plans() -> anyhow::Result<()> {
        for (name, plan) in [
            ("full", plan_for(PlanTarget::Verify)),
            ("fast", verify_plan(&opts(true, false))),
            ("ci-meta", plan_for(PlanTarget::Lane(CiLane::Meta))),
            ("compatibility", plan_for(PlanTarget::CompatibilityCi)),
        ] {
            validate_deployment_plan_check(&plan).with_context(|| format!("{name} plan"))?;
        }
        let mut omitted = verify_plan(&opts(true, false));
        omitted.retain(|step| step.id != GateId::DeploymentPlanCheck);
        assert!(validate_deployment_plan_check(&omitted).is_err());
        let mut wrong = verify_plan(&opts(true, false));
        wrong
            .iter_mut()
            .find(|step| step.id == GateId::DeploymentPlanCheck)
            .context("fast plan lacks deployment gate")?
            .kind = StepKind::Internal(InternalCheck::AssemblyLockCheck);
        assert!(validate_deployment_plan_check(&wrong).is_err());
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
            gate.id.spec().lanes() == [Some(CiLane::Meta), None]
                && gate.id.spec().verify_membership() == VerifyMembership::Included
                && gate.id.spec().compat() == CompatMembership::Included
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
            ("verify", plan_for(PlanTarget::Verify)),
            ("fast", verify_plan(&opts(true, false))),
            ("ci-meta", plan_for(PlanTarget::Lane(CiLane::Meta))),
            ("compatibility", plan_for(PlanTarget::CompatibilityCi)),
        ] {
            validate_l2_assurance_gate(&plan).with_context(|| format!("{name} plan"))?;
        }

        let real_plan = verify_plan(&opts(true, false));

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
            ("verify", plan_for(PlanTarget::Verify)),
            ("fast", verify_plan(&opts(true, false))),
            ("ci-meta", plan_for(PlanTarget::Lane(CiLane::Meta))),
            ("compatibility", plan_for(PlanTarget::CompatibilityCi)),
        ] {
            validate_provider_capabilities_gate(&plan).with_context(|| format!("{name} plan"))?;
        }

        let real_plan = verify_plan(&opts(true, false));
        let mut omitted = real_plan.clone();
        omitted.retain(|step| step.id != GateId::ProviderCapabilitiesCheck);
        assert!(validate_provider_capabilities_gate(&omitted).is_err());

        let mut duplicated = real_plan.clone();
        let duplicate = real_plan
            .iter()
            .find(|step| step.id == GateId::ProviderCapabilitiesCheck)
            .context("committed fast plan lacks provider capabilities check")?
            .clone();
        duplicated.push(duplicate);
        assert!(validate_provider_capabilities_gate(&duplicated).is_err());

        let mut wrong_executor = real_plan;
        wrong_executor
            .iter_mut()
            .find(|step| step.id == GateId::ProviderCapabilitiesCheck)
            .context("committed fast plan lacks provider capabilities check")?
            .kind = StepKind::Internal(InternalCheck::CodegenCheck);
        assert!(validate_provider_capabilities_gate(&wrong_executor).is_err());
        Ok(())
    }

    #[test]
    fn assembly_graph_is_no_compile_internal_gate_after_modules_in_all_lanes() -> anyhow::Result<()>
    {
        for (name, plan) in [
            ("full", plan_for(PlanTarget::Verify)),
            ("fast", verify_plan(&opts(true, false))),
            ("ci", plan_for(PlanTarget::CompatibilityCi)),
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
            let deployment = labels
                .iter()
                .position(|label| *label == "deployment-plan-check")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 deployment-plan-check"))?;
            assert_eq!(providers, modules + 1, "{name} providers lane order drift");
            assert_eq!(lock, providers + 1, "{name} lock lane order drift");
            assert_eq!(deployment, lock + 1, "{name} deployment lane order drift");
            assert_eq!(graph, deployment + 1, "{name} graph lane order drift");
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
        for (name, plan) in [
            ("fast", verify_plan(&opts(true, false))),
            ("ci", plan_for(PlanTarget::CompatibilityCi)),
        ] {
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

    #[test]
    fn integration_batch_args_scope_targets_and_threads() -> anyhow::Result<()> {
        let partition = crate::nextest::HashPartition::new(1, 2)?;
        for shard in IntegrationShard::ALL {
            for (index, batch) in integration_shards::batches(*shard).iter().enumerate() {
                let batch_id = crate::nextest::IntegrationBatchId::new(*shard, index + 1)?;
                let invocation =
                    crate::nextest::NextestInvocation::for_integration_batch(batch_id, None)?;
                let args = invocation.execution_argv();
                assert!(args.iter().any(|arg| arg == "--no-tests=fail"));
                assert_eq!(
                    args.windows(2)
                        .filter(|pair| pair[0] == "--test-threads" && pair[1] == "1")
                        .count(),
                    usize::from(batch.scheduling == Scheduling::Serial)
                );
                let selected_packages: Vec<_> = args
                    .windows(2)
                    .filter(|pair| pair[0] == "-p")
                    .map(|pair| pair[1].as_str())
                    .collect();
                assert_eq!(selected_packages, [batch.package]);
                match batch.kind {
                    integration_shards::TargetKind::Lib => {
                        assert!(args.iter().any(|arg| arg == "--lib"));
                        assert!(!args.iter().any(|arg| arg == "--test"));
                    }
                    integration_shards::TargetKind::Test => {
                        assert!(!args.iter().any(|arg| arg == "--lib"));
                        let selected: Vec<_> = args
                            .windows(2)
                            .filter(|pair| pair[0] == "--test")
                            .map(|pair| pair[1].as_str())
                            .collect();
                        assert_eq!(selected, batch.targets);
                    }
                }
                assert!(
                    args.windows(2).any(|pair| {
                        pair[0] == "-E" && pair[1].as_str() == batch.filter.as_str()
                    })
                );
                let partitioned = crate::nextest::NextestInvocation::for_integration_batch(
                    batch_id,
                    Some(partition),
                )
                .map(|invocation| invocation.execution_argv())
                .unwrap_or_else(|_| args.clone());
                if shard.validate_partition(Some(partition)).is_ok() {
                    assert!(partitioned.iter().any(|arg| arg == "--no-tests=pass"));
                }
            }
        }
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
                    matches!(
                        step.kind,
                        StepKind::Nextest(_) | StepKind::LocalOnlyExecution
                    )
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
        let batch_id =
            crate::nextest::IntegrationBatchId::new(IntegrationShard::EventTransport, 3)?;
        let invocation = crate::nextest::NextestInvocation::for_integration_batch(
            batch_id,
            Some("2/2".parse()?),
        )?;
        assert_eq!(
            invocation.replay_spec(),
            &crate::nextest::ReplaySpec::Integration {
                shard: IntegrationShard::EventTransport,
                batch: 3,
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
                &root
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
                &root
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
        run_labeled_plan("ci", &plan, &opts(false, false), &root)
    }

    /// dylint 步必须带 `DYLINT_RUSTFLAGS=-D warnings`——否则默认 `Warn` 的 `rss_domain_no_serialize`
    /// 不会让 verify 非零，门退化为非 fail-closed（#1023 的核心诉求落空）。
    ///
    /// 注：本测试只断言 **plan 配置**带该 env（无 spawn）；运行时端到端 fail-closed（违例真让 dylint
    /// 非零）经手跑 `cargo xtask verify` 验证——xtask 测试策略不含跑 nightly dylint 的集成测试。
    #[test]
    fn dylint_step_is_fail_closed_via_deny_warnings() -> anyhow::Result<()> {
        let plan = plan_for(PlanTarget::Verify);
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

    /// 缺工具 + 不宽限 ⇒ `run_one` 返回 `Err`（executor 层 anti-vacuity 红例，INVARIANT VERIFY-TOOL-GATE-01）。
    #[test]
    fn run_one_missing_tool_fail_closed_is_err() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let step = missing_coverage_tool_step();
        let probed = std::cell::Cell::new(false);
        assert!(
            run_one("verify", &step, &opts(false, false), &root, |probe| {
                assert_eq!(probe, crate::cmd::CargoSubcommand::LlvmCovReport);
                probed.set(true);
                false
            })
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
        assert!(run_one("verify", &step, &opts(false, true), &root, |_| false).is_ok());
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

    /// CompatibilityCi 顺序与门集（单一事实源；本地兼容聚合顺序）。`audit`（cargo-audit）紧随 `deny` 后
    /// （issue #1133：供应链漏洞检查进入兼容计划，防御纵深独立于 deny advisories）。
    #[test]
    fn compatibility_plan_order_and_count() {
        assert_eq!(
            labels(&plan_for(PlanTarget::CompatibilityCi)),
            vec![
                "fmt",
                "contract-validate",
                "assembly-validate",
                "assembly-artifacts-check",
                "assembly-modules-check",
                "assembly-providers-check",
                "assembly-lock-check",
                "deployment-plan-check",
                "assembly-graph-check",
                "contract-breaking",
                "layer-deps",
                "shipped-feature-guard",
                "wsdeps-drift",
                "source-semantic-guard",
                "promtool-rules",
                "outbox-same-id-guard",
                "consistency-fixtures",
                "event-transport-guard",
                "inbox-cutover-guard",
                "dlx-lifecycle-funnel",
                "runtime-baseline",
                "runtime-root-guard",
                "runtime-env-guard",
                "runtime-deployment-spec",
                "runtime-deps-guard",
                "archrules",
                "codegen-check",
                "l2-assurance-check",
                "provider-capabilities-check",
                "localtx-coverage",
                "local-only-effects",
                "pdp-allow-guard",
                "contract-binding-guard",
                "schema-rls",
                "setlocal-funnel",
                "pg-tenant-tx-guard",
                "repo-scope-guard",
                "tenancy-closeout",
                "migrations-serial",
                "command-symmetry",
                "ci-entry-guard",
                "reconcile-outbox-command-guard",
                "defer-gate",
                "postgres-feature-matrix",
                "build",
                "clippy",
                "coverage",
                "secure-production-trybuild",
                "s3-backend-tests",
                "redis-backend-tests",
                "oidc-backend-tests",
                "prometheus-backend-tests",
                "otel-backend-tests",
                "grpc-backend-tests",
                "vault-backend-tests",
                "settingsonly-tests",
                "identityaudit-tests",
                "testkit-container-tests",
                "deny",
                "audit",
                "dylint",
                "runtime-dylint-ui-tests",
                "public-api",
            ]
        );
    }

    /// ci 的 build/clippy 升 `--all-features --all-targets`（issue 验收：编译态全覆盖）。
    #[test]
    fn ci_build_clippy_use_all_features_all_targets() -> anyhow::Result<()> {
        let plan = plan_for(PlanTarget::CompatibilityCi);
        for label in ["build", "clippy"] {
            let step = plan
                .iter()
                .find(|s| s.label() == label)
                .ok_or_else(|| anyhow::anyhow!("CompatibilityCi 缺 `{label}` 步"))?;
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
        let plan = plan_for(PlanTarget::CompatibilityCi);
        assert!(
            !labels(&plan).contains(&"default-test-runner"),
            "ci 不应有独立 nextest 步（已并入 coverage）"
        );
        let cov = plan
            .iter()
            .find(|s| s.label() == "coverage")
            .ok_or_else(|| anyhow::anyhow!("CompatibilityCi 缺 coverage 步"))?;
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
            .ok_or_else(|| anyhow::anyhow!("CompatibilityCi 缺 public-api 步"))?;
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
        let v = plan_for(PlanTarget::Verify);
        let c = plan_for(PlanTarget::CompatibilityCi);
        let find = |plan: &[Step], label: &str| plan.iter().find(|s| s.label() == label).cloned();
        for label in [
            "fmt",
            "contract-validate",
            "assembly-validate",
            "assembly-artifacts-check",
            "assembly-modules-check",
            "assembly-providers-check",
            "assembly-lock-check",
            "deployment-plan-check",
            "assembly-graph-check",
            "contract-breaking",
            "layer-deps",
            "shipped-feature-guard",
            "wsdeps-drift",
            "source-semantic-guard",
            "promtool-rules",
            "outbox-same-id-guard",
            "consistency-fixtures",
            "event-transport-guard",
            "inbox-cutover-guard",
            "dlx-lifecycle-funnel",
            "runtime-baseline",
            "runtime-root-guard",
            "runtime-env-guard",
            "runtime-deployment-spec",
            "runtime-deps-guard",
            "archrules",
            "codegen-check",
            "l2-assurance-check",
            "provider-capabilities-check",
            "localtx-coverage",
            "local-only-effects",
            "pdp-allow-guard",
            "contract-binding-guard",
            "schema-rls",
            "setlocal-funnel",
            "pg-tenant-tx-guard",
            "repo-scope-guard",
            "tenancy-closeout",
            "migrations-serial",
            "command-symmetry",
            "reconcile-outbox-command-guard",
            "defer-gate",
            "deny",
            "dylint",
        ] {
            assert_eq!(
                find(&v, label),
                find(&c, label),
                "共享门步 `{label}` 在 verify/ci 不一致（漂移）"
            );
        }
    }

    // ---- audit 精简供应链 lane（issue #1133；每日 cron advisory 刷新）----

    /// audit_plan 顺序与门集（单一事实源；scheduled lane 实跑顺序）：advisory-scoped deny + cargo-audit。
    /// 不含 licenses/bans——它们只随 Cargo.lock 变（= 随 PR 变），定时跑无增益；CompatibilityCi 已全查。
    #[test]
    fn audit_plan_order_and_count() {
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
    /// 定时刷新只查漏洞库，licenses/bans 留给 PR-triggered Shadow plan 的全量 `deny check`。
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

    /// cargo-audit 步在 CompatibilityCi 与 audit（定时 lane）里**逐字相同**（同一构造，不漂移）。
    #[test]
    fn cargo_audit_step_shared_between_ci_and_audit_verbatim() {
        let find = |plan: &[Step]| plan.iter().find(|s| s.label() == "audit").cloned();
        assert_eq!(
            find(&plan_for(PlanTarget::CompatibilityCi)),
            find(&audit_plan())
        );
        assert!(
            find(&plan_for(PlanTarget::CompatibilityCi)).is_some(),
            "CompatibilityCi 须含 audit 步"
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

    // ---- CI-ADAPTIVE-WORKFLOW-01：GitHub workflow 委托 typed dynamic matrix ----

    /// setup / workflow 安装步骤只允许 cargo 安装工具；`cargo xtask` 只能作为 lane 委托命令出现。
    const SETUP_CARGO_SUBCOMMANDS: &[&str] = &["install", "binstall"];

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

    fn command_key_and_rest(line: &str) -> Option<&str> {
        line.strip_prefix("- ")
            .map(str::trim)
            .unwrap_or(line)
            .strip_prefix("script:")
            .or_else(|| {
                line.strip_prefix("- ")
                    .map(str::trim)
                    .unwrap_or(line)
                    .strip_prefix("run:")
            })
            .map(str::trim)
    }

    fn is_yaml_block_scalar_marker(rest: &str) -> bool {
        matches!(rest, "|" | "|-" | "|+" | ">" | ">-" | ">+")
    }

    /// 抽出真实 `run:` / `script:` 命令；block scalar 保留命令体行，inline 命令保留冒号后的单行。
    fn yaml_command_scripts(yaml: &str) -> Vec<Vec<&str>> {
        let lines = yaml_indented_code_lines(yaml);
        let mut scripts = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let (indent, text) = lines[i];
            let Some(rest) = command_key_and_rest(text) else {
                i += 1;
                continue;
            };

            if is_yaml_block_scalar_marker(rest) {
                let mut body = Vec::new();
                let mut j = i + 1;
                while j < lines.len() {
                    let (body_indent, body_text) = lines[j];
                    if body_indent <= indent {
                        break;
                    }
                    body.push(body_text);
                    j += 1;
                }
                scripts.push(body);
                i = j;
            } else {
                scripts.push(vec![rest]);
                i += 1;
            }
        }
        scripts
    }

    fn cargo_subcommand(command: &str) -> Option<&str> {
        command
            .strip_prefix("cargo ")
            .and_then(|rest| rest.split_whitespace().next())
    }

    fn line_is_setup_cargo_command(line: &str) -> bool {
        let Some(sub) = cargo_subcommand(line) else {
            return !line.contains("cargo ");
        };
        SETUP_CARGO_SUBCOMMANDS.contains(&sub)
    }

    fn line_is_delegation_prologue(line: &str) -> bool {
        matches!(line, "set -euo pipefail")
    }

    fn command_script_is_setup_only(script: &[&str]) -> bool {
        script.iter().all(|line| {
            let line = line.trim();
            line.is_empty()
                || line_is_delegation_prologue(line)
                || line_is_setup_cargo_command(line)
        })
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

        fn with_exact(&self, key: &str, values: &[&str]) -> bool {
            let matches = self
                .with
                .iter()
                .filter(|(candidate, _)| candidate == key)
                .collect::<Vec<_>>();
            matches.len() == 1
                && matches[0].1.iter().map(String::as_str).collect::<Vec<_>>() == values
        }

        fn env_exact(&self, key: &str, values: &[&str]) -> bool {
            let matches = self
                .env
                .iter()
                .filter(|(candidate, _)| candidate == key)
                .collect::<Vec<_>>();
            matches.len() == 1
                && matches[0].1.iter().map(String::as_str).collect::<Vec<_>>() == values
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

        fn run_contains(&self, needle: &str) -> bool {
            self.run.iter().any(|line| line.contains(needle))
        }

        fn run_has_line(&self, expected: &str) -> bool {
            self.run.iter().any(|line| line == expected)
        }

        fn run_has_sequence(&self, expected: &[&str]) -> bool {
            self.run.windows(expected.len()).any(|window| {
                window
                    .iter()
                    .map(String::as_str)
                    .eq(expected.iter().copied())
            })
        }

        fn run_exact(&self, expected: &[&str]) -> bool {
            self.run
                .iter()
                .map(String::as_str)
                .eq(expected.iter().copied())
        }
    }

    fn workflow_ci_executor_owners(steps: &[TypedStep]) -> Vec<(Option<&str>, String)> {
        steps
            .iter()
            .flat_map(|step| {
                step.run.iter().filter_map(|line| {
                    let words = line
                        .split_whitespace()
                        .map(|word| word.trim_matches(|ch| matches!(ch, '\'' | '"' | ';')))
                        .collect::<Vec<_>>();
                    let mut command = None;
                    for (index, word) in words.iter().enumerate() {
                        if (*word == "cargo" || word.ends_with("hack/cargo.sh"))
                            && words.get(index + 1).copied() == Some("xtask")
                        {
                            command = words.get(index + 2).copied();
                            break;
                        }
                        if (*word == "cargo" || word.ends_with("hack/cargo.sh"))
                            && words.get(index + 1).copied() == Some("run")
                        {
                            let tail = &words[index + 2..];
                            if let Some(separator) = tail.iter().position(|word| *word == "--") {
                                let runner = &tail[..separator];
                                let targets_xtask = runner.windows(2).any(|window| {
                                    window == ["-p", "xtask"]
                                        || window == ["--package", "xtask"]
                                        || (window[0] == "--manifest-path"
                                            && workflow_xtask_manifest(window[1]))
                                }) || runner.iter().any(|argument| {
                                    matches!(*argument, "-pxtask" | "--package=xtask")
                                        || argument
                                            .strip_prefix("--manifest-path=")
                                            .is_some_and(workflow_xtask_manifest)
                                });
                                if targets_xtask {
                                    command = tail.get(separator + 1).copied();
                                    break;
                                }
                            }
                        }
                        if word.ends_with("/xtask") {
                            command = words.get(index + 1).copied();
                            break;
                        }
                    }
                    command
                        .filter(|command| {
                            *command == "ci" || *command == "audit" || command.starts_with("ci-")
                        })
                        .map(|command| (step.id.as_deref(), command.to_owned()))
                })
            })
            .collect()
    }

    fn workflow_xtask_manifest(path: &str) -> bool {
        path == "xtask/Cargo.toml" || path.ends_with("/xtask/Cargo.toml")
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
        const TYPED_COMMAND: &str = "cargo run --locked -p xtask -- ci run --job ci-local-only --required-evidence-output \"$(Agent.TempDirectory)/localonly-execution.json\"";

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
        const COMMAND: &str = "cargo run --locked -p xtask -- ci run --job ci-local-only --required-evidence-output \"$(Agent.TempDirectory)/localonly-execution.json\"";
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
                "wrong typed owner",
                green.replacen("--job ci-local-only", "--job ci-meta", 1),
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

    fn workflow_has_exact_read_permissions(yaml: &str) -> bool {
        let lines = yaml_indented_code_lines(yaml);
        let Some(start) = lines
            .iter()
            .position(|(indent, line)| *indent == 0 && *line == "permissions:")
        else {
            return false;
        };
        let fields = lines[start + 1..]
            .iter()
            .take_while(|(indent, _)| *indent > 0)
            .collect::<Vec<_>>();
        fields.len() == 1 && fields[0] == &(2, "contents: read")
    }

    fn workflow_event_has_exact_branches(
        lines: &[(usize, &str)],
        event: &str,
        expected: &[&str],
    ) -> bool {
        let event_key = format!("{event}:");
        let Some((event_idx, event_indent)) =
            lines.iter().enumerate().find_map(|(idx, (indent, line))| {
                (*indent == 2 && *line == event_key).then_some((idx, *indent))
            })
        else {
            return false;
        };
        let body = lines[event_idx + 1..]
            .iter()
            .take_while(|(indent, _)| *indent > event_indent)
            .copied()
            .collect::<Vec<_>>();
        let Some((field_indent, field)) = body.first().copied() else {
            return false;
        };
        if field_indent != event_indent + 2 {
            return false;
        }
        let Some(value) = field.strip_prefix("branches:") else {
            return false;
        };
        let value = value.trim();
        let actual = if let Some(inline) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']'))
        {
            if body.len() != 1 {
                return false;
            }
            inline
                .split(',')
                .map(|item| item.trim().trim_matches(|c| c == '"' || c == '\''))
                .collect::<Vec<_>>()
        } else if value.is_empty() {
            let mut items = Vec::new();
            for (indent, line) in &body[1..] {
                if *indent != field_indent + 2 {
                    return false;
                }
                let Some(item) = line.strip_prefix("- ") else {
                    return false;
                };
                items.push(item.trim().trim_matches(|c| c == '"' || c == '\''));
            }
            items
        } else {
            return false;
        };
        actual == expected
    }

    fn workflow_dispatch_is_empty(lines: &[(usize, &str)]) -> bool {
        let Some((event_idx, event_indent)) =
            lines.iter().enumerate().find_map(|(idx, (indent, line))| {
                (*indent == 2 && *line == "workflow_dispatch:").then_some((idx, *indent))
            })
        else {
            return false;
        };
        lines[event_idx + 1..]
            .first()
            .is_none_or(|(indent, _)| *indent <= event_indent)
    }

    fn workflow_has_only_safe_ci_events(yaml: &str) -> bool {
        let lines = yaml_indented_code_lines(yaml);
        let Some(start) = lines
            .iter()
            .position(|(indent, line)| *indent == 0 && *line == "on:")
        else {
            return false;
        };
        let on_body = lines[start + 1..]
            .iter()
            .take_while(|(indent, _)| *indent > 0)
            .copied()
            .collect::<Vec<_>>();
        let mut events = on_body
            .iter()
            .filter_map(|(indent, line)| (*indent == 2).then_some(*line))
            .collect::<Vec<_>>();
        events.sort_unstable();
        events == ["pull_request:", "push:", "schedule:", "workflow_dispatch:"]
            && workflow_event_has_exact_branches(&on_body, "pull_request", &["develop"])
            && workflow_event_has_exact_branches(
                &on_body,
                "push",
                &["develop", "codex/**", "feature/**", "fix/**"],
            )
            && on_body.contains(&(4, "- cron: \"0 6 * * *\""))
            && workflow_dispatch_is_empty(&on_body)
    }

    fn workflow_has_pr_only_concurrency(yaml: &str) -> bool {
        let lines = yaml_indented_code_lines(yaml);
        let Some(start) = lines
            .iter()
            .position(|(indent, line)| *indent == 0 && *line == "concurrency:")
        else {
            return false;
        };
        let fields = lines[start + 1..]
            .iter()
            .take_while(|(indent, _)| *indent > 0)
            .copied()
            .collect::<Vec<_>>();
        fields
            == [
                (
                    2,
                    "group: rss-ci-${{ github.event_name }}-${{ github.event.pull_request.number || github.ref }}",
                ),
                (
                    2,
                    "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
                ),
            ]
    }

    fn root_mapping_has_exact_entries(yaml: &str, mapping: &str, expected: &[&str]) -> bool {
        let lines = yaml_indented_code_lines(yaml);
        let marker = format!("{mapping}:");
        let Some(start) = lines
            .iter()
            .position(|(indent, line)| *indent == 0 && *line == marker)
        else {
            return false;
        };
        let entries = lines[start + 1..]
            .iter()
            .take_while(|(indent, _)| *indent > 0)
            .filter_map(|(indent, line)| (*indent == 2).then_some(*line))
            .collect::<Vec<_>>();
        expected.iter().all(|expected| {
            let Some((key, _)) = expected.split_once(':') else {
                return false;
            };
            entries
                .iter()
                .filter(|entry| {
                    entry
                        .split_once(':')
                        .is_some_and(|(entry_key, _)| entry_key == key)
                })
                .copied()
                .eq([*expected])
        })
    }

    fn caller_steps_are_closed(yaml: &str) -> bool {
        let steps = yaml_typed_steps(yaml);
        let names = steps
            .iter()
            .map(|step| step.name.as_deref())
            .collect::<Vec<_>>();
        if names
            != [
                Some("Checkout execution revision"),
                Some("Build typed CI impact plan"),
                Some("Generate LocalTx proof report"),
                Some("Upload typed plan"),
                Some("Upload LocalTx proof report"),
                Some("Generate assembly artifact matrix"),
                Some("Upload assembly artifact matrix"),
                Some("Checkout scheduled audit revision"),
                Some("Setup scheduled audit tools"),
                Some("Scan prose for stale governance claims (advisory)"),
                Some("Run scheduled audit fallback"),
                Some("Checkout gate implementation"),
                Some("Download typed plan"),
                Some("Download closed job receipts"),
                Some("Verify plan, matrix result, and exact receipts"),
                Some("Upload aggregate CI metrics"),
            ]
        {
            return false;
        }
        let plan_checkout = &steps[0];
        let planner = &steps[1];
        let proof_generator = &steps[2];
        let plan_upload = &steps[3];
        let proof_upload = &steps[4];
        let artifact_generator = &steps[5];
        let artifact_upload = &steps[6];
        let gate_checkout = &steps[11];
        let plan_download = &steps[12];
        let receipt_download = &steps[13];
        let gate = &steps[14];
        let metrics_upload = &steps[15];

        let checkout = |step: &TypedStep, depth: &str| {
            step.uses.as_deref() == Some("actions/checkout@v4")
                && step.with_exact("persist-credentials", &["false"])
                && step.with_exact("fetch-depth", &[depth])
                && step.with_exact("ref", &["${{ github.sha }}"])
        };
        checkout(plan_checkout, "0")
            && checkout(gate_checkout, "1")
            && planner.id.as_deref() == Some("plan")
            && planner.env_exact("RSS_CI_FORCE_FULL", &["${{ vars.RSS_CI_FORCE_FULL }}"])
            && planner.run_exact(&[
                "set -euo pipefail",
                "mkdir -p target/ci-impact",
                "cargo run --locked -p xtask -- ci plan \\",
                "--event-path \"$GITHUB_EVENT_PATH\" \\",
                "--policy .config/ci-impact.toml \\",
                "--output target/ci-impact/ci-plan.json \\",
                "--github-output \"$GITHUB_OUTPUT\"",
            ])
            && artifact_generator.id.is_none()
            && artifact_generator.uses.is_none()
            && artifact_generator.if_expr.is_none()
            && artifact_generator.continue_on_error.is_none()
            && artifact_generator.timeout_minutes.is_none()
            && artifact_generator.with.is_empty()
            && artifact_generator.env.is_empty()
            && artifact_generator.run_exact(&[
                "set -euo pipefail",
                "rm -rf target/assembly-artifacts target/assembly-artifacts.tmp",
                "mkdir -p target/assembly-artifacts.tmp",
                "set +e",
                "cargo run --locked -p xtask -- assembly artifacts check > target/assembly-artifacts.tmp/assembly-artifacts.md",
                "status=$?",
                "set -e",
                "mv target/assembly-artifacts.tmp target/assembly-artifacts",
                "exit \"$status\"",
            ])
            && proof_generator.id.is_none()
            && proof_generator.uses.is_none()
            && proof_generator.if_expr.is_none()
            && proof_generator.continue_on_error.is_none()
            && proof_generator.timeout_minutes.is_none()
            && proof_generator.with.is_empty()
            && proof_generator.env.is_empty()
            && proof_generator.run_exact(&[
                "set -euo pipefail",
                "rm -rf target/localtx-proof target/localtx-proof.tmp",
                "mkdir -p target/localtx-proof.tmp",
                "cargo run --locked -p xtask -- localtx report --format json > target/localtx-proof.tmp/localtx-proof.json",
                "cargo run --locked -p xtask -- localtx report --format markdown > target/localtx-proof.tmp/localtx-proof.md",
                "mv target/localtx-proof.tmp target/localtx-proof",
            ])
            && plan_upload.if_expr.as_deref() == Some("${{ always() }}")
            && plan_upload.uses.as_deref() == Some("actions/upload-artifact@v4")
            && plan_upload.with_exact(
                "name",
                &["ci-impact-plan-${{ github.run_id }}-${{ github.run_attempt }}"],
            )
            && plan_upload.with_exact("path", &["target/ci-impact/ci-plan.json"])
            && plan_upload.with_exact("if-no-files-found", &["warn"])
            && plan_upload.with_exact("retention-days", &["30"])
            && artifact_upload.id.is_none()
            && artifact_upload.if_expr.as_deref() == Some("${{ always() }}")
            && artifact_upload.uses.as_deref() == Some("actions/upload-artifact@v4")
            && artifact_upload.continue_on_error.is_none()
            && artifact_upload.timeout_minutes.is_none()
            && artifact_upload.env.is_empty()
            && artifact_upload.run.is_empty()
            && artifact_upload.with.len() == 4
            && artifact_upload.with_exact(
                "name",
                &["assembly-artifacts-${{ github.run_id }}-${{ github.run_attempt }}"],
            )
            && artifact_upload.with_exact(
                "path",
                &["target/assembly-artifacts/assembly-artifacts.md"],
            )
            && artifact_upload.with_exact("if-no-files-found", &["error"])
            && artifact_upload.with_exact("retention-days", &["30"])
            && proof_upload.id.is_none()
            && proof_upload.if_expr.as_deref() == Some("${{ always() }}")
            && proof_upload.uses.as_deref() == Some("actions/upload-artifact@v4")
            && proof_upload.continue_on_error.is_none()
            && proof_upload.timeout_minutes.is_none()
            && proof_upload.env.is_empty()
            && proof_upload.run.is_empty()
            && proof_upload.with.len() == 4
            && proof_upload.with_exact(
                "name",
                &["localtx-proof-${{ github.run_id }}-${{ github.run_attempt }}"],
            )
            && proof_upload.with_exact("path", &["target/localtx-proof"])
            && proof_upload.with_exact("if-no-files-found", &["error"])
            && proof_upload.with_exact("retention-days", &["30"])
            && plan_download.continue_on_error.as_deref() == Some("true")
            && plan_download.uses.as_deref() == Some("actions/download-artifact@v4")
            && plan_download.with_exact(
                "name",
                &["ci-impact-plan-${{ github.run_id }}-${{ github.run_attempt }}"],
            )
            && plan_download.with_exact("path", &["target/ci-plan-download"])
            && receipt_download.continue_on_error.as_deref() == Some("true")
            && receipt_download.uses.as_deref() == Some("actions/download-artifact@v4")
            && receipt_download.with_exact(
                "pattern",
                &["ci-evidence-*-${{ github.run_id }}-${{ github.run_attempt }}"],
            )
            && receipt_download.with_exact("path", &["target/ci-receipts"])
            && receipt_download.with_exact("merge-multiple", &["false"])
            && gate.if_expr.as_deref() == Some("${{ always() }}")
            && gate.run_exact(&[
                "set -euo pipefail",
                "cargo run --locked -p xtask -- ci gate \\",
                "--plan target/ci-plan-download/ci-plan.json \\",
                "--receipts target/ci-receipts \\",
                "--planner-result \"${{ needs.ci-plan.result }}\" \\",
                "--matrix-result \"${{ needs.execute.result }}\" \\",
                "--metrics-output target/ci-gate-metrics.json",
            ])
            && metrics_upload.if_expr.as_deref() == Some("${{ always() }}")
            && metrics_upload.uses.as_deref() == Some("actions/upload-artifact@v4")
            && metrics_upload.with_exact(
                "name",
                &["ci-impact-metrics-${{ github.run_id }}-${{ github.run_attempt }}"],
            )
            && metrics_upload.with_exact("path", &["target/ci-gate-metrics.json"])
            && metrics_upload.with_exact("if-no-files-found", &["error"])
            && metrics_upload.with_exact("retention-days", &["30"])
    }

    fn dynamic_execute_job_is_closed(yaml: &str) -> bool {
        let lines = yaml_indented_code_lines(yaml);
        let Some(jobs) = lines
            .iter()
            .position(|(indent, line)| *indent == 0 && *line == "jobs:")
        else {
            return false;
        };
        let Some(execute) = lines[jobs + 1..]
            .iter()
            .position(|(indent, line)| *indent == 2 && *line == "execute:")
            .map(|offset| jobs + 1 + offset)
        else {
            return false;
        };
        let body = lines[execute + 1..]
            .iter()
            .take_while(|(indent, _)| *indent > 2)
            .copied()
            .collect::<Vec<_>>();
        let direct = body
            .iter()
            .filter_map(|(indent, line)| (*indent == 4).then_some(*line))
            .collect::<Vec<_>>();
        let nested = body
            .iter()
            .filter_map(|(indent, line)| (*indent == 6).then_some(*line))
            .collect::<Vec<_>>();
        direct
            == [
                "name: ${{ matrix.displayName }}",
                "needs: ci-plan",
                "strategy:",
                "uses: ./.github/workflows/rss-rust-lane.yml",
                "with:",
            ]
            && nested
                == [
                    "fail-fast: false",
                    "matrix: ${{ fromJSON(needs.ci-plan.outputs.matrix) }}",
                    "ci-job-key: ${{ matrix.jobKey }}",
                    "plan-digest: ${{ matrix.planDigest }}",
                    "source-revision: ${{ matrix.sourceRevision }}",
                    "lane: ${{ matrix.lane }}",
                    "shard: ${{ matrix.shard || '' }}",
                    "partition: ${{ matrix.partition || '' }}",
                    "partition-label: ${{ matrix.partitionLabel }}",
                    "required-evidence-target: ${{ matrix.requiredEvidenceTarget || '' }}",
                ]
    }

    fn workflow_job_body<'a>(yaml: &'a str, job: &str) -> Option<Vec<(usize, &'a str)>> {
        let lines = yaml_indented_code_lines(yaml);
        let jobs = lines
            .iter()
            .position(|(indent, line)| *indent == 0 && *line == "jobs:")?;
        let marker = format!("{job}:");
        let start = lines[jobs + 1..]
            .iter()
            .position(|(indent, line)| *indent == 2 && *line == marker)
            .map(|offset| jobs + 1 + offset)?;
        Some(
            lines[start + 1..]
                .iter()
                .take_while(|(indent, _)| *indent > 2)
                .copied()
                .collect(),
        )
    }

    fn direct_job_fields<'a>(body: &[(usize, &'a str)]) -> Vec<&'a str> {
        body.iter()
            .filter_map(|(indent, line)| (*indent == 4).then_some(*line))
            .collect()
    }

    fn planner_and_gate_jobs_are_closed(yaml: &str) -> bool {
        let Some(plan) = workflow_job_body(yaml, "ci-plan") else {
            return false;
        };
        let Some(gate) = workflow_job_body(yaml, "ci-gate") else {
            return false;
        };
        let Some(outputs) = plan
            .iter()
            .position(|(indent, line)| *indent == 4 && *line == "outputs:")
        else {
            return false;
        };
        let output_entries = plan[outputs + 1..]
            .iter()
            .take_while(|(indent, _)| *indent > 4)
            .filter_map(|(indent, line)| (*indent == 6).then_some(*line))
            .collect::<Vec<_>>();
        direct_job_fields(&plan)
            == [
                "name: ci-plan",
                "runs-on: ubuntu-latest",
                "timeout-minutes: 15",
                "outputs:",
                "steps:",
            ]
            && output_entries
                == [
                    "matrix: ${{ steps.plan.outputs.matrix }}",
                    "plan-digest: ${{ steps.plan.outputs.plan-digest }}",
                    "policy-version: ${{ steps.plan.outputs.policy-version }}",
                    "decision-kind: ${{ steps.plan.outputs.decision-kind }}",
                    "full-fallback: ${{ steps.plan.outputs.full-fallback }}",
                    "recommended-count: ${{ steps.plan.outputs.recommended-count }}",
                    "executed-count: ${{ steps.plan.outputs.executed-count }}",
                ]
            && direct_job_fields(&gate)
                == [
                    "name: ci-gate",
                    "if: ${{ always() }}",
                    "needs: [ci-plan, execute]",
                    "runs-on: ubuntu-latest",
                    "timeout-minutes: 20",
                    "steps:",
                ]
    }

    fn scheduled_audit_fallback_is_closed(yaml: &str) -> bool {
        let Some(body) = workflow_job_body(yaml, "scheduled-audit-fallback") else {
            return false;
        };
        if direct_job_fields(&body)
            != [
                "name: scheduled-audit-fallback",
                "if: ${{ always() && github.event_name == 'schedule' && needs.ci-plan.result != 'success' }}",
                "needs: ci-plan",
                "runs-on: ubuntu-latest",
                "timeout-minutes: 120",
                "steps:",
            ]
        {
            return false;
        }
        let steps = typed_steps_in_lines(&body);
        if steps
            .iter()
            .map(|step| step.name.as_deref())
            .collect::<Vec<_>>()
            != [
                Some("Checkout scheduled audit revision"),
                Some("Setup scheduled audit tools"),
                Some("Scan prose for stale governance claims (advisory)"),
                Some("Run scheduled audit fallback"),
            ]
        {
            return false;
        }
        let checkout = &steps[0];
        let setup = &steps[1];
        let advisory = &steps[2];
        let audit = &steps[3];
        checkout.uses.as_deref() == Some("actions/checkout@v4")
            && checkout.with.len() == 3
            && checkout.with_exact("persist-credentials", &["false"])
            && checkout.with_exact("fetch-depth", &["1"])
            && checkout.with_exact("ref", &["${{ github.sha }}"])
            && setup.uses.as_deref() == Some("./.github/actions/setup-rss-ci")
            && setup.with.len() == 7
            && setup.with_exact("lane", &["audit"])
            && setup.with_exact("profile", &["audit"])
            && setup.with_exact("toolchain", &["1.96.0"])
            && setup.with_exact("nightly", &["\"\""])
            && setup.with_exact("tool-cache-epoch", &["v4"])
            && setup.with_exact("writer-mode", &["false"])
            && setup.with_exact("evidence-enabled", &["false"])
            && advisory.fields_exact(&["name", "continue-on-error", "run"])
            && advisory.continue_on_error.as_deref() == Some("true")
            && advisory.run_exact(&["bash hack/automation/prose-advisory-scan.sh scan"])
            && audit.run_exact(&[
                "set -euo pipefail",
                "cargo run --locked -p xtask -- ci run --job audit",
            ])
    }

    fn scheduled_prose_advisory_is_closed(caller_yaml: &str, reusable_yaml: &str) -> bool {
        let reusable_matches = yaml_typed_steps(reusable_yaml)
            .into_iter()
            .filter(|step| {
                step.name.as_deref() == Some("Scan prose for stale governance claims (advisory)")
            })
            .collect::<Vec<_>>();
        scheduled_audit_fallback_is_closed(caller_yaml)
            && reusable_matches.len() == 1
            && reusable_matches[0].fields_exact(&["name", "if", "continue-on-error", "run"])
            && reusable_matches[0].if_expr.as_deref()
                == Some("${{ github.event_name == 'schedule' && inputs.lane == 'audit' }}")
            && reusable_matches[0].continue_on_error.as_deref() == Some("true")
            && reusable_matches[0].run_exact(&["bash hack/automation/prose-advisory-scan.sh scan"])
    }

    /// CI caller 的结构化闭集谓词：唯一 planner → typed dynamic matrix → always aggregate gate。
    fn pipeline_delegates_to_xtask_ci(yaml: &str) -> bool {
        let lines = yaml_indented_code_lines(yaml);
        let Some(jobs_start) = lines
            .iter()
            .position(|(indent, line)| *indent == 0 && *line == "jobs:")
        else {
            return false;
        };
        let jobs = lines[jobs_start + 1..]
            .iter()
            .filter_map(|(indent, line)| (*indent == 2).then(|| line.strip_suffix(':')).flatten())
            .collect::<Vec<_>>();
        workflow_has_only_safe_ci_events(yaml)
            && workflow_has_exact_read_permissions(yaml)
            && workflow_has_pr_only_concurrency(yaml)
            && jobs
                == [
                    "ci-plan",
                    "execute",
                    "scheduled-audit-fallback",
                    "ci-gate",
                ]
            && caller_steps_are_closed(yaml)
            && dynamic_execute_job_is_closed(yaml)
            && planner_and_gate_jobs_are_closed(yaml)
            && scheduled_audit_fallback_is_closed(yaml)
            && yaml.matches("fromJSON(needs.ci-plan.outputs.matrix)").count() == 1
            && yaml.matches("uses: ./.github/workflows/rss-rust-lane.yml").count() == 1
            && yaml.contains("cargo run --locked -p xtask -- ci plan")
            && yaml.contains("--policy .config/ci-impact.toml")
            && yaml.contains("RSS_CI_FORCE_FULL: ${{ vars.RSS_CI_FORCE_FULL }}")
            && yaml.contains("ci-job-key: ${{ matrix.jobKey }}")
            && yaml.contains("plan-digest: ${{ matrix.planDigest }}")
            && yaml.contains("source-revision: ${{ matrix.sourceRevision }}")
            && yaml.contains("lane: ${{ matrix.lane }}")
            && yaml.contains("shard: ${{ matrix.shard || '' }}")
            && yaml.contains("partition: ${{ matrix.partition || '' }}")
            && yaml.contains("partition-label: ${{ matrix.partitionLabel }}")
            && yaml.contains("required-evidence-target: ${{ matrix.requiredEvidenceTarget || '' }}")
            && yaml.contains("  ci-gate:\n    name: ci-gate\n    if: ${{ always() }}\n    needs: [ci-plan, execute]")
            && yaml.contains("cargo run --locked -p xtask -- ci gate")
            && yaml.contains("--planner-result \"${{ needs.ci-plan.result }}\"")
            && yaml.contains("--matrix-result \"${{ needs.execute.result }}\"")
            && yaml.contains("--metrics-output target/ci-gate-metrics.json")
            && yaml.contains("name: ci-impact-metrics-${{ github.run_id }}-${{ github.run_attempt }}")
            && !yaml.contains("pull_request_target")
            && !yaml.contains("paths:")
            && !yaml.contains("paths-ignore:")
            && !yaml.contains("id-token: write")
            && !yaml.contains("contents: write")
            && !yaml.contains("matrix:\n        include:")
            && !lines
                .iter()
                .any(|(indent, line)| *indent == 0 && matches!(*line, "env:" | "steps:"))
    }

    /// 被 workflow 引用的本地 composite action 也是 CI 执行面。setup action 只能安装工具，不得把 build /
    /// clippy / nextest / coverage / public-api 等门命令搬进去绕过 workflow 委托守卫。
    fn setup_action_contains_only_setup_cargo_commands(yaml: &str) -> bool {
        yaml_command_scripts(yaml)
            .iter()
            .all(|script| command_script_is_setup_only(script))
    }

    /// CI-TOOL-ADAPTER-01 的 Medium 结构谓词。工具集内容由 shell adapter 运行时派生；
    /// 此处只锁定 GitHub 边界的单源连接、immutable identity 与验证顺序。
    fn ci_tool_adapter_contract_is_hardened(
        reusable_yaml: &str,
        action_yaml: &str,
        adapter_source: &str,
    ) -> bool {
        const INSTALL_ACTION_SHA: &str = "b8cecb83565409bcc297b2df6e77f030b2a468d5";
        const TOOL_LIST_MARKERS: &[&str] = &[
            "cargo-nextest@",
            "cargo-llvm-cov@",
            "cargo-deny@",
            "cargo-audit@",
            "cargo-dylint@",
            "dylint-link@",
            "cargo-public-api@",
        ];

        let reusable_lines = yaml_indented_code_lines(reusable_yaml);
        let reusable_steps = yaml_typed_steps(reusable_yaml);
        let action_lines = yaml_indented_code_lines(action_yaml);
        let action_steps = yaml_typed_steps(action_yaml);
        let unique_step = |steps: &[TypedStep], id: &str| {
            let matches = steps
                .iter()
                .enumerate()
                .filter_map(|(index, step)| (step.id.as_deref() == Some(id)).then_some(index))
                .collect::<Vec<_>>();
            (matches.len() == 1).then(|| matches[0])
        };
        let unique_named_step = |steps: &[TypedStep], name: &str| {
            let matches = steps
                .iter()
                .enumerate()
                .filter_map(|(index, step)| (step.name.as_deref() == Some(name)).then_some(index))
                .collect::<Vec<_>>();
            (matches.len() == 1).then(|| matches[0])
        };

        let workflow_has_no_tool_catalog = !reusable_yaml.contains("prebuilt-tools")
            && !reusable_yaml.contains("fallback-tools")
            && !TOOL_LIST_MARKERS
                .iter()
                .any(|marker| reusable_yaml.contains(marker));
        let action_has_no_arbitrary_tool_inputs = action_lines.iter().all(|(indent, line)| {
            !(*indent == 2
                && line.ends_with(':')
                && matches!(
                    line.trim_end_matches(':'),
                    "prebuilt-tools" | "fallback-tools" | "tools" | "tool-specs"
                ))
        });
        let action_has_no_copied_catalog = !TOOL_LIST_MARKERS
            .iter()
            .any(|marker| action_yaml.contains(marker));

        let setup = unique_step(&reusable_steps, "setup");
        let measure = unique_step(&reusable_steps, "measure-tools");
        let save = unique_step(&reusable_steps, "save-tools");
        let reusable_order_and_epoch = setup.is_some_and(|index| {
            reusable_steps[index].with_exact("tool-cache-epoch", &["v4"])
                && reusable_steps.iter().enumerate().all(|(candidate, step)| {
                    step.uses.as_deref() != Some("actions/cache/save@v4") || index < candidate
                })
                && measure.is_some_and(|measure_index| {
                    reusable_steps[measure_index].run_contains(".rss-tool-seal-v1")
                        && save.is_some_and(|save_index| {
                            index < measure_index && measure_index < save_index
                        })
                })
        });

        let policy = unique_step(&action_steps, "tool-policy");
        let cache_keys = unique_step(&action_steps, "cache-keys");
        let verifiers = action_steps
            .iter()
            .enumerate()
            .filter_map(|(index, step)| {
                step.run_contains(".github/scripts/ci-tool-adapters.sh verify")
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        let install_action = action_steps
            .iter()
            .enumerate()
            .filter_map(|(index, step)| {
                step.uses
                    .as_deref()
                    .is_some_and(|uses| {
                        uses == format!("taiki-e/install-action@{INSTALL_ACTION_SHA}")
                    })
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        let immutable_installer_is_single_and_keyed = install_action.len() == 1
            && action_yaml
                .matches(&format!("taiki-e/install-action@{INSTALL_ACTION_SHA}"))
                .count()
                == 2
            && cache_keys.is_some_and(|index| {
                let step = &action_steps[index];
                step.env_exact(
                    "RSS_ADAPTER_SHA256",
                    &["${{ steps.tool-policy.outputs.adapter-sha256 }}"],
                ) && step.env_exact(
                    "RSS_CATALOG_SHA256",
                    &["${{ steps.tool-policy.outputs.catalog-sha256 }}"],
                ) && step.env_exact(
                    "RSS_INSTALL_ACTION_TOOLS",
                    &["${{ steps.tool-policy.outputs.install-action-tools }}"],
                ) && step.env_exact(
                    "RSS_BINSTALL_TOOLS",
                    &["${{ steps.tool-policy.outputs.binstall-tools }}"],
                ) && step.run_contains("tools_hash=")
                    && step.run_contains(&format!("taiki-e/install-action@{INSTALL_ACTION_SHA}"))
                    && step.run_contains("RSS_ADAPTER_SHA256")
                    && step.run_contains("RSS_CATALOG_SHA256")
                    && step.run_contains("sha256")
                    && step.run_contains("RSS_INSTALL_ACTION_TOOLS")
                    && step.run_contains("RSS_BINSTALL_TOOLS")
            });
        let catalog_is_executable_single_source = policy.is_some_and(|index| {
            let step = &action_steps[index];
            step.run_contains(".github/scripts/ci-tool-adapters.sh specs")
                && step.run_contains("--lane")
                && step.run_contains("--backend install-action")
                && step.run_contains("--backend binstall")
                && step.run_contains("adapter-sha256")
                && step.run_contains("catalog-sha256")
        });
        let verifier_precedes_path =
            (verifiers.len() == 1)
                .then_some(verifiers[0])
                .is_some_and(|index| {
                    let run = &action_steps[index].run;
                    let verify = run
                        .iter()
                        .position(|line| line.contains("ci-tool-adapters.sh verify"));
                    let first_path = run.iter().position(|line| line.contains("GITHUB_PATH"));
                    matches!((verify, first_path), (Some(a), Some(b)) if a < b)
                        && run.iter().any(|line| line.contains("mode=fresh"))
                        && run.iter().any(|line| line.contains("mode=cache"))
                        && run.iter().any(|line| {
                            line.contains("--mode \"$mode\"")
                                && line.contains("--lane \"$RSS_LANE\"")
                                && line.contains("--root \"$RSS_TOOL_ROOT\"")
                        })
                });
        let adapter_binds_its_content_to_seal = adapter_source.contains(".rss-tool-seal-v1")
            && adapter_source.contains("adapter-sha256")
            && adapter_source.contains("catalog-sha256")
            && adapter_source.contains("sha256sum");
        let fallback_installer_precedes_prebuilt_and_verify =
            unique_named_step(&action_steps, "Install fallback tools").is_some_and(|fallback| {
                install_action
                    .first()
                    .copied()
                    .zip(verifiers.first().copied())
                    .is_some_and(|(prebuilt, verify)| fallback < prebuilt && prebuilt < verify)
            });

        workflow_has_no_tool_catalog
            && action_has_no_arbitrary_tool_inputs
            && action_has_no_copied_catalog
            && reusable_lines
                .iter()
                .filter(|(indent, line)| *indent == 0 && *line == "jobs:")
                .count()
                == 1
            && reusable_order_and_epoch
            && immutable_installer_is_single_and_keyed
            && catalog_is_executable_single_source
            && verifier_precedes_path
            && fallback_installer_precedes_prebuilt_and_verify
            && adapter_binds_its_content_to_seal
    }

    /// 真实 committed 执行面：planner、动态 executor、定时审计 fallback 与 aggregate gate 闭合；
    /// lane 生命周期只存在于 reusable workflow。
    #[test]
    fn github_resource_evidence_workflows_have_lifecycle() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let ci_path = root.join(".github/workflows/ci.yml");
        let ci_yaml = std::fs::read_to_string(&ci_path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", ci_path.display()))?;
        assert!(
            pipeline_delegates_to_xtask_ci(&ci_yaml),
            "{} 须以 planner、typed dynamic matrix、定时审计 fallback 与稳定 gate 调用唯一 reusable workflow",
            ci_path.display()
        );
        for removed in ["integration.yml", "audit.yml"] {
            let path = root.join(".github/workflows").join(removed);
            assert!(
                !path.exists(),
                "{} 已由 typed dynamic matrix 取代，不得保留双轨",
                path.display()
            );
        }
        let reusable_path = root.join(".github/workflows/rss-rust-lane.yml");
        let reusable = std::fs::read_to_string(&reusable_path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", reusable_path.display()))?;
        assert!(
            reusable_rust_lane_is_hardened(&reusable),
            "{} 须闭合 lane/writer 并保持 tool-before-xtask、build-after-xtask lifecycle",
            reusable_path.display()
        );
        assert!(
            integration_service_lifecycle_is_hardened(&reusable),
            "{} 须保持 integration-only prepare/collect/cleanup 与 evidence 拓扑",
            reusable_path.display()
        );
        let container_path = root.join("crates/testkit/src/containers.rs");
        let container_source = std::fs::read_to_string(&container_path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", container_path.display()))?;
        let lifecycle_path = root.join(".github/scripts/integration-services.sh");
        let lifecycle_source = std::fs::read_to_string(&lifecycle_path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", lifecycle_path.display()))?;
        let (workspace_rust_sources, workspace_manifests) =
            integration_container_workspace_inputs(&root)?;
        let rust_refs = workspace_rust_sources
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect::<Vec<_>>();
        let manifest_refs = workspace_manifests
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect::<Vec<_>>();
        assert!(
            integration_container_workspace_contract_is_hardened(
                &container_source,
                &lifecycle_source,
                &reusable,
                &rust_refs,
                &manifest_refs,
            ),
            "testkit container funnel 须与 lifecycle shell/workflow 的 env、label、service、partition 契约闭合"
        );
        let action_path = root.join(".github/actions/setup-rss-ci/action.yml");
        let action_yaml = std::fs::read_to_string(&action_path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", action_path.display()))?;
        assert!(
            setup_action_has_exact_split_cache_contract(&action_yaml),
            "{} 须用三个隔离 restore 与 exact cache contract",
            action_path.display()
        );

        Ok(())
    }

    /// Shell selftest 进入 workspace test / verify 执行面，避免只在人工命令中运行。
    #[test]
    fn ci_evidence_shell_selftest_passes() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let status = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::Bash,
            &[".github/scripts/ci-evidence.selftest.sh"],
            &[],
            Some(&root),
        )
        .status()
        .map_err(|e| anyhow::anyhow!("启动 ci-evidence shell selftest 失败: {e}"))?;
        assert!(status.success(), "ci-evidence shell selftest 必须通过");
        Ok(())
    }

    #[test]
    fn ci_sccache_stats_shell_selftest_passes() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let status = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::Bash,
            &[".github/scripts/ci-sccache-stats.selftest.sh"],
            &[],
            Some(&root),
        )
        .status()
        .map_err(|e| anyhow::anyhow!("启动 ci-sccache-stats shell selftest 失败: {e}"))?;
        assert!(status.success(), "ci-sccache-stats shell selftest 必须通过");
        Ok(())
    }

    #[test]
    fn ci_cache_maintenance_shell_selftest_passes() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let status = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::Bash,
            &[".github/scripts/ci-cache-maintain.selftest.sh"],
            &[],
            Some(&root),
        )
        .status()
        .map_err(|e| anyhow::anyhow!("启动 ci-cache-maintain shell selftest 失败: {e}"))?;
        assert!(
            status.success(),
            "ci-cache-maintain shell selftest 必须通过"
        );
        Ok(())
    }

    #[test]
    fn cargo_target_isolation_shell_selftest_passes() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let status = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::Bash,
            &["hack/cargo.selftest.sh"],
            &[],
            Some(&root),
        )
        .status()
        .map_err(|e| anyhow::anyhow!("启动 cargo target isolation shell selftest 失败: {e}"))?;
        assert!(
            status.success(),
            "cargo target isolation shell selftest 必须通过"
        );
        Ok(())
    }

    /// Adapter catalog 是 CI 工具协议的单一事实源；其真实 probe、seal 与 cache-hit
    /// fail-closed 矩阵必须进入 workspace test/verify 执行面。
    #[test]
    fn ci_tool_adapter_shell_selftest_passes() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let status = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::Bash,
            &[".github/scripts/ci-tool-adapters.selftest.sh"],
            &[],
            Some(&root),
        )
        .status()
        .map_err(|e| anyhow::anyhow!("启动 ci-tool-adapters shell selftest 失败: {e}"))?;
        assert!(status.success(), "ci-tool-adapters shell selftest 必须通过");
        Ok(())
    }

    #[test]
    fn ci_cache_result_shell_selftest_passes() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let status = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::Bash,
            &[".github/scripts/ci-cache-result.selftest.sh"],
            &[],
            Some(&root),
        )
        .status()
        .map_err(|e| anyhow::anyhow!("启动 ci-cache-result shell selftest 失败: {e}"))?;
        assert!(status.success(), "ci-cache-result shell selftest 必须通过");
        Ok(())
    }

    /// Docker facade selftest 进入 verify 执行面，锁定 exact-label discovery、re-inspect、
    /// bounded failure archive、幂等与 partial-failure 语义。
    #[test]
    fn integration_service_lifecycle_shell_selftest_passes() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let status = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::Bash,
            &[".github/scripts/integration-services.selftest.sh"],
            &[],
            Some(&root),
        )
        .status()
        .map_err(|e| anyhow::anyhow!("启动 integration-services shell selftest 失败: {e}"))?;
        assert!(
            status.success(),
            "integration-services shell selftest 必须通过"
        );
        Ok(())
    }

    fn split_ci_caller_fixture() -> &'static str {
        include_str!("../../.github/workflows/ci.yml")
    }

    #[test]
    fn split_ci_caller_predicate_green_and_synthetic_red() -> anyhow::Result<()> {
        let green = split_ci_caller_fixture();
        assert!(pipeline_delegates_to_xtask_ci(green), "anti-vacuity");
        let fallback_setup = "      - name: Setup scheduled audit tools\n        uses: ./.github/actions/setup-rss-ci\n        with:\n          lane: audit\n          profile: audit\n          toolchain: 1.96.0\n          nightly: \"\"\n          tool-cache-epoch: v4\n          writer-mode: false\n          evidence-enabled: false\n\n";
        let setup_moved_to_gate = green.replacen(fallback_setup, "", 1).replacen(
            "    steps:\n      - name: Checkout gate implementation",
            &format!("    steps:\n{fallback_setup}      - name: Checkout gate implementation"),
            1,
        );
        for (name, red) in [
            ("missing-plan", green.replacen("  ci-plan:\n", "  plan-missing:\n", 1)),
            ("extra-job", format!("{green}\n  bypass:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n")),
            ("missing-proof-generator", green.replacen("      - name: Generate LocalTx proof report", "      - name: Missing LocalTx proof report", 1)),
            ("missing-assembly-artifact-generator", green.replacen("      - name: Generate assembly artifact matrix", "      - name: Missing assembly artifact matrix", 1)),
            ("artifact-command-alias", green.replacen("-- assembly artifacts check >", "-- assembly artifact check >", 1)),
            ("artifact-wrong-temp-path", green.replacen("mkdir -p target/assembly-artifacts.tmp", "mkdir -p target/assembly-artifacts.stage", 1)),
            ("artifact-direct-final-write", green.replacen("target/assembly-artifacts.tmp/assembly-artifacts.md", "target/assembly-artifacts/assembly-artifacts.md", 1)),
            ("artifact-missing-status-capture", green.replacen("          status=$?\n", "", 1)),
            ("artifact-missing-atomic-publish", green.replacen("          mv target/assembly-artifacts.tmp target/assembly-artifacts\n", "", 1)),
            ("artifact-upload-not-always", green.replacen("      - name: Upload assembly artifact matrix\n        if: ${{ always() }}", "      - name: Upload assembly artifact matrix\n        if: ${{ success() }}", 1)),
            ("artifact-upload-name", green.replacen("name: assembly-artifacts-${{ github.run_id }}-${{ github.run_attempt }}", "name: assembly-artifacts-latest", 1)),
            ("artifact-upload-path", green.replacen("path: target/assembly-artifacts/assembly-artifacts.md", "path: target/assembly-artifacts.tmp/assembly-artifacts.md", 1)),
            ("artifact-upload-missing-files-policy", green.replacen("          path: target/assembly-artifacts/assembly-artifacts.md\n          if-no-files-found: error", "          path: target/assembly-artifacts/assembly-artifacts.md\n          if-no-files-found: warn", 1)),
            ("artifact-upload-retention", green.replacen("          name: assembly-artifacts-${{ github.run_id }}-${{ github.run_attempt }}\n          path: target/assembly-artifacts/assembly-artifacts.md\n          if-no-files-found: error\n          retention-days: 30", "          name: assembly-artifacts-${{ github.run_id }}-${{ github.run_attempt }}\n          path: target/assembly-artifacts/assembly-artifacts.md\n          if-no-files-found: error\n          retention-days: 7", 1)),
            ("proof-json-format", green.replacen("-- localtx report --format json > target/localtx-proof.tmp/localtx-proof.json", "-- localtx report --format markdown > target/localtx-proof.tmp/localtx-proof.json", 1)),
            ("proof-markdown-format", green.replacen("-- localtx report --format markdown > target/localtx-proof.tmp/localtx-proof.md", "-- localtx report --format md > target/localtx-proof.tmp/localtx-proof.md", 1)),
            ("proof-wrong-temp-path", green.replacen("mkdir -p target/localtx-proof.tmp", "mkdir -p target/localtx-proof.stage", 1)),
            ("proof-direct-final-write", green.replacen("target/localtx-proof.tmp/localtx-proof.json", "target/localtx-proof/localtx-proof.json", 1)),
            ("proof-missing-clean", green.replacen("          rm -rf target/localtx-proof target/localtx-proof.tmp\n", "", 1)),
            ("proof-missing-atomic-publish", green.replacen("          mv target/localtx-proof.tmp target/localtx-proof\n", "", 1)),
            ("proof-wrong-final-path", green.replacen("mv target/localtx-proof.tmp target/localtx-proof", "mv target/localtx-proof.tmp target/localtx-proof-output", 1)),
            ("proof-upload-not-always", green.replacen("      - name: Upload LocalTx proof report\n        if: ${{ always() }}", "      - name: Upload LocalTx proof report\n        if: ${{ success() }}", 1)),
            ("proof-upload-name", green.replacen("name: localtx-proof-${{ github.run_id }}-${{ github.run_attempt }}", "name: localtx-proof-latest", 1)),
            ("proof-upload-path", green.replacen("          path: target/localtx-proof\n          if-no-files-found: error", "          path: target/localtx-proof.tmp\n          if-no-files-found: error", 1)),
            ("proof-upload-missing-files-policy", green.replacen("          path: target/localtx-proof\n          if-no-files-found: error\n          retention-days: 30", "          path: target/localtx-proof\n          if-no-files-found: warn\n          retention-days: 30", 1)),
            ("proof-upload-retention", green.replacen("          name: localtx-proof-${{ github.run_id }}-${{ github.run_attempt }}\n          path: target/localtx-proof\n          if-no-files-found: error\n          retention-days: 30", "          name: localtx-proof-${{ github.run_id }}-${{ github.run_attempt }}\n          path: target/localtx-proof\n          if-no-files-found: error\n          retention-days: 7", 1)),
            ("proof-extra-bypass-step", green.replacen("      - name: Upload LocalTx proof report", "      - name: Bypass LocalTx proof\n        run: true\n\n      - name: Upload LocalTx proof report", 1)),
            ("static-matrix", green.replacen("      matrix: ${{ fromJSON(needs.ci-plan.outputs.matrix) }}", "      matrix:\n        include:\n          - { lane: ci-meta }", 1)),
            ("untyped-lane", green.replacen("lane: ${{ matrix.lane }}", "lane: ci-meta", 1)),
            ("missing-job-key", green.replacen("      ci-job-key: ${{ matrix.jobKey }}\n", "", 1)),
            ("missing-plan-digest", green.replacen("      plan-digest: ${{ matrix.planDigest }}\n", "", 1)),
            ("missing-source", green.replacen("      source-revision: ${{ matrix.sourceRevision }}\n", "", 1)),
            ("missing-required-evidence-target", green.replacen("      required-evidence-target: ${{ matrix.requiredEvidenceTarget || '' }}\n", "", 1)),
            ("gate-not-always", green.replacen("  ci-gate:\n    name: ci-gate\n    if: ${{ always() }}", "  ci-gate:\n    name: ci-gate\n    if: ${{ success() }}", 1)),
            ("gate-missing-matrix-result", green.replacen("            --matrix-result \"${{ needs.execute.result }}\"", "", 1)),
            ("permission", green.replacen("contents: read", "contents: write", 1)),
            ("missing-concurrency", green.replacen("concurrency:\n  group: rss-ci-${{ github.event_name }}-${{ github.event.pull_request.number || github.ref }}\n  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n", "", 1)),
            ("branch-cancellation", green.replacen("cancel-in-progress: ${{ github.event_name == 'pull_request' }}", "cancel-in-progress: true", 1)),
            ("missing-event-concurrency-domain", green.replacen("group: rss-ci-${{ github.event_name }}-", "group: rss-ci-", 1)),
            ("unstable-concurrency-key", green.replacen("github.event.pull_request.number || github.ref", "github.run_id", 1)),
            ("unsafe-trigger", green.replacen("  workflow_dispatch:", "  pull_request_target:\n  workflow_dispatch:", 1)),
            ("pr-path-filter", green.replacen("  pull_request:\n    branches: [develop]", "  pull_request:\n    branches: [develop]\n    paths: [\"src/**\"]", 1)),
            ("push-missing-codex", green.replacen(", \"codex/**\"", "", 1)),
            ("push-missing-feature", green.replacen(", \"feature/**\"", "", 1)),
            ("push-missing-fix", green.replacen(", \"fix/**\"", "", 1)),
            ("push-extra-branch", green.replacen(", \"fix/**\"]", ", \"fix/**\", \"release/**\"]", 1)),
            ("manual-input", green.replacen("  workflow_dispatch:", "  workflow_dispatch:\n    inputs:\n      lane:\n        required: false", 1)),
            ("full-override-bypass", green.replacen("${{ vars.RSS_CI_FORCE_FULL }}", "false", 1)),
            ("plan-upload-name", green.replacen("name: ci-impact-plan-${{ github.run_id }}-${{ github.run_attempt }}", "name: stale-plan", 1)),
            ("plan-download-name", green.replacen("name: ci-impact-plan-${{ github.run_id }}-${{ github.run_attempt }}", "name: stale-plan", 2)),
            ("receipt-pattern", green.replacen("pattern: ci-evidence-*-${{ github.run_id }}-${{ github.run_attempt }}", "pattern: ci-evidence-*", 1)),
            ("receipt-merge", green.replacen("merge-multiple: false", "merge-multiple: true", 1)),
            ("gate-missing-plan-path", green.replacen("            --plan target/ci-plan-download/ci-plan.json \\\n", "", 1)),
            ("gate-missing-receipts-path", green.replacen("            --receipts target/ci-receipts \\\n", "", 1)),
            ("planner-overwrites-plan", green.replacen("            --github-output \"$GITHUB_OUTPUT\"", "            --github-output \"$GITHUB_OUTPUT\"\n          : > target/ci-impact/ci-plan.json", 1)),
            ("gate-replaces-receipts", green.replacen("          cargo run --locked -p xtask -- ci gate \\\n", "          rm -rf target/ci-receipts\n          cargo run --locked -p xtask -- ci gate \\\n", 1)),
            ("planner-extra-step", green.replacen("      - name: Upload typed plan", "      - name: Bypass planner\n        run: true\n\n      - name: Upload typed plan", 1)),
            ("missing-audit-fallback", green.replacen("  scheduled-audit-fallback:\n", "  removed-audit-fallback:\n", 1)),
            ("audit-fallback-not-always", green.replacen("if: ${{ always() && github.event_name == 'schedule' && needs.ci-plan.result != 'success' }}", "if: ${{ github.event_name == 'schedule' && needs.ci-plan.result != 'success' }}", 1)),
            ("audit-fallback-not-schedule-only", green.replacen("github.event_name == 'schedule'", "github.event_name != 'pull_request'", 1)),
            ("audit-fallback-no-planner-failure", green.replacen("needs.ci-plan.result != 'success'", "needs.ci-plan.result == 'success'", 1)),
            ("audit-fallback-checkout-ref", green.replacen("      - name: Checkout scheduled audit revision\n        uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n          fetch-depth: 1\n          ref: ${{ github.sha }}", "      - name: Checkout scheduled audit revision\n        uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n          fetch-depth: 1\n          ref: develop", 1)),
            ("audit-fallback-checkout-credentials", green.replacen("      - name: Checkout scheduled audit revision\n        uses: actions/checkout@v4\n        with:\n          persist-credentials: false", "      - name: Checkout scheduled audit revision\n        uses: actions/checkout@v4\n        with:\n          persist-credentials: true", 1)),
            ("audit-fallback-lane", green.replacen("      - name: Setup scheduled audit tools\n        uses: ./.github/actions/setup-rss-ci\n        with:\n          lane: audit", "      - name: Setup scheduled audit tools\n        uses: ./.github/actions/setup-rss-ci\n        with:\n          lane: ci-security", 1)),
            ("audit-fallback-profile", green.replacen("          profile: audit", "          profile: ci-security", 1)),
            ("audit-fallback-toolchain", green.replacen("          toolchain: 1.96.0", "          toolchain: stable", 1)),
            ("audit-fallback-epoch", green.replacen("          tool-cache-epoch: v4", "          tool-cache-epoch: v3", 1)),
            ("audit-fallback-writer", green.replacen("          writer-mode: false", "          writer-mode: true", 1)),
            ("audit-fallback-evidence", green.replacen("          evidence-enabled: false", "          evidence-enabled: true", 1)),
            ("audit-fallback-missing-advisory", green.replacen("      - name: Scan prose for stale governance claims (advisory)\n        continue-on-error: true\n        run: bash hack/automation/prose-advisory-scan.sh scan\n\n", "", 1)),
            ("audit-fallback-blocking-advisory", green.replacen("      - name: Scan prose for stale governance claims (advisory)\n        continue-on-error: true\n        run: bash hack/automation/prose-advisory-scan.sh scan", "      - name: Scan prose for stale governance claims (advisory)\n        continue-on-error: false\n        run: bash hack/automation/prose-advisory-scan.sh scan", 1)),
            ("audit-fallback-advisory-command", green.replacen("run: bash hack/automation/prose-advisory-scan.sh scan", "run: bash hack/automation/prose-advisory-scan.sh selftest", 1)),
            ("audit-fallback-command", green.replacen("          cargo run --locked -p xtask -- ci run --job audit", "          cargo audit", 1)),
            ("audit-fallback-step-moved-to-gate", setup_moved_to_gate),
            ("audit-fallback-extra-step", green.replacen("    steps:\n      - name: Checkout scheduled audit revision", "    steps:\n      - name: Bypass scheduled audit\n        run: true\n\n      - name: Checkout scheduled audit revision", 1)),
            (
                "metrics-missing-warn",
                green.replacen("if-no-files-found: error", "if-no-files-found: warn", 1),
            ),
        ] {
            assert!(!pipeline_delegates_to_xtask_ci(&red), "caller weakening `{name}` must fail closed");
        }
        for step in [
            "Build typed CI impact plan",
            "Generate LocalTx proof report",
            "Verify plan, matrix result, and exact receipts",
        ] {
            for field in ["name", "env"] {
                let red = camouflage_named_step_run(green, step, field)?;
                assert!(
                    !pipeline_delegates_to_xtask_ci(&red),
                    "caller `{step}` run camouflage in `{field}` must fail closed"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn setup_action_delegate_predicate_green_and_red() {
        let green = "runs:\n  using: composite\n  steps:\n    - run: cargo install cargo-binstall@1.20.1 --locked\n    - run: cargo binstall -y --locked cargo-nextest@0.9.137\n";
        assert!(setup_action_contains_only_setup_cargo_commands(green));
        for red in [
            "runs:\n  using: composite\n  steps:\n    - run: cargo nextest run --workspace\n",
            "runs:\n  using: composite\n  steps:\n    - run: cargo run --locked -p server\n",
            "runs:\n  using: composite\n  steps:\n    - run: cargo run --locked -p xtask -- ci\n",
        ] {
            assert!(!setup_action_contains_only_setup_cargo_commands(red));
        }
    }

    /// 真实 committed 文件必须已切换为 planner、动态 executor、定时审计 fallback 与稳定 gate。
    #[test]
    fn github_ci_workflow_delegates_to_split_xtask_lanes() -> anyhow::Result<()> {
        let path = workspace_root()?
            .join(".github")
            .join("workflows")
            .join("ci.yml");
        let yaml = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))?;
        assert!(
            pipeline_delegates_to_xtask_ci(&yaml),
            ".github/workflows/ci.yml 须精确声明 planner、typed dynamic matrix、定时审计 fallback 与稳定 gate"
        );
        let action_path = workspace_root()?
            .join(".github")
            .join("actions")
            .join("setup-rss-ci")
            .join("action.yml");
        let action_yaml = std::fs::read_to_string(&action_path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", action_path.display()))?;
        assert!(
            setup_action_contains_only_setup_cargo_commands(&action_yaml),
            ".github/actions/setup-rss-ci/action.yml 只能包含 cargo install/binstall 类 setup 命令，不得内联门命令"
        );
        Ok(())
    }

    #[test]
    fn github_setup_action_cache_excludes_cargo_home_root() -> anyhow::Result<()> {
        let path = workspace_root()?
            .join(".github")
            .join("actions")
            .join("setup-rss-ci")
            .join("action.yml");
        let yaml = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))?;
        assert!(
            yaml.contains("~/.cargo/registry") && yaml.contains("~/.cargo/git"),
            "setup action cache 应只缓存 cargo registry/git 与 target"
        );
        assert!(
            !yaml.lines().any(|line| line.trim() == "~/.cargo"),
            "setup action 不得缓存整个 ~/.cargo，避免缓存 ~/.cargo/bin、.crates*.toml 或未来凭据"
        );
        Ok(())
    }

    #[test]
    fn github_ci_tool_adapter_contract_is_closed() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let read = |rel: &str| -> anyhow::Result<String> {
            let path = root.join(rel);
            std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))
        };
        let reusable = read(".github/workflows/rss-rust-lane.yml")?;
        let action = read(".github/actions/setup-rss-ci/action.yml")?;
        let adapter = read(".github/scripts/ci-tool-adapters.sh")?;
        assert!(
            ci_tool_adapter_contract_is_hardened(&reusable, &action, &adapter),
            "committed reusable workflow/setup action/adapter 须闭合 CI-TOOL-ADAPTER-01"
        );
        Ok(())
    }

    fn ci_tool_adapter_contract_fixture() -> (&'static str, &'static str, &'static str) {
        const REUSABLE: &str = r#"jobs:
  lane:
    steps:
      - id: policy
        run: |
          echo 'profile=ci-core-tests'
          echo 'nightly='
      - id: setup
        uses: ./.github/actions/setup-rss-ci
        with:
          lane: ${{ inputs.lane }}
          profile: ${{ steps.policy.outputs.profile }}
          tool-cache-epoch: v4
      - id: measure-tools
        run: test -f "$tool_root/.rss-tool-seal-v1"
      - id: save-tools
        uses: actions/cache/save@v4
        with:
          key: ${{ steps.setup.outputs.tools-primary-key }}
"#;
        const ACTION: &str = r#"inputs:
  lane:
    required: true
  profile:
    required: true
  tool-cache-epoch:
    required: true
runs:
  using: composite
  steps:
    - id: tool-policy
      run: |
        adapter_hash="$(sha256sum .github/scripts/ci-tool-adapters.sh | cut -d' ' -f1)"
        catalog_hash="$(sha256sum .github/scripts/ci-tool-catalog.txt | cut -d' ' -f1)"
        echo "adapter-sha256=$adapter_hash" >> "$GITHUB_OUTPUT"
        echo "catalog-sha256=$catalog_hash" >> "$GITHUB_OUTPUT"
        echo "install-action-tools=$(.github/scripts/ci-tool-adapters.sh specs --lane "$RSS_LANE" --backend install-action)" >> "$GITHUB_OUTPUT"
        echo "binstall-tools=$(.github/scripts/ci-tool-adapters.sh specs --lane "$RSS_LANE" --backend binstall)" >> "$GITHUB_OUTPUT"
    - id: cache-keys
      env:
        RSS_ADAPTER_SHA256: ${{ steps.tool-policy.outputs.adapter-sha256 }}
        RSS_CATALOG_SHA256: ${{ steps.tool-policy.outputs.catalog-sha256 }}
        RSS_INSTALL_ACTION_TOOLS: ${{ steps.tool-policy.outputs.install-action-tools }}
        RSS_BINSTALL_TOOLS: ${{ steps.tool-policy.outputs.binstall-tools }}
      run: |
        tools_hash="$(printf '%s\n' 'taiki-e/install-action@b8cecb83565409bcc297b2df6e77f030b2a468d5' "$RSS_ADAPTER_SHA256" "$RSS_CATALOG_SHA256" "$RSS_INSTALL_ACTION_TOOLS" "$RSS_BINSTALL_TOOLS" | sha256sum | cut -d' ' -f1)"
    - name: Install fallback tools
      run: cargo binstall --root "$RSS_TOOL_ROOT" "$spec"
    - name: Install pinned prebuilt tools
      uses: taiki-e/install-action@b8cecb83565409bcc297b2df6e77f030b2a468d5
      with:
        tool: ${{ steps.tool-policy.outputs.install-action-tools }}
    - id: verify-tools
      run: |
        mode=fresh
        if [ "$RSS_TOOLS_HIT" = true ]; then mode=cache; fi
        .github/scripts/ci-tool-adapters.sh verify --mode "$mode" --lane "$RSS_LANE" --root "$RSS_TOOL_ROOT"
        echo "$RSS_TOOL_ROOT/.install-action/bin" >> "$GITHUB_PATH"
        echo "$RSS_TOOL_ROOT/bin" >> "$GITHUB_PATH"
"#;
        const ADAPTER: &str = r#"#!/usr/bin/env bash
seal="$RSS_TOOL_ROOT/.rss-tool-seal-v1"
adapter_hash="$(sha256sum "$0" | cut -d' ' -f1)"
catalog_hash="$(sha256sum ci-tool-catalog.txt | cut -d' ' -f1)"
printf 'adapter-sha256=%s\n' "$adapter_hash" >> "$seal"
printf 'catalog-sha256=%s\n' "$catalog_hash" >> "$seal"
"#;
        (REUSABLE, ACTION, ADAPTER)
    }

    #[test]
    fn ci_tool_adapter_contract_green_and_synthetic_red() {
        let (reusable, action, adapter) = ci_tool_adapter_contract_fixture();
        assert!(
            ci_tool_adapter_contract_is_hardened(reusable, action, adapter),
            "anti-vacuity: canonical adapter fixture must pass"
        );

        for (name, reusable_red, action_red, adapter_red) in [
            (
                "workflow-tool-list",
                reusable.replacen("echo 'nightly='", "echo 'nightly='\n          echo 'prebuilt-tools=cargo-nextest@0.9.137'", 1),
                action.to_owned(),
                adapter.to_owned(),
            ),
            (
                "arbitrary-tool-input",
                reusable.to_owned(),
                action.replacen("  lane:\n", "  prebuilt-tools:\n    required: false\n  lane:\n", 1),
                adapter.to_owned(),
            ),
            (
                "installer-uses-sha-drift",
                reusable.to_owned(),
                action.replacen("uses: taiki-e/install-action@b8cecb83565409bcc297b2df6e77f030b2a468d5", "uses: taiki-e/install-action@13608cbb45b01feb47ef444ab1a42dc41ad56f1a", 1),
                adapter.to_owned(),
            ),
            (
                "installer-key-sha-drift",
                reusable.to_owned(),
                action.replacen("taiki-e/install-action@b8cecb83565409bcc297b2df6e77f030b2a468d5' \"$RSS_ADAPTER_SHA256\"", "taiki-e/install-action@13608cbb45b01feb47ef444ab1a42dc41ad56f1a' \"$RSS_ADAPTER_SHA256\"", 1),
                adapter.to_owned(),
            ),
            (
                "adapter-not-in-key",
                reusable.to_owned(),
                action.replacen(" \"$RSS_ADAPTER_SHA256\" \"$RSS_CATALOG_SHA256\"", " \"$RSS_CATALOG_SHA256\"", 1),
                adapter.to_owned(),
            ),
            (
                "catalog-not-in-key",
                reusable.to_owned(),
                action.replacen(" \"$RSS_CATALOG_SHA256\" \"$RSS_INSTALL_ACTION_TOOLS\"", " \"$RSS_INSTALL_ACTION_TOOLS\"", 1),
                adapter.to_owned(),
            ),
            (
                "adapter-not-in-seal",
                reusable.to_owned(),
                action.to_owned(),
                adapter.replacen("printf 'adapter-sha256=%s\\n' \"$adapter_hash\" >> \"$seal\"", "true", 1),
            ),
            (
                "catalog-not-in-seal",
                reusable.to_owned(),
                action.to_owned(),
                adapter.replacen("printf 'catalog-sha256=%s\\n' \"$catalog_hash\" >> \"$seal\"", "true", 1),
            ),
            (
                "missing-cache-verify",
                reusable.to_owned(),
                action.replacen("if [ \"$RSS_TOOLS_HIT\" = true ]; then mode=cache; fi", "if [ \"$RSS_TOOLS_HIT\" = true ]; then exit 0; fi", 1),
                adapter.to_owned(),
            ),
            (
                "path-before-verify",
                reusable.to_owned(),
                action.replacen(".github/scripts/ci-tool-adapters.sh verify --mode \"$mode\" --lane \"$RSS_LANE\" --root \"$RSS_TOOL_ROOT\"\n        echo \"$RSS_TOOL_ROOT/.install-action/bin\" >> \"$GITHUB_PATH\"", "echo \"$RSS_TOOL_ROOT/.install-action/bin\" >> \"$GITHUB_PATH\"\n        .github/scripts/ci-tool-adapters.sh verify --mode \"$mode\" --lane \"$RSS_LANE\" --root \"$RSS_TOOL_ROOT\"", 1),
                adapter.to_owned(),
            ),
            (
                "prebuilt-before-fallback",
                reusable.to_owned(),
                action.replacen(
                    "    - name: Install fallback tools\n      run: cargo binstall --root \"$RSS_TOOL_ROOT\" \"$spec\"\n    - name: Install pinned prebuilt tools\n      uses: taiki-e/install-action@b8cecb83565409bcc297b2df6e77f030b2a468d5",
                    "    - name: Install pinned prebuilt tools\n      uses: taiki-e/install-action@b8cecb83565409bcc297b2df6e77f030b2a468d5\n    - name: Install fallback tools\n      run: cargo binstall --root \"$RSS_TOOL_ROOT\" \"$spec\"",
                    1,
                ),
                adapter.to_owned(),
            ),
            (
                "save-before-setup",
                reusable.replacen("- id: setup", "- id: save-tools-copy\n        uses: actions/cache/save@v4\n      - id: setup", 1),
                action.to_owned(),
                adapter.to_owned(),
            ),
            (
                "old-epoch",
                reusable.replacen("tool-cache-epoch: v4", "tool-cache-epoch: v3", 1),
                action.to_owned(),
                adapter.to_owned(),
            ),
        ] {
            assert!(
                !ci_tool_adapter_contract_is_hardened(&reusable_red, &action_red, &adapter_red),
                "adapter contract weakening `{name}` must fail closed"
            );
        }
    }

    /// GitHub CI 安装 pinned nightly 时，每个 component 必须显式带 `--component`，否则 rustup 会把后续
    /// component 名误解析成 toolchain 名（GitHub runner 上 fail-fast）。
    #[test]
    fn github_ci_nightly_components_are_explicit() -> anyhow::Result<()> {
        let path = workspace_root()?
            .join(".github")
            .join("actions")
            .join("setup-rss-ci")
            .join("action.yml");
        let yaml = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))?;
        assert!(
            yaml.contains(
                "rustup toolchain install \"${RSS_SETUP_NIGHTLY}\" --profile minimal --component rustc-dev --component llvm-tools-preview --component rust-src"
            ),
            "pinned nightly install 须为每个 component 显式写 `--component`"
        );
        assert!(
            !yaml.contains("--component rustc-dev llvm-tools-preview rust-src"),
            "不得把多个 component 裸接在单个 `--component` 后"
        );
        Ok(())
    }

    // ---- 供应链定时刷新 lane 守卫（issue #1133）----

    /// GitHub audit workflow 谓词（**结构绑定**，fail-closed；codex F1：守卫不可被注释 / displayName 误满足）。
    /// YAML 须同时满足——① 顶层 `schedule:` 键（GitHub Actions 定时触发）；② `workflow_dispatch:` 手动 backstop；
    /// ③ audit 委托形在**真实 script 命令**；④ 每个 `cargo run` 都是完整 xtask audit 委托形，其他 cargo 子命令仅限安装。
    fn github_audit_workflow_has_scheduled_lane(yaml: &str) -> bool {
        workflow_has_top_level_on_event(yaml, "schedule")
            && workflow_has_top_level_on_event(yaml, "workflow_dispatch")
            && pipeline_delegates_to_xtask_ci(yaml)
    }

    /// 谓词绿/红例（anti-vacuity）：逐一抽掉每个必需子句都使谓词变假（守卫非恒真）。
    #[test]
    fn scheduled_audit_lane_predicate_green_and_red() {
        let green = include_str!("../../.github/workflows/ci.yml");
        assert!(
            github_audit_workflow_has_scheduled_lane(green),
            "完整定时 lane 应为真"
        );
        // 红：逐一抽掉一个必需子句。
        assert!(
            !github_audit_workflow_has_scheduled_lane(&green.replace("schedule:", "x_schedule:")),
            "缺 schedule 块"
        );
        assert!(
            !github_audit_workflow_has_scheduled_lane(
                &green.replace("workflow_dispatch:", "x_workflow_dispatch:")
            ),
            "缺 workflow_dispatch backstop"
        );
        assert!(!github_audit_workflow_has_scheduled_lane(
            &green.replace("- cron: \"0 6 * * *\"", "- cron: \"0 7 * * *\"")
        ));
    }

    #[test]
    fn scheduled_prose_advisory_is_non_blocking_and_schedule_only() {
        let caller = include_str!("../../.github/workflows/ci.yml");
        let reusable = include_str!("../../.github/workflows/rss-rust-lane.yml");
        assert!(scheduled_prose_advisory_is_closed(caller, reusable));

        for red in [
            reusable.replacen(
                "if: ${{ github.event_name == 'schedule' && inputs.lane == 'audit' }}",
                "if: ${{ github.event_name == 'pull_request' && inputs.lane == 'audit' }}",
                1,
            ),
            reusable.replacen(
                "if: ${{ github.event_name == 'schedule' && inputs.lane == 'audit' }}",
                "if: ${{ github.event_name == 'schedule' && inputs.lane == 'ci-meta' }}",
                1,
            ),
            reusable.replacen(
                "      - name: Scan prose for stale governance claims (advisory)\n        if: ${{ github.event_name == 'schedule' && inputs.lane == 'audit' }}\n        continue-on-error: true",
                "      - name: Scan prose for stale governance claims (advisory)\n        if: ${{ github.event_name == 'schedule' && inputs.lane == 'audit' }}\n        continue-on-error: false",
                1,
            ),
        ] {
            assert!(
                !scheduled_prose_advisory_is_closed(caller, &red),
                "scheduled prose advisory weakening must fail closed"
            );
        }
    }

    /// 真实 committed 文件：GitHub audit workflow 含每日定时刷新 lane，经 typed audit job 委托
    /// （issue #1133：捕获「未变依赖」新披露 CVE；门逻辑单源在 xtask，不内联）。
    #[test]
    fn github_audit_workflow_has_scheduled_audit_lane() -> anyhow::Result<()> {
        let path = workspace_root()?
            .join(".github")
            .join("workflows")
            .join("ci.yml");
        let yaml = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))?;
        assert!(
            github_audit_workflow_has_scheduled_lane(&yaml),
            ".github/workflows/ci.yml 须以 typed full plan 承载每日 audit 刷新"
        );
        Ok(())
    }

    // ---- capability shard matrix guard (INVARIANT CI-INTEGRATION-MATRIX-01) ----

    fn expected_integration_shards() -> Vec<&'static str> {
        IntegrationShard::ALL
            .iter()
            .map(|shard| shard.as_str())
            .collect()
    }

    fn integration_matrix_rows(yaml: &str) -> Option<Vec<String>> {
        let lines = yaml_indented_code_lines(yaml);
        let start = lines
            .iter()
            .position(|(indent, line)| *indent == 8 && *line == "include:")?;
        lines[start + 1..]
            .iter()
            .take_while(|(indent, _)| *indent > 8)
            .map(|(indent, line)| {
                if *indent != 10 {
                    return None;
                }
                line.strip_prefix("- { ")
                    .and_then(|row| row.strip_suffix(" }"))
                    .map(str::to_owned)
            })
            .collect()
    }

    fn expected_integration_rows() -> Vec<String> {
        IntegrationShard::ALL
            .iter()
            .flat_map(|shard| match shard.partition_policy() {
                integration_shards::PartitionPolicy::Unpartitioned => vec![format!(
                    "shard: {}, partition: \"\", partition-label: unpartitioned",
                    shard.as_str()
                )],
                integration_shards::PartitionPolicy::TwoWayHash => {
                    [("1/2", "1-of-2"), ("2/2", "2-of-2")]
                        .map(|(partition, label)| {
                            format!(
                                "shard: {}, partition: {partition}, partition-label: {label}",
                                shard.as_str()
                            )
                        })
                        .to_vec()
                }
            })
            .collect()
    }

    fn github_integration_workflow_has_shard_matrix_for(
        yaml: &str,
        expected_shards: &[&str],
    ) -> bool {
        expected_shards == expected_integration_shards()
            && pipeline_delegates_to_xtask_ci(yaml)
            && yaml.contains("shard: ${{ matrix.shard || '' }}")
            && yaml.contains("partition: ${{ matrix.partition || '' }}")
    }

    fn github_integration_workflow_has_shard_matrix(yaml: &str) -> bool {
        github_integration_workflow_has_shard_matrix_for(yaml, &expected_integration_shards())
    }

    fn integration_policy_shards(yaml: &str) -> Option<Vec<&str>> {
        let lines = yaml
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect::<Vec<_>>();
        let case = lines
            .iter()
            .position(|line| *line == "case \"$RSS_SHARD\" in")?;
        let allowlist = lines.get(case + 1)?.strip_suffix(") ;;")?;
        let shards = allowlist.split('|').collect::<Vec<_>>();
        (!shards.is_empty() && shards.iter().all(|shard| !shard.is_empty())).then_some(shards)
    }

    fn integration_policy_matches_catalog(yaml: &str, expected_shards: &[&str]) -> bool {
        integration_policy_shards(yaml).as_deref() == Some(expected_shards)
    }

    fn expected_integration_partition_pairs() -> Vec<String> {
        IntegrationShard::ALL
            .iter()
            .flat_map(|shard| match shard.partition_policy() {
                integration_shards::PartitionPolicy::Unpartitioned => {
                    vec![format!("{}:", shard.as_str())]
                }
                integration_shards::PartitionPolicy::TwoWayHash => {
                    vec![
                        format!("{}:1/2", shard.as_str()),
                        format!("{}:2/2", shard.as_str()),
                    ]
                }
            })
            .collect()
    }

    fn integration_partition_pairs(yaml: &str) -> Option<Vec<String>> {
        let lines = yaml.lines().map(str::trim).collect::<Vec<_>>();
        let start = lines
            .iter()
            .position(|line| *line == "case \"$RSS_SHARD:$RSS_PARTITION\" in")?;
        let allowlist = lines.get(start + 1)?.strip_suffix(") ;;")?;
        Some(allowlist.split('|').map(str::to_owned).collect())
    }

    fn expected_reusable_lanes() -> Vec<&'static str> {
        let mut lanes = Vec::new();
        for job in CiJobKey::ALL {
            let lane = job.lane_kind().workflow_name();
            if !lanes.contains(&lane) {
                lanes.push(lane);
            }
        }
        lanes
    }

    fn closed_lane_case(step: &TypedStep) -> Option<Vec<&str>> {
        let start = step
            .run
            .iter()
            .position(|line| line == "case \"$RSS_LANE\" in")?;
        let body = step.run[start + 1..]
            .iter()
            .take_while(|line| line.as_str() != "esac");
        Some(
            body.filter_map(|line| {
                let (arm, _) = line.split_once(')')?;
                (arm != "*"
                    && !arm.is_empty()
                    && arm.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    }))
                .then_some(arm)
            })
            .collect(),
        )
    }

    #[test]
    fn integration_matrix_predicate_green_and_red() {
        let green = include_str!("../../.github/workflows/ci.yml");
        assert!(github_integration_workflow_has_shard_matrix(green));
        assert!(integration_matrix_rows(green).is_none());
        assert_eq!(expected_integration_rows().len(), 8);
        let mut future_catalog = expected_integration_shards();
        future_catalog.push("future-shard");
        assert!(
            !github_integration_workflow_has_shard_matrix_for(green, &future_catalog),
            "catalog 新增 shard 而 committed matrix 未同步时必须 red"
        );
        for red in [
            green.replace("shard: ${{ matrix.shard || '' }}", "shard: postgres-domain"),
            green.replace("partition: ${{ matrix.partition || '' }}", "partition: ''"),
            green.replace(
                "fromJSON(needs.ci-plan.outputs.matrix)",
                "fromJSON(env.SHARDS)",
            ),
            green.replace(
                "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
                "cancel-in-progress: true",
            ),
            green.replace(
                "github.event.pull_request.number || github.ref",
                "github.run_id",
            ),
            format!("{green}\n  bypass:\n    runs-on: ubuntu-latest\n"),
        ] {
            assert!(!github_integration_workflow_has_shard_matrix(&red));
        }
    }

    #[test]
    fn github_integration_workflow_has_integration_shard_matrix() -> anyhow::Result<()> {
        let path = workspace_root()?
            .join(".github")
            .join("workflows")
            .join("ci.yml");
        let yaml = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))?;
        assert!(
            github_integration_workflow_has_shard_matrix(&yaml),
            ".github/workflows/ci.yml must derive integration rows from the typed planner"
        );
        Ok(())
    }

    // ---- CI-CACHE-WRITER-01：restore/save ownership 与显式 cache 生命周期（#1728）----

    fn setup_action_has_exact_split_cache_contract(yaml: &str) -> bool {
        let lines = yaml_indented_code_lines(yaml);
        let steps = yaml_typed_steps(yaml);
        let input_required = |name: &str| {
            let starts = lines
                .iter()
                .enumerate()
                .filter_map(|(index, (indent, line))| {
                    (*indent == 2 && *line == format!("{name}:")).then_some(index)
                })
                .collect::<Vec<_>>();
            let [start] = starts.as_slice() else {
                return false;
            };
            lines[*start + 1..]
                .iter()
                .take_while(|(indent, _)| *indent > 2)
                .any(|(indent, line)| *indent == 4 && *line == "required: true")
        };
        let output_value = |name: &str, value: &str| {
            let starts = lines
                .iter()
                .enumerate()
                .filter_map(|(index, (indent, line))| {
                    (*indent == 2 && *line == format!("{name}:")).then_some(index)
                })
                .collect::<Vec<_>>();
            let [start] = starts.as_slice() else {
                return false;
            };
            lines[*start + 1..]
                .iter()
                .take_while(|(indent, _)| *indent > 2)
                .any(|(indent, line)| *indent == 4 && *line == format!("value: {value}"))
        };
        let restore = |id: &str, paths: &[&str], key: &str| {
            let matches = steps
                .iter()
                .enumerate()
                .filter_map(|(index, step)| {
                    (step.id.as_deref() == Some(id)
                        && step.uses.as_deref() == Some("actions/cache/restore@v4")
                        && step.continue_on_error.as_deref() == Some("true")
                        && step.with_exact("path", paths)
                        && step.with_exact("key", &[key])
                        && !step.with.iter().any(|(name, _)| name == "restore-keys"))
                    .then_some(index)
                })
                .collect::<Vec<_>>();
            (matches.len() == 1).then(|| matches[0])
        };
        let download = restore(
            "download-cache",
            &[
                "~/.cargo/registry/cache",
                "~/.cargo/registry/index",
                "~/.cargo/git/db",
            ],
            "${{ steps.cache-keys.outputs.download-primary-key }}",
        );
        let tools = restore(
            "tools-cache",
            &[".cache/ci-tools/${{ inputs.profile }}"],
            "${{ steps.cache-keys.outputs.tools-primary-key }}",
        );
        let compiler = steps.iter().enumerate().find_map(|(index, step)| {
            (step.id.as_deref() == Some("compiler-cache")
                && step.uses.as_deref() == Some("actions/cache/restore@v4")
                && step.continue_on_error.as_deref() == Some("true")
                && step.with_exact("path", &["${{ runner.temp }}/rss-sccache-cache"])
                && step.with_exact(
                    "key",
                    &["${{ steps.cache-keys.outputs.compiler-cache-primary-key }}"],
                )
                && step.with_exact(
                    "restore-keys",
                    &["rss-sccache-v1-${{ runner.os }}-${{ runner.arch }}-${{ inputs.toolchain }}-${{ inputs.nightly || 'none' }}-"],
                ))
            .then_some(index)
        });
        [
            "lane",
            "profile",
            "toolchain",
            "tool-cache-epoch",
            "writer-mode",
            "evidence-enabled",
        ]
        .iter()
        .all(|name| input_required(name))
            && [
                (
                    "download-primary-key",
                    "${{ steps.cache-keys.outputs.download-primary-key }}",
                ),
                (
                    "download-matched-key",
                    "${{ steps.download-cache.outputs.cache-matched-key }}",
                ),
                (
                    "download-hit",
                    "${{ steps.download-cache.outputs.cache-hit }}",
                ),
                (
                    "tools-primary-key",
                    "${{ steps.cache-keys.outputs.tools-primary-key }}",
                ),
                (
                    "tools-matched-key",
                    "${{ steps.tools-cache.outputs.cache-matched-key }}",
                ),
                ("tools-hit", "${{ steps.tools-cache.outputs.cache-hit }}"),
                (
                    "compiler-cache-primary-key",
                    "${{ steps.cache-keys.outputs.compiler-cache-primary-key }}",
                ),
                (
                    "compiler-cache-matched-key",
                    "${{ steps.compiler-cache.outputs.cache-matched-key }}",
                ),
                (
                    "compiler-cache-hit",
                    "${{ steps.compiler-cache.outputs.cache-hit }}",
                ),
                (
                    "compiler-cache-restore-outcome",
                    "${{ steps.compiler-cache.outcome }}",
                ),
                (
                    "download-restore-result",
                    "${{ steps.after-cache.outputs.download-result }}",
                ),
                (
                    "download-restored-footprint-bytes",
                    "${{ steps.after-cache.outputs.download-bytes }}",
                ),
                (
                    "tools-restore-result",
                    "${{ steps.after-cache.outputs.tools-result }}",
                ),
                (
                    "tools-restored-footprint-bytes",
                    "${{ steps.after-cache.outputs.tools-bytes }}",
                ),
                ("resolved-target-source", "ci-runner-temp"),
                (
                    "resolved-target-dir",
                    "${{ steps.cache-keys.outputs.target-dir }}",
                ),
                (
                    "compiler-cache-enabled",
                    "${{ steps.compiler-policy.outputs.enabled }}",
                ),
                (
                    "compiler-cache-version",
                    "${{ steps.compiler-policy.outputs.version }}",
                ),
                (
                    "compiler-cache-access",
                    "${{ steps.compiler-policy.outputs.access }}",
                ),
                (
                    "compiler-cache-path",
                    "${{ steps.compiler-policy.outputs.path }}",
                ),
            ]
            .iter()
            .all(|(name, value)| output_value(name, value))
            && !lines.iter().any(|(_, line)| {
                matches!(
                    *line,
                    "build-primary-key:" | "build-matched-key:" | "build-hit:"
                )
            })
            && ![
                "target-primary-key",
                "target-matched-key",
                "target-hit",
                "target-cache",
                "rss-target",
                "tree-identity",
                ".cache/cargo-target",
                "ci-cache-result.sh aggregate",
                "SCCACHE_GHA_ENABLED",
                "SCCACHE_GHA_VERSION",
            ]
            .iter()
            .any(|forbidden| yaml.contains(forbidden))
            && steps
                .iter()
                .filter(|step| step.uses.as_deref() == Some("actions/cache/restore@v4"))
                .count()
                == 3
            && matches!((download, tools, compiler), (Some(a), Some(b), Some(c)) if a < b && b < c)
            && lines
                .iter()
                .filter(|(_, line)| line.starts_with("restore-keys:"))
                .count()
                == 1
            && steps.iter().any(|step| {
                step.id.as_deref() == Some("cache-keys")
                    && step.run_contains(
                        "download-primary-key=rss-download-v4-$common-$source_hash",
                    )
                    && step.run_contains("tools-primary-key=rss-tools-$RSS_TOOL_CACHE_EPOCH")
                    && step.run_contains(
                        "compiler-cache-primary-key=rss-sccache-v1-$common-$source_hash-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-$RSS_LANE",
                    )
                    && !step.run_contains("$GITHUB_JOB")
                    && step.run_has_line("mkdir -p \"$RSS_JOB_TARGET\"")
                    && step.run_has_line(
                        "echo \"CARGO_TARGET_DIR=$RSS_JOB_TARGET\" >> \"$GITHUB_ENV\"",
                    )
                    && step.env_exact("RSS_JOB_TARGET", &["${{ runner.temp }}/rss-cargo-target"])
                    && step.run_has_line(
                        "case \"$RSS_LANE\" in ci-meta|ci-core-prerequisites|ci-core-tests|ci-local-only|ci-security|ci-coverage|integration|audit) ;; *) exit 64 ;; esac",
                    )
                    && step.run_has_line(
                        "case \"$RSS_PROFILE\" in ci-meta|ci-core-prerequisites|ci-core-tests|ci-local-only|ci-security|ci-coverage|integration|audit) ;; *) exit 64 ;; esac",
                    )
                    && step.run_contains("[ \"$RSS_PROFILE\" = \"$RSS_LANE\" ]")
            })
            && steps.iter().any(|step| {
                step.id.as_deref() == Some("verify-tools")
                    && step.run_has_line(
                        ".github/scripts/ci-tool-adapters.sh verify --mode \"$mode\" --lane \"$RSS_LANE\" --root \"$RSS_TOOL_ROOT\"",
                    )
                    && step.run_has_line(
                        "compiler_cache_spec=\"$(.github/scripts/ci-tool-adapters.sh sccache-spec)\"",
                    )
                    && step.run_has_line(
                        "compiler_cache_path=\"$(.github/scripts/ci-tool-adapters.sh verify-sccache --candidate \"$RSS_TOOL_ROOT/$compiler_cache_relative\")\"",
                    )
                    && step.run_contains("compiler-cache-path=$compiler_cache_path")
                    && step.run_contains("compiler-cache-version=$compiler_cache_version")
            })
            && steps.iter().any(|step| {
                step.id.as_deref() == Some("compiler-policy")
                    && step.env_exact(
                        "RSS_VERIFIED_SCCACHE_PATH",
                        &["${{ steps.verify-tools.outputs.compiler-cache-path }}"],
                    )
                    && step.env_exact(
                        "RSS_VERIFIED_SCCACHE_VERSION",
                        &["${{ steps.verify-tools.outputs.compiler-cache-version }}"],
                    )
                    && !step.run_contains("ci-tool-catalog.txt")
                    && !step.run_contains("[ -f \"$path\" ]")
                    && step.run_contains("access=remote-read-only")
                    && step.run_contains("access=remote-read-write")
                    && step.run_contains("RSS_INTERNAL_SCCACHE_PATH=$path")
                    && step.run_contains("RUSTC_WRAPPER=$path")
                    && step.run_contains("SCCACHE_DIR=$RUNNER_TEMP/rss-sccache-cache")
                    && step.run_contains("SCCACHE_SERVER_UDS=$RUNNER_TEMP/rss-sccache/server.sock")
            })
            && steps.iter().any(|step| {
                step.id.as_deref() == Some("after-cache")
                    && step.if_expr.as_deref()
                        == Some("${{ always() && inputs.evidence-enabled == 'true' }}")
                    && step.env_exact(
                        "DOWNLOAD_RESTORE_OUTCOME",
                        &["${{ steps.download-cache.outcome }}"],
                    )
                    && step.env_exact(
                        "TOOLS_RESTORE_OUTCOME",
                        &["${{ steps.tools-cache.outcome }}"],
                    )
                    && step.env_exact(
                        "COMPILER_RESTORE_OUTCOME",
                        &["${{ steps.compiler-cache.outcome }}"],
                    )
                    && step.run_has_sequence(&[
                        "download_result=\"$(.github/scripts/ci-cache-result.sh classify --outcome \"$DOWNLOAD_RESTORE_OUTCOME\" --hit \"$DOWNLOAD_HIT\" --matched \"$DOWNLOAD_MATCHED\")\"",
                        "download_bytes=0",
                        "if [ \"$DOWNLOAD_RESTORE_OUTCOME\" = success ]; then",
                        "download_bytes=\"${{ steps.restored-footprints.outputs.download-bytes || 0 }}\"",
                        "fi",
                        "tools_result=\"$(.github/scripts/ci-cache-result.sh classify --outcome \"$TOOLS_RESTORE_OUTCOME\" --hit \"$TOOLS_HIT\" --matched \"$TOOLS_MATCHED\")\"",
                        "tools_bytes=0",
                        "if [ \"$TOOLS_RESTORE_OUTCOME\" = success ]; then",
                        "tools_bytes=\"${{ steps.restored-footprints.outputs.tools-bytes || 0 }}\"",
                        "fi",
                    ])
                    && !step.run_contains("compiler_result")
                    && step.run_has_line(
                        "if [ \"$COMPILER_RESTORE_OUTCOME\" = failure ]; then compiler_error_restore=1; fi",
                    )
                    && step.run_contains(
                        "--compiler-cache-error-restore \"$compiler_error_restore\"",
                    )
                    && step.run_contains("--compiler-cache-error-stats 0")
                    && step.run_contains("--compiler-cache-error-cache-io 0")
                    && step.run_contains("--compiler-cache-error-no-requests 0")
                    && step.run_contains("--compiler-cache-error-measure 0")
                    && step.run_contains("--compiler-cache-error-save 0")
                    && step.run_contains("snapshot after-cache")
            })
    }

    type WorkspaceTextFiles = Vec<(String, String)>;

    fn integration_container_workspace_inputs(
        root: &Path,
    ) -> anyhow::Result<(WorkspaceTextFiles, WorkspaceTextFiles)> {
        fn collect_rust(
            dir: &Path,
            root: &Path,
            output: &mut Vec<(String, String)>,
        ) -> anyhow::Result<()> {
            if !dir.is_dir() {
                return Ok(());
            }
            let mut entries = std::fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                let path = entry.path();
                let metadata = std::fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() {
                    anyhow::bail!(
                        "container ownership source tree contains symlink: {}",
                        path.display()
                    );
                }
                if metadata.is_dir() {
                    collect_rust(&path, root, output)?;
                } else if metadata.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
                    output.push((
                        path.strip_prefix(root)?
                            .to_string_lossy()
                            .replace('\\', "/"),
                        std::fs::read_to_string(&path)?,
                    ));
                }
            }
            Ok(())
        }

        let root_manifest = std::fs::read_to_string(root.join("Cargo.toml"))?;
        let parsed: toml::Value = toml::from_str(&root_manifest)?;
        let members = parsed
            .get("workspace")
            .and_then(|workspace| workspace.get("members"))
            .and_then(toml::Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("workspace.members missing"))?;
        let mut member_roots = Vec::new();
        for member in members {
            let pattern = member
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("workspace member must be a string"))?;
            if let Some(parent) = pattern.strip_suffix("/*") {
                let mut entries =
                    std::fs::read_dir(root.join(parent))?.collect::<std::io::Result<Vec<_>>>()?;
                entries.sort_by_key(std::fs::DirEntry::file_name);
                member_roots.extend(
                    entries
                        .into_iter()
                        .map(|entry| entry.path())
                        .filter(|path| path.join("Cargo.toml").is_file()),
                );
            } else {
                member_roots.push(root.join(pattern));
            }
        }
        member_roots.sort();
        member_roots.dedup();

        let mut rust_sources = Vec::new();
        let mut manifests = vec![("Cargo.toml".to_string(), root_manifest)];
        for member_root in member_roots {
            let manifest = member_root.join("Cargo.toml");
            manifests.push((
                manifest
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/"),
                std::fs::read_to_string(&manifest)?,
            ));
            for source_dir in ["src", "tests", "benches", "examples"] {
                collect_rust(&member_root.join(source_dir), root, &mut rust_sources)?;
            }
            let build = member_root.join("build.rs");
            if build.is_file() {
                rust_sources.push((
                    build
                        .strip_prefix(root)?
                        .to_string_lossy()
                        .replace('\\', "/"),
                    std::fs::read_to_string(build)?,
                ));
            }
        }
        rust_sources.sort_by(|left, right| left.0.cmp(&right.0));
        manifests.sort_by(|left, right| left.0.cmp(&right.0));
        Ok((rust_sources, manifests))
    }

    fn integration_container_workspace_contract_is_hardened(
        rust: &str,
        shell: &str,
        workflow: &str,
        workspace_rust_sources: &[(&str, &str)],
        workspace_manifests: &[(&str, &str)],
    ) -> bool {
        use syn::visit::Visit;

        fn use_mentions_async_runner(item: &syn::ItemUse) -> bool {
            use quote::ToTokens as _;
            let rendered = item.tree.to_token_stream().to_string().replace(' ', "");
            rendered.contains("testcontainers::runners::AsyncRunner")
                || rendered.contains("testcontainers::runners::{AsyncRunner")
                || rendered.contains("testcontainers::runners::*")
        }

        fn async_runner_import_count(file: &syn::File) -> usize {
            struct ImportVisitor(usize);
            impl<'ast> Visit<'ast> for ImportVisitor {
                fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
                    if use_mentions_async_runner(item) {
                        self.0 += 1;
                    }
                    syn::visit::visit_item_use(self, item);
                }
            }
            let mut visitor = ImportVisitor(0);
            visitor.visit_file(file);
            visitor.0
        }

        fn start_method_count(file: &syn::File) -> usize {
            struct StartVisitor(usize);
            impl<'ast> Visit<'ast> for StartVisitor {
                fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
                    if node.method == "start" {
                        self.0 += 1;
                    }
                    syn::visit::visit_expr_method_call(self, node);
                }
            }
            let mut visitor = StartVisitor(0);
            visitor.visit_file(file);
            visitor.0
        }

        #[derive(Default)]
        struct OwnedStartVisitor {
            starts: usize,
            consumer_binding: usize,
            complete_request_chain: usize,
        }

        fn expr_is_path(expr: &syn::Expr, expected: &str) -> bool {
            matches!(expr, syn::Expr::Path(path)
                if path.qself.is_none()
                    && path.path.segments.len() == 1
                    && path.path.segments[0].ident == expected)
        }

        fn pat_is_ident(pattern: &syn::Pat, expected: &str) -> bool {
            match pattern {
                syn::Pat::Ident(ident) => ident.ident == expected,
                syn::Pat::Type(typed) => pat_is_ident(&typed.pat, expected),
                _ => false,
            }
        }

        fn expr_is_shared_ref_to(expr: &syn::Expr, expected: &str) -> bool {
            matches!(expr, syn::Expr::Reference(reference)
                if reference.mutability.is_none() && expr_is_path(&reference.expr, expected))
        }

        fn labels_call_is_exact(labels: &syn::ExprMethodCall) -> bool {
            labels.method == "with_labels"
                && labels.args.len() == 1
                && labels.args.first().is_some_and(|argument| {
                    matches!(argument, syn::Expr::MethodCall(call)
                    if call.method == "labels"
                        && expr_is_path(&call.receiver, "service")
                        && call.args.len() == 1
                        && call.args.first().is_some_and(|argument| {
                            expr_is_shared_ref_to(argument, "context")
                        }))
                })
                && matches!(labels.receiver.as_ref(), syn::Expr::MethodCall(into)
                    if into.method == "into" && into.args.is_empty())
        }

        fn log_consumer_is_exact(argument: &syn::Expr) -> bool {
            let syn::Expr::Closure(closure) = argument else {
                return false;
            };
            if closure.capture.is_none()
                || closure.inputs.len() != 1
                || !closure
                    .inputs
                    .first()
                    .is_some_and(|pattern| pat_is_ident(pattern, "frame"))
            {
                return false;
            }

            struct ConsumerCallVisitor(usize);
            impl<'ast> Visit<'ast> for ConsumerCallVisitor {
                fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
                    if node.method == "write_frame"
                        && expr_is_path(&node.receiver, "consumer")
                        && node.args.len() == 1
                        && node
                            .args
                            .first()
                            .is_some_and(|argument| expr_is_path(argument, "frame"))
                    {
                        self.0 += 1;
                    }
                    syn::visit::visit_expr_method_call(self, node);
                }
            }
            let mut visitor = ConsumerCallVisitor(0);
            visitor.visit_expr(&closure.body);
            visitor.0 == 1
        }

        fn consumer_binding_is_exact(local: &syn::Local) -> bool {
            let Some(initializer) = &local.init else {
                return false;
            };
            let syn::Expr::Try(try_expr) = initializer.expr.as_ref() else {
                return false;
            };
            let syn::Expr::Call(call) = try_expr.expr.as_ref() else {
                return false;
            };
            let constructor_is_exact = matches!(call.func.as_ref(), syn::Expr::Path(path)
                if path.path.segments.iter().map(|segment| segment.ident.to_string()).collect::<Vec<_>>()
                    .ends_with(&["BoundedFileLogConsumer".to_string(), "new".to_string()]));
            let log_dir_is_exact = call.args.first().is_some_and(|argument| {
                matches!(argument, syn::Expr::Reference(reference)
                    if reference.mutability.is_none()
                        && matches!(reference.expr.as_ref(), syn::Expr::Field(field)
                            if expr_is_path(&field.base, "context")
                                && matches!(&field.member, syn::Member::Named(name) if name == "log_dir")))
            });
            pat_is_ident(&local.pat, "consumer")
                && constructor_is_exact
                && call.args.len() == 2
                && log_dir_is_exact
                && call
                    .args
                    .get(1)
                    .is_some_and(|argument| expr_is_path(argument, "service"))
        }

        impl<'ast> Visit<'ast> for OwnedStartVisitor {
            fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
                if node.method == "start" {
                    self.starts += 1;
                }
                if node.method == "with_log_consumer"
                    && node.args.len() == 1
                    && matches!(node.receiver.as_ref(), syn::Expr::MethodCall(labels)
                        if labels_call_is_exact(labels))
                    && node.args.first().is_some_and(log_consumer_is_exact)
                {
                    self.complete_request_chain += 1;
                }
                syn::visit::visit_expr_method_call(self, node);
            }

            fn visit_local(&mut self, local: &'ast syn::Local) {
                if consumer_binding_is_exact(local) {
                    self.consumer_binding += 1;
                }
                syn::visit::visit_local(self, local);
            }
        }

        fn primary_ast_is_closed(source: &str) -> bool {
            let Ok(file) = syn::parse_file(source) else {
                return false;
            };
            if async_runner_import_count(&file) != 1 {
                return false;
            }
            let owned = file
                .items
                .iter()
                .filter_map(|item| match item {
                    syn::Item::Mod(item) if item.ident == "owned" => Some(item),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let [owned] = owned.as_slice() else {
                return false;
            };
            let Some((_, items)) = &owned.content else {
                return false;
            };
            let imports = items
                .iter()
                .filter(
                    |item| matches!(item, syn::Item::Use(item) if use_mentions_async_runner(item)),
                )
                .count();
            let starts = items
                .iter()
                .filter_map(|item| match item {
                    syn::Item::Fn(item) if item.sig.ident == "start_with_context" => Some(item),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let [start] = starts.as_slice() else {
                return false;
            };
            let mut visitor = OwnedStartVisitor::default();
            visitor.visit_block(&start.block);
            imports == 1
                && visitor.starts == 2
                && start_method_count(&file) == visitor.starts
                && visitor.consumer_binding == 1
                && visitor.complete_request_chain == 1
        }

        fn manifests_are_confined(manifests: &[(&str, &str)]) -> bool {
            fn references(
                value: &toml::Value,
                path: &mut Vec<String>,
                output: &mut Vec<Vec<String>>,
            ) {
                if let toml::Value::Table(table) = value {
                    for (key, value) in table {
                        path.push(key.clone());
                        if matches!(key.as_str(), "testcontainers" | "testcontainers-modules") {
                            output.push(path.clone());
                        }
                        references(value, path, output);
                        path.pop();
                    }
                }
            }

            manifests.iter().all(|(path, source)| {
                let Ok(value) = toml::from_str::<toml::Value>(source) else {
                    return false;
                };
                let mut refs = Vec::new();
                references(&value, &mut Vec::new(), &mut refs);
                refs.sort();
                match *path {
                    "Cargo.toml" => {
                        refs == [
                            ["workspace", "dependencies", "testcontainers"]
                                .map(str::to_string)
                                .to_vec(),
                            ["workspace", "dependencies", "testcontainers-modules"]
                                .map(str::to_string)
                                .to_vec(),
                        ]
                    }
                    "crates/testkit/Cargo.toml" => {
                        let expected = [
                            ["dependencies", "testcontainers"]
                                .map(str::to_string)
                                .to_vec(),
                            ["dependencies", "testcontainers-modules"]
                                .map(str::to_string)
                                .to_vec(),
                        ];
                        refs == expected
                            && expected.iter().all(|segments| {
                                let dependency = &segments[1];
                                value["dependencies"][dependency]["workspace"].as_bool()
                                    == Some(true)
                                    && value["dependencies"][dependency]["optional"].as_bool()
                                        == Some(true)
                            })
                    }
                    _ => refs.is_empty(),
                }
            })
        }

        let primary_count = workspace_rust_sources
            .iter()
            .filter(|(path, _)| *path == "crates/testkit/src/containers.rs")
            .count();
        let imports_are_confined = workspace_rust_sources.iter().all(|(path, source)| {
            let Ok(file) = syn::parse_file(source) else {
                return false;
            };
            if *path == "crates/testkit/src/containers.rs" {
                true
            } else {
                async_runner_import_count(&file) == 0
                    && (!path.starts_with("crates/testkit/") || start_method_count(&file) == 0)
            }
        });

        integration_container_source_contract_is_hardened(rust, shell, workflow)
            && primary_count == 1
            && primary_ast_is_closed(rust)
            && imports_are_confined
            && manifests_are_confined(workspace_manifests)
    }

    fn integration_container_source_contract_is_hardened(
        rust: &str,
        shell: &str,
        workflow: &str,
    ) -> bool {
        fn block<'a>(source: &'a str, start: &str, end: &str) -> Option<&'a str> {
            source
                .split_once(start)
                .and_then(|(_, tail)| tail.split_once(end).map(|(body, _)| body))
        }

        let exactly_once = |source: &str, needle: &str| source.matches(needle).count() == 1;

        let Some(owned) = block(rust, "mod owned {", "\n}\n\n/// postgres") else {
            return false;
        };
        let Some(service_enum) = block(
            rust,
            "enum ContainerService {",
            "\n}\n\nimpl ContainerService",
        ) else {
            return false;
        };
        let Some(service_impl) = block(rust, "impl ContainerService {", "\n}\n\n#[derive(Clone)]")
        else {
            return false;
        };
        let Some(label_matcher) = block(shell, "labels_match() {", "\n\ndiscover_candidates()")
        else {
            return false;
        };

        let runner_is_confined = exactly_once(rust, "use testcontainers::runners::AsyncRunner;")
            && owned.contains("use testcontainers::runners::AsyncRunner;")
            && rust.matches(".start()").count() == 2
            && owned.matches(".start()").count() == 2;
        let fixtures_are_closed = [
            "owned::start(image, ContainerService::Postgres).await?",
            "owned::start(Redis::default(), ContainerService::Redis).await?",
            "owned::start(RabbitMq::default(), ContainerService::RabbitMq).await?",
            "owned::start(Mosquitto::default(), ContainerService::Mosquitto).await?",
            "owned::start(MinIO::default(), ContainerService::Minio).await?",
        ]
        .iter()
        .all(|call| exactly_once(rust, call));
        let owned_request_chain_is_complete = exactly_once(
            owned,
            "BoundedFileLogConsumer::new(&context.log_dir, service)?",
        ) && owned.contains(
            ".into()\n            .with_labels(service.labels(&context))\n            .with_log_consumer(",
        );
        let services_are_closed = [
            ("Postgres,", "Self::Postgres => \"postgres\""),
            ("Redis,", "Self::Redis => \"redis\""),
            ("RabbitMq,", "Self::RabbitMq => \"rabbitmq\""),
            ("Mosquitto,", "Self::Mosquitto => \"mosquitto\""),
            ("Minio,", "Self::Minio => \"minio\""),
        ]
        .iter()
        .all(|(variant, arm)| {
            exactly_once(service_enum, variant) && exactly_once(service_impl, arm)
        }) && service_enum
            .lines()
            .filter(|line| line.trim().ends_with(','))
            .count()
            == 5;
        let context_env_is_closed = [
            ("CI_SCOPE_ENV", "RSS_CI_CONTAINER_SCOPE"),
            ("CI_SHARD_ENV", "RSS_CI_INTEGRATION_SHARD"),
            ("CI_PARTITION_ENV", "RSS_CI_INTEGRATION_PARTITION"),
            ("CI_LOG_DIR_ENV", "RSS_CI_CONTAINER_LOG_DIR"),
        ]
        .iter()
        .all(|(constant, value)| {
            exactly_once(rust, &format!("const {constant}: &str = \"{value}\";"))
                && workflow.contains(&format!("echo \"{value}=$"))
        }) && rust.contains(
            "const CI_CONTEXT_KEYS: &[&str] = &[CI_SCOPE_ENV, CI_SHARD_ENV, CI_PARTITION_ENV, CI_LOG_DIR_ENV];",
        );
        let labels_are_closed = [
            ("io.rss.integration.managed", 1),
            ("io.rss.integration.scope", 1),
            ("io.rss.integration.shard", 1),
            ("io.rss.integration.partition", 1),
            ("io.rss.integration.service", 5),
        ]
        .iter()
        .all(|(label, shell_count)| {
            exactly_once(service_impl, label)
                && label_matcher.matches(label).count() == *shell_count
        }) && ["postgres", "redis", "rabbitmq", "mosquitto", "minio"]
            .iter()
            .all(|service| {
                label_matcher.contains(&format!(
                    ".[\"io.rss.integration.service\"] == \"{service}\""
                ))
            });
        let partition_contract_is_closed = rust.contains(
            "matches!(value, \"unpartitioned\" | \"1/2\" | \"2/2\")",
        ) && shell.contains(
            "case \"$partition\" in unpartitioned|1/2|2/2) ;; *) die 'invalid partition' ;; esac",
        ) && workflow.contains(
            "case \"$partition\" in unpartitioned|1/2|2/2) ;; *) exit 64 ;; esac",
        );

        runner_is_confined
            && fixtures_are_closed
            && owned_request_chain_is_complete
            && services_are_closed
            && context_env_is_closed
            && labels_are_closed
            && partition_contract_is_closed
    }

    const REQUIRED_EVIDENCE_ARGS_BINDING: &str = "required_evidence_args=()";
    const REQUIRED_EVIDENCE_OUTPUT_BINDING: &str =
        "required_evidence_output=\"$RUNNER_TEMP/required-evidence.json\"";
    const REQUIRED_EVIDENCE_OUTPUT_ABSENCE_GUARD: &str = "if [ -e \"$required_evidence_output\" ] || [ -L \"$required_evidence_output\" ]; then exit 1; fi";
    const REQUIRED_EVIDENCE_ARGS_REQUEST: &str =
        "required_evidence_args=(--required-evidence-output \"$required_evidence_output\")";
    const REQUIRED_EVIDENCE_INVOCATION: &str = "/usr/bin/time -f 'userSeconds=%U\\nsystemSeconds=%S\\npeakRssKiB=%M' -o \"$RUNNER_TEMP/xtask-resource.txt\" timeout --signal=TERM --kill-after=30s 90m \"$CARGO_TARGET_DIR/debug/xtask\" ci run --job \"$RSS_CI_JOB_KEY\" \"${required_evidence_args[@]}\"";
    const REQUIRED_EVIDENCE_SOURCE_BINDING: &str =
        "required_evidence_source=\"$RUNNER_TEMP/required-evidence.json\"";
    const REQUIRED_EVIDENCE_SOURCE_GUARD: &str = "if [ -L \"$required_evidence_source\" ] || [ ! -f \"$required_evidence_source\" ]; then exit 1; fi";
    const REQUIRED_EVIDENCE_TARGET_ABSENCE_GUARD: &str = "if [ -e \"$required_evidence_target\" ] || [ -L \"$required_evidence_target\" ]; then exit 1; fi";
    const REQUIRED_EVIDENCE_STAGE: &str = "cp --no-dereference --remove-destination -- \"$required_evidence_source\" \"$required_evidence_target\"";
    const REQUIRED_EVIDENCE_TARGET_GUARD: &str = "if [ -L \"$required_evidence_target\" ] || [ ! -f \"$required_evidence_target\" ]; then exit 1; fi";
    const REQUIRED_EVIDENCE_TARGET_PATH_GUARD: &str =
        "case \"$RSS_CI_REQUIRED_EVIDENCE_TARGET\" in target/job-evidence/*) ;; *) exit 64 ;; esac";
    const REQUIRED_EVIDENCE_TYPED_STAGE: &str =
        "stage_required_evidence \"$RSS_CI_REQUIRED_EVIDENCE_TARGET\"";
    const REQUIRED_EVIDENCE_NON_OWNER_GUARD: &str = "if [ -e \"$required_evidence_source\" ] || [ -L \"$required_evidence_source\" ]; then exit 1; fi";

    fn workflow_run_line_count(steps: &[TypedStep], expected: &str) -> usize {
        steps
            .iter()
            .flat_map(|step| &step.run)
            .filter(|line| line.as_str() == expected)
            .count()
    }

    fn workflow_run_fragment_count(steps: &[TypedStep], expected: &str) -> usize {
        steps
            .iter()
            .flat_map(|step| &step.run)
            .map(|line| line.matches(expected).count())
            .sum()
    }

    /// Integration service lifecycle is intentionally modeled as a second, composable predicate:
    /// cache policy changes cannot silently weaken Docker ownership or evidence semantics.
    fn integration_service_lifecycle_is_hardened(yaml: &str) -> bool {
        let steps = yaml_typed_steps(yaml);
        let unique_index = |id: &str| {
            let matches = steps
                .iter()
                .enumerate()
                .filter_map(|(index, step)| (step.id.as_deref() == Some(id)).then_some(index))
                .collect::<Vec<_>>();
            (matches.len() == 1).then(|| matches[0])
        };
        let unique_name_index = |name: &str| {
            let matches = steps
                .iter()
                .enumerate()
                .filter_map(|(index, step)| (step.name.as_deref() == Some(name)).then_some(index))
                .collect::<Vec<_>>();
            (matches.len() == 1).then(|| matches[0])
        };

        let prepare = unique_index("integration-services-prepare");
        let xtask = unique_index("xtask");
        let snapshot = unique_index("integration-services-snapshot");
        let collect = unique_index("integration-services-collect");
        let cleanup = unique_index("integration-services-cleanup");
        let after_build = unique_name_index("Capture after-build evidence");
        let stage = unique_name_index("Stage job evidence");
        let upload = unique_name_index("Upload CI evidence");

        let prepare_ok = prepare.is_some_and(|index| {
            let step = &steps[index];
            step.name.as_deref() == Some("Prepare integration service lifecycle")
                && step.if_expr.as_deref()
                    == Some("${{ always() && inputs.lane == 'integration' }}")
                && step.env_exact("RSS_SHARD", &["${{ inputs.shard }}"])
                && step.env_exact("RSS_PARTITION", &["${{ inputs.partition }}"])
                && step.env_exact("RSS_PARTITION_LABEL", &["${{ inputs.partition-label }}"])
                && step.run_has_line("set -euo pipefail")
                && [
                    "case \"$GITHUB_REPOSITORY_ID\" in ''|*[!0-9]*) exit 64 ;; esac",
                    "case \"$GITHUB_RUN_ID\" in ''|*[!0-9]*) exit 64 ;; esac",
                    "case \"$GITHUB_RUN_ATTEMPT\" in ''|*[!0-9]*) exit 64 ;; esac",
                    "case \"$RSS_SHARD:$RSS_PARTITION_LABEL\" in :|*[!a-z0-9:-]*) exit 64 ;; esac",
                    "case \"$partition\" in unpartitioned|1/2|2/2) ;; *) exit 64 ;; esac",
                ]
                .iter()
                .all(|line| step.run_has_line(line))
                && step.run_has_line(
                    "scope=\"${GITHUB_REPOSITORY_ID}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${RSS_SHARD}-${RSS_PARTITION_LABEL}\"",
                )
                && step.run_has_line("if [ -z \"$partition\" ]; then partition=$RSS_PARTITION_LABEL; fi")
                && [
                    "echo \"RSS_CI_CONTAINER_SCOPE=$scope\"",
                    "echo \"RSS_CI_INTEGRATION_SHARD=$RSS_SHARD\"",
                    "echo \"RSS_CI_INTEGRATION_PARTITION=$partition\"",
                    "echo \"RSS_CI_CONTAINER_LOG_DIR=$log_dir\"",
                ]
                .iter()
                .all(|line| step.run_has_line(line))
                && step.run_has_line(
                    ".github/scripts/integration-services.sh bootstrap --scope \"$scope\" --shard \"$RSS_SHARD\" --partition \"$partition\" --log-dir \"$log_dir\" --evidence \"$evidence\"",
                )
                && step.run_has_line(
                    ".github/scripts/integration-services.sh prepare --scope \"$scope\" --shard \"$RSS_SHARD\" --partition \"$partition\" --log-dir \"$log_dir\" --evidence \"$evidence\"",
                )
        });
        let xtask_ok = xtask.is_some_and(|index| {
            let step = &steps[index];
            step.name.as_deref() == Some("Run closed xtask lane")
                && step.timeout_minutes.as_deref() == Some("92")
                && step.run_has_sequence(&[
                    REQUIRED_EVIDENCE_ARGS_BINDING,
                    "if [ -n \"$RSS_CI_REQUIRED_EVIDENCE_TARGET\" ]; then",
                    REQUIRED_EVIDENCE_OUTPUT_BINDING,
                    REQUIRED_EVIDENCE_OUTPUT_ABSENCE_GUARD,
                    REQUIRED_EVIDENCE_ARGS_REQUEST,
                    "fi",
                    REQUIRED_EVIDENCE_INVOCATION,
                ])
        });
        let snapshot_ok = snapshot.is_some_and(|index| {
            let step = &steps[index];
            step.name.as_deref() == Some("Snapshot integration service disk before cleanup")
                && step.if_expr.as_deref()
                    == Some("${{ always() && inputs.lane == 'integration' && steps.integration-services-prepare.outcome == 'success' }}")
                && step.timeout_minutes.as_deref() == Some("2")
                && step.run_has_line(
                    "timeout --signal=TERM --kill-after=5s 30s .github/scripts/integration-services.sh snapshot --scope \"$RSS_CI_CONTAINER_SCOPE\" --shard \"$RSS_CI_INTEGRATION_SHARD\" --partition \"$RSS_CI_INTEGRATION_PARTITION\" --log-dir \"$RSS_CI_CONTAINER_LOG_DIR\" --evidence \"$RUNNER_TEMP/integration-lifecycle.json\"",
                )
        });
        let collect_ok = collect.is_some_and(|index| {
            let step = &steps[index];
            step.name.as_deref() == Some("Finalize integration outcome and collect failure logs")
                && step.if_expr.as_deref()
                    == Some("${{ always() && inputs.lane == 'integration' && steps.integration-services-prepare.outcome == 'success' }}")
                && step.timeout_minutes.as_deref() == Some("12")
                && step.env_exact("RSS_XTASK_OUTCOME", &["${{ steps.xtask.outcome }}"])
                && step.run_has_line(
                    "case \"$RSS_XTASK_OUTCOME\" in success|failure|cancelled|skipped) ;; *) exit 64 ;; esac",
                )
                && step.run_has_line(
                    "timeout --signal=TERM --kill-after=30s 10m .github/scripts/integration-services.sh collect --scope \"$RSS_CI_CONTAINER_SCOPE\" --shard \"$RSS_CI_INTEGRATION_SHARD\" --partition \"$RSS_CI_INTEGRATION_PARTITION\" --log-dir \"$RSS_CI_CONTAINER_LOG_DIR\" --evidence \"$RUNNER_TEMP/integration-lifecycle.json\" --outcome \"$RSS_XTASK_OUTCOME\" --archive \"$RUNNER_TEMP/integration-service-logs.tar.gz\"",
                )
        });
        let cleanup_ok = cleanup.is_some_and(|index| {
            let step = &steps[index];
            step.name.as_deref() == Some("Cleanup integration services")
                && step.if_expr.as_deref()
                    == Some("${{ always() && inputs.lane == 'integration' && steps.integration-services-prepare.outcome == 'success' }}")
                && step.timeout_minutes.as_deref() == Some("12")
                && step.run_has_line(
                    "timeout --signal=TERM --kill-after=30s 10m .github/scripts/integration-services.sh cleanup --scope \"$RSS_CI_CONTAINER_SCOPE\" --shard \"$RSS_CI_INTEGRATION_SHARD\" --partition \"$RSS_CI_INTEGRATION_PARTITION\" --log-dir \"$RSS_CI_CONTAINER_LOG_DIR\" --evidence \"$RUNNER_TEMP/integration-lifecycle.json\"",
                )
        });
        let stage_ok = stage.is_some_and(|index| {
            let step = &steps[index];
            step.timeout_minutes.as_deref() == Some("5")
                && step.if_expr.as_deref() == Some("${{ always() }}")
                && step.run_has_line("if [ \"${{ inputs.lane }}\" = integration ]; then")
                && step.run_has_line("test -f \"$RUNNER_TEMP/integration-lifecycle.json\"")
                && step.run_has_line(
                    "jq -e '.collection.outcome == \"success\" or .collection.outcome == \"failure\" or .collection.outcome == \"cancelled\" or .collection.outcome == \"skipped\"' \"$RUNNER_TEMP/integration-lifecycle.json\" >/dev/null",
                )
                && step.run_has_line("mkdir -p target/job-evidence/integration")
                && step.run_has_line(
                    "cp \"$RUNNER_TEMP/integration-lifecycle.json\" target/job-evidence/integration/lifecycle.json",
                )
                && step.run_has_line(
                    "if [ -f \"$RUNNER_TEMP/integration-service-logs.tar.gz\" ]; then",
                )
                && step.run_has_line(
                    "cp \"$RUNNER_TEMP/integration-service-logs.tar.gz\" target/job-evidence/integration/service-logs.tar.gz",
                )
                && step.run_has_sequence(&[
                    REQUIRED_EVIDENCE_SOURCE_BINDING,
                    "stage_required_evidence() {",
                    "required_evidence_target=$1",
                    REQUIRED_EVIDENCE_SOURCE_GUARD,
                    "mkdir -p \"${required_evidence_target%/*}\"",
                    REQUIRED_EVIDENCE_TARGET_ABSENCE_GUARD,
                    REQUIRED_EVIDENCE_STAGE,
                    REQUIRED_EVIDENCE_TARGET_GUARD,
                    "}",
                    "if [ -n \"$RSS_CI_REQUIRED_EVIDENCE_TARGET\" ]; then",
                    REQUIRED_EVIDENCE_TARGET_PATH_GUARD,
                    REQUIRED_EVIDENCE_TYPED_STAGE,
                    "else",
                    REQUIRED_EVIDENCE_NON_OWNER_GUARD,
                    "fi",
                ])
                && !step.run.iter().any(|line| {
                    line.contains("RSS_CI_JOB_KEY")
                        || line.contains("localtx-required.json")
                        || line.contains("localonly-execution.json")
                })
        });
        let no_global_prune = steps.iter().flat_map(|step| &step.run).all(|line| {
            ![
                "docker system prune",
                "docker image prune",
                "docker volume prune",
            ]
            .iter()
            .any(|forbidden| line.contains(forbidden))
        });
        let lifecycle_command_owners = steps
            .iter()
            .filter(|step| {
                step.run
                    .iter()
                    .any(|line| line.contains(".github/scripts/integration-services.sh"))
            })
            .filter_map(|step| step.id.as_deref())
            .collect::<Vec<_>>();
        let total_step_budget = steps.iter().try_fold(0_u64, |total, step| {
            step.timeout_minutes
                .as_deref()?
                .parse::<u64>()
                .ok()
                .and_then(|budget| total.checked_add(budget))
        });

        prepare_ok
            && yaml.matches("timeout-minutes: 240").count() == 1
            && total_step_budget == Some(221)
            && xtask_ok
            && collect_ok
            && snapshot_ok
            && cleanup_ok
            && stage_ok
            && yaml.matches("required-evidence-target:").count() == 1
            && yaml
                .matches("RSS_CI_REQUIRED_EVIDENCE_TARGET: ${{ inputs.required-evidence-target }}")
                .count()
                == 1
            && [
                REQUIRED_EVIDENCE_ARGS_BINDING,
                REQUIRED_EVIDENCE_OUTPUT_BINDING,
                REQUIRED_EVIDENCE_OUTPUT_ABSENCE_GUARD,
                REQUIRED_EVIDENCE_ARGS_REQUEST,
                REQUIRED_EVIDENCE_INVOCATION,
                REQUIRED_EVIDENCE_SOURCE_BINDING,
                REQUIRED_EVIDENCE_SOURCE_GUARD,
                REQUIRED_EVIDENCE_TARGET_ABSENCE_GUARD,
                REQUIRED_EVIDENCE_STAGE,
                REQUIRED_EVIDENCE_TARGET_GUARD,
                REQUIRED_EVIDENCE_TARGET_PATH_GUARD,
                REQUIRED_EVIDENCE_TYPED_STAGE,
                REQUIRED_EVIDENCE_NON_OWNER_GUARD,
            ]
            .into_iter()
            .all(|line| workflow_run_line_count(&steps, line) == 1)
            && workflow_run_fragment_count(&steps, "--required-evidence-output") == 1
            && workflow_run_fragment_count(&steps, "localtx-required.json") == 0
            && workflow_run_fragment_count(&steps, "localonly-execution.json") == 0
            && no_global_prune
            && lifecycle_command_owners
                == [
                    "integration-services-prepare",
                    "integration-services-collect",
                    "integration-services-snapshot",
                    "integration-services-cleanup",
                ]
            && matches!(
                (prepare, xtask, collect, snapshot, cleanup, after_build, stage, upload),
                (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f), Some(g), Some(h))
                    if a < b && c == b + 1 && d == c + 1 && e == d + 1 && e < f && f < g && g < h
            )
    }

    fn reusable_rust_lane_is_hardened(yaml: &str) -> bool {
        const WRITER: &str = "RSS_CACHE_WRITER: ${{ (((inputs.lane == 'ci-meta' || inputs.lane == 'ci-core-prerequisites' || (inputs.lane == 'ci-core-tests' && inputs.partition == '1/2') || inputs.lane == 'ci-local-only' || inputs.lane == 'ci-security' || inputs.lane == 'ci-coverage' || (inputs.lane == 'integration' && inputs.shard == 'postgres-domain' && inputs.partition == '')) && github.event_name == 'push') || (inputs.lane == 'audit' && github.event_name == 'schedule')) && github.ref == 'refs/heads/develop' && github.ref_protected }}";
        let lines = yaml_indented_code_lines(yaml);
        let steps = yaml_typed_steps(yaml);
        let index = |id: &str| {
            let matches = steps
                .iter()
                .enumerate()
                .filter_map(|(index, step)| (step.id.as_deref() == Some(id)).then_some(index))
                .collect::<Vec<_>>();
            (matches.len() == 1).then(|| matches[0])
        };
        let name_index = |name: &str| {
            let matches = steps
                .iter()
                .enumerate()
                .filter_map(|(index, step)| (step.name.as_deref() == Some(name)).then_some(index))
                .collect::<Vec<_>>();
            (matches.len() == 1).then(|| matches[0])
        };
        let checkout = name_index("Checkout");
        let start = name_index("Capture start evidence");
        let policy = index("policy");
        let setup = index("setup");
        let measure_tools = index("measure-tools");
        let tools_budget = index("tools-budget");
        let save_tools = index("save-tools");
        let compiler_smoke = index("compiler-cache-smoke");
        let xtask = index("xtask");
        let measure_download = index("measure-download");
        let measure_compiler_cache = index("measure-compiler-cache");
        let before_save = index("before-save");
        let save_download = index("save-download");
        let save_compiler_cache = index("save-compiler-cache");
        let checkout_ok = checkout.is_some_and(|i| {
            steps[i].uses.as_deref() == Some("actions/checkout@v4")
                && steps[i].with_exact("persist-credentials", &["false"])
                && steps[i].with_exact("fetch-depth", &["0"])
                && steps[i].with_exact("ref", &["${{ inputs.source-revision }}"])
        });
        let tool_save_ok = save_tools.is_some_and(|i| {
            let step = &steps[i];
            step.uses.as_deref() == Some("actions/cache/save@v4")
                && step.continue_on_error.as_deref() == Some("true")
                && step.with_exact(
                    "path",
                    &[".cache/ci-tools/${{ steps.policy.outputs.profile }}"],
                )
                && step.with_exact(
                    "key",
                    &["${{ steps.setup.outputs.tools-primary-key }}"],
                )
                && step.if_expr.as_deref()
                    == Some("${{ env.RSS_CACHE_WRITER == 'true' && steps.setup.outcome == 'success' && steps.measure-tools.outcome == 'success' && steps.tools-budget.outcome == 'success' && steps.setup.outputs.tools-hit != 'true' }}")
        });
        let download_save_ok = save_download.is_some_and(|i| {
            let step = &steps[i];
            step.uses.as_deref() == Some("actions/cache/save@v4")
                && step.continue_on_error.as_deref() == Some("true")
                && step.with_exact(
                    "path",
                    &[
                        "~/.cargo/registry/cache",
                        "~/.cargo/registry/index",
                        "~/.cargo/git/db",
                    ],
                )
                && step.with_exact(
                    "key",
                    &["${{ steps.setup.outputs.download-primary-key }}"],
                )
                && step.if_expr.as_deref()
                    == Some("${{ env.RSS_CACHE_WRITER == 'true' && steps.xtask.outcome == 'success' && steps.measure-download.outcome == 'success' && steps.before-save.outcome == 'success' && steps.setup.outputs.download-hit != 'true' }}")
        });
        let compiler_save_ok = save_compiler_cache.is_some_and(|i| {
            let step = &steps[i];
            step.uses.as_deref() == Some("actions/cache/save@v4")
                && step.continue_on_error.as_deref() == Some("true")
                && step.with_exact("path", &["${{ runner.temp }}/rss-sccache-cache"])
                && step.with_exact(
                    "key",
                    &["${{ steps.setup.outputs.compiler-cache-primary-key }}"],
                )
                && step.if_expr.as_deref()
                    == Some("${{ env.RSS_CACHE_WRITER == 'true' && steps.xtask.outcome == 'success' && steps.measure-compiler-cache.outcome == 'success' && steps.before-save.outcome == 'success' }}")
        });
        let setup_ok = setup.is_some_and(|i| {
            let step = &steps[i];
            step.uses.as_deref() == Some("./.github/actions/setup-rss-ci")
                && step.with_exact("lane", &["${{ inputs.lane }}"])
                && step.with_exact("profile", &["${{ steps.policy.outputs.profile }}"])
                && step.with_exact("tool-cache-epoch", &["v4"])
                && step.with_exact("writer-mode", &["${{ env.RSS_CACHE_WRITER }}"])
                && step.with_exact("evidence-enabled", &["true"])
        });
        let policy_ok = policy.is_some_and(|i| {
            let step = &steps[i];
            step.env_exact("RSS_LANE", &["${{ inputs.lane }}"])
                && step.env_exact("RSS_SHARD", &["${{ inputs.shard }}"])
                && step.env_exact("RSS_PARTITION", &["${{ inputs.partition }}"])
                && step.run_contains("if [ \"$RSS_LANE\" = integration ]")
                && integration_policy_matches_catalog(yaml, &expected_integration_shards())
                && integration_partition_pairs(yaml) == Some(expected_integration_partition_pairs())
                && step.run_contains("case \"$RSS_SHARD:$RSS_PARTITION\" in")
                && step.run_contains("elif [ \"$RSS_LANE\" = ci-core-tests ]")
                && step.run_contains("elif [ -n \"$RSS_SHARD\" ]")
                && step.run_contains("case \"$RSS_LANE\" in")
                && [
                    [
                        "ci-meta)",
                        "echo 'profile=ci-meta'",
                        "echo 'nightly='",
                        ";;",
                    ]
                    .as_slice(),
                    [
                        "ci-core-prerequisites)",
                        "echo 'profile=ci-core-prerequisites'",
                        "echo \"nightly=$RSS_NIGHTLY_PINNED\"",
                        ";;",
                    ]
                    .as_slice(),
                    [
                        "ci-core-tests)",
                        "echo 'profile=ci-core-tests'",
                        "echo 'nightly='",
                        ";;",
                    ]
                    .as_slice(),
                    [
                        "ci-security)",
                        "echo 'profile=ci-security'",
                        "echo 'nightly='",
                        ";;",
                    ]
                    .as_slice(),
                    [
                        "ci-local-only)",
                        "echo 'profile=ci-local-only'",
                        "echo 'nightly='",
                        ";;",
                    ]
                    .as_slice(),
                    [
                        "ci-coverage)",
                        "echo 'profile=ci-coverage'",
                        "echo \"nightly=$RSS_NIGHTLY_PINNED\"",
                        ";;",
                    ]
                    .as_slice(),
                ]
                .iter()
                .all(|branch| step.run_has_sequence(branch))
                && step.run.iter().filter(|line| line.ends_with(')')).count() == 8
                && step.run_has_line("integration)")
                && step.run_has_line("audit)")
                && step.run_has_line("*) exit 64 ;;")
                && closed_lane_case(step) == Some(expected_reusable_lanes())
        });
        let xtask_ok = xtask.is_some_and(|i| {
            let step = &steps[i];
            step.env_exact("RSS_LANE", &["${{ inputs.lane }}"])
                && step.env_exact("RSS_SHARD", &["${{ inputs.shard }}"])
                && step.env_exact("RSS_PARTITION", &["${{ inputs.partition }}"])
                && step.env_exact(
                    "RSS_INTERNAL_SCCACHE_PATH",
                    &["${{ steps.setup.outputs.compiler-cache-path }}"],
                )
                && step.env_exact(
                    "RUSTC_WRAPPER",
                    &["${{ steps.setup.outputs.compiler-cache-path }}"],
                )
                && step.run_exact(&[
                    "set -euo pipefail",
                    "cargo build --locked -p xtask",
                    "reset_outcome=success",
                    "if ! \"$RSS_INTERNAL_SCCACHE_PATH\" --zero-stats; then",
                    "reset_outcome=degraded",
                    "fi",
                    "echo \"compiler-cache-reset=$reset_outcome\" >> \"$GITHUB_OUTPUT\"",
                    REQUIRED_EVIDENCE_ARGS_BINDING,
                    "if [ -n \"$RSS_CI_REQUIRED_EVIDENCE_TARGET\" ]; then",
                    REQUIRED_EVIDENCE_OUTPUT_BINDING,
                    REQUIRED_EVIDENCE_OUTPUT_ABSENCE_GUARD,
                    REQUIRED_EVIDENCE_ARGS_REQUEST,
                    "fi",
                    REQUIRED_EVIDENCE_INVOCATION,
                ])
        });
        let unique_ci_executor =
            workflow_ci_executor_owners(&steps) == [(Some("xtask"), "ci".to_owned())];
        let compiler_smoke_ok = compiler_smoke.is_some_and(|i| {
            let step = &steps[i];
            step.if_expr.as_deref() == Some("${{ inputs.lane == 'ci-core-prerequisites' }}")
                && step.timeout_minutes.as_deref() == Some("5")
                && step.run_exact(&[
                    "set -euo pipefail",
                    "smoke=\"$RUNNER_TEMP/rss-sccache-smoke\"",
                    "rm -rf \"$smoke\"",
                    "mkdir -p \"$smoke/src\"",
                    "printf '%s\\n' '[package]' 'name = \"rss-sccache-smoke\"' 'version = \"0.0.0\"' 'edition = \"2024\"' > \"$smoke/Cargo.toml\"",
                    "printf '%s\\n' 'pub fn answer() -> u64 { 42 }' > \"$smoke/src/lib.rs\"",
                    "\"$RSS_INTERNAL_SCCACHE_PATH\" --zero-stats",
                    "CARGO_TARGET_DIR=\"$smoke/target\" cargo check --manifest-path \"$smoke/Cargo.toml\"",
                    "rm -rf \"$smoke/target\"",
                    "CARGO_TARGET_DIR=\"$smoke/target\" cargo check --manifest-path \"$smoke/Cargo.toml\"",
                    "\"$RSS_INTERNAL_SCCACHE_PATH\" --show-stats --stats-format json > \"$smoke/warm-stats.json\"",
                    "jq -e '.stats.compile_requests > 0 and ([.stats.cache_hits.counts[]] | add // 0) > 0' \"$smoke/warm-stats.json\" >/dev/null",
                    "mkdir -p \"$smoke/unavailable\"",
                    "printf occupied > \"$smoke/unavailable/cache-parent\"",
                    "SCCACHE_DIR=\"$smoke/unavailable/cache-parent/child\" SCCACHE_SERVER_UDS=\"$smoke/unavailable-success.sock\" CARGO_TARGET_DIR=\"$smoke/fallback-success\" cargo check --manifest-path \"$smoke/Cargo.toml\"",
                    "printf '%s\\n' 'pub fn broken( {' > \"$smoke/src/lib.rs\"",
                    "if SCCACHE_DIR=\"$smoke/unavailable/cache-parent/child\" SCCACHE_SERVER_UDS=\"$smoke/unavailable-failure.sock\" CARGO_TARGET_DIR=\"$smoke/fallback-failure\" cargo check --manifest-path \"$smoke/Cargo.toml\"; then",
                    "echo 'compiler error was swallowed by unavailable cache backend' >&2",
                    "exit 1",
                    "fi",
                ])
        });
        let after_build_stats_ok = index("after-build").is_some_and(|i| {
            let step = &steps[i];
            step.if_expr.as_deref() == Some("${{ always() }}")
                && step.run_has_line(
                    "requests=0 hits=0 misses=0 non_cacheable=0 stats_valid=false anti_vacuity_failure=false",
                )
                && step.run_has_line(
                    "error_restore=0 error_stats=0 error_cache_io=0 error_no_requests=0 error_measure=0 error_save=0",
                )
                && step.env_exact(
                    "COMPILER_RESTORE_OUTCOME",
                    &["${{ steps.setup.outputs.compiler-cache-restore-outcome || 'skipped' }}"],
                )
                && step.env_exact(
                    "COMPILER_RESET_OUTCOME",
                    &["${{ steps.xtask.outputs.compiler-cache-reset || 'skipped' }}"],
                )
                && step.run_has_line(
                    "if [ \"$COMPILER_RESTORE_OUTCOME\" = failure ]; then error_restore=1; fi",
                )
                && step.run_has_line(
                    "if [ \"$COMPILER_RESET_OUTCOME\" = degraded ]; then error_stats=$((error_stats + 1)); fi",
                )
                && step.run_has_sequence(&[
                    "if \"$RSS_INTERNAL_SCCACHE_PATH\" --show-stats --stats-format json > \"$stats_file\" 2>/dev/null &&",
                    "stats_row=\"$(.github/scripts/ci-sccache-stats.sh parse --input \"$stats_file\" 2>/dev/null)\" &&",
                    "IFS=$'\\t' read -r requests hits misses non_cacheable error_cache_io stats_extra <<< \"$stats_row\" &&",
                    "[ -z \"$stats_extra\" ]; then",
                    "stats_valid=true",
                    "else",
                    "error_stats=$((error_stats + 1))",
                    "fi",
                ])
                && step.run_has_line(
                    "if [ \"$COMPILER_RESET_OUTCOME\" = success ] && [ \"$stats_valid\" = true ] && [ \"${{ inputs.lane }}\" = ci-core-prerequisites ] && [ \"$requests\" -le 0 ]; then",
                )
                && step.run_has_sequence(&[
                    "error_no_requests=$((error_no_requests + 1))",
                    "anti_vacuity_failure=true",
                    "fi",
                ])
                && step.run_contains("--compiler-cache-error-restore \"$error_restore\"")
                && step.run_contains("--compiler-cache-error-stats \"$error_stats\"")
                && step.run_contains("--compiler-cache-error-cache-io \"$error_cache_io\"")
                && step.run_contains(
                    "--compiler-cache-error-no-requests \"$error_no_requests\"",
                )
                && step.run_contains("--compiler-cache-error-measure \"$error_measure\"")
                && step.run_contains("--compiler-cache-error-save \"$error_save\"")
                && matches!(
                    (
                        step.run.iter().position(|line| line.contains("snapshot after-build")),
                        step.run.iter().position(|line| line.contains("ci-disk-budget.sh --stage after-build")),
                        step.run.iter().position(|line| line == "[ \"$anti_vacuity_failure\" = false ]"),
                    ),
                    (Some(snapshot), Some(budget), Some(gate)) if snapshot < budget && budget < gate
                )
        });
        let after_save_errors_ok = name_index("Capture after-save evidence").is_some_and(|i| {
            let step = &steps[i];
            step.if_expr.as_deref() == Some("${{ always() }}")
                && step.run_has_line(
                    "if [ \"${{ steps.measure-compiler-cache.outcome }}\" = failure ]; then error_measure=$((error_measure + 1)); fi",
                )
                && step.run_has_line(
                    "if [ \"${{ steps.save-compiler-cache.outcome }}\" = failure ]; then error_save=$((error_save + 1)); fi",
                )
                && step.run_contains("--compiler-cache-error-measure \"$error_measure\"")
                && step.run_contains("--compiler-cache-error-save \"$error_save\"")
        });
        let evidence_step = |name: &str, commands: &[&str]| {
            let matches = steps
                .iter()
                .filter(|step| {
                    step.name.as_deref() == Some(name)
                        && step.if_expr.as_deref() == Some("${{ always() }}")
                        && commands.iter().all(|command| step.run_contains(command))
                })
                .count();
            matches == 1
        };
        let evidence_ok = evidence_step(
            "Capture start evidence",
            &["snapshot start", "ci-disk-budget.sh --stage start"],
        ) && evidence_step(
            "Capture after-build evidence",
            &[
                "ensure after-cache",
                "snapshot after-build",
                "ci-disk-budget.sh --stage after-build --path \"$GITHUB_WORKSPACE\"",
            ],
        ) && evidence_step(
            "Capture before-save evidence and enforce cache budget",
            &[
                "ensure after-build",
                "snapshot before-save",
                "[ \"$budget_conclusion\" != failure ]",
            ],
        ) && evidence_step(
            "Capture after-save evidence",
            &["ensure before-save", "snapshot after-save"],
        );
        let stage_evidence = steps.iter().position(|step| {
            step.name.as_deref() == Some("Stage job evidence")
                && step.if_expr.as_deref() == Some("${{ always() }}")
                && step.run_has_line("set -euo pipefail")
                && step.run_has_line("rm -rf target/job-evidence")
                && step.run_has_line("mkdir -p target/job-evidence/ci")
                && step.run_has_line(
                    "cp \"$RUNNER_TEMP/$RSS_CI_EVIDENCE_FILE\" target/job-evidence/ci/ci-evidence.json",
                )
                && step.run_has_line("cargo run --locked -p xtask -- nextest-evidence stage")
        });
        let upload_evidence = steps.iter().position(|step| {
                step.name.as_deref() == Some("Upload CI evidence")
                    && step.if_expr.as_deref() == Some("${{ always() }}")
                    && step.uses.as_deref() == Some("actions/upload-artifact@v4")
                    && step.with_exact(
                        "name",
                        &["${{ format('ci-evidence-{0}-{1}-{2}-{3}-{4}', inputs.lane, inputs.shard || 'workspace', inputs.partition-label, github.run_id, github.run_attempt) }}"],
                    )
                    && step.with_exact("path", &["target/job-evidence"])
                    && step.with_exact("if-no-files-found", &["error"])
                    && step.with_exact("retention-days", &["7"])
            });
        let evidence_ok = evidence_ok
            && stage_evidence
                .is_some_and(|stage| upload_evidence.is_some_and(|upload| stage < upload))
            && steps
                .iter()
                .filter(|step| {
                    matches!(
                        step.name.as_deref(),
                        Some("Stage job evidence" | "Upload CI evidence")
                    )
                })
                .count()
                == 2;
        let intermediate_conditions_ok = measure_tools.is_some_and(|i| {
            steps[i].if_expr.as_deref()
                == Some("${{ env.RSS_CACHE_WRITER == 'true' && steps.setup.outcome == 'success' && steps.setup.outputs.tools-hit != 'true' }}")
        }) && tools_budget.is_some_and(|i| {
            steps[i].if_expr.as_deref()
                == Some("${{ env.RSS_CACHE_WRITER == 'true' && steps.measure-tools.outcome == 'success' }}")
        }) && measure_download.is_some_and(|i| {
            steps[i].if_expr.as_deref()
                == Some("${{ env.RSS_CACHE_WRITER == 'true' && steps.xtask.outcome == 'success' && steps.setup.outputs.download-hit != 'true' }}")
        }) && measure_compiler_cache.is_some_and(|i| {
            steps[i].if_expr.as_deref()
                == Some("${{ env.RSS_CACHE_WRITER == 'true' && steps.xtask.outcome == 'success' }}")
        }) && before_save.is_some_and(|i| {
            steps[i].if_expr.as_deref() == Some("${{ always() }}")
        });
        lines
            .iter()
            .any(|(indent, line)| *indent == 2 && *line == "workflow_call:")
            && lines
                .iter()
                .filter(|(indent, line)| *indent == 8 && *line == "required: true")
                .count()
                == 4
            && lines
                .iter()
                .filter(|(indent, line)| *indent == 8 && *line == "required: false")
                .count()
                == 4
            && lines
                .iter()
                .filter(|(indent, line)| *indent == 8 && *line == "type: string")
                .count()
                == 8
            && lines
                .iter()
                .any(|(indent, line)| *indent == 2 && *line == "contents: read")
            && lines
                .iter()
                .any(|(indent, line)| *indent == 2 && *line == "CARGO_INCREMENTAL: 0")
            && lines
                .iter()
                .any(|(indent, line)| *indent == 2 && *line == "CARGO_BUILD_JOBS: 2")
            && root_mapping_has_exact_entries(
                yaml,
                "env",
                &[
                    "RSS_CI_JOB_KEY: ${{ inputs.ci-job-key }}",
                    "RSS_CI_PLAN_DIGEST: ${{ inputs.plan-digest }}",
                    "RSS_CI_SOURCE_REVISION: ${{ inputs.source-revision }}",
                    "RSS_CI_REQUIRED_EVIDENCE_TARGET: ${{ inputs.required-evidence-target }}",
                ],
            )
            && start.is_some_and(|i| {
                steps[i].env_exact("CARGO_TARGET_DIR", &["${{ runner.temp }}/rss-cargo-target"])
            })
            && lines
                .iter()
                .filter(|(indent, line)| *indent == 2 && *line == WRITER)
                .count()
                == 1
            && policy_ok
            && checkout_ok
            && setup_ok
            && tool_save_ok
            && download_save_ok
            && compiler_save_ok
            && xtask_ok
            && unique_ci_executor
            && compiler_smoke_ok
            && after_build_stats_ok
            && after_save_errors_ok
            && evidence_ok
            && intermediate_conditions_ok
            && integration_service_lifecycle_is_hardened(yaml)
            && steps
                .iter()
                .filter(|step| step.uses.as_deref() == Some("actions/cache/save@v4"))
                .count()
                == 3
            && ![
                "target-primary-key",
                "target-cache",
                "save-target",
                "rss-target",
                ".cache/cargo-target",
                "ci-cache-maintain.sh cleanup --workspace",
                "measure-build",
                "SCCACHE_GHA_ENABLED",
                "SCCACHE_GHA_VERSION",
            ]
            .iter()
            .any(|forbidden| yaml.contains(forbidden))
            && matches!((checkout, start, policy, setup, measure_tools, tools_budget, save_tools, compiler_smoke, xtask, measure_download, measure_compiler_cache, before_save, save_download, save_compiler_cache),
                (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f), Some(g), Some(h), Some(i), Some(j), Some(k), Some(l), Some(m), Some(n))
                    if b == a + 1 && c == b + 1 && d == c + 1 && e == d + 1 && f == e + 1 && g == f + 1 && g < h && h < i && i < j && j < k && k < l && l < m && m < n)
    }

    fn reusable_rust_lane_slo_contract(yaml: &str) -> bool {
        let steps = yaml_typed_steps(yaml);
        let unique_name_index = |name: &str| {
            let matches = steps
                .iter()
                .enumerate()
                .filter_map(|(index, step)| (step.name.as_deref() == Some(name)).then_some(index))
                .collect::<Vec<_>>();
            (matches.len() == 1).then(|| matches[0])
        };
        let after_save = unique_name_index("Capture after-save evidence");
        let stage = unique_name_index("Stage job evidence");
        let upload = unique_name_index("Upload CI evidence");
        let evaluate = unique_name_index("Evaluate CI SLO and write summary");

        let upload_ok = upload.is_some_and(|index| {
            let step = &steps[index];
            step.id.as_deref() == Some("upload-evidence")
                && step.if_expr.as_deref() == Some("${{ always() }}")
                && step.continue_on_error.is_none()
                && step.uses.as_deref() == Some("actions/upload-artifact@v4")
        });
        let evaluate_ok = evaluate.is_some_and(|index| {
            let step = &steps[index];
            step.timeout_minutes.as_deref() == Some("3")
                && step.if_expr.as_deref() == Some("${{ always() }}")
                && step.continue_on_error.is_none()
                && step.env_exact("RSS_LANE", &["${{ inputs.lane }}"])
                && step.env_exact("RSS_SHARD", &["${{ inputs.shard }}"])
                && step.env_exact("RSS_PARTITION", &["${{ inputs.partition }}"])
                && step.run_has_line("set -euo pipefail")
                && step.run_has_line("args=(ci-slo evaluate --lane \"$RSS_LANE\")")
                && step.run_has_line("if [ \"$RSS_LANE\" = integration ]; then args+=(--shard \"$RSS_SHARD\"); fi")
                && step.run_has_line("if [ -n \"$RSS_PARTITION\" ]; then args+=(--partition \"$RSS_PARTITION\"); fi")
                && step.run_has_line("args+=(--run-id \"$GITHUB_RUN_ID\" --run-attempt \"$GITHUB_RUN_ATTEMPT\" --upload-outcome \"${{ steps.upload-evidence.outcome }}\")")
                && step.run_has_line("args+=(--github-summary)")
                && step.run_has_line("cargo run --locked -p xtask -- \"${args[@]}\"")
                && !step.run_contains(">> \"$GITHUB_STEP_SUMMARY\"")
        });
        let disk_guard_lines = steps
            .iter()
            .flat_map(|step| step.run.iter())
            .filter(|line| line.contains(".github/scripts/ci-disk-budget.sh"))
            .map(String::as_str)
            .collect::<Vec<_>>();
        let disk_guards_ok = disk_guard_lines
            == [
                ".github/scripts/ci-disk-budget.sh --stage start --path \"$GITHUB_WORKSPACE\"",
                ".github/scripts/ci-disk-budget.sh --stage before-save --path \"$GITHUB_WORKSPACE\"",
                ".github/scripts/ci-disk-budget.sh --stage after-build --path \"$GITHUB_WORKSPACE\"",
                "if .github/scripts/ci-disk-budget.sh --stage before-save --path \"$GITHUB_WORKSPACE\"; then budget_conclusion=success; else budget_conclusion=failure; fi",
            ]
            && steps
                .iter()
                .filter(|step| {
                    step.run_contains(".github/scripts/ci-disk-budget.sh")
                        && step.continue_on_error.is_some()
                })
                .count()
                == 0;

        matches!((after_save, stage, upload, evaluate),
            (Some(a), Some(b), Some(c), Some(d)) if b == a + 1 && c == b + 1 && d == c + 1)
            && upload_ok
            && evaluate_ok
            && disk_guards_ok
    }

    fn reusable_rust_lane_prepares_target_before_start_snapshot(yaml: &str) -> bool {
        const PREPARE_TARGET: &str = "mkdir -p \"$CARGO_TARGET_DIR\"";
        const SNAPSHOT_PREFIX: &str = ".github/scripts/ci-evidence.sh snapshot start ";
        let steps = yaml_typed_steps(yaml);
        let starts = steps
            .iter()
            .filter(|step| step.name.as_deref() == Some("Capture start evidence"))
            .collect::<Vec<_>>();
        if starts.len() != 1 {
            return false;
        }
        let step = starts[0];
        if !step.env_exact("CARGO_TARGET_DIR", &["${{ runner.temp }}/rss-cargo-target"]) {
            return false;
        }
        let run = &step.run;
        let positions = |matches: &dyn Fn(&str) -> bool| {
            run.iter()
                .enumerate()
                .filter_map(|(index, line)| matches(line).then_some(index))
                .collect::<Vec<_>>()
        };
        let strict = positions(&|line| line == "set -euo pipefail");
        let prepare = positions(&|line| line == PREPARE_TARGET);
        let snapshot = positions(&|line| line.starts_with(SNAPSHOT_PREFIX));
        matches!(
            (strict.as_slice(), prepare.as_slice(), snapshot.as_slice()),
            ([strict], [prepare], [snapshot]) if strict < prepare && prepare < snapshot
        )
    }

    fn ci_disk_budget_uses_fixed_config_threshold(shell: &str) -> bool {
        shell.contains("config_path=$path/.config/ci-slo.toml")
            && shell.contains("min_free_gib=$(awk '")
            && shell.contains("if (count == 1 && valid == 1) print value; else exit 1")
            && shell.contains("reason=config-invalid")
            && !shell.contains("--min-free-gib")
            && !shell.contains("min_free_gib=5")
    }

    fn camouflage_step_run(yaml: &str, id: &str, field: &str) -> anyhow::Result<String> {
        camouflage_step_run_marker(yaml, &format!("id: {id}"), field)
    }

    fn camouflage_named_step_run(yaml: &str, name: &str, field: &str) -> anyhow::Result<String> {
        camouflage_step_run_marker(yaml, &format!("name: {name}"), field)
    }

    fn camouflage_step_run_marker(yaml: &str, marker: &str, field: &str) -> anyhow::Result<String> {
        let id_marker = marker.to_owned();
        let id_token = yaml
            .find(&id_marker)
            .ok_or_else(|| anyhow::anyhow!("synthetic step `{marker}` missing"))?;
        let id_index = yaml[..id_token].rfind('\n').map_or(0, |index| index + 1);
        let field_indent = yaml[id_index..id_token].len();
        let field_spaces = " ".repeat(field_indent);
        let item_spaces = " ".repeat(field_indent - 2);
        let run_marker = format!("{field_spaces}run: |");
        let run_offset = yaml[id_index..]
            .find(&run_marker)
            .ok_or_else(|| anyhow::anyhow!("synthetic step `{marker}` has no block run"))?;
        let run_index = id_index + run_offset;
        let end = yaml[run_index + 1..]
            .find(&format!("\n{item_spaces}- name:"))
            .map_or(yaml.len(), |offset| run_index + 1 + offset);
        let body = &yaml[run_index + run_marker.len()..end];
        let camouflage = match field {
            "name" => format!(
                "{field_spaces}run: true\n{field_spaces}name: {}",
                body.lines().map(str::trim).collect::<Vec<_>>().join(" ")
            ),
            "env" => {
                let indented = body
                    .lines()
                    .map(|line| format!("{}{line}", " ".repeat(field_indent + 4)))
                    .collect::<Vec<_>>()
                    .join("\n");
                format!(
                    "{field_spaces}run: true\n{field_spaces}env:\n{field_spaces}  CAMOUFLAGE: |\n{indented}"
                )
            }
            _ => unreachable!(),
        };
        Ok(format!(
            "{}{}{}",
            &yaml[..run_index],
            camouflage,
            &yaml[end..]
        ))
    }

    fn camouflage_step_if(yaml: &str, id: &str, field: &str) -> anyhow::Result<String> {
        let id_marker = format!("id: {id}");
        let id_token = yaml
            .find(&id_marker)
            .ok_or_else(|| anyhow::anyhow!("synthetic step `{id}` missing"))?;
        let id_index = yaml[..id_token].rfind('\n').map_or(0, |index| index + 1);
        let field_indent = yaml[id_index..id_token].len();
        let field_spaces = " ".repeat(field_indent);
        let if_offset = yaml[id_index..]
            .find(&format!("{field_spaces}if: "))
            .ok_or_else(|| anyhow::anyhow!("synthetic step `{id}` has no if field"))?;
        let if_index = id_index + if_offset;
        let end = yaml[if_index..]
            .find('\n')
            .map_or(yaml.len(), |offset| if_index + offset);
        let expression = yaml[if_index + field_indent + "if: ".len()..end].trim();
        let replacement = match field {
            "name" => format!("{field_spaces}name: {expression}"),
            "env" => format!("{field_spaces}env:\n{field_spaces}  CAMOUFLAGE_IF: {expression}"),
            _ => unreachable!(),
        };
        Ok(format!(
            "{}{}{}",
            &yaml[..if_index],
            replacement,
            &yaml[end..]
        ))
    }

    #[test]
    fn typed_steps_ignore_nested_steps_text_in_run_and_env() {
        let synthetic = r#"jobs:
  lane:
    steps:
      - id: real-run
        run: |
          steps:
            - id: fake-run
              uses: actions/cache/save@v4
      - id: real-env
        env:
          SCRIPT: |
            steps:
              - id: fake-env
                if: true
        run: true
"#;
        let steps = yaml_typed_steps(synthetic);
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].id.as_deref(), Some("real-run"));
        assert_eq!(steps[1].id.as_deref(), Some("real-env"));
        assert!(
            steps
                .iter()
                .all(|step| { !matches!(step.id.as_deref(), Some("fake-run" | "fake-env")) })
        );
    }

    #[test]
    fn reusable_rust_lane_evidence_staging_is_single_root_and_fail_closed() -> anyhow::Result<()> {
        let path = workspace_root()?.join(".github/workflows/rss-rust-lane.yml");
        let green = std::fs::read_to_string(path)?;
        for red in [
            green.replacen("      - name: Stage job evidence", "      - name: Other", 1),
            green.replacen("path: target/job-evidence", "path: target", 1),
            green.replacen(
                "cargo run --locked -p xtask -- nextest-evidence stage",
                "cp -R target/nextest-evidence/. target/job-evidence/nextest/",
                1,
            ),
            green.replacen(
                "          path: target/job-evidence",
                "          path: |\n            target/job-evidence\n            target/nextest-evidence",
                1,
            ),
        ] {
            assert!(!reusable_rust_lane_is_hardened(&red));
        }
        Ok(())
    }

    #[test]
    fn reusable_rust_lane_stages_typed_required_evidence_red() -> anyhow::Result<()> {
        let green =
            std::fs::read_to_string(workspace_root()?.join(".github/workflows/rss-rust-lane.yml"))?;
        assert!(integration_service_lifecycle_is_hardened(&green));
        let duplicate_line = |line: &str| -> anyhow::Result<String> {
            let original = green
                .lines()
                .find(|candidate| candidate.trim() == line)
                .with_context(|| format!("committed workflow omits `{line}`"))?;
            Ok(green.replacen(original, &format!("{original}\n{original}"), 1))
        };
        let reds = [
            (
                "missing output binding",
                green.replacen(REQUIRED_EVIDENCE_OUTPUT_BINDING, "true", 1),
            ),
            (
                "duplicate output binding",
                duplicate_line(REQUIRED_EVIDENCE_OUTPUT_BINDING)?,
            ),
            (
                "duplicate temporary source binding",
                duplicate_line(REQUIRED_EVIDENCE_SOURCE_BINDING)?,
            ),
            (
                "owner switch resurrected",
                green.replacen(
                    REQUIRED_EVIDENCE_TYPED_STAGE,
                    &format!(
                        "case \"$RSS_CI_JOB_KEY\" in\nci-local-only) {REQUIRED_EVIDENCE_TYPED_STAGE} ;;\n*) exit 64 ;;\nesac"
                    ),
                    1,
                ),
            ),
            (
                "duplicate staging",
                duplicate_line(REQUIRED_EVIDENCE_STAGE)?,
            ),
            (
                "owner symlink laundering",
                green.replacen(
                    REQUIRED_EVIDENCE_STAGE,
                    "cp \"$required_evidence_source\" \"$required_evidence_target\"",
                    1,
                ),
            ),
            (
                "owner source symlink accepted",
                green.replacen(
                    REQUIRED_EVIDENCE_SOURCE_GUARD,
                    "test -f \"$required_evidence_source\"",
                    1,
                ),
            ),
            (
                "owner target type unchecked",
                green.replacen(REQUIRED_EVIDENCE_TARGET_GUARD, "true", 1),
            ),
            (
                "non-owner dangling symlink accepted",
                green.replacen(
                    REQUIRED_EVIDENCE_NON_OWNER_GUARD,
                    "test ! -e \"$required_evidence_source\"",
                    1,
                ),
            ),
        ];
        for (label, red) in reds {
            assert_ne!(red, green, "{label} fixture must mutate the workflow");
            assert!(
                !integration_service_lifecycle_is_hardened(&red),
                "{label} must fail closed"
            );
        }
        Ok(())
    }

    #[test]
    fn reusable_rust_lane_slo_contract_accepts_committed_workflow() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let green = std::fs::read_to_string(root.join(".github/workflows/rss-rust-lane.yml"))?;
        let disk_guard = std::fs::read_to_string(root.join(".github/scripts/ci-disk-budget.sh"))?;
        assert!(
            reusable_rust_lane_slo_contract(&green),
            "committed reusable workflow must enforce the complete CI SLO lifecycle"
        );
        assert!(
            ci_disk_budget_uses_fixed_config_threshold(&disk_guard),
            "live disk guard must consume the fixed SLO config threshold"
        );
        Ok(())
    }

    #[test]
    fn reusable_rust_lane_prepares_canonical_target_before_start_snapshot() -> anyhow::Result<()> {
        const PREPARE_TARGET: &str = "          mkdir -p \"$CARGO_TARGET_DIR\"";
        let green =
            std::fs::read_to_string(workspace_root()?.join(".github/workflows/rss-rust-lane.yml"))?;
        assert!(
            reusable_rust_lane_prepares_target_before_start_snapshot(&green),
            "clean runner must create the canonical target before its start snapshot"
        );

        let workspace_target = green.replacen(
            "          CARGO_TARGET_DIR: ${{ runner.temp }}/rss-cargo-target",
            "          CARGO_TARGET_DIR: ${{ github.workspace }}/.cache/cargo-target",
            1,
        );
        assert!(!reusable_rust_lane_prepares_target_before_start_snapshot(
            &workspace_target
        ));

        let removed = green.replacen(&format!("{PREPARE_TARGET}\n"), "", 1);
        assert!(!reusable_rust_lane_prepares_target_before_start_snapshot(
            &removed
        ));
        let changed = green.replacen(
            PREPARE_TARGET,
            "          mkdir -p \"$GITHUB_WORKSPACE/target\"",
            1,
        );
        assert!(!reusable_rust_lane_prepares_target_before_start_snapshot(
            &changed
        ));
        let without_prepare = green.replacen(&format!("{PREPARE_TARGET}\n"), "", 1);
        let moved = without_prepare.replacen(
            "          .github/scripts/ci-disk-budget.sh --stage start --path \"$GITHUB_WORKSPACE\"",
            &format!(
                "          .github/scripts/ci-disk-budget.sh --stage start --path \"$GITHUB_WORKSPACE\"\n{PREPARE_TARGET}"
            ),
            1,
        );
        assert!(!reusable_rust_lane_prepares_target_before_start_snapshot(
            &moved
        ));
        Ok(())
    }

    #[test]
    fn reusable_rust_lane_slo_contract_rejects_semantic_weakening() -> anyhow::Result<()> {
        let path = workspace_root()?.join(".github/workflows/rss-rust-lane.yml");
        let green = std::fs::read_to_string(path)?;
        assert!(reusable_rust_lane_slo_contract(&green));
        let disk_guard =
            std::fs::read_to_string(workspace_root()?.join(".github/scripts/ci-disk-budget.sh"))?;
        assert!(ci_disk_budget_uses_fixed_config_threshold(&disk_guard));
        assert!(
            !ci_disk_budget_uses_fixed_config_threshold(&disk_guard.replacen(
                "config_path=$path/.config/ci-slo.toml",
                "config_path=$path/.config/other.toml",
                1,
            )),
            "changed config source must fail closed"
        );
        assert!(
            !ci_disk_budget_uses_fixed_config_threshold(&format!("{disk_guard}\nmin_free_gib=5\n")),
            "reintroduced threshold default must fail closed"
        );
        assert!(
            !ci_disk_budget_uses_fixed_config_threshold(&format!(
                "{disk_guard}\n# legacy --min-free-gib override\n"
            )),
            "reintroduced threshold override must fail closed"
        );
        let replace_last = |source: &str, from: &str, to: &str| -> anyhow::Result<String> {
            let (prefix, suffix) = source
                .rsplit_once(from)
                .ok_or_else(|| anyhow::anyhow!("committed green lacks evaluator line"))?;
            Ok(format!("{prefix}{to}{suffix}"))
        };
        for (label, red) in [
            (
                "renamed evaluator",
                green.replacen(
                    "name: Evaluate CI SLO and write summary",
                    "name: Report CI metrics",
                    1,
                ),
            ),
            (
                "evaluator no longer always",
                green.replacen(
                    "name: Evaluate CI SLO and write summary\n        timeout-minutes: 3\n        if: ${{ always() }}",
                    "name: Evaluate CI SLO and write summary\n        timeout-minutes: 3\n        if: ${{ success() }}",
                    1,
                ),
            ),
            (
                "upload no longer always",
                green.replacen(
                    "id: upload-evidence\n        timeout-minutes: 10\n        if: ${{ always() }}",
                    "id: upload-evidence\n        timeout-minutes: 10\n        if: ${{ success() }}",
                    1,
                ),
            ),
            (
                "upload id removed",
                green.replacen("        id: upload-evidence\n", "", 1),
            ),
            (
                "github summary mode removed",
                green.replacen("          args+=(--github-summary)\n", "", 1),
            ),
            (
                "stdout redirected into summary",
                replace_last(
                    &green,
                    "cargo run --locked -p xtask -- \"${args[@]}\"",
                    "cargo run --locked -p xtask -- \"${args[@]}\" >> \"$GITHUB_STEP_SUMMARY\"",
                )?,
            ),
            (
                "lane omitted",
                green.replacen(" --lane \"$RSS_LANE\"", "", 1),
            ),
            (
                "integration shard omitted",
                green.replacen(" args+=(--shard \"$RSS_SHARD\")", "", 1),
            ),
            (
                "partition omitted",
                replace_last(
                    &green,
                    "if [ -n \"$RSS_PARTITION\" ]; then args+=(--partition \"$RSS_PARTITION\"); fi",
                    "if [ -n \"$RSS_PARTITION\" ]; then :; fi",
                )?,
            ),
            (
                "run id omitted",
                green.replacen("--run-id \"$GITHUB_RUN_ID\" ", "", 1),
            ),
            (
                "run identity omitted",
                green.replacen(
                    " --run-attempt \"$GITHUB_RUN_ATTEMPT\"",
                    "",
                    1,
                ),
            ),
            (
                "upload outcome omitted",
                green.replacen(
                    " --upload-outcome \"${{ steps.upload-evidence.outcome }}\"",
                    "",
                    1,
                ),
            ),
            (
                "disk threshold overridden",
                green.replacen(
                    "--stage start --path \"$GITHUB_WORKSPACE\"",
                    "--stage start --path \"$GITHUB_WORKSPACE\" --min-free-gib 1",
                    1,
                ),
            ),
            (
                "disk guard weakened",
                green.replacen(
                    ".github/scripts/ci-disk-budget.sh --stage after-build --path \"$GITHUB_WORKSPACE\"",
                    ".github/scripts/ci-disk-budget.sh --stage after-build --path \"$GITHUB_WORKSPACE\" || true",
                    1,
                ),
            ),
        ] {
            assert!(
                !reusable_rust_lane_slo_contract(&red),
                "{label} must fail closed"
            );
        }
        let evaluator_start = green
            .find("      - name: Evaluate CI SLO and write summary")
            .ok_or_else(|| anyhow::anyhow!("committed green lacks evaluator step"))?;
        assert!(
            !reusable_rust_lane_slo_contract(&green[..evaluator_start]),
            "deleted evaluator step must fail closed"
        );
        let moved_before_stage = green
            .replacen(
                "name: Evaluate CI SLO and write summary",
                "name: TEMP SLO",
                1,
            )
            .replacen(
                "name: Stage job evidence",
                "name: Evaluate CI SLO and write summary",
                1,
            )
            .replacen("name: TEMP SLO", "name: Stage job evidence", 1);
        assert!(
            !reusable_rust_lane_slo_contract(&moved_before_stage),
            "evaluator before stage/upload must fail closed"
        );
        Ok(())
    }

    fn assert_reusable_step_camouflage_rejected(green: &str) -> anyhow::Result<()> {
        for id in ["policy", "compiler-cache-smoke", "xtask", "before-save"] {
            for field in ["name", "env"] {
                assert!(!reusable_rust_lane_is_hardened(&camouflage_step_run(
                    green, id, field
                )?));
            }
        }
        for id in ["save-tools", "compiler-cache-smoke", "before-save"] {
            for field in ["name", "env"] {
                assert!(!reusable_rust_lane_is_hardened(&camouflage_step_if(
                    green, id, field
                )?));
            }
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn reusable_rust_lane_guard_rejects_semantic_weakening() -> anyhow::Result<()> {
        let path = workspace_root()?.join(".github/workflows/rss-rust-lane.yml");
        let green = std::fs::read_to_string(&path)?;
        assert!(root_mapping_has_exact_entries(
            &green,
            "env",
            &[
                "RSS_CI_JOB_KEY: ${{ inputs.ci-job-key }}",
                "RSS_CI_PLAN_DIGEST: ${{ inputs.plan-digest }}",
                "RSS_CI_SOURCE_REVISION: ${{ inputs.source-revision }}",
                "RSS_CI_REQUIRED_EVIDENCE_TARGET: ${{ inputs.required-evidence-target }}",
            ],
        ));
        let green_steps = yaml_typed_steps(&green);
        let checkout = green_steps
            .iter()
            .find(|step| step.name.as_deref() == Some("Checkout"))
            .context("checkout step")?;
        assert!(checkout.with_exact("ref", &["${{ inputs.source-revision }}"]));
        let policy = green_steps
            .iter()
            .find(|step| step.id.as_deref() == Some("policy"))
            .context("closed lane policy step")?;
        assert_eq!(
            closed_lane_case(policy),
            Some(expected_reusable_lanes()),
            "policy"
        );
        assert!(reusable_rust_lane_is_hardened(&green));
        assert_eq!(
            integration_policy_shards(&green),
            Some(expected_integration_shards()),
            "reusable policy allowlist 必须与 typed catalog 精确一致"
        );
        let mut future_catalog = expected_integration_shards();
        future_catalog.push("future-shard");
        assert!(
            !integration_policy_matches_catalog(&green, &future_catalog),
            "catalog 新增 shard 而 reusable allowlist 未同步时必须 red"
        );
        for (needle, replacement) in [
            ("required: true", "required: false"),
            (
                "ref: ${{ inputs.source-revision }}",
                "ref: ${{ github.sha }}",
            ),
            (
                "RSS_CI_JOB_KEY: ${{ inputs.ci-job-key }}",
                "RSS_CI_JOB_KEY: ci-meta",
            ),
            (
                "RSS_CI_PLAN_DIGEST: ${{ inputs.plan-digest }}",
                "RSS_CI_PLAN_DIGEST: stale",
            ),
            (
                "RSS_CI_SOURCE_REVISION: ${{ inputs.source-revision }}",
                "RSS_CI_SOURCE_REVISION: ${{ github.sha }}",
            ),
            (" && github.ref_protected", ""),
            ("profile=ci", "profile=shared"),
            (
                "ci-core-tests)\n              echo 'profile=ci-core-tests'",
                "ci-core-tests)\n              echo 'profile=ci-core'",
            ),
            ("continue-on-error: true", "continue-on-error: false"),
            ("tool-cache-epoch: v4", "tool-cache-epoch: v3"),
            (
                "steps.setup.outputs.tools-primary-key",
                "steps.setup.outputs.target-primary-key",
            ),
            (
                "CARGO_TARGET_DIR: ${{ runner.temp }}/rss-cargo-target",
                "CARGO_TARGET_DIR: ${{ github.workspace }}/.cache/cargo-target",
            ),
            ("~/.cargo/registry/cache", "~/.cargo/registry"),
            ("evidence-enabled: true", "evidence-enabled: false"),
            ("retention-days: 7", "retention-days: 8"),
            ("inputs.partition-label, github.run_id", "github.run_id"),
            ("event-transport:2/2|", ""),
            ("event-transport:2/2", "event-transport:2/3"),
            (
                "(inputs.lane == 'ci-core-tests' && inputs.partition == '1/2')",
                "inputs.lane == 'ci-core-tests'",
            ),
            ("inputs.partition == '1/2'", "inputs.partition == '2/2'"),
            (
                "|cdc-projection-saga:|object-storage:) ;;",
                "|future-shard:|cdc-projection-saga:|object-storage:) ;;",
            ),
            (
                "requests=0 hits=0 misses=0 non_cacheable=0 stats_valid=false anti_vacuity_failure=false",
                "requests=0 hits=0 misses=0 non_cacheable=0 stats_valid=false",
            ),
            (
                "if [ \"$COMPILER_RESTORE_OUTCOME\" = failure ]; then error_restore=1; fi",
                "true",
            ),
            (
                "if [ \"$COMPILER_RESET_OUTCOME\" = success ] && [ \"$stats_valid\" = true ] && [ \"${{ inputs.lane }}\" = ci-core-prerequisites ]",
                "if [ \"$stats_valid\" = true ] && [ \"${{ inputs.lane }}\" = ci-core-prerequisites ]",
            ),
            (
                "if [ \"$COMPILER_RESET_OUTCOME\" = degraded ]; then error_stats=$((error_stats + 1)); fi",
                "true",
            ),
            (
                "stats_row=\"$(.github/scripts/ci-sccache-stats.sh parse --input \"$stats_file\" 2>/dev/null)\" &&",
                "stats_row='0 0 0 0 0' &&",
            ),
            ("[ -z \"$stats_extra\" ]; then", "true; then"),
            ("anti_vacuity_failure=true", "anti_vacuity_failure=false"),
            ("[ \"$anti_vacuity_failure\" = false ]", "true"),
            (
                "ci run --job \"$RSS_CI_JOB_KEY\"",
                "ci run --job \"ci-meta\"",
            ),
            (
                "if [ \"${{ steps.measure-compiler-cache.outcome }}\" = failure ]; then error_measure=$((error_measure + 1)); fi",
                "true",
            ),
            (
                "if [ \"${{ steps.save-compiler-cache.outcome }}\" = failure ]; then error_save=$((error_save + 1)); fi",
                "true",
            ),
        ] {
            let red = green.replacen(needle, replacement, 1);
            assert!(
                !reusable_rust_lane_is_hardened(&red),
                "weakening `{needle}` must fail closed"
            );
        }
        for (label, red) in [
            (
                "typed-executor-omits-job",
                green.replacen(
                    " ci run --job \"$RSS_CI_JOB_KEY\"",
                    " ci run",
                    1,
                ),
            ),
            (
                "legacy-lane-case-restored",
                green.replacen(
                    "          cargo build --locked -p xtask",
                    "          case \"$RSS_LANE\" in ci-meta) args=(ci-meta) ;; esac\n          cargo build --locked -p xtask",
                    1,
                ),
            ),
            (
                "extra-executor-restored",
                green.replacen(
                    "          cargo build --locked -p xtask",
                    "          cargo build --locked -p xtask\n          cargo run --locked -p xtask -- ci-meta",
                    1,
                ),
            ),
            (
                "cross-step-extra-executor",
                green.replacen(
                    "          requests=0 hits=0 misses=0 non_cacheable=0 stats_valid=false anti_vacuity_failure=false",
                    "          cargo run --locked -p xtask -- ci run --job ci-meta\n          requests=0 hits=0 misses=0 non_cacheable=0 stats_valid=false anti_vacuity_failure=false",
                    1,
                ),
            ),
            (
                "cross-step-package-equals-executor",
                green.replacen(
                    "          requests=0 hits=0 misses=0 non_cacheable=0 stats_valid=false anti_vacuity_failure=false",
                    "          cargo run --package=xtask -- ci run --job ci-meta\n          requests=0 hits=0 misses=0 non_cacheable=0 stats_valid=false anti_vacuity_failure=false",
                    1,
                ),
            ),
            (
                "cross-step-manifest-executor",
                green.replacen(
                    "          requests=0 hits=0 misses=0 non_cacheable=0 stats_valid=false anti_vacuity_failure=false",
                    "          cargo run --manifest-path xtask/Cargo.toml -- audit\n          requests=0 hits=0 misses=0 non_cacheable=0 stats_valid=false anti_vacuity_failure=false",
                    1,
                ),
            ),
            (
                "smoke-delete",
                green.replacen("          \"$RSS_INTERNAL_SCCACHE_PATH\" --zero-stats\n", "", 1),
            ),
            (
                "smoke-reorder",
                green.replacen(
                    "          CARGO_TARGET_DIR=\"$smoke/target\" cargo check --manifest-path \"$smoke/Cargo.toml\"\n          rm -rf \"$smoke/target\"",
                    "          rm -rf \"$smoke/target\"\n          CARGO_TARGET_DIR=\"$smoke/target\" cargo check --manifest-path \"$smoke/Cargo.toml\"",
                    1,
                ),
            ),
            (
                "smoke-no-op",
                green.replacen(
                    "          CARGO_TARGET_DIR=\"$smoke/target\" cargo check --manifest-path \"$smoke/Cargo.toml\"",
                    "          CARGO_TARGET_DIR=\"$smoke/target\" cargo check --manifest-path \"$smoke/Cargo.toml\" || true",
                    1,
                ),
            ),
            (
                "smoke-unreachable",
                green.replacen(
                    "          \"$RSS_INTERNAL_SCCACHE_PATH\" --zero-stats",
                    "          exit 0\n          \"$RSS_INTERNAL_SCCACHE_PATH\" --zero-stats",
                    1,
                ),
            ),
        ] {
            assert!(
                !reusable_rust_lane_is_hardened(&red),
                "{label} must fail closed"
            );
        }
        for forbidden in [
            "target-primary-key: stale",
            "id: target-cache",
            "id: save-target",
            "run: ci-cache-maintain.sh cleanup --workspace /tmp --target /tmp/target",
            "path: .cache/cargo-target",
        ] {
            assert!(
                !reusable_rust_lane_is_hardened(&format!("{green}\n{forbidden}\n")),
                "removed target cache lifecycle `{forbidden}` must remain rejected"
            );
        }
        let post_execution_tools = green.replacen(
            "      - name: Save verified tool cache before repository execution",
            "      - name: Run closed xtask lane copy\n        id: xtask-copy\n        run: cargo run --locked -p xtask -- ci\n\n      - name: Save verified tool cache before repository execution",
            1,
        );
        assert!(
            !reusable_rust_lane_is_hardened(&post_execution_tools),
            "arbitrary repository execution before tool save must be rejected"
        );
        assert_reusable_step_camouflage_rejected(&green)?;
        for (index, camouflage) in [
            green.replace("id: save-tools", "name: save-tools"),
            green.replace("uses: actions/cache/save@v4", "name: actions/cache/save@v4"),
            green.replace(
                "key: ${{ steps.setup.outputs.tools-primary-key }}",
                "run: echo 'key: ${{ steps.setup.outputs.tools-primary-key }}'",
            ),
            green.lines().map(|line| format!("# {line}\n")).collect(),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                !reusable_rust_lane_is_hardened(&camouflage),
                "camouflage {index}"
            );
        }
        Ok(())
    }

    #[test]
    fn integration_container_source_contract_accepts_committed_sources() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let rust = std::fs::read_to_string(root.join("crates/testkit/src/containers.rs"))?;
        let shell = std::fs::read_to_string(root.join(".github/scripts/integration-services.sh"))?;
        let workflow = std::fs::read_to_string(root.join(".github/workflows/rss-rust-lane.yml"))?;
        let (workspace_rust_sources, workspace_manifests) =
            integration_container_workspace_inputs(&root)?;
        let rust_refs = workspace_rust_sources
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect::<Vec<_>>();
        let manifest_refs = workspace_manifests
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect::<Vec<_>>();
        assert!(
            integration_container_workspace_contract_is_hardened(
                &rust,
                &shell,
                &workflow,
                &rust_refs,
                &manifest_refs,
            ),
            "committed testkit/shell/workflow contract must exercise the source guard"
        );
        Ok(())
    }

    #[test]
    fn integration_container_source_contract_synthetic_red() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let rust = std::fs::read_to_string(root.join("crates/testkit/src/containers.rs"))?;
        let shell = std::fs::read_to_string(root.join(".github/scripts/integration-services.sh"))?;
        let workflow = std::fs::read_to_string(root.join(".github/workflows/rss-rust-lane.yml"))?;
        let red_cases = [
            (
                rust.replacen(
                    "use testcontainers::runners::AsyncRunner;",
                    "use testcontainers::runners::AsyncRunner as Runner;",
                    1,
                ),
                shell.clone(),
                workflow.clone(),
            ),
            (
                rust.replacen(
                    "owned::start(Redis::default(), ContainerService::Redis).await?",
                    "Redis::default().start().await?",
                    1,
                ),
                shell.clone(),
                workflow.clone(),
            ),
            (
                rust.replacen("    Mosquitto,", "    Nats,", 1),
                shell.clone(),
                workflow.clone(),
            ),
            (
                rust.replacen(
                    "const CI_LOG_DIR_ENV: &str = \"RSS_CI_CONTAINER_LOG_DIR\";",
                    "const CI_LOG_DIR_ENV: &str = \"RSS_CI_LOG_DIRECTORY\";",
                    1,
                ),
                shell.clone(),
                workflow.clone(),
            ),
            (
                rust.replacen("io.rss.integration.service", "io.rss.integration.kind", 1),
                shell.clone(),
                workflow.clone(),
            ),
            (
                rust.replacen(
                    ".with_labels(service.labels(&context))",
                    ".without_ownership_labels(service.labels(&context))",
                    1,
                ),
                shell.clone(),
                workflow.clone(),
            ),
            (
                rust.replacen(".with_log_consumer(", ".without_log_consumer(", 1),
                shell.clone(),
                workflow.clone(),
            ),
            (
                rust.replacen(
                    "matches!(value, \"unpartitioned\" | \"1/2\" | \"2/2\")",
                    "matches!(value, \"unpartitioned\" | \"1/3\" | \"2/3\" | \"3/3\")",
                    1,
                ),
                shell.clone(),
                workflow.clone(),
            ),
            (
                rust.clone(),
                shell.replacen(
                    "case \"$partition\" in unpartitioned|1/2|2/2) ;; *) die 'invalid partition' ;; esac",
                    "case \"$partition\" in unpartitioned|1/3|2/3|3/3) ;; *) die 'invalid partition' ;; esac",
                    1,
                ),
                workflow.clone(),
            ),
            (
                rust.clone(),
                shell.clone(),
                workflow.replacen(
                    "echo \"RSS_CI_INTEGRATION_SHARD=$RSS_SHARD\"",
                    "echo \"RSS_CI_SHARD=$RSS_SHARD\"",
                    1,
                ),
            ),
        ];
        for (index, (red_rust, red_shell, red_workflow)) in red_cases.into_iter().enumerate() {
            assert!(
                !integration_container_source_contract_is_hardened(
                    &red_rust,
                    &red_shell,
                    &red_workflow,
                ),
                "container source contract synthetic red {index} must fail closed"
            );
        }
        Ok(())
    }

    #[test]
    fn integration_container_guard_covers_cross_source_and_manifest_bypasses() -> anyhow::Result<()>
    {
        let root = workspace_root()?;
        let rust = std::fs::read_to_string(root.join("crates/testkit/src/containers.rs"))?;
        let shell = std::fs::read_to_string(root.join(".github/scripts/integration-services.sh"))?;
        let workflow = std::fs::read_to_string(root.join(".github/workflows/rss-rust-lane.yml"))?;
        let (workspace_rust_sources, workspace_manifests) =
            integration_container_workspace_inputs(&root)?;

        let mut bypass_sources = workspace_rust_sources.clone();
        bypass_sources.push((
            "crates/testkit/src/raw_runner_bypass.rs".to_string(),
            "use testcontainers::runners::AsyncRunner as RawRunner;\nasync fn bypass() { let _ = image.start().await; }\n".to_string(),
        ));
        let bypass_refs = bypass_sources
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect::<Vec<_>>();
        let manifest_refs = workspace_manifests
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect::<Vec<_>>();

        for (name, mutated) in [
            (
                "empty ownership labels",
                rust.replacen("service.labels(&context)", "BTreeMap::new()", 1),
            ),
            (
                "no-op log consumer",
                rust.replacen(
                    "if let Err(error) = consumer.write_frame(frame) {",
                    "if let Err(error) = Ok::<(), anyhow::Error>(()) {",
                    1,
                ),
            ),
        ] {
            let mut mutated_sources = workspace_rust_sources.clone();
            let primary = mutated_sources
                .iter_mut()
                .find(|(path, _)| path == "crates/testkit/src/containers.rs")
                .ok_or_else(|| anyhow::anyhow!("testkit containers source missing"))?;
            primary.1 = mutated.clone();
            let mutated_refs = mutated_sources
                .iter()
                .map(|(path, source)| (path.as_str(), source.as_str()))
                .collect::<Vec<_>>();
            assert!(
                !integration_container_workspace_contract_is_hardened(
                    &mutated,
                    &shell,
                    &workflow,
                    &mutated_refs,
                    &manifest_refs,
                ),
                "{name} must fail the AST ownership funnel"
            );
        }

        assert!(
            !integration_container_workspace_contract_is_hardened(
                &rust,
                &shell,
                &workflow,
                &bypass_refs,
                &manifest_refs,
            ),
            "an AsyncRunner import in a second testkit source must fail closed"
        );

        let mut start_bypass_sources = workspace_rust_sources.clone();
        start_bypass_sources.push((
            "crates/testkit/src/preimported_runner_bypass.rs".to_string(),
            "async fn bypass() { let _ = image.start().await; }\n".to_string(),
        ));
        let start_bypass_refs = start_bypass_sources
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect::<Vec<_>>();
        assert!(
            !integration_container_workspace_contract_is_hardened(
                &rust,
                &shell,
                &workflow,
                &start_bypass_refs,
                &manifest_refs,
            ),
            "a pre-imported direct start in a second testkit source must fail closed"
        );

        let mut bypass_manifests = workspace_manifests;
        bypass_manifests.push((
            "crates/identity/Cargo.toml".to_string(),
            "[package]\nname='bypass'\nversion='0.0.0'\n[dependencies]\ntestcontainers={ workspace=true }\n"
                .to_string(),
        ));
        let rust_refs = workspace_rust_sources
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect::<Vec<_>>();
        let bypass_manifest_refs = bypass_manifests
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect::<Vec<_>>();
        assert!(
            !integration_container_workspace_contract_is_hardened(
                &rust,
                &shell,
                &workflow,
                &rust_refs,
                &bypass_manifest_refs,
            ),
            "a direct testcontainers dependency outside testkit must fail closed"
        );
        Ok(())
    }

    #[test]
    fn core_test_plans_include_the_testkit_container_gate() {
        for target in [
            PlanTarget::Verify,
            PlanTarget::CompatibilityCi,
            PlanTarget::Core(CoreExecution::Tests),
        ] {
            let count = labels(&plan_for(target))
                .into_iter()
                .filter(|label| *label == "testkit-container-tests")
                .count();
            assert_eq!(
                count, 1,
                "{target:?} must execute the targeted testkit containers scope exactly once"
            );
        }
    }

    #[test]
    fn integration_service_lifecycle_predicate_green_and_synthetic_red() -> anyhow::Result<()> {
        let path = workspace_root()?.join(".github/workflows/rss-rust-lane.yml");
        let green = std::fs::read_to_string(path)?;
        assert!(
            integration_service_lifecycle_is_hardened(&green),
            "committed reusable workflow must exercise the lifecycle predicate"
        );

        let reorder_cleanup_before_collect = green
            .replacen(
                "name: Finalize integration outcome and collect failure logs",
                "name: TEMP",
                1,
            )
            .replacen(
                "name: Cleanup integration services",
                "name: Finalize integration outcome and collect failure logs",
                1,
            )
            .replacen("name: TEMP", "name: Cleanup integration services", 1);
        let reorder_collect_before_snapshot = green
            .replacen(
                "name: Snapshot integration service disk before cleanup",
                "name: TEMP",
                1,
            )
            .replacen(
                "name: Finalize integration outcome and collect failure logs",
                "name: Snapshot integration service disk before cleanup",
                1,
            )
            .replacen(
                "name: TEMP",
                "name: Finalize integration outcome and collect failure logs",
                1,
            );
        let reds = [
            green.replacen(
                "      - name: Prepare integration service lifecycle",
                "      - name: Disabled integration service lifecycle",
                1,
            ),
            green.replacen(
                "always() && inputs.lane == 'integration' && steps.integration-services-prepare.outcome == 'success'",
                "always() && inputs.lane == 'integration'",
                1,
            ),
            green.replacen(
                "id: integration-services-cleanup\n        if: ${{ always() && inputs.lane == 'integration' && steps.integration-services-prepare.outcome == 'success' }}",
                "id: integration-services-cleanup\n        if: ${{ inputs.lane == 'integration' && steps.integration-services-prepare.outcome == 'success' }}",
                1,
            ),
            green.replacen(
                "if: ${{ always() && inputs.lane == 'integration' }}",
                "if: ${{ inputs.lane == 'integration' }}",
                1,
            ),
            green.replacen(
                ".github/scripts/integration-services.sh bootstrap --scope \"$scope\"",
                ".github/scripts/integration-services.sh prepare-state --scope \"$scope\"",
                1,
            ),
            green.replacen("--scope \"$RSS_CI_CONTAINER_SCOPE\"", "--scope integration", 1),
            green.replacen(
                "integration-services.sh cleanup",
                "integration-services.sh cleanup && docker system prune -af",
                1,
            ),
            green.replacen(
                "test -f \"$RUNNER_TEMP/integration-lifecycle.json\"",
                "true",
                1,
            ),
            green.replacen(
                "if [ -f \"$RUNNER_TEMP/integration-service-logs.tar.gz\" ]; then",
                "if true; then",
                1,
            ),
            green.replacen(
                "      required-evidence-target:",
                "      required-evidence-destination:",
                1,
            ),
            green.replacen(REQUIRED_EVIDENCE_OUTPUT_BINDING, "true", 1),
            green.replacen(REQUIRED_EVIDENCE_SOURCE_GUARD, "true", 1),
            green.replacen(
                REQUIRED_EVIDENCE_STAGE,
                "cp \"$required_evidence_source\" \"$required_evidence_target\"",
                1,
            ),
            green.replacen(
                "RSS_CI_REQUIRED_EVIDENCE_TARGET: ${{ inputs.required-evidence-target }}",
                "RSS_CI_REQUIRED_EVIDENCE_TARGET: target/job-evidence/forged.json",
                1,
            ),
            green.replacen(REQUIRED_EVIDENCE_NON_OWNER_GUARD, "true", 1),
            green.replacen(
                "case \"$RSS_XTASK_OUTCOME\" in success|failure|cancelled|skipped) ;; *) exit 64 ;; esac",
                "case \"$RSS_XTASK_OUTCOME\" in success|failure) ;; *) exit 64 ;; esac",
                1,
            ),
            green.replacen(
                REQUIRED_EVIDENCE_INVOCATION,
                "cargo run --locked -p xtask -- ci full",
                1,
            ),
            green.replacen(
                "      - name: Checkout\n        timeout-minutes: 5",
                "      - name: Checkout",
                1,
            ),
            green.replacen("timeout-minutes: 240", "timeout-minutes: 219", 1),
            green.replacen(
                "jq -e '.collection.outcome == \"success\" or .collection.outcome == \"failure\" or .collection.outcome == \"cancelled\" or .collection.outcome == \"skipped\"'",
                "jq -e .",
                1,
            ),
            reorder_cleanup_before_collect,
            reorder_collect_before_snapshot,
        ];
        for (index, red) in reds.into_iter().enumerate() {
            assert!(
                !integration_service_lifecycle_is_hardened(&red),
                "lifecycle synthetic red {index} must fail closed"
            );
        }
        Ok(())
    }

    #[test]
    fn integration_finally_chain_has_terminal_outcomes_and_independent_budgets()
    -> anyhow::Result<()> {
        let path = workspace_root()?.join(".github/workflows/rss-rust-lane.yml");
        let workflow = std::fs::read_to_string(path)?;
        let steps = yaml_typed_steps(&workflow);
        let step_budgets = steps
            .iter()
            .map(|step| {
                step.timeout_minutes
                    .as_deref()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "workflow step {:?} is outside the total timeout proof",
                            step.name
                        )
                    })?
                    .parse::<u64>()
                    .map_err(Into::into)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let job_budget = 240_u64;
        assert!(
            workflow.contains("    timeout-minutes: 240"),
            "job ceiling must reserve the closed sum of all step budgets"
        );
        assert!(
            step_budgets.iter().sum::<u64>() <= job_budget,
            "step timeout sum must fit inside the job ceiling"
        );
        let index = |id: &str| {
            steps
                .iter()
                .position(|step| step.id.as_deref() == Some(id))
                .unwrap_or(usize::MAX)
        };
        let xtask = index("xtask");
        let collect = index("integration-services-collect");
        let snapshot = index("integration-services-snapshot");
        let cleanup = index("integration-services-cleanup");
        assert_eq!(collect, xtask + 1, "collect must start the finally chain");
        assert_eq!(
            snapshot,
            collect + 1,
            "snapshot must follow collect directly"
        );
        assert_eq!(
            cleanup,
            snapshot + 1,
            "cleanup must follow snapshot directly"
        );

        for contract in [
            "timeout-minutes: 240",
            "case \"$RSS_SHARD:$RSS_PARTITION_LABEL\" in :|*[!a-z0-9:-]*) exit 64 ;; esac",
            "id: xtask\n        timeout-minutes: 92",
            "RSS_CI_REQUIRED_EVIDENCE_TARGET: ${{ inputs.required-evidence-target }}",
            REQUIRED_EVIDENCE_ARGS_BINDING,
            REQUIRED_EVIDENCE_OUTPUT_BINDING,
            REQUIRED_EVIDENCE_OUTPUT_ABSENCE_GUARD,
            REQUIRED_EVIDENCE_ARGS_REQUEST,
            REQUIRED_EVIDENCE_INVOCATION,
            "RSS_XTASK_OUTCOME: ${{ steps.xtask.outcome }}",
            "case \"$RSS_XTASK_OUTCOME\" in success|failure|cancelled|skipped) ;; *) exit 64 ;; esac",
            "timeout --signal=TERM --kill-after=30s 10m .github/scripts/integration-services.sh collect",
            "timeout --signal=TERM --kill-after=5s 30s .github/scripts/integration-services.sh snapshot",
            "timeout --signal=TERM --kill-after=30s 10m .github/scripts/integration-services.sh cleanup",
            "jq -e '.collection.outcome == \"success\" or .collection.outcome == \"failure\" or .collection.outcome == \"cancelled\" or .collection.outcome == \"skipped\"'",
            REQUIRED_EVIDENCE_SOURCE_BINDING,
            REQUIRED_EVIDENCE_SOURCE_GUARD,
            REQUIRED_EVIDENCE_TARGET_ABSENCE_GUARD,
            REQUIRED_EVIDENCE_STAGE,
            REQUIRED_EVIDENCE_TARGET_GUARD,
            REQUIRED_EVIDENCE_TARGET_PATH_GUARD,
            REQUIRED_EVIDENCE_TYPED_STAGE,
            REQUIRED_EVIDENCE_NON_OWNER_GUARD,
        ] {
            assert!(
                workflow.contains(contract),
                "integration terminal lifecycle is missing exact contract: {contract}"
            );
        }
        assert_eq!(
            workflow.matches("timeout-minutes: 12").count(),
            2,
            "collect and cleanup must each reserve a 12-minute step budget"
        );
        assert_eq!(
            steps[snapshot].timeout_minutes.as_deref(),
            Some("2"),
            "snapshot must reserve its own two-minute step budget"
        );
        for outcome in ["success", "failure", "cancelled", "skipped"] {
            assert!(
                workflow.contains(outcome),
                "xtask terminal outcome vocabulary is missing {outcome}"
            );
        }
        Ok(())
    }

    #[test]
    fn reusable_guard_locks_start_order_and_after_build_budget() -> anyhow::Result<()> {
        let path = workspace_root()?.join(".github/workflows/rss-rust-lane.yml");
        let green = std::fs::read_to_string(&path)?;
        let start_after_policy = green
            .replacen(
                "name: Validate lane and derive closed policy",
                "name: TEMP policy",
                1,
            )
            .replacen(
                "name: Capture start evidence",
                "name: Validate lane and derive closed policy",
                1,
            )
            .replacen("name: TEMP policy", "name: Capture start evidence", 1);
        assert!(
            !reusable_rust_lane_is_hardened(&start_after_policy),
            "start evidence must be the first repository-owned post-checkout step"
        );
        let missing_budget = green.replacen(
            "ci-disk-budget.sh --stage after-build --path \"$GITHUB_WORKSPACE\"",
            "missing-after-build-budget",
            1,
        );
        assert!(!reusable_rust_lane_is_hardened(&missing_budget));
        for field in ["name", "env"] {
            assert!(
                !reusable_rust_lane_is_hardened(&camouflage_named_step_run(
                    &green,
                    "Capture after-build evidence",
                    field,
                )?),
                "after-build evidence and budget in {field} with run:true must fail closed"
            );
        }
        Ok(())
    }

    #[test]
    fn thin_lane_callers_reject_dynamic_or_expanded_execution() -> anyhow::Result<()> {
        let root = workspace_root()?.join(".github/workflows");
        for removed in ["integration.yml", "audit.yml"] {
            assert!(
                !root.join(removed).exists(),
                "legacy caller {removed} must stay deleted"
            );
        }
        let green = std::fs::read_to_string(root.join("ci.yml"))?;
        assert!(pipeline_delegates_to_xtask_ci(&green));
        for (index, red) in [
            green.replace("lane: ${{ matrix.lane }}", "lane: integration"),
            green.replace(
                "uses: ./.github/workflows/rss-rust-lane.yml",
                "name: ./.github/workflows/rss-rust-lane.yml",
            ),
            green.replace("contents: read", "contents: write"),
            format!("{green}\nenv:\n  RSS_CACHE_WRITER: true\n"),
            format!("{green}\nsteps:\n  - run: true\n"),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(!pipeline_delegates_to_xtask_ci(&red), "caller red {index}");
        }
        Ok(())
    }

    fn assert_action_step_camouflage_rejected(green: &str) -> anyhow::Result<()> {
        for id in [
            "cache-keys",
            "verify-tools",
            "compiler-policy",
            "after-cache",
        ] {
            for field in ["name", "env"] {
                assert!(!setup_action_has_exact_split_cache_contract(
                    &camouflage_step_run(green, id, field)?
                ));
            }
        }
        for field in ["name", "env"] {
            assert!(!setup_action_has_exact_split_cache_contract(
                &camouflage_step_if(green, "after-cache", field)?
            ));
        }
        Ok(())
    }

    #[test]
    fn split_cache_action_guard_rejects_field_camouflage_and_prefix_restore() -> anyhow::Result<()>
    {
        let path = workspace_root()?.join(".github/actions/setup-rss-ci/action.yml");
        let green = std::fs::read_to_string(path)?;
        assert!(setup_action_has_exact_split_cache_contract(&green));
        for (needle, replacement) in [
            ("required: true", "required: false"),
            (
                "value: ${{ steps.download-cache.outputs.cache-hit }}",
                "value: false",
            ),
            (
                "key: ${{ steps.cache-keys.outputs.download-primary-key }}",
                "key: wrong",
            ),
            (
                "RSS_JOB_TARGET: ${{ runner.temp }}/rss-cargo-target",
                "RSS_JOB_TARGET: ${{ github.workspace }}/.cache/cargo-target",
            ),
            (
                "COMPILER_RESTORE_OUTCOME: ${{ steps.compiler-cache.outcome }}",
                "COMPILER_RESTORE_OUTCOME: success",
            ),
            (
                "DOWNLOAD_RESTORE_OUTCOME: ${{ steps.download-cache.outcome }}",
                "DOWNLOAD_RESTORE_OUTCOME: success",
            ),
            (
                "TOOLS_RESTORE_OUTCOME: ${{ steps.tools-cache.outcome }}",
                "TOOLS_RESTORE_OUTCOME: success",
            ),
            ("--outcome \"$DOWNLOAD_RESTORE_OUTCOME\" --hit", "--hit"),
            ("--outcome \"$TOOLS_RESTORE_OUTCOME\" --hit", "--hit"),
            (
                "if [ \"$DOWNLOAD_RESTORE_OUTCOME\" = success ]; then",
                "if true; then",
            ),
            (
                "if [ \"$TOOLS_RESTORE_OUTCOME\" = success ]; then",
                "if true; then",
            ),
            ("[ \"$RSS_PROFILE\" = \"$RSS_LANE\" ]", "true"),
            (
                "$GITHUB_RUN_ATTEMPT-$RSS_LANE",
                "$GITHUB_RUN_ATTEMPT-$GITHUB_JOB",
            ),
            (
                "RSS_VERIFIED_SCCACHE_PATH: ${{ steps.verify-tools.outputs.compiler-cache-path }}",
                "RSS_VERIFIED_SCCACHE_PATH: /usr/bin/sccache",
            ),
            (
                ".github/scripts/ci-tool-adapters.sh verify-sccache --candidate",
                "printf '%s'",
            ),
            (
                "ci-meta|ci-core-prerequisites|ci-core-tests|ci-local-only|ci-security|ci-coverage|integration|audit",
                "ci|integration|audit",
            ),
        ] {
            assert!(
                !setup_action_has_exact_split_cache_contract(&green.replacen(
                    needle,
                    replacement,
                    1
                )),
                "action weakening `{needle}` must fail closed"
            );
        }
        let download_prefix = green.replacen(
            "        key: ${{ steps.cache-keys.outputs.download-primary-key }}",
            "        key: ${{ steps.cache-keys.outputs.download-primary-key }}\n        restore-keys: rss-download-v4-",
            1,
        );
        assert!(!setup_action_has_exact_split_cache_contract(
            &download_prefix
        ));
        let tools_prefix = green.replacen(
            "        key: ${{ steps.cache-keys.outputs.tools-primary-key }}",
            "        key: ${{ steps.cache-keys.outputs.tools-primary-key }}\n        restore-keys: rss-tools-v3-",
            1,
        );
        assert!(!setup_action_has_exact_split_cache_contract(&tools_prefix));
        let compiler_lane_prefix = green.replacen(
            "rss-sccache-v1-${{ runner.os }}-${{ runner.arch }}-${{ inputs.toolchain }}-${{ inputs.nightly || 'none' }}-",
            "rss-sccache-v1-${{ runner.os }}-${{ runner.arch }}-${{ inputs.toolchain }}-${{ inputs.nightly || 'none' }}-${{ inputs.lane }}-",
            1,
        );
        assert!(
            !setup_action_has_exact_split_cache_contract(&compiler_lane_prefix),
            "compiler restore prefix must remain lane-agnostic"
        );
        for forbidden in [
            "target-primary-key: stale",
            "id: target-cache",
            "run: ci-cache-result.sh aggregate",
            "run: ci-cache-maintain.sh tree-identity",
            "path: .cache/cargo-target",
        ] {
            assert!(
                !setup_action_has_exact_split_cache_contract(&format!("{green}\n{forbidden}\n")),
                "removed target-cache contract `{forbidden}` must remain rejected"
            );
        }
        for invalid_download_paths in [
            green.replacen("          ~/.cargo/registry/index\n", "", 1),
            green.replacen(
                "          ~/.cargo/git/db\n",
                "          ~/.cargo/git/db\n          ~/.cargo/git/checkouts\n",
                1,
            ),
            green.replacen(
                "          ~/.cargo/registry/cache\n",
                "          ~/.cargo/registry\n",
                1,
            ),
        ] {
            assert!(
                !setup_action_has_exact_split_cache_contract(&invalid_download_paths),
                "download restore path set must be exact"
            );
        }
        assert_action_step_camouflage_rejected(&green)?;
        for camouflage in [
            green.replace("id: tools-cache", "name: tools-cache"),
            green.replace(
                "uses: actions/cache/restore@v4",
                "name: actions/cache/restore@v4",
            ),
            green.replace(
                "key: ${{ steps.cache-keys.outputs.download-primary-key }}",
                "run: echo 'key: ${{ steps.cache-keys.outputs.download-primary-key }}'",
            ),
        ] {
            assert!(!setup_action_has_exact_split_cache_contract(&camouflage));
        }
        Ok(())
    }

    // ---- SAST / CodeQL workflow 守卫（issue #1145 第⑤项；INVARIANT SAST-CODEQL-PRESENT-01）----

    /// CodeQL workflow 必备要素（**结构绑定**，content-scan，Medium）。GitHub Actions 承载 CI/SAST，
    /// 守卫须锁住「SAST 真的会随 push/定时跑 + 真的扫 Rust + 真的产 alert」整条不变式，
    /// 而非仅找关键字子串（review #281 F2，对标 sibling azure 守卫的结构绑定）。经 [`yaml_code_lines`] 先剥 `#` 注释：
    ///
    /// - **① 触发器**：`push:` + `schedule:` 两结构键都在（行起头）——否则退化成仅 `workflow_dispatch`，SAST 不随
    ///   镜像 push / 定时跑（静默失效）。
    /// - **② init step**：某 step 块有**真实** `uses: github/codeql-action/init@v4`（[`block_uses_action`]，非 name /
    ///   注释值），**且同块**含 `languages: rust` + `build-mode: none`（Rust GA 免编译，绑定到该 init step 的 `with`）。
    /// - **③ analyze step**：某 step 块有真实 `uses: github/codeql-action/analyze@v4`（产 code-scanning alert）。
    /// - **④ 写权限**：`security-events: write`（advanced setup 必需）。
    ///
    /// 任一不满足即 SAST 被静默削弱 / 禁用（关键字落注释 / name / 错 step、或退化触发器均 fail-closed）。
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
    /// INVARIANT: NIGHTLY-PIN-01 { level = "Medium", exec = "verify", source = "code" }.
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
