//! `cargo xtask verify` —— 本地全量治理门聚合入口。
//!
//! RSS 本地全量治理门。GitHub Actions 以 Meta / Core / Security / Coverage 四类门作为合入阻断，
//! 其中 Core 拆成单次 prerequisites 与两份 partition tests；本命令保留为 stable-only 本地快门。
//! 聚合（fail-fast，无编译的步最先）：
//!
//!   1. `cargo fmt --all -- --check`
//!   2. in-process meta：contract validate + assembly validate + runtime-baseline + runtime-deps-guard + archrules + layer-deps + codegen --check + localtx-coverage + local-only-effects + repo-scope-guard + tenancy-closeout
//!   3. `cargo build --workspace`
//!   4. `cargo clippy --workspace --all-targets -- -D warnings`
//!   5. `cargo nextest run --workspace --no-tests=pass`（外部工具）
//!   6. feature-gated 行为测试门（确定性 mock / lazy）：`cargo nextest run -p s3 --features backend` +
//!      `-p redis-adapter --features backend`（默认 feature workspace nextest 不编入这些 `#[cfg(feature)]`
//!      测试模块；按 registry 的 Core gate 显式补跑——不用 `--all-features --workspace` 以免误触
//!      postgres/redis 的 `integration`（需 live 后端）门）
//!   7. `cargo deny check`（外部工具）
//!   8. `cargo dylint --all`（外部工具；跑 `lints/` 嵌套 nightly workspace；`DYLINT_RUSTFLAGS=-D warnings`
//!      把默认 `Warn` 的注册 lint 升为 fail-closed）
//!
//! `--fast` 只跑无需编译的步（fmt + meta + deny），供快速迭代。`--allow-missing-tools` 在缺
//! 外部工具时显式宽限（默认 fail-closed）。
//!
//! **`cargo xtask ci`（[`run_ci`]）= 本地兼容 CI 聚合**（issue #1132）：
//! verify 全门 + build/clippy 升 `--all-features --all-targets` + 覆盖率门（`cargo llvm-cov nextest` 替
//! nextest，强制 basis/engine ≥90%，见 `coverage.rs`）+ `public-api --check`（轴 A，见 `publicapi.rs`）。
//! `verify` 仍是 **stable-only 本地快门**（不需 nightly / llvm-cov）；`ci` 只供本地一次性跑全部
//! CI 门。二者与四条 GitHub lane 均经 [`plan_for`] 从 Hard 闭集 registry 派生，杜绝门集漂移。
//!
//! **`cargo xtask audit`（[`run_audit`]）= 供应链漏洞定时刷新 lane**（issue #1133，GitHub Actions
//! `schedule:` 调用入口）：advisory-scoped `cargo deny check advisories` + `cargo audit` 两门
//! （皆 no-compile、快）。PR 门（ci）已含全量 `deny check`（advisories+licenses+bans+sources）+ cargo-audit；
//! audit lane 专攻**时间维度**——对「未变依赖」新披露的 CVE，PR 门要等下个 PR 才捕获，故每日重跑漏洞维度。
//! audit lane = **告警**（无 PR 可阻断）；PR 门 ci = **合入阻断**。
//!
//! **`cargo-udeps` 仍不入三者**（多余/未声明依赖，需 nightly `-Z`，与根 stable 1.96 冲突）——独立可选门。
//! `cargo-semver-checks`（轴 A 语义破坏检测）当前所有 crate `publish = false` ⇒ `--workspace` 选 0 包、门
//! 空转，故本轮不入 ci（public-api --check 已非空转兜轴 A）；待 crate 可发布后 follow-up 接入（见 PR body）。
//!
//! INVARIANT: VERIFY-AGGREGATE-01 { level = "Medium", exec = "verify", source = "code" }—— 任一门步失败 ⇒ verify/ci/audit 非零退出（聚合 fail-fast，不吞错）。
//! INVARIANT: VERIFY-TOOL-GATE-01 { level = "Medium", exec = "verify", source = "code" }—— 缺外部工具默认 fail-closed；豁免仅经显式 `--allow-missing-tools`。
//! INVARIANT: CI-PIPELINE-DELEGATE-01 { level = "Medium", exec = "verify", source = "code" }—— GitHub CI workflow
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
//! INVARIANT: CI-TEST-PARTITION-MATRIX-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "split_ci_caller_predicate_green_and_synthetic_red", anti_vacuity = "github_ci_workflow_delegates_to_split_xtask_lanes" }—— Core 与 integration partition topology 必须是闭合、无重复的 committed matrix。
//! INVARIANT: CI-TEST-EVIDENCE-UPLOAD-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "reusable_rust_lane_guard_rejects_semantic_weakening", anti_vacuity = "github_resource_evidence_workflows_have_lifecycle" }—— evidence 必须 always 上传、唯一命名、精确路径且只保留七天。
//! INVARIANT: CI-INTEGRATION-MATRIX-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "integration_matrix_predicate_green_and_red", anti_vacuity = "github_integration_workflow_has_integration_shard_matrix" }—— Integration caller 必须是精确七行 typed matrix，逐 shard 委托 reusable workflow，不内联低层门。

use crate::ci_lanes::{
    CiLane, CompatMembership, CompileKind, GateId, REGISTRY, StandaloneReason, ToolRequirement,
    VerifyMembership,
};
use crate::diagnostic::run_check;
use crate::integration_shards::{self, IntegrationShard, Scheduling};
use crate::workspace_root;
use crate::{
    archrules, assembly, codegen, consistency_effects, consistency_fixtures, contract,
    doc_contracts, layerdeps, reconcile_outbox_command_guard, repo_scope_guard, runtime_baseline,
    runtime_deps_guard, shipped_feature_guard, wsdeps,
};
use anyhow::{Result, bail};
use std::path::Path;
use std::process::Stdio;

#[cfg(test)]
const CI_TOOL_SPECS: &[&str] = &[
    "cargo-nextest@0.9.137",
    "cargo-deny@0.19.9",
    "cargo-dylint@6.0.1",
    "dylint-link@6.0.1",
    "cargo-llvm-cov@0.8.7",
    "cargo-public-api@0.52.0",
    "cargo-audit@0.22.2",
];

/// verify 选项。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifyOpts {
    /// 只跑无需编译的步（fmt + meta + deny），跳过 build/clippy/nextest/dylint。
    fast: bool,
    /// 缺外部工具时显式宽限（默认 fail-closed，唯一门不建议）。
    allow_missing_tools: bool,
    partition: Option<crate::nextest::HashPartition>,
    nextest_lane: crate::nextest::NextestLane,
}

/// in-process Rust 门（无外部进程 / 自管子进程）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InternalCheck {
    ContractValidate,
    /// assembly-level DI provider 声明校验（RevocationStore active provider 必须持久）。
    AssemblyValidate,
    /// assembly.toml domains → committed modules_gen.rs 漂移门（ASSEMBLY-MODULES-CODEGEN-01）。
    AssemblyModulesCheck,
    /// wire JSON-Schema 跨版本破坏检测门（ADR-008，WIRE-BREAKING-01）。窗口分级：默认 warn（退出码 0），
    /// env `RSS_WIRE_BREAKING=deny` 对 active 契约破坏升 deny（退出码 1）；against = origin/develop。
    ContractBreaking,
    LayerDeps,
    /// server/rss 实际 Cargo feature graph 禁止通过 feature unification 启用 httpserve/test-util。
    ShippedFeatureGuard,
    WsDepsDrift,
    /// docs/rules + docs/spec 中 command/outbox tenant-aware 签名漂移门（DOC-CONTRACTS-01）。
    DocContracts,
    /// consistency crash matrix fixture/DSL 骨架门（CONSISTENCY-CRASH-FIXTURE-01）。
    ConsistencyFixtures,
    /// runtime event transport consumer 禁回 Redis claimer（EVENT-TRANSPORT-PG-INBOX-01）。
    EventTransportGuard,
    /// inbox receipt runtime cutover 旧 token 回流守卫（INBOX-RECEIPTS-CUTOVER-01）。
    InboxCutoverGuard,
    /// runtime assembly baseline 漂移门（RUNTIME-BASELINE-DRIFT-01）。
    RuntimeBaseline,
    /// SharedRuntimeDeps infra-only 字段类型守卫（WIRING-DEPS-INFRA-ONLY-01）。
    RuntimeDepsGuard,
    /// ArchRules 派生索引 + 11 行持久化 funnel matrix 文档漂移门。
    ArchRules,
    CodegenCheck,
    /// active LocalTx manifest/generated/owner route/test typed marker closure.
    LocalTxCoverage,
    /// active LocalOnly HTTP contracts effect profile allowlist（LOCAL-ONLY-EFFECTS-01）。
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
    /// reconcile scheduler transactional command outbox seam guard（RECONCILE-COMMAND-OUTBOX-SEAM-01）。
    ReconcileOutboxCommandGuard,
    /// governed scope（docs/rules + docs/architecture + .claude/rules + 根 config）结构化 defer 完整性 + 经典注解门
    /// （DEFER-GATE-01；内容扫描 .md/.toml，no-compile）。
    DeferGate,
    /// ci 专用：`cargo llvm-cov nextest`（兼 nextest 门）+ basis/engine ≥90% 覆盖率判定（见 `coverage.rs`）。
    Coverage,
    /// ci 专用：`public-api --check`（basis+engine+curated extras 封装面 baseline 漂移门 = 轴 A，见 `publicapi.rs`）。
    PublicApiCheck,
}

/// 门步 executor。工具要求、探测和安装提示只由 gate registry 提供。
#[derive(Debug, Clone, PartialEq, Eq)]
enum StepKind {
    Internal(InternalCheck),
    Cargo,
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
fn step_assembly_modules_check() -> Step {
    Step {
        id: GateId::AssemblyModulesCheck,
        args: &[],
        kind: StepKind::Internal(InternalCheck::AssemblyModulesCheck),
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
fn step_doc_contracts() -> Step {
    Step {
        id: GateId::DocContracts,
        args: &[],
        kind: StepKind::Internal(InternalCheck::DocContracts),
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
fn step_runtime_baseline() -> Step {
    Step {
        id: GateId::RuntimeBaseline,
        args: &[],
        kind: StepKind::Internal(InternalCheck::RuntimeBaseline),
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
/// licenses/bans 留给 PR 门的全量 [`step_deny`]）。issue #1133 每日 cron 刷新只需漏洞维度。
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

// verify 专用：workspace 默认 feature 的 build/clippy/nextest（stable-only 本地快门）。
fn step_build_workspace() -> Step {
    Step {
        id: GateId::BuildWorkspace,
        args: &["build", "--workspace"],
        kind: StepKind::Cargo,
        env: &[],
    }
}
/// F7 + #1137：postgres/redis/amqp 集成测试由 `#[cfg(feature = "integration")]` gate，verify 的
/// build/clippy/nextest 仅 workspace 默认 feature ⇒ 关键状态机测试（崩溃重投 / CAS fencing / DLX / sweep /
/// redis 幂等 / amqp pub-sub + 跨 vhost / durable journey）默认门外、回归漏网。本步 `--no-run` 仅编译（不跑、
/// 无需真实后端 / docker）纳入默认 verify 抓**编译漂移**；有 docker / env URL 时经
/// `cargo xtask ci-integration --shard <name>` 按 target 实跑。ci lane 经 `--all-features --all-targets`
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
            GateId::BuildAllFeatures | GateId::ClippyAllFeatures | GateId::Dylint
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

/// audit 精简供应链门步计划（issue #1133；GitHub Actions schedule 调 `cargo xtask audit`）。
/// advisory-scoped deny + cargo-audit 两门，皆 no-compile、快——定时刷新只查漏洞库（捕获「未变依赖」新
/// 披露 CVE）。**不含** licenses/bans：它们只随 Cargo.lock 变（= 随 PR 变），定时跑无增益；PR 门的
/// `CompatibilityCi` 计划已用全量 `deny check` + cargo-audit 覆盖。audit 步与 ci 共享同一
/// [`step_cargo_audit`] 构造。
///
/// INVARIANT: CI-PIPELINE-DELEGATE-01 { level = "Medium", exec = "verify", source = "code" }—— audit lane 亦经 YAML 委托 `cargo xtask audit`（不内联门命令），
/// 由 `github_audit_workflow_has_scheduled_audit_lane` 守。
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

/// 纯函数：按 opts 产出有序门步计划。`--fast` 裁掉 `needs_compile` 步（fmt+meta+deny 保留）。
fn verify_plan(opts: &VerifyOpts) -> Vec<Step> {
    let plan = plan_for(PlanTarget::Verify);
    if opts.fast {
        plan.into_iter().filter(|s| !s.needs_compile()).collect()
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
        StepKind::Internal(check) => run_internal(check),
        StepKind::Nextest(scope) => {
            crate::nextest::NextestInvocation::for_core(scope, opts.nextest_lane, opts.partition)
                .run(root, step.env)
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
        ToolRequirement::Nextest => {
            crate::nextest::run_gated(lane, opts.allow_missing_tools, step.label(), execute)
                .map(|_| ())
        }
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

fn run_internal(check: InternalCheck) -> Result<()> {
    match check {
        InternalCheck::ContractValidate => run_check(&contract::validate::ContractValidate),
        InternalCheck::AssemblyValidate => run_check(&assembly::AssemblyValidate),
        InternalCheck::AssemblyModulesCheck => crate::assembly_codegen::run(true),
        // wire 破坏门：against=origin/develop，窗口分级经 env（默认 warn，退出码 0；deny 模式 active 破坏退出码 1）。
        InternalCheck::ContractBreaking => contract::breaking::run(
            contract::breaking::DEFAULT_AGAINST,
            contract::breaking::EnforcementMode::from_env(),
        ),
        InternalCheck::LayerDeps => run_check(&layerdeps::LayerDeps),
        InternalCheck::ShippedFeatureGuard => {
            run_check(&shipped_feature_guard::ShippedFeatureGuard)
        }
        InternalCheck::WsDepsDrift => run_check(&wsdeps::WsDepsDrift),
        InternalCheck::DocContracts => run_check(&doc_contracts::DocContracts),
        InternalCheck::ConsistencyFixtures => run_check(&consistency_fixtures::ConsistencyFixtures),
        InternalCheck::EventTransportGuard => {
            run_check(&crate::event_transport_guard::EventTransportGuard)
        }
        InternalCheck::InboxCutoverGuard => {
            run_check(&crate::inbox_cutover_guard::InboxCutoverGuard)
        }
        InternalCheck::RuntimeBaseline => run_check(&runtime_baseline::RuntimeBaseline),
        InternalCheck::RuntimeDepsGuard => run_check(&runtime_deps_guard::RuntimeDepsGuard),
        InternalCheck::ArchRules => run_check(&archrules::ArchRules),
        InternalCheck::CodegenCheck => codegen::run(true),
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
        InternalCheck::ReconcileOutboxCommandGuard => {
            run_check(&reconcile_outbox_command_guard::ReconcileOutboxCommandGuard)
        }
        InternalCheck::DeferGate => run_check(&crate::defergate::DeferGate),
        InternalCheck::Coverage => crate::coverage::run(),
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
pub(crate) fn run(fast: bool, allow_missing_tools: bool) -> Result<()> {
    let opts = VerifyOpts {
        fast,
        allow_missing_tools,
        partition: None,
        nextest_lane: crate::nextest::NextestLane::Verify,
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

/// ci 本地兼容聚合入口（issue #1132）：按 [`plan_for`] 的兼容计划顺序跑每步，
/// fail-fast。GitHub Actions 不调此聚合，而是分别调用四条 [`CiLane`]；本地全工具机器可 `make ci`。
/// `allow_missing_tools` 仅本地便利——CI 不传 = 缺工具 fail-closed。
pub(crate) fn run_ci(allow_missing_tools: bool) -> Result<()> {
    let opts = VerifyOpts {
        fast: false,
        allow_missing_tools,
        partition: None,
        nextest_lane: crate::nextest::NextestLane::CiCore,
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

/// audit 入口（issue #1133 供应链定时刷新 lane）：按 [`audit_plan`] 顺序跑每步，fail-fast。
/// GitHub Actions schedule 调 `cargo xtask audit`（薄壳唯一入口，CI-PIPELINE-DELEGATE-01 同族）。
/// `allow_missing_tools` 仅本地便利——CI 不传 = 缺 deny/audit 工具 fail-closed。
pub(crate) fn run_audit(allow_missing_tools: bool) -> Result<()> {
    let opts = VerifyOpts {
        fast: false,
        allow_missing_tools,
        partition: None,
        nextest_lane: crate::nextest::NextestLane::Verify,
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

    fn opts(fast: bool, allow_missing_tools: bool) -> VerifyOpts {
        VerifyOpts {
            fast,
            allow_missing_tools,
            partition: None,
            nextest_lane: crate::nextest::NextestLane::Verify,
        }
    }

    fn labels(plan: &[Step]) -> Vec<&'static str> {
        plan.iter().map(|s| s.label()).collect()
    }

    #[test]
    fn ci_lane_plans_are_registry_derived_and_partitioned() {
        assert_eq!(labels(&plan_for(PlanTarget::Lane(CiLane::Meta))).len(), 29);
        assert_eq!(
            labels(&plan_for(PlanTarget::Lane(CiLane::Security))),
            vec!["deny", "audit"]
        );
        assert_eq!(
            labels(&plan_for(PlanTarget::Lane(CiLane::Coverage))),
            vec!["coverage", "public-api"]
        );
        let core = labels(&plan_for(PlanTarget::Lane(CiLane::Core)));
        assert_eq!(core.first(), Some(&"build"));
        assert!(core.contains(&"default-test-runner"));
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
        assert_eq!(prerequisites.len(), 3);
        assert_eq!(tests.len(), 8);
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
    fn ci_lane_compatibility_plan_keeps_43_unique_gates_and_supersedes_nextest() {
        let plan = plan_for(PlanTarget::CompatibilityCi);
        assert_eq!(plan.len(), 43);
        assert!(!labels(&plan).contains(&"default-test-runner"));
        let mut ids: Vec<_> = plan.iter().map(|step| step.id as usize).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 43);
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
    fn verify_plan_order_and_count() {
        let plan = verify_plan(&opts(false, false));
        assert_eq!(
            labels(&plan),
            vec![
                "fmt",
                "contract-validate",
                "assembly-validate",
                "assembly-modules-check",
                "contract-breaking",
                "layer-deps",
                "shipped-feature-guard",
                "wsdeps-drift",
                "doc-contracts",
                "consistency-fixtures",
                "event-transport-guard",
                "inbox-cutover-guard",
                "runtime-baseline",
                "runtime-deps-guard",
                "archrules",
                "codegen-check",
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
                "build",
                "integration-compile",
                "clippy",
                "default-test-runner",
                "s3-backend-tests",
                "redis-backend-tests",
                "oidc-backend-tests",
                "prometheus-backend-tests",
                "otel-backend-tests",
                "grpc-backend-tests",
                "vault-backend-tests",
                "deny",
                "dylint",
            ]
        );
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

    /// `--fast` 只留无需编译的步：fmt + meta + deny；裁掉 build/clippy/nextest/dylint。
    #[test]
    fn fast_plan_keeps_fmt_meta_deny_drops_compile() {
        let plan = verify_plan(&opts(true, false));
        assert_eq!(
            labels(&plan),
            vec![
                "fmt",
                "contract-validate",
                "assembly-validate",
                "assembly-modules-check",
                "contract-breaking",
                "layer-deps",
                "shipped-feature-guard",
                "wsdeps-drift",
                "doc-contracts",
                "consistency-fixtures",
                "event-transport-guard",
                "inbox-cutover-guard",
                "runtime-baseline",
                "runtime-deps-guard",
                "archrules",
                "codegen-check",
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
                "deny"
            ]
        );
        for dropped in ["build", "clippy", "default-test-runner", "dylint"] {
            assert!(!labels(&plan).contains(&dropped), "fast 不应含 {dropped}");
        }
    }

    /// meta checks（contract validate / assembly validate / contract breaking / layer-deps / wsdeps-drift /
    /// doc-contracts / consistency-fixtures / event-transport-guard / inbox-cutover-guard /
    /// runtime-baseline / runtime-deps-guard / archrules / codegen / pdp-allow-guard / contract-binding-guard /
    /// schema-rls / setlocal-funnel / pg-tenant-tx-guard / repo-scope-guard / tenancy-closeout / migrations-serial / command-symmetry /
    /// reconcile-outbox-command-guard / defer-gate）在两种模式恒在。
    #[test]
    fn meta_checks_present_in_both_modes() {
        for fast in [true, false] {
            let plan = verify_plan(&opts(fast, false));
            let internals: Vec<_> = plan
                .iter()
                .filter(|s| matches!(s.kind, StepKind::Internal(_)))
                .map(|s| s.label())
                .collect();
            assert_eq!(
                internals,
                vec![
                    "contract-validate",
                    "assembly-validate",
                    "assembly-modules-check",
                    "contract-breaking",
                    "layer-deps",
                    "shipped-feature-guard",
                    "wsdeps-drift",
                    "doc-contracts",
                    "consistency-fixtures",
                    "event-transport-guard",
                    "inbox-cutover-guard",
                    "runtime-baseline",
                    "runtime-deps-guard",
                    "archrules",
                    "codegen-check",
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
    fn local_only_effects_is_no_compile_internal_gate_after_codegen_in_all_lanes()
    -> anyhow::Result<()> {
        for (name, plan) in [
            ("full", plan_for(PlanTarget::Verify)),
            ("fast", verify_plan(&opts(true, false))),
            ("ci", plan_for(PlanTarget::CompatibilityCi)),
        ] {
            let labels = labels(&plan);
            let codegen = labels
                .iter()
                .position(|label| *label == "codegen-check")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 codegen-check"))?;
            let effects = labels
                .iter()
                .position(|label| *label == "local-only-effects")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 local-only-effects"))?;
            assert_eq!(effects, codegen + 2, "{name} lane order drift");
            assert!(
                !plan[effects].needs_compile(),
                "{name} gate must be no-compile"
            );
            assert!(matches!(
                plan[effects].kind,
                StepKind::Internal(InternalCheck::LocalOnlyEffects)
            ));
        }
        Ok(())
    }

    #[test]
    fn localtx_coverage_is_no_compile_internal_gate_immediately_after_codegen() -> anyhow::Result<()>
    {
        for (name, plan) in [
            ("full", plan_for(PlanTarget::Verify)),
            ("fast", verify_plan(&opts(true, false))),
            ("ci", plan_for(PlanTarget::CompatibilityCi)),
        ] {
            let labels = labels(&plan);
            let codegen = labels
                .iter()
                .position(|label| *label == "codegen-check")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 codegen-check"))?;
            let coverage = labels
                .iter()
                .position(|label| *label == "localtx-coverage")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 localtx-coverage"))?;
            assert_eq!(coverage, codegen + 1, "{name} lane order drift");
            assert!(!plan[coverage].needs_compile());
            assert!(matches!(
                plan[coverage].kind,
                StepKind::Internal(InternalCheck::LocalTxCoverage)
            ));
        }
        Ok(())
    }

    #[test]
    fn assembly_modules_codegen_is_no_compile_internal_gate_after_validation_in_all_lanes()
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
            let codegen = labels
                .iter()
                .position(|label| *label == "assembly-modules-check")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 assembly-modules-check"))?;
            assert_eq!(codegen, validate + 1, "{name} lane order drift");
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
                binding_is_valid(spec.tool(), matches!(step.kind, StepKind::Nextest(_))),
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

    /// CompatibilityCi 顺序与门集（单一事实源；CI lane 实跑顺序）。`audit`（cargo-audit）紧随 `deny` 后
    /// （issue #1133：供应链漏洞门入 PR 阻断 lane，防御纵深独立于 deny advisories）。
    #[test]
    fn compatibility_plan_order_and_count() {
        assert_eq!(
            labels(&plan_for(PlanTarget::CompatibilityCi)),
            vec![
                "fmt",
                "contract-validate",
                "assembly-validate",
                "assembly-modules-check",
                "contract-breaking",
                "layer-deps",
                "shipped-feature-guard",
                "wsdeps-drift",
                "doc-contracts",
                "consistency-fixtures",
                "event-transport-guard",
                "inbox-cutover-guard",
                "runtime-baseline",
                "runtime-deps-guard",
                "archrules",
                "codegen-check",
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
                "build",
                "clippy",
                "coverage",
                "s3-backend-tests",
                "redis-backend-tests",
                "oidc-backend-tests",
                "prometheus-backend-tests",
                "otel-backend-tests",
                "grpc-backend-tests",
                "vault-backend-tests",
                "deny",
                "audit",
                "dylint",
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
            "assembly-modules-check",
            "contract-breaking",
            "layer-deps",
            "shipped-feature-guard",
            "wsdeps-drift",
            "doc-contracts",
            "consistency-fixtures",
            "event-transport-guard",
            "inbox-cutover-guard",
            "runtime-baseline",
            "runtime-deps-guard",
            "archrules",
            "codegen-check",
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
    /// 不含 licenses/bans——它们只随 Cargo.lock 变（= 随 PR 变），定时跑无增益；PR 门的 ci 已全查。
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
    /// 定时刷新只查漏洞库，licenses/bans 留给 PR 门的全量 `deny check`。
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

    /// cargo-audit 步在 ci（PR 阻断门）与 audit（定时 lane）里**逐字相同**（同一构造，不漂移）。
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

    // ---- CI-PIPELINE-DELEGATE-01：GitHub workflow 委托四条 split xtask lane ----

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

    fn command_matches_delegation_form(command: &str, form: &str) -> bool {
        command == form
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

    fn line_is_delegate_command(line: &str, forms: &[&str]) -> bool {
        forms
            .iter()
            .any(|form| command_matches_delegation_form(line, form))
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

    fn command_script_is_exact_delegation(script: &[&str], forms: &[&str]) -> bool {
        let mut seen_delegate = false;
        for line in script
            .iter()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
        {
            if line_is_delegation_prologue(line) {
                continue;
            }
            if line_is_delegate_command(line, forms) {
                if seen_delegate {
                    return false;
                }
                seen_delegate = true;
                continue;
            }
            return false;
        }
        seen_delegate
    }

    fn workflow_delegates_to_xtask_lane(yaml: &str, forms: &[&str]) -> bool {
        let scripts = yaml_command_scripts(yaml);
        let mut delegate_count = 0;
        for script in &scripts {
            if command_script_is_exact_delegation(script, forms) {
                delegate_count += 1;
                continue;
            }
            if !command_script_is_setup_only(script) {
                return false;
            }
        }
        delegate_count == 1
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
        id: Option<String>,
        name: Option<String>,
        uses: Option<String>,
        if_expr: Option<String>,
        continue_on_error: Option<String>,
        with: Vec<(String, Vec<String>)>,
        env: Vec<(String, Vec<String>)>,
        run: Vec<String>,
    }

    impl TypedStep {
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
    }

    fn yaml_typed_steps(yaml: &str) -> Vec<TypedStep> {
        let lines = yaml_indented_code_lines(yaml);
        let mut steps = Vec::new();
        for (steps_index, (steps_indent, text)) in lines.iter().enumerate() {
            if *text != "steps:" || !matches!(*steps_indent, 2 | 4) {
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
            match key {
                "id" => step.id = Some(value.to_owned()),
                "name" => step.name = Some(value.to_owned()),
                "uses" => step.uses = Some(value.to_owned()),
                "if" => step.if_expr = Some(value.to_owned()),
                "continue-on-error" => step.continue_on_error = Some(value.to_owned()),
                "run" => {
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
                "with" | "env" => {
                    let target = if key == "with" {
                        &mut step.with
                    } else {
                        &mut step.env
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

    #[derive(Debug, Default)]
    struct ReusableCallerJob {
        id: String,
        fields: Vec<String>,
        needs: Option<String>,
        uses: Option<String>,
        lane: Option<String>,
        with_fields: Vec<String>,
        matrix_rows: Option<Vec<Option<(String, String)>>>,
    }

    fn reusable_caller_jobs(yaml: &str) -> Vec<ReusableCallerJob> {
        let lines = yaml_indented_code_lines(yaml);
        let Some(jobs_start) = lines
            .iter()
            .position(|(indent, line)| *indent == 0 && *line == "jobs:")
        else {
            return Vec::new();
        };
        let jobs_end = lines[jobs_start + 1..]
            .iter()
            .position(|(indent, _)| *indent == 0)
            .map_or(lines.len(), |offset| jobs_start + 1 + offset);
        let body = &lines[jobs_start + 1..jobs_end];
        let starts = body
            .iter()
            .enumerate()
            .filter_map(|(index, (indent, line))| {
                (*indent == 2)
                    .then(|| line.strip_suffix(':'))
                    .flatten()
                    .map(|id| (index, id))
            })
            .collect::<Vec<_>>();
        starts
            .iter()
            .enumerate()
            .map(|(position, (start, id))| {
                let end = starts
                    .get(position + 1)
                    .map_or(body.len(), |(next, _)| *next);
                parse_reusable_caller_job(id, &body[start + 1..end])
            })
            .collect()
    }

    fn parse_reusable_caller_job(id: &str, lines: &[(usize, &str)]) -> ReusableCallerJob {
        let mut job = ReusableCallerJob {
            id: id.to_owned(),
            ..ReusableCallerJob::default()
        };
        for (indent, line) in lines {
            if *indent == 4 {
                let Some((key, value)) = line.split_once(':') else {
                    job.fields.push((*line).to_owned());
                    continue;
                };
                job.fields.push(key.to_owned());
                match key {
                    "needs" => job.needs = Some(value.trim().to_owned()),
                    "uses" => job.uses = Some(value.trim().to_owned()),
                    _ => {}
                }
            } else if *indent == 6
                && let Some((key, value)) = line.split_once(':')
            {
                job.with_fields.push(key.to_owned());
                if key == "lane" {
                    job.lane = Some(value.trim().to_owned());
                }
            }
        }
        job.matrix_rows = parse_core_matrix_rows(lines);
        job
    }

    fn parse_core_matrix_rows(lines: &[(usize, &str)]) -> Option<Vec<Option<(String, String)>>> {
        let strategy_starts = lines
            .iter()
            .enumerate()
            .filter_map(|(index, (indent, line))| {
                (*indent == 4 && *line == "strategy:").then_some(index)
            })
            .collect::<Vec<_>>();
        let [strategy_start] = strategy_starts.as_slice() else {
            return None;
        };
        let strategy = lines[*strategy_start + 1..]
            .iter()
            .take_while(|(indent, _)| *indent > 4)
            .copied()
            .collect::<Vec<_>>();
        let strategy_fields = strategy
            .iter()
            .filter_map(|(indent, line)| (*indent == 6).then_some(*line))
            .collect::<Vec<_>>();
        if strategy_fields != ["fail-fast: false", "matrix:"] {
            return None;
        }
        let matrix_start = strategy
            .iter()
            .position(|(indent, line)| *indent == 6 && *line == "matrix:")?;
        let matrix = strategy[matrix_start + 1..]
            .iter()
            .take_while(|(indent, _)| *indent > 6)
            .copied()
            .collect::<Vec<_>>();
        if matrix
            .iter()
            .filter_map(|(indent, line)| (*indent == 8).then_some(*line))
            .collect::<Vec<_>>()
            != ["include:"]
        {
            return None;
        }
        let include_start = matrix
            .iter()
            .position(|(indent, line)| *indent == 8 && *line == "include:")?;
        let include = matrix[include_start + 1..]
            .iter()
            .take_while(|(indent, _)| *indent > 8)
            .copied()
            .collect::<Vec<_>>();
        if include.is_empty() || include.iter().any(|(indent, _)| *indent != 10) {
            return None;
        }
        Some(
            include
                .iter()
                .map(|(_, line)| parse_core_partition_row(line))
                .collect(),
        )
    }

    fn parse_core_partition_row(line: &str) -> Option<(String, String)> {
        let body = line.strip_prefix("- {")?.strip_suffix('}')?;
        let mut fields = body.split(',').map(str::trim);
        let partition = fields.next()?.strip_prefix("partition: ")?;
        let label = fields.next()?.strip_prefix("partition-label: ")?;
        if fields.next().is_some()
            || partition.contains("${{")
            || label.contains("${{")
            || partition.is_empty()
            || label.is_empty()
        {
            return None;
        }
        Some((partition.to_owned(), label.to_owned()))
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
        events == ["pull_request:", "push:", "workflow_dispatch:"]
            && workflow_event_has_exact_branches(&on_body, "pull_request", &["develop"])
            && workflow_event_has_exact_branches(
                &on_body,
                "push",
                &["develop", "codex/**", "feature/**", "fix/**"],
            )
            && workflow_dispatch_is_empty(&on_body)
    }

    fn reusable_job_matches(
        job: &ReusableCallerJob,
        lane: &str,
        expected_needs: Option<&str>,
    ) -> bool {
        let mut actual_fields = job.fields.iter().map(String::as_str).collect::<Vec<_>>();
        actual_fields.sort_unstable();
        let expected_fields = if lane == "ci-core-tests" {
            &["name", "needs", "strategy", "uses", "with"][..]
        } else if expected_needs.is_some() {
            &["needs", "uses", "with"][..]
        } else {
            &["uses", "with"][..]
        };
        job.id == lane
            && actual_fields == expected_fields
            && job.needs.as_deref() == expected_needs
            && job.uses.as_deref() == Some("./.github/workflows/rss-rust-lane.yml")
            && job.lane.as_deref() == Some(lane)
            && if lane == "ci-core-tests" {
                job.with_fields
                    == [
                        "fail-fast",
                        "matrix",
                        "lane",
                        "partition",
                        "partition-label",
                    ]
                    && job.matrix_rows
                        == Some(vec![
                            Some(("1/2".to_owned(), "1-of-2".to_owned())),
                            Some(("2/2".to_owned(), "2-of-2".to_owned())),
                        ])
            } else {
                job.with_fields == ["lane"] && job.matrix_rows.is_none()
            }
    }

    /// CI caller 的结构化闭集谓词：四个 literal job 直接调唯一 reusable workflow，
    /// Core/Coverage 仅依赖 Meta，Meta/Security 无依赖，不允许额外 job/field 或宽权限。
    fn pipeline_delegates_to_xtask_ci(yaml: &str) -> bool {
        let jobs = reusable_caller_jobs(yaml);
        workflow_has_only_safe_ci_events(yaml)
            && workflow_has_exact_read_permissions(yaml)
            && jobs.len() == 5
            && yaml.contains("partition: ${{ matrix.partition }}")
            && yaml.contains("partition-label: ${{ matrix.partition-label }}")
            && [
                ("ci-meta", None),
                ("ci-core-prerequisites", Some("ci-meta")),
                ("ci-core-tests", Some("ci-core-prerequisites")),
                ("ci-security", None),
                ("ci-coverage", Some("ci-meta")),
            ]
            .iter()
            .all(|(lane, expected_needs)| {
                jobs.iter()
                    .find(|job| job.id == *lane)
                    .is_some_and(|job| reusable_job_matches(job, lane, *expected_needs))
            })
    }

    /// Thin callers may only select a literal member of the closed lane set.  Match the
    /// `uses` and `with.lane` fields, never display names, comments, env, or run text.
    fn workflow_calls_reusable_lane(yaml: &str, lane: &str) -> bool {
        let lines = yaml_indented_code_lines(yaml);
        let jobs_start = lines
            .iter()
            .position(|(indent, line)| *indent == 0 && *line == "jobs:");
        let Some(jobs_start) = jobs_start else {
            return false;
        };
        let jobs = &lines[jobs_start + 1..];
        let job_fields = jobs
            .iter()
            .filter(|(indent, _)| *indent == 4)
            .map(|(_, line)| *line)
            .collect::<Vec<_>>();
        let with_fields = jobs
            .iter()
            .filter(|(indent, _)| *indent == 6)
            .map(|(_, line)| *line)
            .collect::<Vec<_>>();
        let permission_fields = lines
            .iter()
            .skip_while(|(indent, line)| !(*indent == 0 && *line == "permissions:"))
            .skip(1)
            .take_while(|(indent, _)| *indent > 0)
            .collect::<Vec<_>>();
        matches!(
            lane,
            "ci-meta" | "ci-core" | "ci-security" | "ci-coverage" | "integration" | "audit"
        ) && !lines
            .iter()
            .any(|(indent, line)| *indent == 0 && matches!(*line, "env:" | "steps:"))
            && jobs
                .iter()
                .filter(|(indent, line)| *indent == 2 && line.ends_with(':'))
                .count()
                == 1
            && job_fields == ["uses: ./.github/workflows/rss-rust-lane.yml", "with:"]
            && with_fields == [format!("lane: {lane}")]
            && permission_fields.len() == 1
            && permission_fields[0].0 == 2
            && permission_fields[0].1 == "contents: read"
    }

    /// 被 workflow 引用的本地 composite action 也是 CI 执行面。setup action 只能安装工具，不得把 build /
    /// clippy / nextest / coverage / public-api 等门命令搬进去绕过 workflow 委托守卫。
    fn setup_action_contains_only_setup_cargo_commands(yaml: &str) -> bool {
        yaml_command_scripts(yaml)
            .iter()
            .all(|script| command_script_is_setup_only(script))
    }

    /// 真实 committed 执行面：三个 caller 只绑定 literal lane，生命周期只存在于 reusable workflow。
    #[test]
    fn github_resource_evidence_workflows_have_lifecycle() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let ci_path = root.join(".github/workflows/ci.yml");
        let ci_yaml = std::fs::read_to_string(&ci_path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", ci_path.display()))?;
        assert!(
            pipeline_delegates_to_xtask_ci(&ci_yaml),
            "{} 须以四个 literal jobs 调用唯一 reusable workflow",
            ci_path.display()
        );
        for (workflow, lane) in [("integration.yml", "integration"), ("audit.yml", "audit")] {
            let path = root.join(".github/workflows").join(workflow);
            let yaml = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))?;
            let delegates = if lane == "integration" {
                github_integration_workflow_has_shard_matrix(&yaml)
            } else {
                workflow_calls_reusable_lane(&yaml, lane)
            };
            assert!(
                delegates,
                "{} 须以 literal lane 调用唯一 reusable workflow",
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

    fn split_ci_caller_fixture() -> &'static str {
        r#"name: CI
on:
  pull_request:
    branches: [develop]
  push:
    branches: [develop, "codex/**", "feature/**", "fix/**"]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  ci-meta:
    uses: ./.github/workflows/rss-rust-lane.yml
    with:
      lane: ci-meta
  ci-core-prerequisites:
    needs: ci-meta
    uses: ./.github/workflows/rss-rust-lane.yml
    with:
      lane: ci-core-prerequisites
  ci-core-tests:
    name: ci-core-tests / ${{ matrix.partition }}
    needs: ci-core-prerequisites
    strategy:
      fail-fast: false
      matrix:
        include:
          - { partition: 1/2, partition-label: 1-of-2 }
          - { partition: 2/2, partition-label: 2-of-2 }
    uses: ./.github/workflows/rss-rust-lane.yml
    with:
      lane: ci-core-tests
      partition: ${{ matrix.partition }}
      partition-label: ${{ matrix.partition-label }}
  ci-security:
    uses: ./.github/workflows/rss-rust-lane.yml
    with:
      lane: ci-security
  ci-coverage:
    needs: ci-meta
    uses: ./.github/workflows/rss-rust-lane.yml
    with:
      lane: ci-coverage
"#
    }

    #[test]
    fn split_ci_caller_predicate_green_and_synthetic_red() {
        let green = split_ci_caller_fixture();
        assert!(pipeline_delegates_to_xtask_ci(green), "anti-vacuity");
        for (name, red) in [
            ("missing", green.replacen("  ci-security:\n    uses: ./.github/workflows/rss-rust-lane.yml\n    with:\n      lane: ci-security\n", "", 1)),
            ("extra", format!("{green}  ci-extra:\n    uses: ./.github/workflows/rss-rust-lane.yml\n    with:\n      lane: ci-meta\n")),
            ("rename", green.replacen("ci-security:", "security:", 1)),
            ("lane-swap", green.replacen("lane: ci-core-tests", "lane: ci-coverage", 1)),
            ("missing-partition", green.replacen("          - { partition: 2/2, partition-label: 2-of-2 }\n", "", 1)),
            ("duplicate-partition", green.replacen("          - { partition: 2/2, partition-label: 2-of-2 }", "          - { partition: 1/2, partition-label: 1-of-2 }", 1)),
            ("extra-partition", green.replacen("          - { partition: 2/2, partition-label: 2-of-2 }", "          - { partition: 2/2, partition-label: 2-of-2 }\n          - { partition: 3/3, partition-label: 3-of-3 }", 1)),
            ("dynamic-partition", green.replacen("partition: 1/2, partition-label: 1-of-2", "partition: ${{ matrix.dynamic }}, partition-label: 1-of-2", 1)),
            ("include-to-exclude", green.replacen("        include:", "        exclude:", 1)),
            ("rows-under-other-key", green.replacen("        include:", "        other:", 1)),
            ("wrong-needs", green.replacen("needs: ci-meta", "needs: ci-security", 1)),
            ("dynamic-lane", green.replacen("lane: ci-meta", "lane: ${{ inputs.lane }}", 1)),
            ("inline-run", green.replacen("    uses: ./.github/workflows/rss-rust-lane.yml", "    run: cargo build --workspace\n    uses: ./.github/workflows/rss-rust-lane.yml", 1)),
            ("always", green.replacen("    needs: ci-meta", "    needs: ci-meta\n    if: ${{ always() }}", 1)),
            ("permission", green.replacen("contents: read", "contents: write", 1)),
            ("unsafe-trigger", green.replacen("  workflow_dispatch:", "  pull_request_target:\n  workflow_dispatch:", 1)),
            ("pr-activity-filter", green.replacen("  pull_request:\n    branches: [develop]", "  pull_request:\n    branches: [develop]\n    types: [closed]", 1)),
            ("pr-path-filter", green.replacen("  pull_request:\n    branches: [develop]", "  pull_request:\n    branches: [develop]\n    paths: [\"src/**\"]", 1)),
            ("push-path-ignore", green.replacen("  push:\n    branches: [develop, \"codex/**\", \"feature/**\", \"fix/**\"]", "  push:\n    branches: [develop, \"codex/**\", \"feature/**\", \"fix/**\"]\n    paths-ignore: [\"docs/**\"]", 1)),
            ("push-branches-ignore", green.replacen("  push:\n    branches: [develop, \"codex/**\", \"feature/**\", \"fix/**\"]", "  push:\n    branches: [develop, \"codex/**\", \"feature/**\", \"fix/**\"]\n    branches-ignore: [\"release/**\"]", 1)),
            ("manual-input", green.replacen("  workflow_dispatch:", "  workflow_dispatch:\n    inputs:\n      lane:\n        required: false", 1)),
            ("missing-develop", green.replacen("branches: [develop]", "branches: []", 1)),
            ("wrong-develop", green.replacen("branches: [develop]", "branches: [main]", 1)),
            ("extra-push-branch", green.replacen("\"fix/**\"]", "\"fix/**\", \"release/**\"]", 1)),
            ("field-camouflage", format!("env:\n  pull_request:\n    branches: [develop]\n{}", green.replacen("  pull_request:\n    branches: [develop]", "  pull_request:\n    branches: [develop]\n    types: [closed]", 1))),
        ] {
            assert!(!pipeline_delegates_to_xtask_ci(&red), "caller weakening `{name}` must fail closed");
        }
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

    /// 真实 committed 文件必须已切换为四个 literal reusable jobs。
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
            ".github/workflows/ci.yml 须精确声明 ci-meta/core/security/coverage 四个 literal reusable jobs 与 Meta DAG"
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
    fn ci_tool_versions_are_pinned_in_docs_and_workflows() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let read = |rel: &str| -> anyhow::Result<String> {
            let path = root.join(rel);
            std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))
        };
        let ci_surface = [
            ".github/actions/setup-rss-ci/action.yml",
            ".github/workflows/ci.yml",
            ".github/workflows/integration.yml",
            ".github/workflows/audit.yml",
            ".github/workflows/rss-rust-lane.yml",
        ]
        .iter()
        .map(|rel| read(rel))
        .collect::<anyhow::Result<Vec<_>>>()?
        .join("\n");
        for spec in CI_TOOL_SPECS {
            assert!(
                ci_surface.contains(spec),
                "GitHub CI surface 须包含钉版工具 `{spec}`"
            );
        }
        assert!(
            ci_surface
                .contains("cargo-bins/cargo-binstall@732870f031d2fb36309d0deaf36abcc704a7be65")
                && ci_surface.contains("version: 1.20.1"),
            "cargo-binstall action 与工具版本必须分别不可变钉选"
        );

        let readme = read("README.md")?;
        for spec in CI_TOOL_SPECS.iter().copied() {
            assert!(readme.contains(spec), "README 治理工具须钉版 `{spec}`");
        }
        Ok(())
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

    /// xtask audit 委托的规范形（至少一种须在 YAML 出现，anti-vacuity）：alias 形与 CI 锁定入口形。
    const XTASK_AUDIT_FORMS: &[&str] =
        &["cargo xtask audit", "cargo run --locked -p xtask -- audit"];

    /// GitHub audit workflow 谓词（**结构绑定**，fail-closed；codex F1：守卫不可被注释 / displayName 误满足）。
    /// YAML 须同时满足——① 顶层 `schedule:` 键（GitHub Actions 定时触发）；② `workflow_dispatch:` 手动 backstop；
    /// ③ audit 委托形在**真实 script 命令**；④ 每个 `cargo run` 都是完整 xtask audit 委托形，其他 cargo 子命令仅限安装。
    fn github_audit_workflow_has_scheduled_lane(yaml: &str) -> bool {
        workflow_has_top_level_on_event(yaml, "schedule")
            && workflow_has_top_level_on_event(yaml, "workflow_dispatch")
            && (workflow_delegates_to_xtask_lane(yaml, XTASK_AUDIT_FORMS)
                || workflow_calls_reusable_lane(yaml, "audit"))
    }

    /// 谓词绿/红例（anti-vacuity）：逐一抽掉每个必需子句都使谓词变假（守卫非恒真）。
    #[test]
    fn scheduled_audit_lane_predicate_green_and_red() {
        let green = "on:\n  schedule:\n    - cron: \"0 6 * * *\"\n  workflow_dispatch:\njobs:\n  audit:\n    steps:\n      - run: cargo install cargo-binstall\n      - run: cargo run --locked -p xtask -- audit\n";
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
        assert!(
            !github_audit_workflow_has_scheduled_lane(
                &green.replace("cargo run --locked -p xtask -- audit", "cargo xtask ci")
            ),
            "缺 audit 委托形"
        );
        // 红：内联 `cargo audit` 门命令（不委托 xtask）——门逻辑须单源在 xtask。
        assert!(
            !github_audit_workflow_has_scheduled_lane(&format!("{green}  - script: cargo audit\n")),
            "内联 cargo audit 门命令"
        );
        // 红（codex F1 核心）：全部关键字仅在**注释**里、无真实结构 → 结构绑定守卫不满足
        //（旧裸 `yaml.contains` 谓词会误判为真）。安装步使 cargo 命令白名单通过，隔离出结构断言失败。
        assert!(
            !github_audit_workflow_has_scheduled_lane(
                "# schedule:\n# workflow_dispatch:\n# cargo run --locked -p xtask -- audit\nsteps:\n  - run: cargo install cargo-binstall\n"
            ),
            "关键字仅在注释里不应满足守卫（fail-closed）"
        );
        // 红：`schedule:` / `workflow_dispatch:` 不在顶层 `on:` 下，不能凑出触发器。
        assert!(
            !github_audit_workflow_has_scheduled_lane(
                "env:\n  schedule: true\njobs:\n  audit:\n    workflow_dispatch: true\n    steps:\n      - run: cargo run --locked -p xtask -- audit\n"
            ),
            "触发器键不在顶层 on 块下不应满足守卫（fail-closed）"
        );
        // 红（codex F1 核心）：audit 委托形仅在 **displayName**（字符串字段值）、无真实 audit script → 不满足。
        assert!(
            !github_audit_workflow_has_scheduled_lane(
                "on:\n  schedule:\n    - cron: \"0 6 * * *\"\n  workflow_dispatch:\nsteps:\n  - run: cargo install cargo-binstall\n    name: 'cargo run --locked -p xtask -- audit'\n"
            ),
            "audit 形仅在 displayName 不应满足守卫（fail-closed）"
        );
        assert!(
            !github_audit_workflow_has_scheduled_lane(
                "on:\n  schedule:\n    - cron: \"0 6 * * *\"\n  workflow_dispatch:\nsteps:\n  - run: cargo run --locked -p xtask -- audit --allow-missing-tools\n"
            ),
            "audit lane 不得在 workflow 中宽限缺工具"
        );
        assert!(
            !github_audit_workflow_has_scheduled_lane(
                "on:\n  schedule:\n    - cron: \"0 6 * * *\"\n  workflow_dispatch:\nsteps:\n  - run: |\n      exit 0\n      cargo run --locked -p xtask -- audit\n"
            ),
            "audit 委托命令不可被前置控制流绕过"
        );
    }

    /// 真实 committed 文件：GitHub audit workflow 含每日定时刷新 lane，经 `cargo xtask audit` 委托
    /// （issue #1133：捕获「未变依赖」新披露 CVE；门逻辑单源在 xtask，不内联）。
    #[test]
    fn github_audit_workflow_has_scheduled_audit_lane() -> anyhow::Result<()> {
        let path = workspace_root()?
            .join(".github")
            .join("workflows")
            .join("audit.yml");
        let yaml = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))?;
        assert!(
            github_audit_workflow_has_scheduled_lane(&yaml),
            ".github/workflows/audit.yml 须含 `schedule:` 定时刷新 lane 且经 `cargo xtask audit` 委托"
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
        let lines = yaml_indented_code_lines(yaml);
        let Some(jobs_start) = lines
            .iter()
            .position(|(indent, line)| *indent == 0 && *line == "jobs:")
        else {
            return false;
        };
        let jobs_body = lines[jobs_start + 1..]
            .iter()
            .take_while(|(indent, _)| *indent > 0)
            .copied()
            .collect::<Vec<_>>();
        let jobs = jobs_body
            .iter()
            .filter_map(|(indent, line)| (*indent == 2).then(|| line.strip_suffix(':')).flatten())
            .collect::<Vec<_>>();
        let top_fields = jobs_body
            .iter()
            .filter_map(|(indent, line)| {
                (*indent == 4)
                    .then(|| line.split_once(':').map(|(key, _)| key))
                    .flatten()
            })
            .collect::<Vec<_>>();
        workflow_has_only_safe_ci_events(yaml)
            && workflow_has_exact_read_permissions(yaml)
            && jobs == ["integration"]
            && top_fields == ["name", "strategy", "uses", "with"]
            && lines.contains(&(
                4,
                "name: integration / ${{ matrix.shard }} / ${{ matrix.partition-label }}",
            ))
            && lines.contains(&(6, "fail-fast: false"))
            && expected_shards == expected_integration_shards()
            && integration_matrix_rows(yaml) == Some(expected_integration_rows())
            && lines.contains(&(4, "uses: ./.github/workflows/rss-rust-lane.yml"))
            && lines.contains(&(6, "lane: integration"))
            && lines.contains(&(6, "shard: ${{ matrix.shard }}"))
            && lines.contains(&(6, "partition: ${{ matrix.partition }}"))
            && lines.contains(&(6, "partition-label: ${{ matrix.partition-label }}"))
            && !yaml.contains("continue-on-error")
            && !yaml.contains("cargo nextest")
            && !yaml.contains("--allow-missing-tools")
            && !yaml.contains("fromJSON")
            && !lines
                .iter()
                .any(|(indent, line)| *indent == 0 && matches!(*line, "env:" | "steps:"))
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

    #[test]
    fn integration_matrix_predicate_green_and_red() {
        let green = include_str!("../../.github/workflows/integration.yml");
        assert!(github_integration_workflow_has_shard_matrix(green));
        let mut future_catalog = expected_integration_shards();
        future_catalog.push("future-shard");
        assert!(
            !github_integration_workflow_has_shard_matrix_for(green, &future_catalog),
            "catalog 新增 shard 而 committed matrix 未同步时必须 red"
        );
        for red in [
            green.replacen("          - { shard: postgres-domain, partition: \"\", partition-label: unpartitioned }\n", "", 1),
            green.replace("fail-fast: false", "fail-fast: true"),
            green.replace("shard: ${{ matrix.shard }}", "shard: fromJSON(env.SHARDS)"),
            format!("{green}    continue-on-error: true\n"),
            format!("{green}    run: cargo nextest run\n"),
        ] {
            assert!(!github_integration_workflow_has_shard_matrix(&red));
        }
    }

    #[test]
    fn github_integration_workflow_has_integration_shard_matrix() -> anyhow::Result<()> {
        let path = workspace_root()?
            .join(".github")
            .join("workflows")
            .join("integration.yml");
        let yaml = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))?;
        assert!(
            github_integration_workflow_has_shard_matrix(&yaml),
            ".github/workflows/integration.yml must contain the exact closed shard matrix"
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
        let target = restore(
            "target-cache",
            &[".cache/cargo-target"],
            "${{ steps.cache-keys.outputs.target-primary-key }}",
        );
        let tools = restore(
            "tools-cache",
            &[".cache/ci-tools/${{ inputs.profile }}"],
            "${{ steps.cache-keys.outputs.tools-primary-key }}",
        );
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
                    "target-primary-key",
                    "${{ steps.cache-keys.outputs.target-primary-key }}",
                ),
                (
                    "target-matched-key",
                    "${{ steps.target-cache.outputs.cache-matched-key }}",
                ),
                ("target-hit", "${{ steps.target-cache.outputs.cache-hit }}"),
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
                    "build-restore-result",
                    "${{ steps.after-cache.outputs.build-result }}",
                ),
                (
                    "build-restored-footprint-bytes",
                    "${{ steps.after-cache.outputs.build-bytes }}",
                ),
                (
                    "tools-restore-result",
                    "${{ steps.after-cache.outputs.tools-result }}",
                ),
                (
                    "tools-restored-footprint-bytes",
                    "${{ steps.after-cache.outputs.tools-bytes }}",
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
            && steps
                .iter()
                .filter(|step| step.uses.as_deref() == Some("actions/cache/restore@v4"))
                .count()
                == 3
            && matches!((download, target, tools), (Some(a), Some(b), Some(c)) if a < b && b < c)
            && !lines
                .iter()
                .any(|(_, line)| line.starts_with("restore-keys:"))
            && steps.iter().any(|step| {
                step.id.as_deref() == Some("cache-keys")
                    && step.run_contains("tree-identity --workspace")
                    && step.run_contains(
                        "target-primary-key=rss-target-v3-$common-$source_hash-$tree_identity",
                    )
                    && step.run_contains("tools-primary-key=rss-tools-$RSS_TOOL_CACHE_EPOCH")
                    && step.run_has_line(
                        "case \"$RSS_LANE\" in ci-meta|ci-core-prerequisites|ci-core-tests|ci-security|ci-coverage|integration|audit) ;; *) exit 64 ;; esac",
                    )
                    && step.run_has_line(
                        "case \"$RSS_PROFILE\" in ci-meta|ci-core-prerequisites|ci-core-tests|ci-security|ci-coverage|integration|audit) ;; *) exit 64 ;; esac",
                    )
                    && step.run_contains("[ \"$RSS_PROFILE\" = \"$RSS_LANE\" ]")
            })
            && steps.iter().any(|step| {
                step.id.as_deref() == Some("after-cache")
                    && step.if_expr.as_deref()
                        == Some("${{ always() && inputs.evidence-enabled == 'true' }}")
                    && step.run_contains("ci-cache-result.sh aggregate")
                    && step.run_contains("snapshot after-cache")
            })
    }

    fn reusable_rust_lane_is_hardened(yaml: &str) -> bool {
        const WRITER: &str = "RSS_CACHE_WRITER: ${{ (((inputs.lane == 'ci-meta' || inputs.lane == 'ci-core-prerequisites' || (inputs.lane == 'ci-core-tests' && inputs.partition == '1/2') || inputs.lane == 'ci-security' || inputs.lane == 'ci-coverage') && github.event_name == 'push') || (inputs.lane == 'audit' && github.event_name == 'schedule')) && github.ref == 'refs/heads/develop' && github.ref_protected }}";
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
        let xtask = index("xtask");
        let cleanup = index("cleanup");
        let measure_build = index("measure-build");
        let before_save = index("before-save");
        let save_download = index("save-download");
        let save_target = index("save-target");
        let checkout_ok = checkout.is_some_and(|i| {
            steps[i].uses.as_deref() == Some("actions/checkout@v4")
                && steps[i].with_exact("persist-credentials", &["false"])
                && steps[i].with_exact("fetch-depth", &["0"])
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
                    == Some("${{ env.RSS_CACHE_WRITER == 'true' && steps.xtask.outcome == 'success' && steps.cleanup.outcome == 'success' && steps.measure-build.outcome == 'success' && steps.before-save.outcome == 'success' && steps.setup.outputs.download-hit != 'true' }}")
        });
        let target_save_ok = save_target.is_some_and(|i| {
            let step = &steps[i];
            step.uses.as_deref() == Some("actions/cache/save@v4")
                && step.continue_on_error.as_deref() == Some("true")
                && step.with_exact("path", &[".cache/cargo-target"])
                && step.with_exact(
                    "key",
                    &["${{ steps.setup.outputs.target-primary-key }}"],
                )
                && step.if_expr.as_deref()
                    == Some("${{ env.RSS_CACHE_WRITER == 'true' && steps.xtask.outcome == 'success' && steps.cleanup.outcome == 'success' && steps.measure-build.outcome == 'success' && steps.before-save.outcome == 'success' && steps.setup.outputs.target-hit != 'true' }}")
        });
        let setup_ok = setup.is_some_and(|i| {
            let step = &steps[i];
            step.uses.as_deref() == Some("./.github/actions/setup-rss-ci")
                && step.with_exact("lane", &["${{ inputs.lane }}"])
                && step.with_exact("profile", &["${{ steps.policy.outputs.profile }}"])
                && step.with_exact("tool-cache-epoch", &["v3"])
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
                        "echo 'prebuilt-tools='",
                        "echo 'fallback-tools='",
                        ";;",
                    ]
                    .as_slice(),
                    [
                        "ci-core-prerequisites)",
                        "echo 'profile=ci-core-prerequisites'",
                        "echo \"nightly=$RSS_NIGHTLY_PINNED\"",
                        "echo 'prebuilt-tools='",
                        "echo 'fallback-tools=cargo-dylint@6.0.1,dylint-link@6.0.1'",
                        ";;",
                    ]
                    .as_slice(),
                    [
                        "ci-core-tests)",
                        "echo 'profile=ci-core-tests'",
                        "echo 'nightly='",
                        "echo 'prebuilt-tools=cargo-nextest@0.9.137'",
                        "echo 'fallback-tools='",
                        ";;",
                    ]
                    .as_slice(),
                    [
                        "ci-security)",
                        "echo 'profile=ci-security'",
                        "echo 'nightly='",
                        "echo 'prebuilt-tools=cargo-deny@0.19.9,cargo-audit@0.22.2'",
                        "echo 'fallback-tools='",
                        ";;",
                    ]
                    .as_slice(),
                    [
                        "ci-coverage)",
                        "echo 'profile=ci-coverage'",
                        "echo \"nightly=$RSS_NIGHTLY_PINNED\"",
                        "echo 'prebuilt-tools=cargo-llvm-cov@0.8.7,cargo-nextest@0.9.137'",
                        "echo 'fallback-tools=cargo-public-api@0.52.0'",
                        ";;",
                    ]
                    .as_slice(),
                ]
                .iter()
                .all(|branch| step.run_has_sequence(branch))
                && step.run.iter().filter(|line| line.ends_with(')')).count() == 7
                && step.run_has_line("integration)")
                && step.run_has_line("audit)")
                && step.run_has_line("*) exit 64 ;;")
        });
        let xtask_ok = xtask.is_some_and(|i| {
            let step = &steps[i];
            step.env_exact("RSS_LANE", &["${{ inputs.lane }}"])
                && step.env_exact("RSS_SHARD", &["${{ inputs.shard }}"])
                && step.env_exact("RSS_PARTITION", &["${{ inputs.partition }}"])
                && step.run_contains("case \"$RSS_LANE\" in")
                && [
                    "ci-meta) cargo run --locked -p xtask -- ci-meta ;;",
                    "ci-core-prerequisites) cargo run --locked -p xtask -- ci-core-prerequisites ;;",
                    "ci-core-tests) cargo run --locked -p xtask -- ci-core-tests --partition \"$RSS_PARTITION\" ;;",
                    "ci-security) cargo run --locked -p xtask -- ci-security ;;",
                    "ci-coverage) cargo run --locked -p xtask -- ci-coverage ;;",
                    "audit) cargo run --locked -p xtask -- audit ;;",
                ]
                .iter()
                .all(|line| step.run_has_line(line))
                && step.run_has_line("integration)")
                && step.run_contains("args=(ci-integration --shard \"$RSS_SHARD\")")
                && step.run_contains("args+=(--partition \"$RSS_PARTITION\")")
                && step.run_contains("cargo run --locked -p xtask -- \"${args[@]}\"")
                && step.run_has_line("*) exit 64 ;;")
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
            "Capture before-save evidence and enforce build budget",
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
        }) && cleanup.is_some_and(|i| {
            steps[i].if_expr.as_deref()
                == Some("${{ env.RSS_CACHE_WRITER == 'true' && steps.xtask.outcome == 'success' && (steps.setup.outputs.download-hit != 'true' || steps.setup.outputs.target-hit != 'true') }}")
        }) && measure_build.is_some_and(|i| {
            steps[i].if_expr.as_deref()
                == Some("${{ env.RSS_CACHE_WRITER == 'true' && steps.xtask.outcome == 'success' && steps.cleanup.outcome == 'success' }}")
        }) && before_save.is_some_and(|i| {
            steps[i].if_expr.as_deref() == Some("${{ always() }}")
        });
        lines
            .iter()
            .any(|(indent, line)| *indent == 2 && *line == "workflow_call:")
            && lines
                .iter()
                .any(|(indent, line)| *indent == 8 && *line == "required: true")
            && lines
                .iter()
                .any(|(indent, line)| *indent == 8 && *line == "type: string")
            && lines
                .iter()
                .any(|(indent, line)| *indent == 2 && *line == "contents: read")
            && lines
                .iter()
                .any(|(indent, line)| *indent == 2 && *line == "CARGO_INCREMENTAL: 0")
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
            && target_save_ok
            && xtask_ok
            && evidence_ok
            && intermediate_conditions_ok
            && steps
                .iter()
                .filter(|step| step.uses.as_deref() == Some("actions/cache/save@v4"))
                .count()
                == 3
            && matches!((checkout, start, policy, setup, measure_tools, tools_budget, save_tools, xtask, cleanup, measure_build, before_save, save_download, save_target),
                (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f), Some(g), Some(h), Some(i), Some(j), Some(k), Some(l), Some(m))
                    if b == a + 1 && c == b + 1 && d == c + 1 && e == d + 1 && f == e + 1 && g == f + 1 && g < h && h < i && i < j && j < k && k < l && l < m)
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
    fn reusable_rust_lane_guard_rejects_semantic_weakening() -> anyhow::Result<()> {
        let path = workspace_root()?.join(".github/workflows/rss-rust-lane.yml");
        let green = std::fs::read_to_string(&path)?;
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
            (" && github.ref_protected", ""),
            ("profile=ci", "profile=shared"),
            (
                "ci-core-tests)\n              echo 'profile=ci-core-tests'",
                "ci-core-tests)\n              echo 'profile=ci-core'",
            ),
            ("tool-cache-epoch: v3", "tool-cache-epoch: v2"),
            (
                "prebuilt-tools=cargo-llvm-cov@0.8.7,cargo-nextest@0.9.137",
                "prebuilt-tools=cargo-llvm-cov@0.8.7",
            ),
            (
                "steps.setup.outputs.tools-primary-key",
                "steps.setup.outputs.target-primary-key",
            ),
            ("path: .cache/cargo-target", "path: .cache/ci-tools/ci"),
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
                "|cdc-projection-saga:) ;;",
                "|future-shard:|cdc-projection-saga:) ;;",
            ),
        ] {
            let red = green.replacen(needle, replacement, 1);
            assert!(
                !reusable_rust_lane_is_hardened(&red),
                "weakening `{needle}` must fail closed"
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
        for id in ["policy", "xtask", "before-save"] {
            for field in ["name", "env"] {
                assert!(
                    !reusable_rust_lane_is_hardened(&camouflage_step_run(&green, id, field)?),
                    "{id} commands in {field} with run:true must fail closed"
                );
            }
        }
        for id in ["save-tools", "before-save"] {
            for field in ["name", "env"] {
                assert!(
                    !reusable_rust_lane_is_hardened(&camouflage_step_if(&green, id, field)?),
                    "{id} if expression in {field} must fail closed"
                );
            }
        }
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
        for (file, lane) in [("integration.yml", "integration"), ("audit.yml", "audit")] {
            let green = std::fs::read_to_string(root.join(file))?;
            let delegates = |yaml: &str| {
                if lane == "integration" {
                    github_integration_workflow_has_shard_matrix(yaml)
                } else {
                    workflow_calls_reusable_lane(yaml, lane)
                }
            };
            assert!(delegates(&green));
            for (index, red) in [
                green.replace(&format!("lane: {lane}"), "lane: ${{ inputs.lane }}"),
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
                assert!(!delegates(&red), "caller red {index}");
            }
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
            ("path: .cache/cargo-target", "path: .cache/ci-tools/ci"),
            (
                "key: ${{ steps.cache-keys.outputs.target-primary-key }}",
                "key: wrong",
            ),
            ("[ \"$RSS_PROFILE\" = \"$RSS_LANE\" ]", "true"),
            (
                "ci-meta|ci-core-prerequisites|ci-core-tests|ci-security|ci-coverage|integration|audit",
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
        let target_prefix = green.replacen(
            "        key: ${{ steps.cache-keys.outputs.target-primary-key }}",
            "        key: ${{ steps.cache-keys.outputs.target-primary-key }}\n        restore-keys: rss-target-v3-",
            1,
        );
        assert!(!setup_action_has_exact_split_cache_contract(&target_prefix));
        let tools_prefix = green.replacen(
            "        key: ${{ steps.cache-keys.outputs.tools-primary-key }}",
            "        key: ${{ steps.cache-keys.outputs.tools-primary-key }}\n        restore-keys: rss-tools-v3-",
            1,
        );
        assert!(!setup_action_has_exact_split_cache_contract(&tools_prefix));
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
        for id in ["cache-keys", "after-cache"] {
            for field in ["name", "env"] {
                assert!(
                    !setup_action_has_exact_split_cache_contract(&camouflage_step_run(
                        &green, id, field
                    )?),
                    "action {id} commands in {field} with run:true must fail closed"
                );
            }
        }
        for field in ["name", "env"] {
            assert!(
                !setup_action_has_exact_split_cache_contract(&camouflage_step_if(
                    &green,
                    "after-cache",
                    field,
                )?),
                "after-cache if expression in {field} must fail closed"
            );
        }
        for camouflage in [
            green.replace("id: target-cache", "name: target-cache"),
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
