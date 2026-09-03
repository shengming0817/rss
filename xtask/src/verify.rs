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
//! nextest，强制 basis/engine ≥90%，见 `coverage.rs`）+ 唯一 `public-api` gate（internal/release
//! exact-set、逐包 SemVer、公共依赖与类型泄漏，见 `publicapi.rs`）。
//! `verify` 仍是 **stable-only 本地快门**（不需 nightly / llvm-cov）；`ci full` 只供本地一次性跑全部
//! CI 门。两者与固定 GitHub jobs 均经 [`plan_for`] 与 [`FixedCiJob`] 的 Hard 闭集派生，杜绝门集漂移。
//!
//! **`cargo xtask ci audit`（[`run_audit`]）= 供应链漏洞显式诊断入口**（issue #1133）：
//! advisory-scoped `cargo deny check advisories` + `cargo audit` 两门
//! （皆 no-compile、快）。PR-triggered adaptive plan 按影响选择 `deny check`
//! （advisories+licenses+bans+sources）+ cargo-audit；显式 audit 专攻**时间维度**，捕获未改依赖的新披露
//! CVE。两者在各自 run 内 fail-closed；`ci-gate` 激活为 required check 或建立 forge bridge 前均不阻断 Azure 合入。
//!
//! **`cargo-udeps` 仍不入三者**（多余/未声明依赖，需 nightly `-Z`，与根 stable 1.96 冲突）——独立可选门。
//! `cargo-semver-checks` 只对 base/current Release Surface 交集逐包执行，禁止 `--workspace` 空转；首次
//! 选入只建立 release baseline。internal exported-symbol baseline 始终独立执行且不因此获得 SemVer。
//!
//! INVARIANT: VERIFY-AGGREGATE-01 { level = "Medium", exec = "check", source = "code" }—— 本地 verify/ci-full 默认 keep-going、显式 fail-fast；远端 typed job 保持 fail-fast；任一门步失败均非零退出。
//! INVARIANT: VERIFY-TOOL-GATE-01 { level = "Medium", exec = "check", source = "code" }—— 缺外部工具默认 fail-closed；豁免仅经显式 `--allow-missing-tools`。
//! INVARIANT: RUNTIME-DYLINT-UI-GATE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "dylint_workspace_ui_gate_is_release_owned_once", anti_vacuity = "dylint_workspace_ui_gate_is_release_owned_once" }—— Dylint UI goldens run once as typed `cargo test --locked --workspace` from `lints` in release-check; fast remains no-compile.
//! INVARIANT: L2-ASSURANCE-VERIFY-GATE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "l2_assurance_gate_is_typed_once_and_ordered_in_all_aggregate_plans", anti_vacuity = "l2_assurance::tests::workspace_typed_inventory_closes_active_l2" }—— L2 assurance closure validation is a typed, in-process, no-compile gate present exactly once immediately after codegen in every aggregate plan.
//! Fixed PR execution is projected by the closed [`FixedCiJob`] enum below. The committed caller
//! and reusable workflow are guarded structurally by `CI-FIXED-WORKFLOW-01`; integration uses one
//! aggregate scope with bounded diagnostics and always-cleanup, while LocalTx/LocalOnly reports
//! are validated by their producers rather than reconciled by a central receipt gate.
//! INVARIANT: CI-RESULT-GATE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "fixed_ci_workflow_guard_rejects_structural_weakening", anti_vacuity = "committed_fixed_ci_workflow_is_closed" }—— external GitHub job results are aggregated by two checkout-free, Cargo-free exact result gates; every non-success state fails closed.

#[cfg(test)]
use crate::ci_lanes::{CompileKind, REGISTRY};
use crate::ci_lanes::{EvidenceKind, FixedCiInvocation, FixedCiJob};
use crate::ci_lanes::{GateExecutor, GateGroup, GateId, LocalMetaPolicy, ToolRequirement};
use crate::diagnostic::run_check;
use crate::execution_profiles::{ExecutionProfile, ExecutionUnitSpec};
use crate::integration_shards::{
    self, IntegrationJobGroup, IntegrationSelection, IntegrationShard, IntegrationUnitId,
    Scheduling,
};
use crate::workspace_root;
use crate::{archrules, layerdeps, wsdeps};
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
    /// Adaptive PR check: exact internal public-api baseline owners selected from direct package impact.
    public_api: Option<PublicApiCheckScope>,
    execution_policy: crate::cmd::ExecutionPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PublicApiCheckScope {
    Affected(Vec<String>),
    CompleteInternal,
}

/// in-process Rust 门（无外部进程 / 自管子进程）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InternalCheck {
    LayerDeps,
    WsDepsDrift,
    /// Production Rustdoc semantic and token-profile trust-chain source guard.
    SourceSemanticGuard,
    /// ArchRules 派生索引 + 持久化 funnel 语义 closure 门。
    ArchRules,
    /// provider declaration ↔ live behavior runner ↔ owner/reachability ↔ typed integration shard.
    ProviderCapabilitiesCheck,
    /// bins 生产 src 的 `#[allow(rss_pdp_impl_adapter_only)]` 逃生门计数门（信任根二次门，PDP-ALLOW-CONFINE-01）。
    PdpAllowGuard,
    /// Makefile 的 canonical `ci` / `ci-full` executable 入口守卫（CI-LOCAL-ENTRY-01）。
    CiEntryGuard,
    /// 根 `deny.toml` / `clippy.toml` 结构化 defer 完整性 + 经典注解门
    /// （DEFER-GATE-01；只扫描机器拥有的 TOML，no-compile）。
    DeferGate,
    /// ci 专用：`cargo llvm-cov nextest`（兼 nextest 门）+ basis/engine ≥90% 覆盖率判定（见 `coverage.rs`）。
    Coverage,
    /// ci 专用：`public-api internal --check`（internal signature exact-set 漂移审查，见 `publicapi.rs`）。
    PublicApiCheck,
}

/// 门步 executor。工具要求、探测和安装提示只由 gate registry 提供。
#[derive(Debug, Clone, PartialEq, Eq)]
enum StepKind {
    Internal(InternalCheck),
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
        matches!(self.kind, StepKind::Nextest)
            || matches!(self.kind, StepKind::Internal(InternalCheck::Coverage))
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
fn step_layer_deps() -> Step {
    Step {
        id: GateId::LayerDeps,
        args: &[],
        kind: StepKind::Internal(InternalCheck::LayerDeps),
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
fn step_archrules() -> Step {
    Step {
        id: GateId::ArchRules,
        args: &[],
        kind: StepKind::Internal(InternalCheck::ArchRules),
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
fn step_pdp_allow_guard() -> Step {
    Step {
        id: GateId::PdpAllowGuard,
        args: &[],
        kind: StepKind::Internal(InternalCheck::PdpAllowGuard),
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
        args: &["deny", "check", "-D", "unused-wrapper"],
        kind: StepKind::Cargo,
        env: &[],
    }
}
/// audit 显式诊断专用：advisory-scoped `cargo deny check advisories`（只查 RustSec 漏洞库，
/// licenses/bans 留给 PR-triggered adaptive plan 的 [`step_deny`]）。
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
/// F7 + #1137：postgres/redis/amqp 等集成测试由 Cargo `[[test]] required-features`（catalog
/// LocalEligibility / INTEGRATION-SHARD-ELIGIBILITY-01）门控，verify 的 build/clippy/nextest 仅
/// workspace 默认 feature ⇒ 关键状态机测试（崩溃重投 / CAS fencing / DLX / sweep / redis 幂等 /
/// amqp pub-sub + 跨 vhost）默认门外、回归漏网。本步 `--no-run` 仅编译（不跑、
/// 无需真实后端 / docker）纳入默认 verify 抓**编译漂移**；有 docker / env URL 时经
/// 固定 `integration-critical` Job 按 typed selection 实跑。远端 check 经 `--all-features --all-targets`
/// 已覆盖该编译面，故 release-check 通过 typed subsumption 只保留 all-features owner。
fn step_integration_compile() -> Step {
    Step {
        id: GateId::IntegrationCompile,
        args: &[
            "test",
            "-p",
            "redis-adapter",
            "-p",
            "amqp",
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
#[allow(
    clippy::unreachable,
    reason = "typed GateId catalog closes core-test executor ownership at compile time"
)]
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
// 唯一 public-api gate 聚合 internal/release exact-set、SemVer、公共依赖与类型泄漏。
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
            GateGroup::Meta | GateGroup::Security | GateGroup::Coverage | GateGroup::Audit,
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
    if target == PlanProjection::Lane(GateGroup::Audit) {
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

/// audit 精简供应链门步计划（issue #1133；显式人工诊断入口）。
/// advisory-scoped deny + cargo-audit 两门，皆 no-compile、快，用于检查「未变依赖」后来披露的新
/// CVE。**不含** licenses/bans：它们只随 Cargo.lock 变（= 随 PR 变），重复检查无增益；
/// `release-check` 计划已用全量 `deny check` + cargo-audit 覆盖。audit 步与 ci 共享同一
/// [`step_cargo_audit`] 构造。
///
/// Audit 亦经统一动态 executor 委托（不内联门命令），由 `CI-ADAPTIVE-WORKFLOW-01` 守。
fn audit_plan() -> Vec<Step> {
    plan_for(PlanProjection::Lane(GateGroup::Audit))
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

fn run_integration_batch(
    selection: &IntegrationSelection,
    batch: &integration_shards::ShardBatch,
    partition: Option<crate::nextest::HashPartition>,
    root: &Path,
) -> Result<()> {
    crate::nextest::NextestInvocation::for_integration_batch(selection, batch, partition)?
        .run(root, INTEGRATION_ENV)
}

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
        |batch| run_integration_batch(selection, batch, partition, root),
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
        run_integration_batch(selection, batch, partition, workspace.root())
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
    run_step_with_status_source(lane, label, subcommand, args, execution_policy, |args| {
        crate::cmd::cargo_cmd(subcommand, args, env, Some(cwd)).status()
    })
}

fn run_step_with_status_source(
    lane: &str,
    label: &str,
    subcommand: crate::cmd::CargoSubcommand,
    args: &[&str],
    execution_policy: crate::cmd::ExecutionPolicy,
    status_source: impl FnOnce(&[&str]) -> std::io::Result<std::process::ExitStatus>,
) -> Result<()> {
    let args = cargo_args_for_policy(subcommand, args, execution_policy);
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let rendered = std::iter::once(subcommand.as_str())
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    let status = status_source(&args).map_err(|e| {
        anyhow::anyhow!("{lane}: 启动门步 `{label}`（cargo {}）失败: {e}", rendered)
    })?;
    step_status_result(lane, label, &rendered, status)
}

fn step_status_result(
    lane: &str,
    label: &str,
    rendered: &str,
    status: std::process::ExitStatus,
) -> Result<()> {
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
                ToolRequirement::PublicApiTools { .. } => {
                    bail!(
                        "{}: public-api tools 只允许绑定 internal executor",
                        step.label()
                    )
                }
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
        ToolRequirement::PublicApiTools { install_hint } => run_public_api_tools_gated(
            lane,
            opts.allow_missing_tools,
            step.label(),
            tool_available(crate::cmd::CargoSubcommand::PublicApi),
            install_hint,
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

fn run_public_api_tools_gated(
    lane: &str,
    allow_missing: bool,
    label: &str,
    public_api_available: bool,
    install_hint: &str,
    on_run: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if public_api_available {
        // SemVer is a lazy prerequisite: an empty or first-release-only surface has no
        // comparison target and must not require the tool. The in-process proof probes it
        // fail-closed immediately before the first actual comparison.
        return on_run();
    }
    run_tool_gated(
        lane,
        false,
        allow_missing,
        "public-api",
        install_hint,
        label,
        on_run,
    )
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
    let allow_missing = allow_missing_tools;
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
        InternalCheck::LayerDeps => run_check(&layerdeps::LayerDeps),
        InternalCheck::WsDepsDrift => run_check(&wsdeps::WsDepsDrift),
        InternalCheck::SourceSemanticGuard => {
            run_check(&crate::source_semantic_guard::SourceSemanticGuard)
        }
        InternalCheck::ArchRules => {
            let facts = command_facts
                .get()
                .context(command_scope_facts_context("archrules"))?;
            run_check(&archrules::ArchRules::new(facts))
        }
        InternalCheck::ProviderCapabilitiesCheck => crate::provider_capabilities::run(true),
        InternalCheck::PdpAllowGuard => run_check(&crate::pdpallow::PdpAllowGuard),
        InternalCheck::CiEntryGuard => crate::ci_entry_guard::run(),
        InternalCheck::DeferGate => run_check(&crate::defergate::DeferGate),
        InternalCheck::Coverage => {
            let scope = if opts.coverage_typed_job {
                crate::ci_impact::coverage_scope_for_typed_job(root)?
            } else {
                crate::ci_impact::coverage_scope_for_full_ci()
            };
            crate::coverage::run(scope, opts.execution_policy)
        }
        InternalCheck::PublicApiCheck => {
            let facts = command_facts
                .get()
                .context(command_scope_facts_context("public-api-check"))?;
            if let Some(scope) = &opts.public_api {
                return match scope {
                    PublicApiCheckScope::Affected(packages) => {
                        crate::publicapi::run_affected_internal_check(root, facts, packages)
                    }
                    PublicApiCheckScope::CompleteInternal => {
                        crate::publicapi::run_complete_internal_check(root, facts)
                    }
                };
            }
            let surface = crate::publicapi::run_release_check(
                root,
                facts,
                &opts.contract_against,
                opts.allow_missing_tools,
            )?;
            crate::package_proof::run(root, facts, &surface, None)
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
        if !plan.iter().any(|step| step.label() == label) {
            bail!("verify --only 未知或不属于当前计划的 gate: {label}");
        }
    }
    Ok(plan
        .into_iter()
        .filter(|step| only.iter().any(|label| label == step.label()))
        .collect())
}

fn listed_verify_labels(plan: &[Step]) -> Vec<&'static str> {
    let mut seen = std::collections::BTreeSet::new();
    plan.iter()
        .map(Step::label)
        .filter(|label| seen.insert(*label))
        .collect()
}

/// Execute the selected local meta gates inside the already provenance-checked snapshot worker.
/// This is the in-process equivalent of the historical nested `cargo xtask verify --only ...`.
pub(crate) fn run_local_meta(
    root: &Path,
    gates: &[GateId],
    contract_against: &str,
    execution_policy: crate::cmd::ExecutionPolicy,
) -> Result<()> {
    let opts = VerifyOpts {
        fast: false,
        allow_missing_tools: false,
        partition: None,
        nextest_lane: crate::nextest::NextestLane::Verify,
        core_test_selection: crate::nextest::CoreTestSelection::workspace(),
        contract_against: contract_against.to_owned(),
        coverage_typed_job: false,
        public_api: None,
        execution_policy,
    };
    let only = gates
        .iter()
        .map(|gate| gate.spec().label().to_owned())
        .collect::<Vec<_>>();
    let plan = select_verify_plan(verify_plan(&opts), &only)?;
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(root);
    run_labeled_plan("verify", &plan, &opts, root, &command_facts)
}

/// verify 入口：按 registry 顺序执行所选 plan；默认 keep-going，显式 `--fail-fast` 首错停止。
pub(crate) fn run(
    list_gates: bool,
    fast: bool,
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
        contract_against: contract_against.unwrap_or("origin/develop").to_owned(),
        coverage_typed_job: false,
        public_api: None,
        execution_policy: crate::cmd::ExecutionPolicy::from_fail_fast(fail_fast),
    };
    if list_gates {
        for label in listed_verify_labels(&verify_plan(&opts)) {
            println!("{label}");
        }
        return Ok(());
    }
    let root = workspace_root()?;
    let plan = select_verify_plan(verify_plan(&opts), only)?;
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
    run_labeled_plan("verify", &plan, &opts, &root, &command_facts)?;
    if only.is_empty() {
        eprintln!("verify（{mode}）：全部通过");
    } else {
        eprintln!("verify（{mode} partial）：所选 gate 通过；不代表完整 CI 通过");
    }
    Ok(())
}

/// Remote bounded preflight. It is a scheduling prerequisite, never a canonical proof owner.
pub(crate) fn run_remote_preflight(selection: &crate::ci_impact::SelectionPlan) -> Result<()> {
    let root = workspace_root()?;
    let opts = VerifyOpts {
        fast: true,
        allow_missing_tools: false,
        partition: None,
        nextest_lane: crate::nextest::NextestLane::Verify,
        core_test_selection: crate::nextest::CoreTestSelection::workspace(),
        contract_against: "origin/develop".to_owned(),
        coverage_typed_job: false,
        public_api: None,
        execution_policy: crate::cmd::ExecutionPolicy::FailFast,
    };
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
    run_labeled_plan(
        "ci-preflight-governance",
        &[step_for_id(GateId::Fmt)],
        &opts,
        &root,
        &command_facts,
    )?;
    let Some(owned_args) = remote_preflight_check_args(selection) else {
        eprintln!("ci-preflight: no affected Rust packages; compile screen is empty");
        return Ok(());
    };
    let args = owned_args.iter().map(String::as_str).collect::<Vec<_>>();
    run_step(
        "ci-preflight",
        "selection-scoped all-targets check",
        crate::cmd::CargoSubcommand::Check,
        &args,
        &[],
        &root,
        crate::cmd::ExecutionPolicy::FailFast,
    )
}

fn remote_preflight_check_args(selection: &crate::ci_impact::SelectionPlan) -> Option<Vec<String>> {
    let mut owned_args = vec!["--locked".to_owned(), "--all-targets".to_owned()];
    match selection.mode() {
        crate::ci_impact::SelectionMode::Adaptive if selection.affected_packages().is_empty() => {
            return None;
        }
        crate::ci_impact::SelectionMode::Adaptive => {
            for package in selection.affected_packages() {
                owned_args.push("--package".to_owned());
                owned_args.push(package.clone());
            }
        }
        crate::ci_impact::SelectionMode::PrComplete
        | crate::ci_impact::SelectionMode::ReleaseCheck => {
            owned_args.extend(["--workspace".to_owned(), "--all-features".to_owned()]);
        }
    }
    Some(owned_args)
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
        contract_against: "origin/develop".to_owned(),
        coverage_typed_job: false,
        public_api: None,
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

fn execution_selection_for_shard(
    selection: &IntegrationSelection,
    shard: IntegrationShard,
) -> Result<IntegrationSelection> {
    match selection.profile() {
        ExecutionProfile::IntegrationCritical => {
            IntegrationSelection::critical(selection.unit_ids_for_shard(shard))
        }
        ExecutionProfile::ReleaseCheck => Ok(selection.clone()),
        ExecutionProfile::Check | ExecutionProfile::Test => {
            bail!("IntegrationSelection excludes non-integration profiles")
        }
    }
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
                #[allow(
                    clippy::unreachable,
                    reason = "the integration-critical job returns before fixed profile projection"
                )]
                FixedCiJob::IntegrationCritical => unreachable!(),
            }
        }
        crate::ci_impact::SelectionMode::ReleaseCheck => ExecutionProfile::ReleaseCheck,
    };
    let mut plan = ExecutionUnitSpec::project(profile)
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
        .collect::<Vec<_>>();
    if job == FixedCiJob::Check
        && !matches!(
            selection.public_api_selection(),
            crate::ci_impact::ProjectedPublicApiSelection::None
        )
        && !plan.iter().any(|step| step.id == GateId::PublicApi)
    {
        plan.push(step_public_api());
    }
    plan
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
        contract_against: "origin/develop".to_owned(),
        coverage_typed_job: false,
        public_api: match selection.public_api_selection() {
            crate::ci_impact::ProjectedPublicApiSelection::None => None,
            crate::ci_impact::ProjectedPublicApiSelection::Affected(packages) => {
                Some(PublicApiCheckScope::Affected(packages.as_slice().to_vec()))
            }
            crate::ci_impact::ProjectedPublicApiSelection::CompleteInternal => {
                Some(PublicApiCheckScope::CompleteInternal)
            }
        },
        execution_policy: crate::cmd::ExecutionPolicy::FailFast,
    };
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
    run_labeled_plan(job.as_str(), &plan, &opts, &root, &command_facts)
}

fn execute_fixed_integration_shards(
    integration: &IntegrationSelection,
    group: IntegrationJobGroup,
) -> Result<()> {
    let root = workspace_root()?;
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
    let selected_shards = group
        .shards()
        .filter(|shard| !integration.unit_ids_for_shard(*shard).is_empty())
        .collect::<Vec<_>>();
    integration_shards::with_validated_workspace(&command_facts, |workspace| {
        execute_labeled_items(
            &format!("integration-critical/{group}"),
            &selected_shards,
            crate::cmd::ExecutionPolicy::FailFast,
            &SystemAggregateClock,
            |shard| shard.as_str().to_owned(),
            |shard| {
                let shard_selection = execution_selection_for_shard(integration, *shard)?;
                run_ci_integration_with_policy(
                    workspace,
                    *shard,
                    &shard_selection,
                    false,
                    None,
                    crate::cmd::ExecutionPolicy::FailFast,
                )
            },
        )
    })
}

fn execute_non_producer_integration_group(
    integration: &IntegrationSelection,
    group: IntegrationJobGroup,
) -> Result<()> {
    execute_fixed_integration_shards(integration, group)
}

fn run_fixed_integration_group(
    selection: &crate::ci_impact::SelectionPlan,
    group: IntegrationJobGroup,
) -> Result<()> {
    let integration = selection.integration_selection()?;
    if integration.unit_ids_for_group(group).is_empty() {
        eprintln!("integration-critical/{group}: selection is empty; fixed carrier succeeds");
        return Ok(());
    }
    execute_non_producer_integration_group(&integration, group)
}

pub(crate) fn run_fixed_job(
    invocation: FixedCiInvocation,
    selection: &crate::ci_impact::SelectionPlan,
) -> Result<()> {
    match invocation {
        FixedCiInvocation::Check => run_fixed_gate_job(FixedCiJob::Check, selection),
        FixedCiInvocation::TestAffected => run_fixed_gate_job(FixedCiJob::TestAffected, selection),
        FixedCiInvocation::Integration { group } => run_fixed_integration_group(selection, group),
    }
}

/// audit 入口（issue #1133 供应链显式诊断）：按 [`audit_plan`] 顺序跑每步，fail-fast。
/// `allow_missing_tools` 仅本地便利——CI 不传 = 缺 deny/audit 工具 fail-closed。
pub(crate) fn run_audit(allow_missing_tools: bool) -> Result<()> {
    let opts = VerifyOpts {
        fast: false,
        allow_missing_tools,
        partition: None,
        nextest_lane: crate::nextest::NextestLane::Verify,
        core_test_selection: crate::nextest::CoreTestSelection::workspace(),
        contract_against: "origin/develop".to_owned(),
        coverage_typed_job: false,
        public_api: None,
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

    #[test]
    fn deny_gate_fails_on_unused_wrappers() {
        assert_eq!(step_deny().args, &["deny", "check", "-D", "unused-wrapper"]);
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
    fn remote_preflight_compile_screen_is_selection_scoped() -> anyhow::Result<()> {
        let adaptive = crate::ci_impact::test_adaptive_selection_plan()?;
        assert_eq!(remote_preflight_check_args(&adaptive), None);

        let mut affected_wire = serde_json::to_value(&adaptive)?;
        affected_wire["selection"]["affected_packages"] =
            serde_json::json!(["application-services", "domain-core"]);
        let affected = serde_json::to_string(&affected_wire)?.parse()?;
        assert_eq!(
            remote_preflight_check_args(&affected),
            Some(vec![
                "--locked".to_owned(),
                "--all-targets".to_owned(),
                "--package".to_owned(),
                "application-services".to_owned(),
                "--package".to_owned(),
                "domain-core".to_owned(),
            ])
        );

        for selection in [
            crate::ci_impact::test_pr_complete_selection_plan()?,
            crate::ci_impact::test_selection_plan()?,
        ] {
            assert_eq!(
                remote_preflight_check_args(&selection),
                Some(vec![
                    "--locked".to_owned(),
                    "--all-targets".to_owned(),
                    "--workspace".to_owned(),
                    "--all-features".to_owned(),
                ])
            );
        }
        Ok(())
    }

    #[test]
    fn affected_internal_api_adds_the_canonical_gate_to_check_only() -> anyhow::Result<()> {
        let adaptive = crate::ci_impact::test_adaptive_selection_plan()?;
        let mut wire = serde_json::to_value(&adaptive)?;
        wire["selection"]["affected_packages"] = serde_json::json!(["diport"]);
        wire["selection"]["public_api"] =
            serde_json::json!({"scope": "affected", "packages": ["diport"]});
        let selection: crate::ci_impact::SelectionPlan = serde_json::to_string(&wire)?.parse()?;

        assert_eq!(selection.public_api_packages(), ["diport"]);
        assert_eq!(
            fixed_gate_plan(FixedCiJob::Check, &selection)
                .iter()
                .filter(|step| step.id == GateId::PublicApi)
                .count(),
            1
        );
        assert!(
            fixed_gate_plan(FixedCiJob::TestAffected, &selection)
                .iter()
                .all(|step| step.id != GateId::PublicApi)
        );

        let mut complete_wire =
            serde_json::to_value(crate::ci_impact::test_pr_complete_selection_plan()?)?;
        complete_wire["selection"]["public_api"] =
            serde_json::json!({"scope": "complete-internal"});
        let complete: crate::ci_impact::SelectionPlan =
            serde_json::to_string(&complete_wire)?.parse()?;
        assert!(matches!(
            complete.public_api_selection(),
            crate::ci_impact::ProjectedPublicApiSelection::CompleteInternal
        ));
        assert_eq!(
            fixed_gate_plan(FixedCiJob::Check, &complete)
                .iter()
                .filter(|step| step.id == GateId::PublicApi)
                .count(),
            1
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
            contract_against: "origin/develop".to_owned(),
            coverage_typed_job: false,
            public_api: None,
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
    fn verify_only_uses_registry_membership_and_canonical_order() -> anyhow::Result<()> {
        let plan = verify_plan(&opts(false, false));
        let selected = select_verify_plan(plan, &["clippy".to_owned(), "fmt".to_owned()])?;
        assert_eq!(labels(&selected), ["fmt", "clippy"]);
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
    fn listed_verify_labels_are_unique_and_each_is_selectable() -> anyhow::Result<()> {
        let plan = verify_plan(&opts(false, false));
        let listed = listed_verify_labels(&plan);
        let unique = listed
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(listed.len(), unique.len());
        for label in listed {
            select_verify_plan(plan.clone(), &[label.to_owned()])?;
        }
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
    fn labeled_plan_reexecutes_every_item_on_each_invocation() -> Result<()> {
        use crate::cmd::ExecutionPolicy;
        use std::cell::RefCell;

        let items = ["first", "second", "third"];
        let attempts = RefCell::new(std::collections::BTreeMap::<String, usize>::new());

        for _ in 0..2 {
            execute_labeled_items(
                "verify-test",
                &items,
                ExecutionPolicy::KeepGoing,
                &SystemAggregateClock,
                |item| (*item).to_owned(),
                |item| {
                    *attempts.borrow_mut().entry((*item).to_owned()).or_default() += 1;
                    Ok(())
                },
            )?;
        }
        assert_eq!(
            attempts.borrow().values().copied().collect::<Vec<_>>(),
            [2, 2, 2]
        );
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
            .args = &["test", "-p", "rss_instrument_err_level"];
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
        }
        let fast = verify_plan(&opts(true, false));
        assert!(!labels(&fast).contains(&"doc-contracts"));
        assert!(!labels(&fast).contains(&"source-semantic-guard"));
    }

    #[test]
    fn verify_plan_matches_registry_membership() -> anyhow::Result<()> {
        let plan = verify_plan(&opts(false, false));
        ensure_plan_has_exact_gate_ids(&plan, registry_gate_ids(|spec| spec.included_in_verify()))?;
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
    fn archrules_semantics_is_full_only_no_compile_internal_gate() -> anyhow::Result<()> {
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
            .kind = StepKind::Internal(InternalCheck::WsDepsDrift);
        assert!(validate_provider_capabilities_gate(&wrong_executor).is_err());
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
    fn run_step_nonzero_is_err_without_spawning_a_noisy_command() -> anyhow::Result<()> {
        #[cfg(unix)]
        let status = std::os::unix::process::ExitStatusExt::from_raw(2 << 8);
        #[cfg(windows)]
        let status = std::os::windows::process::ExitStatusExt::from_raw(2);

        let Err(error) = run_step_with_status_source(
            "verify",
            "redcase",
            crate::cmd::CargoSubcommand::Fmt,
            &["--check"],
            crate::cmd::ExecutionPolicy::FailFast,
            |args| {
                assert_eq!(args, ["--check"]);
                Ok(status)
            },
        ) else {
            anyhow::bail!("nonzero cargo gate must fail closed");
        };
        assert_eq!(
            error.to_string(),
            "verify: 门步 `redcase` 失败（cargo fmt --check 退出码 2）"
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

    #[test]
    fn public_api_gate_requires_capture_tool_but_defers_semver_tool_until_comparison() {
        let executed = std::cell::Cell::new(false);
        assert!(
            run_public_api_tools_gated(
                "release-check",
                false,
                "public-api",
                false,
                "install",
                || {
                    executed.set(true);
                    Ok(())
                }
            )
            .is_err()
        );
        assert!(!executed.get());

        assert!(
            run_public_api_tools_gated(
                "release-check",
                false,
                "public-api",
                true,
                "install",
                || {
                    executed.set(true);
                    Ok(())
                }
            )
            .is_ok()
        );
        assert!(
            executed.get(),
            "empty/first-release proof must not require SemVer tooling"
        );
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

    /// Check / ReleaseCheck 的 typed Clippy owner 必须 exact-once 且参数闭合；release 以
    /// `ClippyAllFeatures` 精确替代 `ClippyWorkspace`，不允许双 owner 或参数漂移。
    #[test]
    fn ci_build_clippy_use_all_features_all_targets() -> anyhow::Result<()> {
        let check = plan_for(PlanProjection::Profile(ExecutionProfile::Check));
        let check_clippy = check
            .iter()
            .filter(|step| step.id == GateId::ClippyWorkspace)
            .collect::<Vec<_>>();
        assert_eq!(check_clippy.len(), 1, "Check must own ClippyWorkspace once");
        assert_eq!(
            check_clippy[0].args,
            [
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings"
            ]
        );
        assert!(
            check
                .iter()
                .all(|step| step.id != GateId::ClippyAllFeatures),
            "Check must not project the release-only Clippy owner"
        );

        let release = plan_for(RELEASE_CHECK);
        let release_clippy = release
            .iter()
            .filter(|step| step.id == GateId::ClippyAllFeatures)
            .collect::<Vec<_>>();
        assert_eq!(
            release_clippy.len(),
            1,
            "ReleaseCheck must own ClippyAllFeatures once"
        );
        assert_eq!(
            release_clippy[0].args,
            [
                "clippy",
                "--workspace",
                "--all-features",
                "--all-targets",
                "--locked",
                "--",
                "-D",
                "warnings",
            ]
        );
        assert!(
            release
                .iter()
                .all(|step| step.id != GateId::ClippyWorkspace),
            "ReleaseCheck must subsume ClippyWorkspace with the all-features owner"
        );

        let build = release
            .iter()
            .find(|step| step.label() == "build")
            .context("release-check missing build step")?;
        assert_eq!(
            build.args,
            [
                "build",
                "--workspace",
                "--all-features",
                "--all-targets",
                "--locked",
            ]
        );
        Ok(())
    }

    /// ci 用覆盖率门**替** nextest（同跑兼测试），并由唯一 public-api gate 聚合 internal/release
    /// exact-set、SemVer、公共依赖与 forbidden-type leakage。二者皆 ToolGatedInternal。
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
            ToolRequirement::PublicApiTools { .. }
        ));
        assert_eq!(
            plan.iter()
                .filter(|step| step.id == GateId::PublicApi)
                .count(),
            1,
            "release compatibility proofs must retain one canonical gate"
        );
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

    // ---- audit 精简供应链 lane（issue #1133；显式 advisory 诊断）----

    /// audit_plan 顺序与门集（单一事实源）：advisory-scoped deny + cargo-audit。
    /// 不含 licenses/bans——它们只随 Cargo.lock 变（= 随 PR 变），重复跑无增益；release-check 已全查。
    #[test]
    fn audit_plan_keeps_local_supply_chain_order() {
        assert_eq!(labels(&audit_plan()), vec!["deny-advisories", "audit"]);
    }

    /// integration-compile（默认 verify 抓编译漂移）`--no-run` 覆盖各 adapter。
    #[test]
    fn integration_compile_covers_adapters_no_run() {
        let step = step_integration_compile();
        assert_eq!(step.label(), "integration-compile");
        assert_eq!(
            step.id.spec().tool(),
            ToolRequirement::CargoBuiltin(crate::cmd::CargoSubcommand::Test)
        );
        assert!(step.args.contains(&"--no-run"), "默认门只编译不实跑");
        for p in ["redis-adapter", "amqp"] {
            assert!(step.args.contains(&p), "integration-compile 须覆盖 {p}");
        }
    }

    /// audit lane 的 deny 步是 **advisory-scoped**（`deny check advisories`），非裸 `deny check`——
    /// 显式诊断只查漏洞库，licenses/bans 留给 PR-triggered adaptive plan 的 `deny check`。
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

    fn yaml_keys_exact_owned(mapping: &serde_yaml_ng::Mapping, expected: &[String]) -> bool {
        mapping
            .keys()
            .filter_map(serde_yaml_ng::Value::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            == expected.iter().map(String::as_str).collect()
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

    fn yaml_sequence_exact_owned(value: &serde_yaml_ng::Value, expected: &[String]) -> bool {
        value.as_sequence().is_some_and(|items| {
            items
                .iter()
                .filter_map(serde_yaml_ng::Value::as_str)
                .eq(expected.iter().map(String::as_str))
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

    fn fixed_caller_job_is_exact(
        jobs: &serde_yaml_ng::Mapping,
        identity: &str,
        job_identity: &str,
        group: Option<&str>,
    ) -> bool {
        let Some(job) = yaml_field(jobs, identity).and_then(yaml_map) else {
            return false;
        };
        let Some(with) = yaml_field(job, "with").and_then(yaml_map) else {
            return false;
        };
        yaml_keys_exact(job, &["name", "needs", "uses", "with"])
            && yaml_scalar(job, "needs") == Some("preflight")
            && yaml_scalar(job, "uses") == Some("./.github/workflows/rss-rust-job.yml")
            && yaml_keys_exact(
                with,
                if group.is_some() {
                    &["integration-group", "job", "selection", "source-revision"]
                } else {
                    &["job", "selection", "source-revision"]
                },
            )
            && yaml_scalar(with, "job") == Some(job_identity)
            && yaml_scalar(with, "integration-group") == group
            && yaml_scalar(with, "selection") == Some("${{ needs.preflight.outputs.selection }}")
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

    fn result_gate_step_is_exact(
        step: &serde_yaml_ng::Mapping,
        expected_env: &[(&str, &str)],
        dependencies: &[(&str, &str)],
    ) -> bool {
        let dependency_lines = dependencies
            .iter()
            .map(|(name, variable)| format!("  \"{name}={variable}\""))
            .collect::<Vec<_>>()
            .join(" \\\n");
        let expected_run = format!(
            "set -euo pipefail\nfailed=false\nfor dependency in \\\n{dependency_lines}; do\n  printf '%s\\n' \"$dependency\"\n  case \"$dependency\" in *=success) ;; *) failed=true ;; esac\ndone\n[ \"$failed\" = false ]"
        );
        yaml_keys_exact(step, &["env", "id", "name", "run"])
            && yaml_field(step, "env")
                .and_then(yaml_map)
                .is_some_and(|env| {
                    yaml_keys_exact(
                        env,
                        &expected_env.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
                    ) && expected_env
                        .iter()
                        .all(|(key, value)| yaml_scalar(env, key) == Some(*value))
                })
            && yaml_scalar(step, "run").is_some_and(|run| run.trim_end() == expected_run)
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

    fn cache_caller_is_exact(
        job: &serde_yaml_ng::Mapping,
        setup_id: &str,
        execution_id: &str,
        finalize_id: &str,
    ) -> bool {
        let Some(steps) = yaml_field(job, "steps").and_then(serde_yaml_ng::Value::as_sequence)
        else {
            return false;
        };
        let Some(setup) = unique_step_by_id(steps, setup_id) else {
            return false;
        };
        if unique_step_by_id(steps, execution_id).is_none() {
            return false;
        }
        let Some(finalize) = unique_step_by_id(steps, finalize_id) else {
            return false;
        };
        let expected_context = format!("${{{{ steps.{setup_id}.outputs.cache-context }}}}");
        let expected_outcome = format!("${{{{ steps.{execution_id}.outcome }}}}");
        let expected_eligibility = format!(
            "${{{{ steps.{execution_id}.outcome == 'success' || steps.{execution_id}.outcome == 'failure' }}}}"
        );
        let exact_action_pair = steps
            .iter()
            .filter_map(serde_yaml_ng::Value::as_mapping)
            .filter_map(|step| yaml_scalar(step, "uses"))
            .filter(|uses| {
                matches!(
                    *uses,
                    "./.github/actions/setup-rss-ci" | "./.github/actions/finalize-rss-ci"
                )
            })
            .collect::<Vec<_>>()
            == [
                "./.github/actions/setup-rss-ci",
                "./.github/actions/finalize-rss-ci",
            ];
        exact_action_pair
            && step_ids_are_ordered(job, &[setup_id, execution_id, finalize_id])
            && yaml_scalar(setup, "uses") == Some("./.github/actions/setup-rss-ci")
            && yaml_scalar(finalize, "if")
                == Some(&format!(
                    "${{{{ always() && !cancelled() && steps.{setup_id}.outcome == 'success' }}}}"
                ))
            && yaml_field(finalize, "continue-on-error").and_then(serde_yaml_ng::Value::as_bool)
                == Some(true)
            && yaml_scalar(finalize, "uses") == Some("./.github/actions/finalize-rss-ci")
            && yaml_field(finalize, "with")
                .and_then(yaml_map)
                .is_some_and(|with| {
                    yaml_keys_exact(
                        with,
                        &["cache-context", "execution-outcome", "save-eligible"],
                    ) && yaml_scalar(with, "cache-context") == Some(&expected_context)
                        && yaml_scalar(with, "execution-outcome") == Some(&expected_outcome)
                        && yaml_scalar(with, "save-eligible") == Some(&expected_eligibility)
                })
    }

    /// INVARIANT: CI-FIXED-WORKFLOW-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "fixed_ci_workflow_guard_rejects_structural_weakening", anti_vacuity = "committed_fixed_ci_workflow_is_closed" }.
    fn fixed_ci_workflow_is_closed(
        caller: &str,
        reusable: &str,
        setup: &str,
        finalize: &str,
        cache_policy: &str,
    ) -> bool {
        let groups = IntegrationJobGroup::ALL.map(IntegrationJobGroup::as_str);
        fixed_ci_workflow_is_closed_for_groups(
            caller,
            reusable,
            setup,
            finalize,
            cache_policy,
            &groups,
        )
    }

    fn fixed_ci_workflow_is_closed_for_groups(
        caller: &str,
        reusable: &str,
        setup: &str,
        finalize: &str,
        cache_policy: &str,
        groups: &[&str],
    ) -> bool {
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
        let integration_jobs = groups
            .iter()
            .map(|group| format!("integration-{group}"))
            .collect::<Vec<_>>();
        let mut expected_jobs = vec![
            "preflight".to_owned(),
            "check".to_owned(),
            "test-affected".to_owned(),
        ];
        expected_jobs.extend(integration_jobs.iter().cloned());
        expected_jobs.extend(["integration-critical".to_owned(), "ci-gate".to_owned()]);
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
                    == ["integration-group", "job", "selection", "source-revision"]
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
        let fixed_calls = fixed_caller_job_is_exact(jobs, "check", "check", None)
            && fixed_caller_job_is_exact(jobs, "test-affected", "test-affected", None)
            && groups.iter().all(|group| {
                let job = format!("integration-{group}");
                fixed_caller_job_is_exact(jobs, &job, "integration-critical", Some(group))
            });
        let group_case = groups
            .iter()
            .map(|group| format!("integration-critical:{group}"))
            .collect::<Vec<_>>()
            .join("|");
        let fixed_events_are_exact = yaml_field(caller_root, "on")
            .and_then(yaml_map)
            .is_some_and(|events| {
                yaml_keys_exact(events, &["pull_request", "push", "workflow_dispatch"])
                    && ["pull_request", "push"].into_iter().all(|event| {
                        yaml_field(events, event)
                            .and_then(yaml_map)
                            .and_then(|event| yaml_field(event, "branches"))
                            .is_some_and(|branches| yaml_sequence_exact(branches, &["develop"]))
                    })
            });
        let integration_gate = yaml_field(jobs, "integration-critical").and_then(yaml_map);
        let exact_integration_gate = integration_gate.is_some_and(|gate| {
            yaml_scalar(gate, "if") == Some("${{ always() }}")
                && yaml_field(gate, "needs")
                    .is_some_and(|needs| yaml_sequence_exact_owned(needs, &integration_jobs))
                && step_by_id(gate, "integration-result-gate").is_some_and(|step| {
                    let env = groups
                        .iter()
                        .map(|group| {
                            let key = format!("{}_RESULT", group.to_ascii_uppercase());
                            let value = format!("${{{{ needs.integration-{group}.result }}}}");
                            (key, value)
                        })
                        .collect::<Vec<_>>();
                    let env_refs = env
                        .iter()
                        .map(|(key, value)| (key.as_str(), value.as_str()))
                        .collect::<Vec<_>>();
                    let dependencies = groups
                        .iter()
                        .map(|group| {
                            let variable = format!("${}_RESULT", group.to_ascii_uppercase());
                            (*group, variable)
                        })
                        .collect::<Vec<_>>();
                    let dependency_refs = dependencies
                        .iter()
                        .map(|(name, variable)| (*name, variable.as_str()))
                        .collect::<Vec<_>>();
                    result_gate_step_is_exact(step, &env_refs, &dependency_refs)
                })
        });
        let exact_gate = yaml_field(jobs, "ci-gate")
            .and_then(yaml_map)
            .is_some_and(|gate| {
                yaml_scalar(gate, "if") == Some("${{ always() }}")
                    && yaml_field(gate, "needs").is_some_and(|needs| {
                        yaml_sequence_exact(
                            needs,
                            &[
                                "preflight",
                                "check",
                                "test-affected",
                                "integration-critical",
                            ],
                        )
                    })
                    && step_by_id(gate, "fixed-job-gate").is_some_and(|step| {
                        result_gate_step_is_exact(
                            step,
                            &[
                                ("PREFLIGHT_RESULT", "${{ needs.preflight.result }}"),
                                ("CHECK_RESULT", "${{ needs.check.result }}"),
                                ("TEST_RESULT", "${{ needs.test-affected.result }}"),
                                (
                                    "INTEGRATION_RESULT",
                                    "${{ needs.integration-critical.result }}",
                                ),
                            ],
                            &[
                                ("preflight", "$PREFLIGHT_RESULT"),
                                ("check", "$CHECK_RESULT"),
                                ("test-affected", "$TEST_RESULT"),
                                ("integration-critical", "$INTEGRATION_RESULT"),
                            ],
                        )
                    })
            });
        let preflight = yaml_field(jobs, "preflight").and_then(yaml_map);
        let exact_preflight = preflight.is_some_and(|job| {
            yaml_field(job, "timeout-minutes").and_then(serde_yaml_ng::Value::as_i64) == Some(10)
                && step_ids_are_ordered(
                    job,
                    &[
                        "preflight-budget",
                        "preflight-setup",
                        "select",
                        "preflight-run",
                        "preflight-finalize",
                    ],
                )
                && step_by_id(job, "preflight-budget").is_some_and(|step| {
                    yaml_scalar(step, "run")
                        == Some(
                            "echo \"deadline-epoch=$(( $(date +%s) + 540 ))\" >> \"$GITHUB_OUTPUT\"",
                        )
                })
                && cache_caller_is_exact(
                    job,
                    "preflight-setup",
                    "preflight-run",
                    "preflight-finalize",
                )
                && step_by_id(job, "select")
                    .and_then(|step| yaml_scalar(step, "run"))
                    .is_some_and(|run| run.contains("$CARGO_TARGET_DIR/debug/xtask\" ci plan"))
                && step_by_id(job, "preflight-run").is_some_and(|step| {
                    yaml_field(step, "env")
                        .and_then(yaml_map)
                        .is_some_and(|env| {
                            yaml_keys_exact(
                                env,
                                &["RSS_PREFLIGHT_DEADLINE_EPOCH", "RSS_SELECTION"],
                            ) && yaml_scalar(env, "RSS_PREFLIGHT_DEADLINE_EPOCH")
                                == Some(
                                    "${{ steps.preflight-budget.outputs.deadline-epoch }}",
                                )
                                && yaml_scalar(env, "RSS_SELECTION")
                                    == Some("${{ steps.select.outputs.selection }}")
                        })
                        && yaml_scalar(step, "run").is_some_and(|run| {
                            run.contains(
                                "remaining=$(( RSS_PREFLIGHT_DEADLINE_EPOCH - $(date +%s) ))",
                            ) && run.contains("--kill-after=15s \"${remaining}s\"")
                                && run.contains(
                                    "$CARGO_TARGET_DIR/debug/xtask\" ci preflight --selection \"$RSS_SELECTION\"",
                                )
                                && !run.contains(" 8m ")
                        })
                })
        });
        let cleanup_is_always = step_by_id(execute, "integration-cleanup")
            .is_some_and(|step| {
                yaml_scalar(step, "if")
                    == Some("${{ always() && inputs.job == 'integration-critical' && steps.integration-prepare.outcome == 'success' }}")
            });
        let cache_lifecycle =
            preflight.is_some_and(|job| {
                cache_caller_is_exact(
                    job,
                    "preflight-setup",
                    "preflight-run",
                    "preflight-finalize",
                )
            }) && cache_caller_is_exact(execute, "rss-setup", "xtask", "rss-finalize")
                && workflow_has_no_direct_cache(caller_root)
                && workflow_has_no_direct_cache(reusable_root)
                && fixed_cache_actions_are_closed(setup, finalize, cache_policy);
        let lifecycle = step_ids_are_ordered(
            execute,
            &[
                "policy",
                "rss-setup",
                "integration-prepare",
                "xtask",
                "integration-collect",
                "integration-snapshot",
                "integration-cleanup",
                "upload-integration-failure",
                "rss-finalize",
            ],
        ) && step_by_id(execute, "xtask")
            .and_then(|step| yaml_scalar(step, "run"))
            .is_some_and(|run| {
                run.contains(
                    "args=(ci run --job \"$RSS_FIXED_JOB\" --selection \"$RSS_SELECTION\")",
                ) && run.contains("args+=(--integration-group \"$RSS_INTEGRATION_GROUP\")")
            })
            && artifact_step_is_exact(
                execute,
                "upload-integration-failure",
                "${{ failure() && inputs.job == 'integration-critical' && steps.policy.outcome == 'success' }}",
                "integration-failure-${{ github.run_id }}-${{ github.run_attempt }}-${{ steps.policy.outputs.artifact-suffix }}",
                "${{ runner.temp }}/integration-lifecycle-${{ steps.policy.outputs.artifact-suffix }}.json\n${{ runner.temp }}/integration-service-logs-${{ steps.policy.outputs.artifact-suffix }}.tar.gz\n",
                "warn",
            )
            && reusable.contains("case \"$RSS_FIXED_JOB:$RSS_INTEGRATION_GROUP\"")
            && reusable.contains("invalid fixed invocation: job=%s integration-group=%s; allowed:")
            && reusable.contains(&group_case)
            && cache_policy.contains(&group_case)
            && reusable
                .contains("compiler-partition: ${{ steps.policy.outputs.compiler-partition }}")
            && reusable.contains("log_dir=\"$RUNNER_TEMP/integration-service-logs-$RSS_SCOPE\"")
            && reusable.matches("ci validate-evidence").count() == 0
            && reusable.matches("${{ inputs.integration-group }}").count() == 2
            && !reusable.contains("${{ inputs.integration-group }}.tar.gz")
            && setup
                .find("ci-cache-maintain.sh derive-keys")
                .is_some_and(|validated| {
                    [
                        "ci-cache-maintain.sh prepare-roots",
                        "ci-cache-maintain.sh reset-descendant",
                        "mkdir -p \"$RSS_JOB_TARGET\"",
                    ]
                    .into_iter()
                    .all(|operation| setup.find(operation).is_some_and(|index| index > validated))
                });
        yaml_keys_exact_owned(jobs, &expected_jobs)
            && yaml_keys_exact(reusable_jobs, &["execute"])
            && exact_permissions
            && exact_inputs
            && fixed_calls
            && fixed_events_are_exact
            && exact_preflight
            && exact_integration_gate
            && exact_gate
            && cleanup_is_always
            && cache_lifecycle
            && lifecycle
            && caller.matches("cargo build --locked -p xtask").count() == 1
            && !caller.contains("cargo run --locked -p xtask -- ci gate")
            && !caller.contains("  selector:")
            && banned
                .into_iter()
                .all(|needle| !caller.contains(needle) && !reusable.contains(needle))
    }

    #[test]
    fn committed_fixed_ci_workflow_is_closed() {
        assert!(fixed_ci_workflow_is_closed(
            include_str!("../../.github/workflows/ci.yml"),
            include_str!("../../.github/workflows/rss-rust-job.yml"),
            include_str!("../../.github/actions/setup-rss-ci/action.yml"),
            include_str!("../../.github/actions/finalize-rss-ci/action.yml"),
            include_str!("../../.github/scripts/ci-cache-maintain.sh"),
        ));
    }

    #[test]
    fn candidate_bundle_runs_package_proof_once() {
        let workflow = include_str!("../../.github/workflows/candidate-bundle.yml");
        assert_eq!(workflow.matches("xtask package-proof").count(), 1);
    }

    #[test]
    fn committed_ci_workflow_has_no_scheduled_nightly() -> anyhow::Result<()> {
        let workflow = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(include_str!(
            "../../.github/workflows/ci.yml"
        ))?;
        let root = yaml_map(&workflow).context("committed CI workflow must be a mapping")?;
        let triggers = yaml_field(root, "on")
            .and_then(yaml_map)
            .context("committed CI workflow must declare triggers")?;
        let jobs = yaml_field(root, "jobs")
            .and_then(yaml_map)
            .context("committed CI workflow must declare jobs")?;

        assert!(
            yaml_field(triggers, "schedule").is_none(),
            "fixed CI must not repeat ReleaseCheck on a nightly schedule"
        );
        assert!(
            yaml_field(jobs, "scheduled-audit-fallback").is_none(),
            "fixed CI must not retain the scheduled-only fallback job"
        );
        Ok(())
    }

    #[test]
    fn committed_scheduled_security_audit_is_narrow() -> anyhow::Result<()> {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/security-audit.yml");
        let workflow =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let value = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&workflow)?;
        let root = yaml_map(&value).context("scheduled security audit must be a mapping")?;
        let triggers = yaml_field(root, "on")
            .and_then(yaml_map)
            .context("scheduled security audit must declare triggers")?;
        let schedule = yaml_field(triggers, "schedule")
            .and_then(serde_yaml_ng::Value::as_sequence)
            .context("scheduled security audit must declare a UTC cron")?;
        let jobs = yaml_field(root, "jobs")
            .and_then(yaml_map)
            .context("scheduled security audit must declare jobs")?;

        assert!(yaml_keys_exact(
            triggers,
            &["schedule", "workflow_dispatch"]
        ));
        assert_eq!(schedule.len(), 1);
        assert_eq!(
            schedule[0]
                .as_mapping()
                .and_then(|entry| yaml_scalar(entry, "cron")),
            Some("0 6 * * *")
        );
        assert!(exact_read_permissions(root));
        assert!(yaml_keys_exact(jobs, &["audit"]));
        assert_eq!(
            workflow
                .matches("cargo run --locked -p xtask -- ci audit")
                .count(),
            1
        );
        for forbidden in ["ci full", "ci run --job", "nextest", "cargo test"] {
            assert!(
                !workflow.contains(forbidden),
                "scheduled security audit must not execute `{forbidden}`"
            );
        }
        Ok(())
    }

    #[test]
    fn fixed_ci_workflow_guard_rejects_structural_weakening() {
        let caller = include_str!("../../.github/workflows/ci.yml");
        let reusable = include_str!("../../.github/workflows/rss-rust-job.yml");
        let setup = include_str!("../../.github/actions/setup-rss-ci/action.yml");
        let finalize = include_str!("../../.github/actions/finalize-rss-ci/action.yml");
        let cache_policy = include_str!("../../.github/scripts/ci-cache-maintain.sh");
        let reds = [
            (caller.replacen("  integration-postgres:\n", "  integration-postgres-removed:\n", 1), reusable.to_owned()),
            (caller.replacen("  check:\n", "  check:\n    strategy:\n      matrix: { shard: [one] }\n", 1), reusable.to_owned()),
            (caller.replacen("contents: read", "contents: write", 1), reusable.to_owned()),
            (caller.replacen("needs: preflight", "needs: check", 1), reusable.to_owned()),
            (caller.replacen("integration-group: postgres", "integration-group: transport", 1), reusable.to_owned()),
            (caller.replacen("INTEGRATION_RESULT: ${{ needs.integration-critical.result }}", "INTEGRATION_RESULT: success", 1), reusable.to_owned()),
            (caller.replacen("POSTGRES_RESULT: ${{ needs.integration-postgres.result }}", "POSTGRES_RESULT: success", 1), reusable.to_owned()),
            (caller.replacen("+ 540", "+ 600", 1), reusable.to_owned()),
            (caller.replacen("ci preflight --selection \"$RSS_SELECTION\"", "ci preflight", 1), reusable.to_owned()),
            (caller.replacen("--kill-after=15s \"${remaining}s\"", "--kill-after=30s 8m", 1), reusable.to_owned()),
            (caller.replace("case \"$dependency\" in *=success) ;; *) failed=true ;; esac", "true"), reusable.to_owned()),
            (caller.replace("*=success) ;;", "*=failure) ;;"), reusable.to_owned()),
            (caller.replace("    branches: [develop]\n", "    branches: [develop, feature/**]\n"), reusable.to_owned()),
            (caller.replacen("  workflow_dispatch:\n", "  schedule:\n    - cron: \"0 6 * * *\"\n  workflow_dispatch:\n", 1), reusable.to_owned()),
            (caller.replacen("  ci-gate:\n", "  scheduled-audit-fallback:\n    runs-on: ubuntu-latest\n  ci-gate:\n", 1), reusable.to_owned()),
            (caller.to_owned(), reusable.replacen("      source-revision:\n", "      legacy-lane:\n        required: false\n        type: string\n      source-revision:\n", 1)),
            (caller.to_owned(), reusable.replacen("compiler-partition: ${{ steps.policy.outputs.compiler-partition }}", "compiler-partition: integration-critical", 1)),
            (caller.to_owned(), reusable.replacen("integration-service-logs-$RSS_SCOPE", "integration-service-logs-$RSS_GROUP", 1)),
            (caller.to_owned(), reusable.replacen("invalid fixed invocation: job=%s integration-group=%s; allowed:", "invalid invocation:", 1)),
            (caller.to_owned(), reusable.replacen("steps.policy.outputs.artifact-suffix", "inputs.integration-group", 1)),
            (caller.replacen("cargo build --locked -p xtask", "cargo run --locked -p xtask -- ci gate", 1), reusable.to_owned()),
        ];
        for (index, (red_caller, red_reusable)) in reds.into_iter().enumerate() {
            assert!(red_caller != caller || red_reusable != reusable);
            assert!(
                !fixed_ci_workflow_is_closed(
                    &red_caller,
                    &red_reusable,
                    setup,
                    finalize,
                    cache_policy,
                ),
                "fixed workflow synthetic red {index} was accepted"
            );
        }
        for (label, red_setup, red_finalize) in [
            (
                "combined compiler cache",
                setup.replacen(
                    "      id: compiler-cache\n      continue-on-error: true\n      uses: actions/cache/restore@v4",
                    "      id: compiler-cache\n      continue-on-error: true\n      uses: actions/cache@v4",
                    1,
                ),
                finalize.to_owned(),
            ),
            (
                "missing broad compiler restore",
                setup.replacen(
                    "          ${{ steps.cache-keys.outputs.compiler-broad-restore-prefix }}\n",
                    "",
                    1,
                ),
                finalize.to_owned(),
            ),
            (
                "cache failure changes job verdict",
                setup.replacen(
                    "      continue-on-error: true\n      uses: actions/cache/restore@v4",
                    "      continue-on-error: false\n      uses: actions/cache/restore@v4",
                    1,
                ),
                finalize.to_owned(),
            ),
            (
                "input-derived path before identity validation",
                setup.replacen(
                    "        # derive-keys is the closed identity validator and must run before any\n        # input-derived path is created or reset.\n        .github/scripts/ci-cache-maintain.sh derive-keys",
                    "        mkdir -p \"$RSS_JOB_TARGET\"\n        # derive-keys is the closed identity validator and must run before any\n        # input-derived path is created or reset.\n        .github/scripts/ci-cache-maintain.sh derive-keys",
                    1,
                ),
                finalize.to_owned(),
            ),
            (
                "matched key used for save",
                setup.to_owned(),
                finalize.replace(
                    "steps.policy.outputs.compiler-primary-key",
                    "steps.policy.outputs.compiler-matched-key",
                ),
            ),
            (
                "cancelled compiler save",
                setup.to_owned(),
                finalize.replace("!cancelled() && ", ""),
            ),
            (
                "download restore path rewire",
                setup.replacen(
                    "${{ runner.temp }}/rss-cargo-home/registry/cache\n          ${{ runner.temp }}/rss-cargo-home/registry/index\n          ${{ runner.temp }}/rss-cargo-home/git/db",
                    ".cache/ci-tools/${{ inputs.lane }}",
                    1,
                ),
                finalize.to_owned(),
            ),
            (
                "download save key rewire",
                setup.to_owned(),
                finalize.replacen(
                    "key: ${{ steps.policy.outputs.download-primary-key }}",
                    "key: ${{ steps.policy.outputs.compiler-primary-key }}",
                    1,
                ),
            ),
        ] {
            assert!(
                !fixed_ci_workflow_is_closed(
                    caller,
                    reusable,
                    &red_setup,
                    &red_finalize,
                    cache_policy,
                ),
                "fixed workflow action synthetic red `{label}` was accepted"
            );
        }
        assert!(fixed_ci_workflow_is_closed_for_groups(
            caller,
            reusable,
            setup,
            finalize,
            cache_policy,
            &["postgres", "transport", "runtime"],
        ));
        assert!(!fixed_ci_workflow_is_closed_for_groups(
            caller,
            reusable,
            setup,
            finalize,
            cache_policy,
            &["postgres", "transport", "runtime", "future"],
        ));
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
        let cached_verify = step_by_id(runs, "tools-cache-verify");
        let reset = step_by_id(runs, "tools-reset");
        let verify = step_by_id(runs, "tools-verify");
        let save = step_by_id(runs, "tools-save");
        let tool_cache_funnel = yaml_field(runs, "steps")
            .and_then(serde_yaml_ng::Value::as_sequence)
            .is_some_and(|steps| {
                cache_steps_with_id_prefix_match_exact(
                    steps,
                    "tools-",
                    &[
                        ("tools-cache", "actions/cache/restore@v4"),
                        ("tools-save", "actions/cache/save@v4"),
                    ],
                )
            });
        let sealed_cache = step_ids_are_ordered(
            runs,
            &[
                "tools-cache",
                "tools-cache-verify",
                "tools-reset",
                "tools-verify",
                "tools-save",
            ],
        )
            && restore.is_some_and(|step| {
                yaml_scalar(step, "uses") == Some("actions/cache/restore@v4")
            })
            && cached_verify
                .and_then(|step| yaml_scalar(step, "run"))
                .is_some_and(|run| run.contains("verify --mode cache"))
            && reset.is_some_and(|step| {
                yaml_scalar(step, "if") == Some("${{ steps.tools-cache.outcome != 'success' || steps.tools-cache.outputs.cache-hit != 'true' || steps.tools-cache-verify.outcome != 'success' }}")
                    && yaml_scalar(step, "run").is_some_and(|run| run.contains("reset-descendant"))
            })
            && verify.and_then(|step| yaml_scalar(step, "run")).is_some_and(|run| {
                run.contains(".github/scripts/ci-tool-adapters.sh verify --mode \"$mode\" --lane \"$RSS_LANE\"")
            })
            && save.is_some_and(|step| {
                yaml_scalar(step, "if") == Some("${{ steps.tools-cache-verify.outcome != 'success' && steps.tools-verify.outcome == 'success' && github.event_name == 'push' && github.ref == 'refs/heads/develop' }}")
                    && yaml_scalar(step, "uses") == Some("actions/cache/save@v4")
                    && yaml_field(step, "with").and_then(yaml_map).is_some_and(|with| {
                        yaml_scalar(with, "path") == Some(".cache/ci-tools/${{ inputs.lane }}")
                            && yaml_scalar(with, "key") == Some("${{ steps.cache-keys.outputs.tools-primary-key }}")
                    })
            });
        adapter.contains("all|preflight|check|test-affected|integration-critical|audit)")
            && action.contains(".github/scripts/ci-tool-adapters.sh specs --lane \"$RSS_LANE\"")
            && !action.contains("compiler-cache-identity:")
            && !action.contains("  profile:")
            && tool_cache_funnel
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
                "restore-only tool cache",
                action.replacen(
                    "      id: tools-cache\n      continue-on-error: true\n      uses: actions/cache/restore@v4",
                    "      id: tools-cache\n      continue-on-error: true\n      uses: actions/cache@v4",
                    1,
                ),
                adapter.to_owned(),
            ),
            (
                "invalid restored tools reset",
                action.replacen(
                    "steps.tools-cache-verify.outcome != 'success'",
                    "steps.tools-cache-verify.outcome == 'success'",
                    1,
                ),
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

    fn cache_action_steps(root: &serde_yaml_ng::Mapping) -> Option<&Vec<serde_yaml_ng::Value>> {
        yaml_field(root, "runs")?
            .as_mapping()
            .and_then(|runs| yaml_field(runs, "steps"))?
            .as_sequence()
    }

    fn unique_step_by_id<'a>(
        steps: &'a [serde_yaml_ng::Value],
        id: &str,
    ) -> Option<&'a serde_yaml_ng::Mapping> {
        let mut matches = steps
            .iter()
            .filter_map(serde_yaml_ng::Value::as_mapping)
            .filter(|step| yaml_scalar(step, "id") == Some(id));
        let step = matches.next()?;
        matches.next().is_none().then_some(step)
    }

    fn cache_step_is_exact(
        steps: &[serde_yaml_ng::Value],
        id: &str,
        uses: &str,
        condition: Option<&str>,
        with_fields: &[(&str, &str)],
    ) -> bool {
        let Some(step) = unique_step_by_id(steps, id) else {
            return false;
        };
        let expected_step_keys = if condition.is_some() {
            &["name", "id", "if", "continue-on-error", "uses", "with"][..]
        } else {
            &["name", "id", "continue-on-error", "uses", "with"][..]
        };
        let Some(with) = yaml_field(step, "with").and_then(yaml_map) else {
            return false;
        };
        yaml_keys_exact(step, expected_step_keys)
            && yaml_scalar(step, "uses") == Some(uses)
            && condition.is_none_or(|expected| yaml_scalar(step, "if") == Some(expected))
            && yaml_field(step, "continue-on-error").and_then(serde_yaml_ng::Value::as_bool)
                == Some(true)
            && yaml_keys_exact(
                with,
                &with_fields.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            )
            && with_fields
                .iter()
                .all(|(key, value)| yaml_scalar(with, key) == Some(*value))
    }

    fn cache_steps_match_exact_funnel(
        steps: &[serde_yaml_ng::Value],
        expected: &[(&str, &str)],
    ) -> bool {
        steps
            .iter()
            .filter_map(serde_yaml_ng::Value::as_mapping)
            .filter_map(|step| {
                let uses = yaml_scalar(step, "uses")?;
                uses.starts_with("actions/cache")
                    .then(|| (yaml_scalar(step, "id"), uses))
            })
            .map(|(id, uses)| id.map(|id| (id, uses)))
            .collect::<Option<Vec<_>>>()
            .is_some_and(|actual| actual == expected)
    }

    fn cache_steps_with_id_prefix_match_exact(
        steps: &[serde_yaml_ng::Value],
        id_prefix: &str,
        expected: &[(&str, &str)],
    ) -> bool {
        steps
            .iter()
            .filter_map(serde_yaml_ng::Value::as_mapping)
            .filter_map(|step| {
                let id = yaml_scalar(step, "id")?;
                let uses = yaml_scalar(step, "uses")?;
                (id.starts_with(id_prefix) && uses.starts_with("actions/cache"))
                    .then_some((id, uses))
            })
            .collect::<Vec<_>>()
            == expected
    }

    fn cache_steps_without_id_prefix_match_exact(
        steps: &[serde_yaml_ng::Value],
        excluded_prefix: &str,
        expected: &[(&str, &str)],
    ) -> bool {
        steps
            .iter()
            .filter_map(serde_yaml_ng::Value::as_mapping)
            .filter_map(|step| {
                let id = yaml_scalar(step, "id")?;
                let uses = yaml_scalar(step, "uses")?;
                (uses.starts_with("actions/cache") && !id.starts_with(excluded_prefix))
                    .then_some((id, uses))
            })
            .collect::<Vec<_>>()
            == expected
    }

    fn workflow_has_no_direct_cache(root: &serde_yaml_ng::Mapping) -> bool {
        yaml_field(root, "jobs")
            .and_then(yaml_map)
            .is_some_and(|jobs| {
                jobs.values().all(|job| {
                    let Some(job) = job.as_mapping() else {
                        return false;
                    };
                    yaml_field(job, "steps")
                        .and_then(serde_yaml_ng::Value::as_sequence)
                        .is_none_or(|steps| {
                            steps
                                .iter()
                                .filter_map(serde_yaml_ng::Value::as_mapping)
                                .filter_map(|step| yaml_scalar(step, "uses"))
                                .all(|uses| !uses.starts_with("actions/cache"))
                        })
                })
            })
    }

    fn fixed_cache_actions_are_closed(setup: &str, finalize: &str, policy: &str) -> bool {
        let Ok(setup_value) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(setup) else {
            return false;
        };
        let Ok(finalize_value) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(finalize) else {
            return false;
        };
        let Some(setup_root) = yaml_map(&setup_value) else {
            return false;
        };
        let Some(finalize_root) = yaml_map(&finalize_value) else {
            return false;
        };
        let Some(setup_steps) = cache_action_steps(setup_root) else {
            return false;
        };
        let Some(finalize_steps) = cache_action_steps(finalize_root) else {
            return false;
        };
        let Some(setup_runs) = yaml_field(setup_root, "runs").and_then(yaml_map) else {
            return false;
        };
        let Some(finalize_runs) = yaml_field(finalize_root, "runs").and_then(yaml_map) else {
            return false;
        };
        let setup_outputs_context = yaml_field(setup_root, "outputs")
            .and_then(yaml_map)
            .is_some_and(|outputs| {
                yaml_keys_exact(outputs, &["cache-context"])
                    && yaml_field(outputs, "cache-context")
                        .and_then(yaml_map)
                        .and_then(|output| yaml_scalar(output, "value"))
                        == Some("${{ steps.cache-context.outputs.value }}")
            });
        let setup_funnel = cache_steps_without_id_prefix_match_exact(
            setup_steps,
            "tools-",
            &[
                ("download-cache", "actions/cache/restore@v4"),
                ("compiler-cache", "actions/cache/restore@v4"),
            ],
        ) && cache_step_is_exact(
            setup_steps,
            "download-cache",
            "actions/cache/restore@v4",
            None,
            &[
                (
                    "path",
                    "${{ runner.temp }}/rss-cargo-home/registry/cache\n${{ runner.temp }}/rss-cargo-home/registry/index\n${{ runner.temp }}/rss-cargo-home/git/db\n",
                ),
                (
                    "key",
                    "${{ steps.cache-keys.outputs.download-primary-key }}",
                ),
                (
                    "restore-keys",
                    "${{ steps.cache-keys.outputs.download-input-restore-prefix }}\n${{ steps.cache-keys.outputs.download-restore-prefix }}\n",
                ),
            ],
        ) && cache_step_is_exact(
            setup_steps,
            "compiler-cache",
            "actions/cache/restore@v4",
            None,
            &[
                ("path", "${{ runner.temp }}/rss-sccache-cache"),
                (
                    "key",
                    "${{ steps.cache-keys.outputs.compiler-primary-key }}",
                ),
                (
                    "restore-keys",
                    "${{ steps.cache-keys.outputs.compiler-input-restore-prefix }}\n${{ steps.cache-keys.outputs.compiler-broad-restore-prefix }}\n",
                ),
            ],
        );
        let finalize_funnel = cache_steps_match_exact_funnel(
            finalize_steps,
            &[
                ("download-save", "actions/cache/save@v4"),
                ("compiler-save", "actions/cache/save@v4"),
            ],
        ) && cache_step_is_exact(
            finalize_steps,
            "download-save",
            "actions/cache/save@v4",
            Some("${{ !cancelled() && steps.policy.outputs.save-download == 'true' }}"),
            &[
                (
                    "path",
                    "${{ runner.temp }}/rss-cargo-home/registry/cache\n${{ runner.temp }}/rss-cargo-home/registry/index\n${{ runner.temp }}/rss-cargo-home/git/db\n",
                ),
                ("key", "${{ steps.policy.outputs.download-primary-key }}"),
            ],
        ) && cache_step_is_exact(
            finalize_steps,
            "compiler-save",
            "actions/cache/save@v4",
            Some(
                "${{ !cancelled() && steps.policy.outputs.save-cache == 'true' && steps.snapshot.outcome == 'success' }}",
            ),
            &[
                ("path", "${{ runner.temp }}/rss-sccache-cache"),
                ("key", "${{ steps.policy.outputs.compiler-primary-key }}"),
            ],
        );
        let setup_lifecycle = step_ids_are_ordered(
            setup_runs,
            &[
                "cache-keys",
                "download-cache",
                "download-reset",
                "download-configure",
                "compiler-cache",
                "compiler-reset",
                "compiler-configure",
                "zero-sccache-stats",
                "cache-context",
            ],
        ) && step_by_id(setup_runs, "download-reset")
            .and_then(|step| yaml_scalar(step, "run"))
            .is_some_and(|run| run.contains("reset-descendant --parent \"$RUNNER_TEMP\" --path \"$RUNNER_TEMP/rss-cargo-home\""))
            && step_by_id(setup_runs, "compiler-reset")
                .and_then(|step| yaml_scalar(step, "run"))
                .is_some_and(|run| run.contains("reset-descendant --parent \"$RUNNER_TEMP\" --path \"$RUNNER_TEMP/rss-sccache-cache\""))
            && step_by_id(setup_runs, "compiler-configure")
                .and_then(|step| yaml_scalar(step, "run"))
                .is_some_and(|run| {
                    [
                        "SCCACHE_CACHE_SIZE=2G",
                        "SCCACHE_IGNORE_SERVER_IO_ERROR=1",
                        "SCCACHE_DIR=$RUNNER_TEMP/rss-sccache-cache",
                    ]
                    .into_iter()
                    .all(|binding| run.contains(binding))
                })
            && step_by_id(setup_runs, "zero-sccache-stats")
                .and_then(|step| yaml_scalar(step, "run"))
                .is_some_and(|run| run.contains("--zero-stats"));
        let finalize_lifecycle = step_ids_are_ordered(
            finalize_runs,
            &[
                "policy",
                "stats",
                "stop",
                "diagnostics",
                "snapshot",
                "download-save",
                "compiler-save",
                "summary",
            ],
        ) && step_by_id(finalize_runs, "stats")
            .is_some_and(|step| {
                yaml_scalar(step, "if")
                    == Some("${{ always() && !cancelled() && env.RSS_SCCACHE_ENABLED == 'true' }}")
                    && yaml_scalar(step, "run")
                        .is_some_and(|run| run.contains("--show-stats --stats-format json"))
            })
            && step_by_id(finalize_runs, "stop").is_some_and(|step| {
                yaml_scalar(step, "if")
                    == Some("${{ always() && !cancelled() && env.RSS_SCCACHE_ENABLED == 'true' }}")
                    && yaml_scalar(step, "run").is_some_and(|run| run.contains("--stop-server"))
            })
            && step_by_id(finalize_runs, "snapshot").is_some_and(|step| {
                yaml_scalar(step, "if") == Some("${{ !cancelled() && steps.policy.outputs.save-cache == 'true' && steps.stats.outcome == 'success' && steps.stop.outcome == 'success' && steps.diagnostics.outcome == 'success' }}")
                    && yaml_scalar(step, "run").is_some_and(|run| {
                        run.contains("ci-cache-maintain.sh snapshot")
                            && run.contains("--path \"$RUNNER_TEMP/rss-sccache-cache\"")
                            && run.contains("--max-bytes 2147483648")
                    })
            })
            && step_by_id(finalize_runs, "summary")
                .and_then(|step| yaml_scalar(step, "run"))
                .is_some_and(|run| run.contains("$GITHUB_STEP_SUMMARY"));
        let namespaces_only_in_policy = [
            "rss-download-$download_epoch",
            "rss-tools-$tool_epoch",
            "rss-sccache-$compiler_epoch",
        ]
        .into_iter()
        .all(|needle| {
            policy.contains(needle) && !setup.contains(needle) && !finalize.contains(needle)
        });
        let no_target_snapshot = [setup, finalize]
            .into_iter()
            .all(|source| !source.contains("actions/cache") || !source.contains("target/**"));

        setup_outputs_context
            && setup_funnel
            && finalize_funnel
            && setup_lifecycle
            && finalize_lifecycle
            && namespaces_only_in_policy
            && no_target_snapshot
    }

    fn committed_shell_selftest_passes(relative: &str) -> anyhow::Result<()> {
        let root = workspace_root()?;
        let script = root
            .join(relative)
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("CI selftest path is not UTF-8: {relative}"))?
            .to_owned();
        let output = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::SystemShell,
            &["-c", "exec \"$1\"", "ci-selftest", script.as_str()],
            &[],
            Some(&root),
        )
        .output()?;
        assert!(
            output.status.success(),
            "{relative} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    #[test]
    fn ci_cache_maintenance_shell_selftest_passes() -> anyhow::Result<()> {
        committed_shell_selftest_passes(".github/scripts/ci-cache-maintain.selftest.sh")
    }

    #[test]
    fn ci_sccache_stats_shell_selftest_passes() -> anyhow::Result<()> {
        committed_shell_selftest_passes(".github/scripts/ci-sccache-stats.selftest.sh")
    }

    #[test]
    fn ci_cache_result_shell_selftest_passes() -> anyhow::Result<()> {
        committed_shell_selftest_passes(".github/scripts/ci-cache-result.selftest.sh")
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
            ToolRequirement::PublicApiTools { install_hint } => install_hint,
            _ => "",
        };
        assert!(
            install_hint.contains(pin),
            "public-api install_hint 须为 ToolGatedInternal 且含钉版 nightly {pin}\
             （NIGHTLY-PIN-01，与 publicapi::PINNED_NIGHTLY 同步）；当前: {install_hint:?}"
        );
    }
}
