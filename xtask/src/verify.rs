//! `cargo xtask verify` —— 本地全量治理门聚合入口。
//!
//! RSS 本地全量治理门。GitHub Actions 调 `cargo xtask ci` 作为合入阻断门；本命令保留为
//! stable-only 本地快门。聚合（fail-fast，无编译的步最先）：
//!
//!   1. `cargo fmt --all -- --check`
//!   2. in-process meta：contract validate + assembly validate + archrules + layer-deps + codegen --check + tenancy-closeout
//!   3. `cargo build --workspace`
//!   4. `cargo clippy --workspace --all-targets -- -D warnings`
//!   5. `cargo nextest run --workspace --no-tests=pass`（外部工具）
//!   6. feature-gated 行为测试门（确定性 mock / lazy）：`cargo nextest run -p s3 --features backend` +
//!      `-p redis-adapter --features backend`（默认 feature workspace nextest 不编入这些 `#[cfg(feature)]`
//!      测试模块；按包显式补跑，见 [`feature_test_steps`]——不用 `--all-features --workspace` 以免误触
//!      postgres/redis 的 `integration`（需 live 后端）门）
//!   7. `cargo deny check`（外部工具）
//!   8. `cargo dylint --all`（外部工具；跑 `lints/` 嵌套 nightly workspace；`DYLINT_RUSTFLAGS=-D warnings`
//!      把默认 `Warn` 的注册 lint 升为 fail-closed）
//!
//! `--fast` 只跑无需编译的步（fmt + meta + deny），供快速迭代。`--allow-missing-tools` 在缺
//! 外部工具时显式宽限（默认 fail-closed）。
//!
//! **`cargo xtask ci`（[`run_ci`]）= CI lane 超集**（issue #1132，GitHub Actions 薄壳唯一调用入口）：
//! verify 全门 + build/clippy 升 `--all-features --all-targets` + 覆盖率门（`cargo llvm-cov nextest` 替
//! nextest，强制 basis/engine ≥90%，见 `coverage.rs`）+ `public-api --check`（轴 A，见 `publicapi.rs`）。
//! `verify` 仍是 **stable-only 本地快门**（不需 nightly / llvm-cov）；`ci` 是 **CI 全工具超集**——二者经
//! [`full_plan`] / [`ci_plan`] 共享 fmt/meta/deny/dylint 同一构造，杜绝两份计划漂移。
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
//! INVARIANT: CI-PIPELINE-DELEGATE-01 { level = "Medium", exec = "verify", source = "code" }—— GitHub CI workflow 只调 `cargo xtask ci`、不逐条重列门 run
//!   命令（门逻辑单源在 xtask）；由 `github_ci_workflow_delegates_to_xtask_ci` 治理测试守。

use crate::diagnostic::run_check;
use crate::workspace_root;
use crate::{
    archrules, assembly, codegen, consistency_fixtures, contract, doc_contracts, layerdeps, wsdeps,
};
use anyhow::{Result, bail};
use std::path::Path;
use std::process::Stdio;

#[cfg(test)]
const CI_TOOL_SPECS: &[&str] = &[
    "cargo-binstall@1.20.1",
    "cargo-nextest@0.9.137",
    "cargo-deny@0.19.9",
    "cargo-dylint@6.0.1",
    "dylint-link@6.0.1",
    "cargo-llvm-cov@0.8.7",
    "cargo-public-api@0.52.0",
    "cargo-audit@0.22.2",
];
const INSTALL_HINT_DENY: &str = "cargo install cargo-deny@0.19.9 --locked";
const INSTALL_HINT_AUDIT: &str = "cargo install cargo-audit@0.22.2 --locked";
const INSTALL_HINT_DYLINT: &str = "cargo install cargo-dylint@6.0.1 dylint-link@6.0.1 --locked";
const INSTALL_HINT_NEXTEST: &str = "cargo install cargo-nextest@0.9.137 --locked";
const INSTALL_HINT_INTEGRATION: &str = "cargo install cargo-nextest@0.9.137 --locked（实跑还需 docker 或设 RSS_TEST_ALLOW_EXTERNAL_POSTGRES + PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD + REDIS_TEST_URL + RSS_AMQP_TEST_URL + RSS_MQTT_TEST_URL 等 env URL）";
const INSTALL_HINT_LLVM_COV: &str = "cargo install cargo-llvm-cov@0.8.7 --locked";
const INSTALL_HINT_PUBLIC_API: &str =
    "rustup toolchain install nightly-2026-04-16 && cargo install cargo-public-api@0.52.0 --locked";

/// verify 选项。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifyOpts {
    /// 只跑无需编译的步（fmt + meta + deny），跳过 build/clippy/nextest/dylint。
    fast: bool,
    /// 缺外部工具时显式宽限（默认 fail-closed，唯一门不建议）。
    allow_missing_tools: bool,
}

/// in-process Rust 门（无外部进程 / 自管子进程）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InternalCheck {
    ContractValidate,
    /// assembly-level DI provider 声明校验（RevocationStore active provider 必须持久）。
    AssemblyValidate,
    /// wire JSON-Schema 跨版本破坏检测门（ADR-008，WIRE-BREAKING-01）。窗口分级：默认 warn（退出码 0），
    /// env `RSS_WIRE_BREAKING=deny` 对 active 契约破坏升 deny（退出码 1）；against = origin/develop。
    ContractBreaking,
    LayerDeps,
    WsDepsDrift,
    /// docs/rules + docs/spec 中 command/outbox tenant-aware 签名漂移门（DOC-CONTRACTS-01）。
    DocContracts,
    /// consistency crash matrix fixture/DSL 骨架门（CONSISTENCY-CRASH-FIXTURE-01）。
    ConsistencyFixtures,
    /// runtime event transport consumer 禁回 Redis claimer（EVENT-TRANSPORT-PG-INBOX-01）。
    EventTransportGuard,
    /// ArchRules 派生索引：真实 carrier 的 INVARIANT 锚点 + fixture/gate 反向索引。
    ArchRules,
    CodegenCheck,
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
    /// tenancy/AuthZ/projection closeout reverse self-check（TENANCY-CLOSEOUT-REVERSE-01；no-compile）。
    TenancyCloseout,
    /// migration 文件序号唯一性 + 连续性守卫（MIGRATION-SERIAL-UNIQUE-01；内容扫描文件名，no-compile）。
    MigrationsSerial,
    /// generated command module 双侧对称 + 裸 emit 出口封堵（COMMAND-SYMMETRY-01）。
    CommandSymmetry,
    /// governed scope（docs/rules + docs/architecture + .claude/rules + 根 config）结构化 defer 完整性 + 经典注解门
    /// （DEFER-GATE-01；内容扫描 .md/.toml，no-compile）。
    DeferGate,
    /// ci 专用：`cargo llvm-cov nextest`（兼 nextest 门）+ basis/engine ≥90% 覆盖率判定（见 `coverage.rs`）。
    Coverage,
    /// ci 专用：`public-api --check`（basis+engine+curated extras 封装面 baseline 漂移门 = 轴 A，见 `publicapi.rs`）。
    PublicApiCheck,
}

impl InternalCheck {
    /// 该 in-process 检查的 xtask 源文件（archrules `xtask_gate` 表里的 carrier 路径）。
    /// 穷举 match（无 `_` 臂）⇒ 新增 `InternalCheck` 变体必须同步登记 carrier，否则编译失败；
    /// 供 `archrules::tests::gate_strings_bound_to_verify_ci_plan_membership` 把 gate 字符串与
    /// plan 成员资格机器绑定（ARCHRULES-GATE-PLAN-BIND-01，#1574）。
    #[cfg(test)]
    pub(crate) fn carrier_file(self) -> &'static str {
        match self {
            Self::ContractValidate => "xtask/src/contract/validate.rs",
            Self::AssemblyValidate => "xtask/src/assembly.rs",
            Self::ContractBreaking => "xtask/src/contract/breaking.rs",
            Self::LayerDeps => "xtask/src/layerdeps.rs",
            Self::WsDepsDrift => "xtask/src/wsdeps.rs",
            Self::DocContracts => "xtask/src/doc_contracts.rs",
            Self::ConsistencyFixtures => "xtask/src/consistency_fixtures.rs",
            Self::EventTransportGuard => "xtask/src/event_transport_guard.rs",
            Self::ArchRules => "xtask/src/archrules.rs",
            Self::CodegenCheck => "xtask/src/codegen.rs",
            Self::PdpAllowGuard => "xtask/src/pdpallow.rs",
            Self::ContractBindingGuard => "xtask/src/contract_binding_guard.rs",
            Self::SchemaRlsGuard => "xtask/src/schema_rls.rs",
            Self::SetLocalFunnel => "xtask/src/setlocal_funnel.rs",
            Self::PgTenantTxGuard => "xtask/src/pg_tenant_tx_guard.rs",
            Self::TenancyCloseout => "xtask/src/tenancy_closeout.rs",
            Self::MigrationsSerial => "xtask/src/migrations.rs",
            Self::CommandSymmetry => "xtask/src/command_symmetry.rs",
            Self::DeferGate => "xtask/src/defergate.rs",
            Self::Coverage => "xtask/src/coverage.rs",
            Self::PublicApiCheck => "xtask/src/publicapi.rs",
        }
    }
}

/// 门步载体。`Internal` 在进程内跑；`CargoBuiltin` 是 toolchain 自带子命令（免探测）；
/// `Tool` 是第三方 cargo 子命令（先探测，缺则按 [`resolve_tool`] 决策）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum StepKind {
    Internal(InternalCheck),
    CargoBuiltin,
    Tool {
        /// 探测子命令名（`cargo <probe> --version`）。
        probe: &'static str,
        /// 缺工具时给的安装指引。
        install_hint: &'static str,
    },
    /// 工具门控的进程内门：先探测 `probe`（缺则按 `allow_missing_tools` 经 [`resolve_tool`] 决策），
    /// 在则跑 `check` 内部逻辑（其自管子进程，如 coverage 跑 llvm-cov、public-api 跑 cargo-public-api）。
    ToolGatedInternal {
        probe: &'static str,
        install_hint: &'static str,
        check: InternalCheck,
    },
}

/// 单个门步。`program` 恒为 `cargo`，故只存 `args`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Step {
    label: &'static str,
    args: &'static [&'static str],
    kind: StepKind,
    /// 该步额外设置的环境变量（如 dylint 的 `DYLINT_RUSTFLAGS=-D warnings` 把 lint 升为 fail-closed）。
    env: &'static [(&'static str, &'static str)],
    /// 是否需要编译全 workspace —— `--fast` 据此裁剪（true 的步在 fast 下跳过）。
    needs_compile: bool,
}

impl Step {
    pub(crate) fn label(&self) -> &'static str {
        self.label
    }

    /// 该步对应的 xtask carrier 源文件——仅 in-process 检查（`Internal` / `ToolGatedInternal`）有；
    /// `CargoBuiltin`（fmt/build/clippy…）与外部 `Tool`（deny/audit/dylint/nextest）非 archrules carrier，返回 `None`。
    /// 供 gate↔plan 绑定测试遍历（ARCHRULES-GATE-PLAN-BIND-01，#1574）。
    #[cfg(test)]
    pub(crate) fn carrier_file(&self) -> Option<&'static str> {
        match &self.kind {
            StepKind::Internal(check) | StepKind::ToolGatedInternal { check, .. } => {
                Some(check.carrier_file())
            }
            StepKind::CargoBuiltin | StepKind::Tool { .. } => None,
        }
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
        label: "fmt",
        args: &["fmt", "--all", "--", "--check"],
        kind: StepKind::CargoBuiltin,
        env: &[],
        needs_compile: false,
    }
}
fn step_contract_validate() -> Step {
    Step {
        label: "contract-validate",
        args: &[],
        kind: StepKind::Internal(InternalCheck::ContractValidate),
        env: &[],
        needs_compile: false,
    }
}
fn step_assembly_validate() -> Step {
    Step {
        label: "assembly-validate",
        args: &[],
        kind: StepKind::Internal(InternalCheck::AssemblyValidate),
        env: &[],
        needs_compile: false,
    }
}
fn step_contract_breaking() -> Step {
    Step {
        label: "contract-breaking",
        args: &[],
        kind: StepKind::Internal(InternalCheck::ContractBreaking),
        env: &[],
        needs_compile: false,
    }
}
fn step_layer_deps() -> Step {
    Step {
        label: "layer-deps",
        args: &[],
        kind: StepKind::Internal(InternalCheck::LayerDeps),
        env: &[],
        needs_compile: false,
    }
}
fn step_wsdeps_drift() -> Step {
    Step {
        label: "wsdeps-drift",
        args: &[],
        kind: StepKind::Internal(InternalCheck::WsDepsDrift),
        env: &[],
        needs_compile: false,
    }
}
fn step_doc_contracts() -> Step {
    Step {
        label: "doc-contracts",
        args: &[],
        kind: StepKind::Internal(InternalCheck::DocContracts),
        env: &[],
        needs_compile: false,
    }
}
fn step_consistency_fixtures() -> Step {
    Step {
        label: "consistency-fixtures",
        args: &[],
        kind: StepKind::Internal(InternalCheck::ConsistencyFixtures),
        env: &[],
        needs_compile: false,
    }
}
fn step_event_transport_guard() -> Step {
    Step {
        label: "event-transport-guard",
        args: &[],
        kind: StepKind::Internal(InternalCheck::EventTransportGuard),
        env: &[],
        needs_compile: false,
    }
}
fn step_archrules() -> Step {
    Step {
        label: "archrules",
        args: &[],
        kind: StepKind::Internal(InternalCheck::ArchRules),
        env: &[],
        needs_compile: false,
    }
}
fn step_codegen_check() -> Step {
    Step {
        label: "codegen-check",
        args: &[],
        kind: StepKind::Internal(InternalCheck::CodegenCheck),
        env: &[],
        needs_compile: false,
    }
}
fn step_pdp_allow_guard() -> Step {
    Step {
        label: "pdp-allow-guard",
        args: &[],
        kind: StepKind::Internal(InternalCheck::PdpAllowGuard),
        env: &[],
        needs_compile: false,
    }
}
fn step_contract_binding_guard() -> Step {
    Step {
        label: "contract-binding-guard",
        args: &[],
        kind: StepKind::Internal(InternalCheck::ContractBindingGuard),
        env: &[],
        needs_compile: false,
    }
}
fn step_schema_rls_guard() -> Step {
    Step {
        label: "schema-rls",
        args: &[],
        kind: StepKind::Internal(InternalCheck::SchemaRlsGuard),
        env: &[],
        needs_compile: false,
    }
}
fn step_setlocal_funnel() -> Step {
    Step {
        label: "setlocal-funnel",
        args: &[],
        kind: StepKind::Internal(InternalCheck::SetLocalFunnel),
        env: &[],
        needs_compile: false,
    }
}
fn step_pg_tenant_tx_guard() -> Step {
    Step {
        label: "pg-tenant-tx-guard",
        args: &[],
        kind: StepKind::Internal(InternalCheck::PgTenantTxGuard),
        env: &[],
        needs_compile: false,
    }
}
fn step_tenancy_closeout() -> Step {
    Step {
        label: "tenancy-closeout",
        args: &[],
        kind: StepKind::Internal(InternalCheck::TenancyCloseout),
        env: &[],
        needs_compile: false,
    }
}
fn step_migrations_serial() -> Step {
    Step {
        label: "migrations-serial",
        args: &[],
        kind: StepKind::Internal(InternalCheck::MigrationsSerial),
        env: &[],
        needs_compile: false,
    }
}
fn step_command_symmetry() -> Step {
    Step {
        label: "command-symmetry",
        args: &[],
        kind: StepKind::Internal(InternalCheck::CommandSymmetry),
        env: &[],
        needs_compile: false,
    }
}
fn step_defer_gate() -> Step {
    Step {
        label: "defer-gate",
        args: &[],
        kind: StepKind::Internal(InternalCheck::DeferGate),
        env: &[],
        needs_compile: false,
    }
}
fn step_deny() -> Step {
    Step {
        label: "deny",
        args: &["deny", "check"],
        kind: StepKind::Tool {
            probe: "deny",
            install_hint: INSTALL_HINT_DENY,
        },
        env: &[],
        needs_compile: false,
    }
}
/// audit 定时 lane 专用：advisory-scoped `cargo deny check advisories`（只查 RustSec 漏洞库，
/// licenses/bans 留给 PR 门的全量 [`step_deny`]）。issue #1133 每日 cron 刷新只需漏洞维度。
fn step_deny_advisories() -> Step {
    Step {
        label: "deny-advisories",
        args: &["deny", "check", "advisories"],
        kind: StepKind::Tool {
            probe: "deny",
            install_hint: INSTALL_HINT_DENY,
        },
        env: &[],
        needs_compile: false,
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
        label: "audit",
        args: &["audit", "--ignore", "RUSTSEC-2023-0071"],
        kind: StepKind::Tool {
            probe: "audit",
            install_hint: INSTALL_HINT_AUDIT,
        },
        env: &[],
        needs_compile: false,
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
        label: "dylint",
        args: &["dylint", "--all"],
        kind: StepKind::Tool {
            probe: "dylint",
            install_hint: INSTALL_HINT_DYLINT,
        },
        // `rss_domain_no_serialize` 默认 `Warn`（warning 不退非零）；`-D warnings` 把它（及其它
        // 注册 lint）升为 deny ⇒ 违例即非零退出，使 dylint 成 fail-closed 门（#1023 的核心诉求）。
        // 已验证干净树下 exit 0、无 nightly 误报。
        env: &[("DYLINT_RUSTFLAGS", "-D warnings")],
        needs_compile: true,
    }
}

// verify 专用：workspace 默认 feature 的 build/clippy/nextest（stable-only 本地快门）。
fn step_build_workspace() -> Step {
    Step {
        label: "build",
        args: &["build", "--workspace"],
        kind: StepKind::CargoBuiltin,
        env: &[],
        needs_compile: true,
    }
}
/// F7 + #1137：postgres/redis/amqp 集成测试由 `#[cfg(feature = "integration")]` gate，verify 的
/// build/clippy/nextest 仅 workspace 默认 feature ⇒ 关键状态机测试（崩溃重投 / CAS fencing / DLX / sweep /
/// redis 幂等 / amqp pub-sub + 跨 vhost / durable journey）默认门外、回归漏网。本步 `--no-run` 仅编译（不跑、
/// 无需真实后端 / docker）纳入默认 verify 抓**编译漂移**；有 docker / env URL 时经 `cargo xtask integration`
/// 行实跑（[`integration_plan`]）。ci lane 经 `--all-features --all-targets` 已覆盖该编译面，故仅入
/// [`full_plan`]、不入 [`ci_plan`]。
fn step_integration_compile() -> Step {
    Step {
        label: "integration-compile",
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
        kind: StepKind::CargoBuiltin,
        env: &[],
        needs_compile: true,
    }
}

/// #1137：真集成 lane 实跑步——nextest 跑 postgres/redis/amqp 的 `integration` 测试（self-provision
/// 容器 / 对接 env URL）。专用 `--profile integration`（放宽 slow-timeout，容器冷启动；见 .config/nextest.toml）。
/// **仅** [`integration_plan`]（opt-in `cargo xtask integration`）——不入 verify/ci（默认门只 `--no-run` 编译，
/// 须无 docker 可跑；实跑需 docker / 长存后端，由 [`run_integration`] 的 docker 门把守）。
fn step_integration_run() -> Step {
    Step {
        label: "integration-tests",
        args: &[
            "nextest",
            "run",
            "--profile",
            "integration",
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
        ],
        kind: StepKind::Tool {
            probe: "nextest",
            install_hint: INSTALL_HINT_INTEGRATION,
        },
        env: &[],
        needs_compile: true,
    }
}
fn step_clippy_workspace() -> Step {
    Step {
        label: "clippy",
        args: &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        kind: StepKind::CargoBuiltin,
        env: &[],
        needs_compile: true,
    }
}
fn step_nextest() -> Step {
    Step {
        label: "nextest",
        args: &["nextest", "run", "--workspace", "--no-tests=pass"],
        kind: StepKind::Tool {
            probe: "nextest",
            install_hint: INSTALL_HINT_NEXTEST,
        },
        env: &[],
        needs_compile: true,
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
        label: "s3-backend-tests",
        args: &["nextest", "run", "-p", "s3", "--features", "backend"],
        kind: StepKind::Tool {
            probe: "nextest",
            install_hint: INSTALL_HINT_NEXTEST,
        },
        env: &[],
        needs_compile: true,
    }
}
fn step_redis_backend_tests() -> Step {
    Step {
        label: "redis-backend-tests",
        args: &[
            "nextest",
            "run",
            "-p",
            "redis-adapter",
            "--features",
            "backend",
        ],
        kind: StepKind::Tool {
            probe: "nextest",
            install_hint: INSTALL_HINT_NEXTEST,
        },
        env: &[],
        needs_compile: true,
    }
}
fn step_oidc_backend_tests() -> Step {
    Step {
        label: "oidc-backend-tests",
        args: &["nextest", "run", "-p", "oidc", "--features", "backend"],
        kind: StepKind::Tool {
            probe: "nextest",
            install_hint: INSTALL_HINT_NEXTEST,
        },
        env: &[],
        needs_compile: true,
    }
}
fn step_prometheus_backend_tests() -> Step {
    Step {
        label: "prometheus-backend-tests",
        args: &[
            "nextest",
            "run",
            "-p",
            "prometheus-adapter",
            "--features",
            "backend",
        ],
        kind: StepKind::Tool {
            probe: "nextest",
            install_hint: INSTALL_HINT_NEXTEST,
        },
        env: &[],
        needs_compile: true,
    }
}
fn step_otel_backend_tests() -> Step {
    // otel OTLP/gRPC trace 导出确定性单测（#1011：InMemorySpanExporter round-trip + observ::MetricLabel→KeyValue
    // 映射 + OtelEndpoint typed 安全边界 + 导出边界脱敏）。`backend` feature 的 `#[cfg(feature)]` 测试模块默认
    // workspace nextest 不编入，按包显式补跑——#1253 让 otel 成为 runtime 生产依赖后，确定性测试须入机器门（同 prometheus 范式）。
    Step {
        label: "otel-backend-tests",
        args: &["nextest", "run", "-p", "otel", "--features", "backend"],
        kind: StepKind::Tool {
            probe: "nextest",
            install_hint: INSTALL_HINT_NEXTEST,
        },
        env: &[],
        needs_compile: true,
    }
}
fn step_grpc_backend_tests() -> Step {
    Step {
        label: "grpc-backend-tests",
        args: &["nextest", "run", "-p", "grpc", "--features", "backend"],
        kind: StepKind::Tool {
            probe: "nextest",
            install_hint: INSTALL_HINT_NEXTEST,
        },
        env: &[],
        needs_compile: true,
    }
}
fn step_vault_backend_tests() -> Step {
    // vault Transit `sign_impl` HTTP 编排层确定性单测（#1179：wiremock loopback mock，4 分支 + percent-encode/
    // header）+ 非 2xx 状态分级（#1180：classify_status 表驱动）。`backend` feature 的 `#[cfg(feature)]` 测试模块
    // 默认 workspace nextest 不编入，按包显式补跑——否则 azure 无 CI 下这些确定性测试不被任何 gate 实跑。
    Step {
        label: "vault-backend-tests",
        args: &["nextest", "run", "-p", "vault", "--features", "backend"],
        kind: StepKind::Tool {
            probe: "nextest",
            install_hint: INSTALL_HINT_NEXTEST,
        },
        env: &[],
        needs_compile: true,
    }
}
/// 确定性 feature 行为测试门集（verify 与 ci 共用，单一事实源；新增确定性 feature 行为测试的 adapter 在此追加）。
fn feature_test_steps() -> Vec<Step> {
    vec![
        step_s3_backend_tests(),
        step_redis_backend_tests(),
        step_oidc_backend_tests(),
        step_prometheus_backend_tests(),
        // otel backend 行为测试（OTLP/gRPC trace 导出 round-trip via InMemorySpanExporter）：确定性 + hermetic
        // （connect_lazy，无 live collector），同 prometheus 范式入机器门（#1253 otel 升为 runtime 生产依赖）。
        step_otel_backend_tests(),
        // grpc backend 行为测试（tonic 0.14 health server）：自绑 127.0.0.1:0 ephemeral loopback、in-process
        // tonic client roundtrip，确定性 + hermetic（无 live 后端），同 s3/redis 范式入机器门（#1011）。
        step_grpc_backend_tests(),
        step_vault_backend_tests(),
    ]
}

// ci 专用：build/clippy 升 `--all-features --all-targets`（编译态全覆盖，含 integration-gated 代码——
// 仅编译不运行 ⇒ 无需 DB/broker）；覆盖率门替 nextest（兼跑 workspace 测试 + basis/engine ≥90%）；
// public-api --check（轴 A）。
// ci 的 cargo 门带 `--locked`：CI 确定性构建——Cargo.lock 缺失/漂移即 fail（不静默改锁），与
// `cargo run --locked -p xtask -- ci` 入口共同锁全链（入口锁 xtask 子树，build --workspace --locked 锁
// 全 workspace 依赖解析）。verify（本地快门）**不**带 --locked，留本地迭代余地（review #206 codex F2）。
fn step_build_all_features() -> Step {
    Step {
        label: "build",
        args: &[
            "build",
            "--workspace",
            "--all-features",
            "--all-targets",
            "--locked",
        ],
        kind: StepKind::CargoBuiltin,
        env: &[],
        needs_compile: true,
    }
}
fn step_clippy_all_features() -> Step {
    Step {
        label: "clippy",
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
        kind: StepKind::CargoBuiltin,
        env: &[],
        needs_compile: true,
    }
}
fn step_coverage() -> Step {
    Step {
        label: "coverage",
        args: &[],
        kind: StepKind::ToolGatedInternal {
            probe: "llvm-cov",
            install_hint: INSTALL_HINT_LLVM_COV,
            check: InternalCheck::Coverage,
        },
        env: &[],
        needs_compile: true,
    }
}
fn step_public_api() -> Step {
    Step {
        label: "public-api",
        args: &[],
        kind: StepKind::ToolGatedInternal {
            probe: "public-api",
            // 钉版 nightly + 钉版工具：须含 publicapi::PINNED_NIGHTLY（`&'static str` 字段无法引 const，
            // 故字面量）；NIGHTLY-PIN-01 治理测试断言 verify.rs 含该值，bump 漏改即 fail。
            install_hint: INSTALL_HINT_PUBLIC_API,
            check: InternalCheck::PublicApiCheck,
        },
        env: &[],
        needs_compile: true,
    }
}

/// verify 全量门步计划（单一事实源；顺序 = 执行顺序）。feature-test 门紧随 nextest（同测试相位）。
pub(crate) fn full_plan() -> Vec<Step> {
    let mut plan = vec![
        step_fmt(),
        step_contract_validate(),
        step_assembly_validate(),
        step_contract_breaking(),
        step_layer_deps(),
        step_wsdeps_drift(),
        step_doc_contracts(),
        step_consistency_fixtures(),
        step_event_transport_guard(),
        step_archrules(),
        step_codegen_check(),
        step_pdp_allow_guard(),
        step_contract_binding_guard(),
        step_schema_rls_guard(),
        step_setlocal_funnel(),
        step_pg_tenant_tx_guard(),
        step_tenancy_closeout(),
        step_migrations_serial(),
        step_command_symmetry(),
        step_defer_gate(),
        step_build_workspace(),
        step_integration_compile(),
        step_clippy_workspace(),
        step_nextest(),
    ];
    plan.extend(feature_test_steps());
    plan.push(step_deny());
    plan.push(step_dylint());
    plan
}

/// ci 超集门步计划（issue #1132 CI lane）。与 verify 共享 fmt/meta/deny/dylint 同一构造；build/clippy 升
/// `--all-features --all-targets`；覆盖率门替 nextest（兼跑 workspace 测试）；尾追 public-api --check（轴 A）。
/// `audit`（cargo-audit）紧随 `deny` 后（issue #1133：供应链漏洞门入 PR 阻断 lane，独立于 deny advisories 的
/// 防御纵深）。ci 恒全量（无 `--fast`）。
pub(crate) fn ci_plan() -> Vec<Step> {
    let mut plan = vec![
        step_fmt(),
        step_contract_validate(),
        step_assembly_validate(),
        step_contract_breaking(),
        step_layer_deps(),
        step_wsdeps_drift(),
        step_doc_contracts(),
        step_consistency_fixtures(),
        step_event_transport_guard(),
        step_archrules(),
        step_codegen_check(),
        step_pdp_allow_guard(),
        step_contract_binding_guard(),
        step_schema_rls_guard(),
        step_setlocal_funnel(),
        step_pg_tenant_tx_guard(),
        step_tenancy_closeout(),
        step_migrations_serial(),
        step_command_symmetry(),
        step_defer_gate(),
        step_build_all_features(),
        step_clippy_all_features(),
        step_coverage(),
    ];
    plan.extend(feature_test_steps());
    plan.push(step_deny());
    plan.push(step_cargo_audit());
    plan.push(step_dylint());
    plan.push(step_public_api());
    plan
}

/// audit 精简供应链门步计划（issue #1133；GitHub Actions schedule 调 `cargo xtask audit`）。
/// advisory-scoped deny + cargo-audit 两门，皆 no-compile、快——定时刷新只查漏洞库（捕获「未变依赖」新
/// 披露 CVE）。**不含** licenses/bans：它们只随 Cargo.lock 变（= 随 PR 变），定时跑无增益；PR 门的
/// [`ci_plan`] 已用全量 `deny check` + cargo-audit 覆盖。audit 步与 ci 共享同一 [`step_cargo_audit`] 构造。
///
/// INVARIANT: CI-PIPELINE-DELEGATE-01 { level = "Medium", exec = "verify", source = "code" }—— audit lane 亦经 YAML 委托 `cargo xtask audit`（不内联门命令），
/// 由 `github_audit_workflow_has_scheduled_audit_lane` 守。
fn audit_plan() -> Vec<Step> {
    vec![step_deny_advisories(), step_cargo_audit()]
}

/// #1137：真集成 lane 门步计划（opt-in `cargo xtask integration`）。当前单步 nextest 跑三 adapter 的
/// `integration` 测试；与 verify/ci 完全隔离（默认门只编译 integration 代码、不实跑——见 [`step_integration_compile`]）。
fn integration_plan() -> Vec<Step> {
    vec![step_integration_run()]
}

/// 四资源 env URL 全在 ⇒ 对接长存外部 pg/redis/rabbitmq/mosquitto，无需 docker self-provision（testkit 的
/// `env_or_*` resolver 同款判据）。任一缺则容器路径，需 docker。
///
/// **postgres 外部路径**：须同时满足：
/// 1. `RSS_TEST_ALLOW_EXTERNAL_POSTGRES` 存在（非空，显式 opt-in，
///    与 `testkit::env_or_postgres` fail-closed 语义一致）；
/// 2. 5 元组 `PGHOST`/`PGPORT`/`PGDATABASE`/`PGUSER`/`PGPASSWORD` 全在。
///
/// 仅满足其一不足以跳过 docker（testkit 会用容器路径或报缺失 key 错误）。
///
/// redis / amqp / mqtt 路径：`REDIS_TEST_URL` / `RSS_AMQP_TEST_URL` / `RSS_MQTT_TEST_URL` 存在（不变）。
fn all_integration_env_urls_present() -> bool {
    let pg_opt_in = std::env::var_os("RSS_TEST_ALLOW_EXTERNAL_POSTGRES").is_some();
    let pg_five_tuple = ["PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD"]
        .iter()
        .all(|k| std::env::var_os(k).is_some());
    let pg_all = pg_opt_in && pg_five_tuple;
    let redis = std::env::var_os("REDIS_TEST_URL").is_some();
    let amqp = std::env::var_os("RSS_AMQP_TEST_URL").is_some();
    let mqtt = std::env::var_os("RSS_MQTT_TEST_URL").is_some();
    pg_all && redis && amqp && mqtt
}

/// docker daemon 是否可达（容器 self-provision 前置；`docker version` 退出 0）。经 [`crate::cmd::clean_cmd`]
/// 漏斗构造（CMD-FUNNEL-01；docker 非 cargo 子命令，故不走 [`crate::cmd::tool_available`]）。
fn docker_available() -> bool {
    crate::cmd::clean_cmd("docker", &["version"], &[], None)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// integration 入口（#1137 真集成 lane，opt-in）：docker 门把守后按 [`integration_plan`] 跑。
/// **docker-gated（fail-closed，对齐 VERIFY-TOOL-GATE-01）**：三 env URL 全在 → 跳过 docker 探测（env 路径
/// 不 self-provision）；否则探测 docker，缺 + 未宽限 → fail-closed（清晰指引），缺 + `--allow-missing-tools`
/// → 警告跳过。**不入** verify/ci（默认门须无 docker 可跑）；**已接入 GitHub Actions PR/push lane**（#1145，
/// CI-INTEGRATION-LANE-01；ubuntu-latest runner 预装 docker ⇒ testkit self-provision，由 `github_integration_workflow_has_integration_lane` 守）。
pub(crate) fn run_integration(allow_missing_tools: bool) -> Result<()> {
    let opts = VerifyOpts {
        fast: false,
        allow_missing_tools,
    };
    let root = workspace_root()?;
    // docker 门：env URL 全在则跳过（env 路径不需 docker）。
    if !all_integration_env_urls_present() {
        match resolve_tool(docker_available(), allow_missing_tools) {
            ToolAction::Run => {}
            ToolAction::SkipWarn => {
                eprintln!(
                    "integration: [跳过] docker daemon 不可达（--allow-missing-tools 宽限）。\
                     外部路径需四资源全在（与 all_integration_env_urls_present 逐项对齐）：\
                     RSS_TEST_ALLOW_EXTERNAL_POSTGRES + PGHOST+PGPORT+PGDATABASE+PGUSER+PGPASSWORD（PG 5 元组）；\
                     + REDIS_TEST_URL + RSS_AMQP_TEST_URL + RSS_MQTT_TEST_URL 指向长存 pg/redis/rabbitmq/mosquitto 可免 docker。"
                );
                return Ok(());
            }
            ToolAction::Fail => bail!(
                "integration: docker daemon 不可达（容器 self-provision 需 docker）。\
                 启动 Docker，或同时设四资源 env（与 all_integration_env_urls_present 逐项对齐）：\
                 RSS_TEST_ALLOW_EXTERNAL_POSTGRES + PGHOST+PGPORT+PGDATABASE+PGUSER+PGPASSWORD（PG 5 元组）\
                 + REDIS_TEST_URL + RSS_AMQP_TEST_URL + RSS_MQTT_TEST_URL 指向运行中的 pg/redis/rabbitmq/mosquitto；\
                 确需跳过用 --allow-missing-tools。"
            ),
        }
    }
    let plan = integration_plan();
    eprintln!(
        "integration：{} 步（真集成 lane；docker self-provision 或 env URL）",
        plan.len()
    );
    for (i, step) in plan.iter().enumerate() {
        eprintln!("integration: [{}/{}] {}", i + 1, plan.len(), step.label);
        run_one("integration", step, &opts, &root)?;
    }
    eprintln!("integration：全部通过");
    Ok(())
}

/// 纯函数：按 opts 产出有序门步计划。`--fast` 裁掉 `needs_compile` 步（fmt+meta+deny 保留）。
fn verify_plan(opts: &VerifyOpts) -> Vec<Step> {
    let plan = full_plan();
    if opts.fast {
        plan.into_iter().filter(|s| !s.needs_compile).collect()
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
    args: &[&str],
    env: &[(&str, &str)],
    cwd: &Path,
) -> Result<()> {
    let status = crate::cmd::clean_cmd("cargo", args, env, Some(cwd))
        .status()
        .map_err(|e| {
            anyhow::anyhow!(
                "{lane}: 启动门步 `{label}`（cargo {}）失败: {e}",
                args.join(" ")
            )
        })?;
    if status.success() {
        return Ok(());
    }
    let code = status
        .code()
        .map_or_else(|| "signal".to_owned(), |c| c.to_string());
    bail!(
        "{lane}: 门步 `{label}` 失败（cargo {} 退出码 {code}）",
        args.join(" ")
    )
}

/// 跑单步：Internal 进程内执行；CargoBuiltin 直接 spawn；Tool 先探测再按决策分派。
fn run_one(lane: &str, step: &Step, opts: &VerifyOpts, root: &Path) -> Result<()> {
    match &step.kind {
        StepKind::Internal(check) => run_internal(*check),
        StepKind::CargoBuiltin => run_step(lane, step.label, step.args, step.env, root),
        StepKind::Tool {
            probe,
            install_hint,
        } => run_tool_gated(
            lane,
            crate::cmd::tool_available(probe),
            opts.allow_missing_tools,
            probe,
            install_hint,
            step.label,
            || run_step(lane, step.label, step.args, step.env, root),
        ),
        StepKind::ToolGatedInternal {
            probe,
            install_hint,
            check,
        } => run_tool_gated(
            lane,
            crate::cmd::tool_available(probe),
            opts.allow_missing_tools,
            probe,
            install_hint,
            step.label,
            || run_internal(*check),
        ),
    }
}

/// 工具门控分派（[`StepKind::Tool`] 与 [`StepKind::ToolGatedInternal`] 共用）：探测结果 + 宽限标志经
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
        // wire 破坏门：against=origin/develop，窗口分级经 env（默认 warn，退出码 0；deny 模式 active 破坏退出码 1）。
        InternalCheck::ContractBreaking => contract::breaking::run(
            contract::breaking::DEFAULT_AGAINST,
            contract::breaking::EnforcementMode::from_env(),
        ),
        InternalCheck::LayerDeps => run_check(&layerdeps::LayerDeps),
        InternalCheck::WsDepsDrift => run_check(&wsdeps::WsDepsDrift),
        InternalCheck::DocContracts => run_check(&doc_contracts::DocContracts),
        InternalCheck::ConsistencyFixtures => run_check(&consistency_fixtures::ConsistencyFixtures),
        InternalCheck::EventTransportGuard => {
            run_check(&crate::event_transport_guard::EventTransportGuard)
        }
        InternalCheck::ArchRules => run_check(&archrules::ArchRules),
        InternalCheck::CodegenCheck => codegen::run(true),
        InternalCheck::PdpAllowGuard => run_check(&crate::pdpallow::PdpAllowGuard),
        InternalCheck::ContractBindingGuard => {
            run_check(&crate::contract_binding_guard::ContractBindingGuard)
        }
        InternalCheck::SchemaRlsGuard => run_check(&crate::schema_rls::SchemaRlsGuard),
        InternalCheck::SetLocalFunnel => run_check(&crate::setlocal_funnel::SetLocalFunnelGuard),
        InternalCheck::PgTenantTxGuard => run_check(&crate::pg_tenant_tx_guard::PgTenantTxGuard),
        InternalCheck::TenancyCloseout => run_check(&crate::tenancy_closeout::TenancyCloseout),
        InternalCheck::MigrationsSerial => run_check(&crate::migrations::MigrationSerialGuard),
        InternalCheck::CommandSymmetry => run_check(&crate::command_symmetry::CommandSymmetry),
        InternalCheck::DeferGate => run_check(&crate::defergate::DeferGate),
        InternalCheck::Coverage => crate::coverage::run(),
        // 轴 A 封装面：basis+engine+curated extras 全集（layer=None）；check=true 漂移门 fail-closed（PUBLICAPI-DRIFT-GATE-01）。
        InternalCheck::PublicApiCheck => crate::publicapi::run(true, false, None),
    }
}

fn run_labeled_plan(lane: &str, plan: &[Step], opts: &VerifyOpts, root: &Path) -> Result<()> {
    for (i, step) in plan.iter().enumerate() {
        eprintln!("{lane}: [{}/{}] {}", i + 1, plan.len(), step.label);
        run_one(lane, step, opts, root)?;
    }
    Ok(())
}

/// verify 入口：按 plan 顺序跑每步，fail-fast。
pub(crate) fn run(fast: bool, allow_missing_tools: bool) -> Result<()> {
    let opts = VerifyOpts {
        fast,
        allow_missing_tools,
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

/// ci 入口（issue #1132 CI lane 超集）：按 [`ci_plan`] 顺序跑每步，fail-fast。CI 由 GitHub Actions
/// 调 `cargo xtask ci`（薄壳唯一入口，CI-PIPELINE-DELEGATE-01）；本地全工具机器亦可 `make ci`。
/// `allow_missing_tools` 仅本地便利——CI 不传 = 缺工具 fail-closed。
pub(crate) fn run_ci(allow_missing_tools: bool) -> Result<()> {
    let opts = VerifyOpts {
        fast: false,
        allow_missing_tools,
    };
    let root = workspace_root()?;
    let plan = ci_plan();
    eprintln!("ci：{} 步（CI lane 超集）", plan.len());
    run_labeled_plan("ci", &plan, &opts, &root)?;
    eprintln!("ci：全部通过");
    Ok(())
}

/// audit 入口（issue #1133 供应链定时刷新 lane）：按 [`audit_plan`] 顺序跑每步，fail-fast。
/// GitHub Actions schedule 调 `cargo xtask audit`（薄壳唯一入口，CI-PIPELINE-DELEGATE-01 同族）。
/// `allow_missing_tools` 仅本地便利——CI 不传 = 缺 deny/audit 工具 fail-closed。
pub(crate) fn run_audit(allow_missing_tools: bool) -> Result<()> {
    let opts = VerifyOpts {
        fast: false,
        allow_missing_tools,
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
        }
    }

    fn labels(plan: &[Step]) -> Vec<&'static str> {
        plan.iter().map(|s| s.label).collect()
    }

    #[test]
    fn full_plan_order_and_count() {
        let plan = verify_plan(&opts(false, false));
        assert_eq!(
            labels(&plan),
            vec![
                "fmt",
                "contract-validate",
                "assembly-validate",
                "contract-breaking",
                "layer-deps",
                "wsdeps-drift",
                "doc-contracts",
                "consistency-fixtures",
                "event-transport-guard",
                "archrules",
                "codegen-check",
                "pdp-allow-guard",
                "contract-binding-guard",
                "schema-rls",
                "setlocal-funnel",
                "pg-tenant-tx-guard",
                "tenancy-closeout",
                "migrations-serial",
                "command-symmetry",
                "defer-gate",
                "build",
                "integration-compile",
                "clippy",
                "nextest",
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
                "contract-breaking",
                "layer-deps",
                "wsdeps-drift",
                "doc-contracts",
                "consistency-fixtures",
                "event-transport-guard",
                "archrules",
                "codegen-check",
                "pdp-allow-guard",
                "contract-binding-guard",
                "schema-rls",
                "setlocal-funnel",
                "pg-tenant-tx-guard",
                "tenancy-closeout",
                "migrations-serial",
                "command-symmetry",
                "defer-gate",
                "deny"
            ]
        );
        for dropped in ["build", "clippy", "nextest", "dylint"] {
            assert!(!labels(&plan).contains(&dropped), "fast 不应含 {dropped}");
        }
    }

    /// meta checks（contract validate / assembly validate / contract breaking / layer-deps / wsdeps-drift /
    /// doc-contracts / consistency-fixtures / event-transport-guard / archrules / codegen /
    /// pdp-allow-guard / contract-binding-guard / schema-rls / setlocal-funnel / pg-tenant-tx-guard /
    /// tenancy-closeout / migrations-serial / command-symmetry / defer-gate）在两种模式恒在。
    #[test]
    fn meta_checks_present_in_both_modes() {
        for fast in [true, false] {
            let plan = verify_plan(&opts(fast, false));
            let internals: Vec<_> = plan
                .iter()
                .filter(|s| matches!(s.kind, StepKind::Internal(_)))
                .map(|s| s.label)
                .collect();
            assert_eq!(
                internals,
                vec![
                    "contract-validate",
                    "assembly-validate",
                    "contract-breaking",
                    "layer-deps",
                    "wsdeps-drift",
                    "doc-contracts",
                    "consistency-fixtures",
                    "event-transport-guard",
                    "archrules",
                    "codegen-check",
                    "pdp-allow-guard",
                    "contract-binding-guard",
                    "schema-rls",
                    "setlocal-funnel",
                    "pg-tenant-tx-guard",
                    "tenancy-closeout",
                    "migrations-serial",
                    "command-symmetry",
                    "defer-gate"
                ],
                "fast={fast}"
            );
        }
    }

    #[test]
    fn archrules_is_no_compile_internal_gate_in_fast_and_ci() -> anyhow::Result<()> {
        for (name, plan) in [("fast", verify_plan(&opts(true, false))), ("ci", ci_plan())] {
            let step = plan
                .iter()
                .find(|s| s.label == "archrules")
                .ok_or_else(|| anyhow::anyhow!("{name} plan 缺 archrules 步"))?;
            assert!(!step.needs_compile, "archrules 须是 no-compile gate");
            assert!(matches!(
                step.kind,
                StepKind::Internal(InternalCheck::ArchRules)
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

    /// anti-vacuity 红例（INVARIANT VERIFY-AGGREGATE-01）：门步非零退出 ⇒ `Err`，证明门真会 fail。
    #[test]
    fn run_step_nonzero_is_err() -> anyhow::Result<()> {
        let root = workspace_root()?;
        assert!(
            run_step(
                "verify",
                "redcase",
                &["zzz-not-a-cargo-subcommand"],
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
        assert!(run_step("verify", "greencase", &["--version"], &[], &root).is_ok());
        Ok(())
    }

    #[test]
    fn run_labeled_plan_executes_small_plan_with_lane_prefix() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let plan = [Step {
            label: "cargo-version",
            args: &["--version"],
            kind: StepKind::CargoBuiltin,
            env: &[],
            needs_compile: false,
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
        let plan = full_plan();
        let dylint = plan
            .iter()
            .find(|s| s.label == "dylint")
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
        let step = missing_tool_step();
        assert!(run_one("verify", &step, &opts(false, false), &root).is_err());
        Ok(())
    }

    /// 缺工具 + 显式宽限 ⇒ `run_one` 警告跳过、返回 `Ok`（`--allow-missing-tools` 路径）。
    #[test]
    fn run_one_missing_tool_skipwarn_is_ok() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let step = missing_tool_step();
        assert!(run_one("verify", &step, &opts(false, true), &root).is_ok());
        Ok(())
    }

    /// 构造一个探测必失败的 Tool 步（`cargo zzz-... --version` 非零 ⇒ tool_available=false）。
    fn missing_tool_step() -> Step {
        Step {
            label: "redtool",
            args: &["zzz-not-a-cargo-subcommand"],
            kind: StepKind::Tool {
                probe: "zzz-not-a-cargo-subcommand",
                install_hint: "（测试用，不存在）",
            },
            env: &[],
            needs_compile: false,
        }
    }

    // ---- ci 超集计划（issue #1132）----

    /// ci_plan 顺序与门集（单一事实源；CI lane 实跑顺序）。`audit`（cargo-audit）紧随 `deny` 后
    /// （issue #1133：供应链漏洞门入 PR 阻断 lane，防御纵深独立于 deny advisories）。
    #[test]
    fn ci_plan_order_and_count() {
        assert_eq!(
            labels(&ci_plan()),
            vec![
                "fmt",
                "contract-validate",
                "assembly-validate",
                "contract-breaking",
                "layer-deps",
                "wsdeps-drift",
                "doc-contracts",
                "consistency-fixtures",
                "event-transport-guard",
                "archrules",
                "codegen-check",
                "pdp-allow-guard",
                "contract-binding-guard",
                "schema-rls",
                "setlocal-funnel",
                "pg-tenant-tx-guard",
                "tenancy-closeout",
                "migrations-serial",
                "command-symmetry",
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
        let plan = ci_plan();
        for label in ["build", "clippy"] {
            let step = plan
                .iter()
                .find(|s| s.label == label)
                .ok_or_else(|| anyhow::anyhow!("ci_plan 缺 `{label}` 步"))?;
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
        let plan = ci_plan();
        assert!(
            !labels(&plan).contains(&"nextest"),
            "ci 不应有独立 nextest 步（已并入 coverage）"
        );
        let cov = plan
            .iter()
            .find(|s| s.label == "coverage")
            .ok_or_else(|| anyhow::anyhow!("ci_plan 缺 coverage 步"))?;
        assert!(matches!(
            cov.kind,
            StepKind::ToolGatedInternal {
                check: InternalCheck::Coverage,
                ..
            }
        ));
        let pa = plan
            .iter()
            .find(|s| s.label == "public-api")
            .ok_or_else(|| anyhow::anyhow!("ci_plan 缺 public-api 步"))?;
        assert!(matches!(
            pa.kind,
            StepKind::ToolGatedInternal {
                check: InternalCheck::PublicApiCheck,
                ..
            }
        ));
        Ok(())
    }

    /// 共享门步在 verify 与 ci 里**逐字相同**（同一构造，不漂移）。Step 派生 PartialEq ⇒ 直接比对。
    #[test]
    fn ci_shares_meta_deny_dylint_with_verify_verbatim() {
        let v = full_plan();
        let c = ci_plan();
        let find = |plan: &[Step], label: &str| plan.iter().find(|s| s.label == label).cloned();
        for label in [
            "fmt",
            "contract-validate",
            "assembly-validate",
            "contract-breaking",
            "layer-deps",
            "wsdeps-drift",
            "doc-contracts",
            "consistency-fixtures",
            "event-transport-guard",
            "archrules",
            "codegen-check",
            "pdp-allow-guard",
            "contract-binding-guard",
            "schema-rls",
            "setlocal-funnel",
            "pg-tenant-tx-guard",
            "tenancy-closeout",
            "migrations-serial",
            "command-symmetry",
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

    /// #1137：integration lane 与 verify/ci **完全隔离**——单步 `integration-tests`，不出现在 verify/ci
    /// （默认门只 `--no-run` 编译 integration 代码、不实跑；实跑需 docker，由 run_integration 门把守）。
    #[test]
    fn integration_plan_isolated_from_verify_and_ci() {
        assert_eq!(labels(&integration_plan()), vec!["integration-tests"]);
        assert!(!labels(&verify_plan(&opts(false, false))).contains(&"integration-tests"));
        assert!(!labels(&ci_plan()).contains(&"integration-tests"));
    }

    /// integration 实跑步：`--profile integration`（放宽 timeout）+ `--features integration` + 全包覆盖
    /// （postgres/redis-adapter/amqp/mqtt/journeys + runtime）；Tool gate probe `nextest`（缺工具 fail-closed）。
    #[test]
    fn integration_run_step_profile_feature_and_coverage() {
        let step = step_integration_run();
        assert_eq!(step.label, "integration-tests");
        assert!(matches!(
            step.kind,
            StepKind::Tool {
                probe: "nextest",
                ..
            }
        ));
        assert!(
            step.args
                .windows(2)
                .any(|w| w == ["--profile", "integration"]),
            "须 --profile integration，实际 {:?}",
            step.args
        );
        assert!(step.args.contains(&"--features") && step.args.contains(&"integration"));
        for p in [
            "postgres",
            "redis-adapter",
            "amqp",
            "mqtt",
            "journeys",
            "runtime",
        ] {
            assert!(step.args.contains(&p), "integration 实跑须覆盖 {p}");
        }
    }

    /// integration-compile（默认 verify 抓编译漂移）`--no-run` 覆盖各 adapter + journeys durable journey
    /// （F7 + #1137：原仅 postgres；#1010 加 mqtt；#1298 加 runtime assembly integration 测试）。
    #[test]
    fn integration_compile_covers_adapters_and_journeys_no_run() {
        let step = step_integration_compile();
        assert_eq!(step.label, "integration-compile");
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
            .find(|s| s.label == "deny-advisories")
            .ok_or_else(|| anyhow::anyhow!("audit_plan 缺 deny-advisories 步"))?;
        assert_eq!(deny.args, &["deny", "check", "advisories"]);
        assert!(matches!(deny.kind, StepKind::Tool { probe: "deny", .. }));
        Ok(())
    }

    /// cargo-audit 步是 Tool gate、probe `audit`（缺工具 fail-closed，复用 VERIFY-TOOL-GATE-01）；
    /// 首 arg 是 `audit` 子命令，no-compile。
    #[test]
    fn cargo_audit_step_is_tool_gate_probe_audit() {
        let step = step_cargo_audit();
        assert_eq!(step.label, "audit");
        assert_eq!(step.args.first(), Some(&"audit"));
        assert!(matches!(step.kind, StepKind::Tool { probe: "audit", .. }));
        assert!(!step.needs_compile, "cargo audit 只读 Cargo.lock，无需编译");
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
        let find = |plan: &[Step]| plan.iter().find(|s| s.label == "audit").cloned();
        assert_eq!(find(&ci_plan()), find(&audit_plan()));
        assert!(find(&ci_plan()).is_some(), "ci_plan 须含 audit 步");
    }

    /// ToolGatedInternal 缺工具 + 不宽限 ⇒ `Err`（fail-closed；不执行内部逻辑）。INVARIANT VERIFY-TOOL-GATE-01。
    #[test]
    fn run_one_toolgated_missing_fail_closed_is_err() -> anyhow::Result<()> {
        let root = workspace_root()?;
        assert!(
            run_one(
                "verify",
                &missing_toolgated_step(),
                &opts(false, false),
                &root
            )
            .is_err()
        );
        Ok(())
    }

    /// ToolGatedInternal 缺工具 + 宽限 ⇒ `Ok`（SkipWarn；不执行内部逻辑）。
    #[test]
    fn run_one_toolgated_missing_skipwarn_is_ok() -> anyhow::Result<()> {
        let root = workspace_root()?;
        assert!(
            run_one(
                "verify",
                &missing_toolgated_step(),
                &opts(false, true),
                &root
            )
            .is_ok()
        );
        Ok(())
    }

    /// 探测必失败的 ToolGatedInternal 步——若误执行内部 CodegenCheck 会真跑 codegen，但 probe 缺 ⇒
    /// 决策在执行前短路，故内部逻辑不被触达（验证 gate 先于 run）。
    fn missing_toolgated_step() -> Step {
        Step {
            label: "redtoolgated",
            args: &[],
            kind: StepKind::ToolGatedInternal {
                probe: "zzz-not-a-cargo-subcommand",
                install_hint: "（测试用，不存在）",
                check: InternalCheck::CodegenCheck,
            },
            env: &[],
            needs_compile: true,
        }
    }

    // ---- CI-PIPELINE-DELEGATE-01：GitHub workflow 委托 `cargo xtask ci`、不逐条重列门 ----

    /// setup / workflow 安装步骤只允许 cargo 安装工具；`cargo xtask` 只能作为 lane 委托命令出现。
    const SETUP_CARGO_SUBCOMMANDS: &[&str] = &["install", "binstall"];

    /// xtask ci 委托的规范形（至少一种须在 YAML 出现，anti-vacuity）：alias 形（本地/文档）与 CI 锁定入口
    /// 形（`--locked` 锁 xtask 子树依赖解析，与内部 `--workspace --locked` 门共同锁全链，codex F2）。
    const XTASK_CI_FORMS: &[&str] = &["cargo xtask ci", "cargo run --locked -p xtask -- ci"];

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

    fn workflow_pr_push_triggers_develop(yaml: &str) -> bool {
        workflow_event_has_develop_branch(yaml, "pull_request")
            && workflow_event_has_develop_branch(yaml, "push")
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

    /// step 块内是否有**真实 `uses:` 键**引用某 action（行去 `- ` 前缀后须以 `uses:` 起头 + 含 action 路径）——
    /// 排除 `name:` / `displayName:` 值、注释、`category:` 等字符串字段里的同名子串（结构绑定，非裸 `contains`，
    /// review #281 F2）。
    fn block_uses_action(block: &[&str], action: &str) -> bool {
        block.iter().any(|raw| {
            let line = raw.strip_prefix("- ").map(str::trim).unwrap_or(raw);
            line.starts_with("uses:") && line.contains(action)
        })
    }

    /// 委托谓词（正向白名单）：YAML 的 PR/push 触发器绑定 develop，且 run/script 执行面只有安装步骤
    /// 和一个受限 prologue + 规范 xtask ci 委托命令。
    fn pipeline_delegates_to_xtask_ci(yaml: &str) -> bool {
        workflow_pr_push_triggers_develop(yaml)
            && workflow_delegates_to_xtask_lane(yaml, XTASK_CI_FORMS)
    }

    /// 被 workflow 引用的本地 composite action 也是 CI 执行面。setup action 只能安装工具，不得把 build /
    /// clippy / nextest / coverage / public-api 等门命令搬进去绕过 workflow 委托守卫。
    fn setup_action_contains_only_setup_cargo_commands(yaml: &str) -> bool {
        yaml_command_scripts(yaml)
            .iter()
            .all(|script| command_script_is_setup_only(script))
    }

    fn develop_triggers() -> &'static str {
        "on:\n  pull_request:\n    branches: [develop]\n  push:\n    branches: [develop]\n"
    }

    /// 谓词绿/红例（anti-vacuity）：委托=真；不委托或重列**任一**门（含黑名单曾漏的 build/llvm-cov/
    /// public-api）=假。
    #[test]
    // reason: 表驱动 anti-vacuity 用例集中覆盖正反例；本轮只补 workspace clippy 门，不拆验证语义。
    #[allow(clippy::cognitive_complexity)]
    fn pipeline_delegate_predicate_green_and_red() {
        let triggers = develop_triggers();
        assert!(pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}steps:\n  - script: cargo xtask ci\n"
        )));
        assert!(!pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}steps:\n  - script: cargo clippy --workspace\n"
        )));
    }

    #[test]
    fn pipeline_delegate_accepts_allowed_delegation_forms() {
        let triggers = develop_triggers();
        // 绿：安装形（install/binstall）豁免，连字符 arg 不误判。
        assert!(pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}steps:\n  - script: cargo install cargo-binstall\n  - script: cargo binstall -y cargo-nextest cargo-deny\n  - script: cargo xtask ci\n"
        )));
        // 绿：散文注释里的 `cargo <词>`（如「cargo 默认 target …」/「cargo build 历史」）不计入门 run 判定。
        assert!(pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}  # cargo 默认 target 在 repo 根；曾用 cargo build 直跑\nsteps:\n  - script: cargo xtask ci\n"
        )));
        // 绿：CI 锁定入口形 `cargo run --locked -p xtask -- ci`（run 跑 xtask 非门）+ 安装形（codex F2）。
        assert!(pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}steps:\n  - script: cargo install cargo-binstall@1.20.1 --locked\n  - script: cargo run --locked -p xtask -- ci\n"
        )));
    }

    #[test]
    fn pipeline_delegate_rejects_wrong_develop_triggers() {
        // 红：PR/push 触发未绑定 develop。
        assert!(!pipeline_delegates_to_xtask_ci(
            "on:\n  pull_request:\n  push:\nsteps:\n  - script: cargo run --locked -p xtask -- ci\n"
        ));
        assert!(!pipeline_delegates_to_xtask_ci(
            "on:\n  pull_request:\n    branches: [main]\n  push:\n    branches: [develop]\nsteps:\n  - script: cargo run --locked -p xtask -- ci\n"
        ));
        // 红：分支名必须精确等于 develop，不能用 substring 命中 development / not-develop。
        assert!(!pipeline_delegates_to_xtask_ci(
            "on:\n  pull_request:\n    branches: [development]\n  push:\n    branches: [develop]\nsteps:\n  - script: cargo run --locked -p xtask -- ci\n"
        ));
        assert!(!pipeline_delegates_to_xtask_ci(
            "on:\n  pull_request:\n    branches:\n      - not-develop\n  push:\n    branches: [develop]\nsteps:\n  - script: cargo run --locked -p xtask -- ci\n"
        ));
    }

    #[test]
    fn pipeline_delegate_rejects_unsafe_or_missing_delegation() {
        let triggers = develop_triggers();
        // 红：run 形入口但仍重列门（build）——run 放行不削弱门捕获。
        assert!(!pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}steps:\n  - script: cargo run --locked -p xtask -- ci\n  - script: cargo build --workspace\n"
        )));
        // 红：`cargo run` 不是 xtask 委托形。
        assert!(!pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}steps:\n  - script: cargo run --locked -p xtask -- ci\n  - script: cargo run -p server\n"
        )));
        // 红：未委托。
        assert!(!pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}steps:\n  - script: cargo clippy --workspace\n"
        )));
        // 红（codex F1）：xtask ci 形仅在**注释**里、无真实 script 委托 → 结构绑定不满足。
        assert!(!pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}# cargo xtask ci\nsteps:\n  - script: cargo install cargo-binstall\n"
        )));
        // 红（codex F1）：xtask ci 形仅在 **displayName**（字符串字段值）、无真实 script 委托 → 不满足。
        assert!(!pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}steps:\n  - script: cargo install cargo-binstall\n    displayName: 'cargo xtask ci'\n"
        )));
    }

    #[test]
    fn pipeline_delegate_rejects_relisted_gates() {
        let triggers = develop_triggers();
        // 红：调了 xtask ci 但仍重列门——逐一覆盖（含黑名单曾漏的 build / llvm-cov / public-api / fmt）。
        for gate in [
            "cargo clippy -- -D warnings",
            "cargo fmt --check",
            "cargo nextest run --workspace",
            "cargo deny check",
            "cargo dylint --all",
            "cargo build --workspace",
            "cargo llvm-cov nextest",
            "cargo public-api --check",
        ] {
            let yaml =
                format!("{triggers}steps:\n  - script: cargo xtask ci\n  - script: {gate}\n");
            assert!(
                !pipeline_delegates_to_xtask_ci(&yaml),
                "重列门 `{gate}` 应被谓词捕获"
            );
        }
    }

    #[test]
    fn setup_action_delegate_predicate_green_and_red() {
        let green = "runs:\n  using: composite\n  steps:\n    - run: cargo install cargo-binstall@1.20.1 --locked\n    - run: cargo binstall -y --locked cargo-nextest@0.9.137\n";
        assert!(setup_action_contains_only_setup_cargo_commands(green));
        assert!(!setup_action_contains_only_setup_cargo_commands(
            "runs:\n  using: composite\n  steps:\n    - run: cargo nextest run --workspace\n"
        ));
        assert!(!setup_action_contains_only_setup_cargo_commands(
            "runs:\n  using: composite\n  steps:\n    - run: cargo run --locked -p server\n"
        ));
        assert!(!setup_action_contains_only_setup_cargo_commands(
            "runs:\n  using: composite\n  steps:\n    - run: cargo xtask ci\n"
        ));
        assert!(!setup_action_contains_only_setup_cargo_commands(
            "runs:\n  using: composite\n  steps:\n    - run: cargo run --locked -p xtask -- ci\n"
        ));
    }

    #[test]
    fn pipeline_delegate_rejects_echoed_commands() {
        let triggers = develop_triggers();

        // 红（#1643）：真实 run/script 行只是 echo/printf 委托命令文本，不等于执行委托命令。
        assert!(!pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}steps:\n  - run: echo cargo run --locked -p xtask -- ci\n"
        )));
        assert!(!pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}steps:\n  - run: printf 'cargo xtask ci'\n"
        )));
    }

    #[test]
    fn pipeline_delegate_rejects_delegation_prefix_false_positives() {
        let triggers = develop_triggers();

        for command in [
            "cargo xtask ci-fake",
            "cargo xtask ci || true",
            "cargo run --locked -p xtask -- ci-fake",
            "cargo run --locked -p xtask -- ci || true",
        ] {
            let yaml = format!("{triggers}steps:\n  - run: {command}\n");
            assert!(
                !pipeline_delegates_to_xtask_ci(&yaml),
                "`{command}` must not satisfy xtask CI delegation"
            );
        }
    }

    #[test]
    fn pipeline_delegate_rejects_allow_missing_tools_and_unreachable_blocks() {
        let triggers = develop_triggers();

        assert!(!pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}steps:\n  - run: cargo run --locked -p xtask -- ci --allow-missing-tools\n"
        )));
        assert!(!pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}steps:\n  - run: cargo xtask ci --allow-missing-tools\n"
        )));
        assert!(!pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}steps:\n  - run: |\n      exit 0\n      cargo run --locked -p xtask -- ci\n"
        )));
        assert!(!pipeline_delegates_to_xtask_ci(&format!(
            "{triggers}steps:\n  - run: |\n      set -euo pipefail\n      if true; then\n        cargo run --locked -p xtask -- ci\n      fi\n"
        )));
    }

    /// 真实 committed 文件：GitHub CI workflow 委托 `cargo xtask ci`、不重列门；被引用的本地 setup action
    /// 也只能安装工具，不能承载门命令（INVARIANT CI-PIPELINE-DELEGATE-01）。
    #[test]
    fn github_ci_workflow_delegates_to_xtask_ci() -> anyhow::Result<()> {
        let path = workspace_root()?
            .join(".github")
            .join("workflows")
            .join("ci.yml");
        let yaml = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))?;
        assert!(
            pipeline_delegates_to_xtask_ci(&yaml),
            ".github/workflows/ci.yml 须只调 `cargo xtask ci` 且不逐条重列门 run 命令"
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

        let readme = read("README.md")?;
        for spec in CI_TOOL_SPECS
            .iter()
            .copied()
            .filter(|spec| !spec.starts_with("cargo-binstall"))
        {
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
            && workflow_delegates_to_xtask_lane(yaml, XTASK_AUDIT_FORMS)
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

    // ---- 集成测试 lane 守卫（issue #1145 第②项；INVARIANT CI-INTEGRATION-LANE-01）----

    /// xtask integration 委托的规范形（至少一种须在 YAML 出现，anti-vacuity）：alias 形与 CI 锁定入口形。
    const XTASK_INTEGRATION_FORMS: &[&str] = &[
        "cargo xtask integration",
        "cargo run --locked -p xtask -- integration",
    ];

    /// GitHub integration workflow 谓词（**结构绑定**，fail-closed）。YAML 须同时满足——① `pull_request:` +
    /// `push:` 触发且都绑定 develop；② integration 委托形在真实 run/script 命令；③ 每个 `cargo run`
    /// 都是完整 xtask integration 委托形，其他 cargo 子命令仅限安装（不内联门）。
    fn github_integration_workflow_has_lane(yaml: &str) -> bool {
        workflow_pr_push_triggers_develop(yaml)
            && workflow_delegates_to_xtask_lane(yaml, XTASK_INTEGRATION_FORMS)
    }

    /// 谓词绿/红例（anti-vacuity）：逐一抽掉每个必需子句都使谓词变假（守卫非恒真）。
    #[test]
    fn integration_lane_predicate_green_and_red() {
        let green = "on:\n  pull_request:\n    branches: [develop]\n  push:\n    branches: [develop]\njobs:\n  integration:\n    steps:\n      - run: cargo run --locked -p xtask -- integration\n";
        assert!(
            github_integration_workflow_has_lane(green),
            "完整集成 lane 应为真"
        );
        // 红：缺 integration 委托形（只剩 ci 步）。
        assert!(
            !github_integration_workflow_has_lane(
                "on:\n  pull_request:\n    branches: [develop]\n  push:\n    branches: [develop]\njobs:\n  integration:\n    steps:\n      - run: cargo run --locked -p xtask -- ci\n"
            ),
            "缺 integration 委托形"
        );
        // 红：缺 pull_request 触发。
        assert!(
            !github_integration_workflow_has_lane(
                &green.replace("pull_request:", "x_pull_request:")
            ),
            "缺 pull_request 触发"
        );
        assert!(
            !github_integration_workflow_has_lane(
                &green.replace("branches: [develop]", "branches: [main]")
            ),
            "触发器未绑定 develop"
        );
        // 红（codex F1）：integration 形仅在**注释**里、无真实 script 委托 → 结构绑定不满足。
        assert!(
            !github_integration_workflow_has_lane(
                "# cargo run --locked -p xtask -- integration\non:\n  pull_request:\n    branches: [develop]\n  push:\n    branches: [develop]\nsteps:\n  - run: cargo install cargo-binstall\n"
            ),
            "integration 形仅在注释不应满足守卫（fail-closed）"
        );
        // 红（codex F1）：integration 形仅在 **displayName**（字符串字段值）、无真实 script → 不满足。
        assert!(
            !github_integration_workflow_has_lane(
                "on:\n  pull_request:\n    branches: [develop]\n  push:\n    branches: [develop]\nsteps:\n  - run: cargo install cargo-binstall\n    name: 'cargo run --locked -p xtask -- integration'\n"
            ),
            "integration 形仅在 displayName 不应满足守卫（fail-closed）"
        );
        // 红：内联集成门命令（`cargo nextest`，不委托 xtask）——门逻辑须单源在 xtask。
        assert!(
            !github_integration_workflow_has_lane(&format!(
                "{green}  - script: cargo nextest run --features integration\n"
            )),
            "内联 nextest 集成门命令"
        );
        assert!(
            !github_integration_workflow_has_lane(
                "on:\n  pull_request:\n    branches: [develop]\n  push:\n    branches: [develop]\njobs:\n  integration:\n    steps:\n      - run: cargo run --locked -p xtask -- integration --allow-missing-tools\n"
            ),
            "integration lane 不得在 workflow 中宽限缺工具"
        );
        assert!(
            !github_integration_workflow_has_lane(
                "on:\n  pull_request:\n    branches: [develop]\n  push:\n    branches: [develop]\njobs:\n  integration:\n    steps:\n      - run: |\n          exit 0\n          cargo run --locked -p xtask -- integration\n"
            ),
            "integration 委托命令不可被前置控制流绕过"
        );
    }

    /// 真实 committed 文件：GitHub integration workflow 含集成测试 lane，经 `cargo xtask integration` 委托
    /// （issue #1145 第②项：真集成测试入 PR lane；门逻辑单源在 xtask，不内联）。
    #[test]
    fn github_integration_workflow_has_integration_lane() -> anyhow::Result<()> {
        let path = workspace_root()?
            .join(".github")
            .join("workflows")
            .join("integration.yml");
        let yaml = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))?;
        assert!(
            github_integration_workflow_has_lane(&yaml),
            ".github/workflows/integration.yml 须含集成测试 lane 且经 `cargo xtask integration` 委托"
        );
        Ok(())
    }

    // ---- SAST / CodeQL workflow 守卫（issue #1145 第⑤项；INVARIANT SAST-CODEQL-PRESENT-01）----

    /// CodeQL workflow 必备要素（**结构绑定**，content-scan，Medium）。GitHub Actions 承载 CI/SAST，
    /// 守卫须锁住「SAST 真的会随 push/定时跑 + 真的扫 Rust + 真的产 alert」整条不变式，
    /// 而非仅找关键字子串（review #281 F2，对标 sibling azure 守卫的结构绑定）。经 [`yaml_code_lines`] 先剥 `#` 注释：
    ///
    /// - **① 触发器**：`push:` + `schedule:` 两结构键都在（行起头）——否则退化成仅 `workflow_dispatch`，SAST 不随
    ///   镜像 push / 定时跑（静默失效）。
    /// - **② init step**：某 step 块有**真实** `uses: github/codeql-action/init`（[`block_uses_action`]，非 name /
    ///   注释值），**且同块**含 `languages: rust` + `build-mode: none`（Rust GA 免编译，绑定到该 init step 的 `with`）。
    /// - **③ analyze step**：某 step 块有真实 `uses: github/codeql-action/analyze`（产 code-scanning alert）。
    /// - **④ 写权限**：`security-events: write`（advanced setup 必需）。
    ///
    /// 任一不满足即 SAST 被静默削弱 / 禁用（关键字落注释 / name / 错 step、或退化触发器均 fail-closed）。
    fn codeql_workflow_well_formed(yaml: &str) -> bool {
        let code = yaml_code_lines(yaml);
        let blocks = yaml_step_blocks(yaml);
        let triggers = workflow_event_has_develop_branch(yaml, "push")
            && workflow_has_top_level_on_event(yaml, "schedule");
        let init_bound = blocks.iter().any(|b| {
            block_uses_action(b, "github/codeql-action/init")
                && b.iter().any(|l| l.contains("languages: rust"))
                && b.iter().any(|l| l.contains("build-mode: none"))
        });
        let analyze = blocks
            .iter()
            .any(|b| block_uses_action(b, "github/codeql-action/analyze"));
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
        let install_hint = match step_public_api().kind {
            StepKind::ToolGatedInternal { install_hint, .. } => install_hint,
            _ => "",
        };
        assert!(
            install_hint.contains(pin),
            "public-api install_hint 须为 ToolGatedInternal 且含钉版 nightly {pin}\
             （NIGHTLY-PIN-01，与 publicapi::PINNED_NIGHTLY 同步）；当前: {install_hint:?}"
        );
    }
}
