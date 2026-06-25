//! `cargo xtask verify` —— 本地全量治理门聚合入口。
//!
//! RSS 激活 forge=azure **无 CI**（见 issue #1023），CI 收敛降级为本地 `make verify` ⇒ 本命令是
//! 治理门的**唯一**实际 gate。聚合（fail-fast，无编译的步最先）：
//!
//!   1. `cargo fmt --all -- --check`
//!   2. in-process meta：contract validate + layer-deps + codegen --check
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
//! **`cargo xtask ci`（[`run_ci`]）= CI lane 超集**（issue #1132，azure-pipelines.yml 薄壳唯一调用入口）：
//! verify 全门 + build/clippy 升 `--all-features --all-targets` + 覆盖率门（`cargo llvm-cov nextest` 替
//! nextest，强制 basis/engine ≥90%，见 `coverage.rs`）+ `public-api --check`（轴 A，见 `publicapi.rs`）。
//! `verify` 仍是 **stable-only 本地快门**（不需 nightly / llvm-cov）；`ci` 是 **CI 全工具超集**——二者经
//! [`full_plan`] / [`ci_plan`] 共享 fmt/meta/deny/dylint 同一构造，杜绝两份计划漂移。
//!
//! **`cargo xtask audit`（[`run_audit`]）= 供应链漏洞定时刷新 lane**（issue #1133，azure-pipelines.yml
//! 每日 `schedules:` cron 调用入口）：advisory-scoped `cargo deny check advisories` + `cargo audit` 两门
//! （皆 no-compile、快）。PR 门（ci）已含全量 `deny check`（advisories+licenses+bans+sources）+ cargo-audit；
//! audit lane 专攻**时间维度**——对「未变依赖」新披露的 CVE，PR 门要等下个 PR 才捕获，故每日重跑漏洞维度。
//! audit lane = **告警**（无 PR 可阻断）；PR 门 ci = **合入阻断**。
//!
//! **`cargo-udeps` 仍不入三者**（多余/未声明依赖，需 nightly `-Z`，与根 stable 1.96 冲突）——独立可选门。
//! `cargo-semver-checks`（轴 A 语义破坏检测）当前所有 crate `publish = false` ⇒ `--workspace` 选 0 包、门
//! 空转，故本轮不入 ci（public-api --check 已非空转兜轴 A）；待 crate 可发布后 follow-up 接入（见 PR body）。
//!
//! INVARIANT: VERIFY-AGGREGATE-01 —— 任一门步失败 ⇒ verify/ci/audit 非零退出（聚合 fail-fast，不吞错）。
//! INVARIANT: VERIFY-TOOL-GATE-01 —— 缺外部工具默认 fail-closed；豁免仅经显式 `--allow-missing-tools`。
//! INVARIANT: CI-PIPELINE-DELEGATE-01 —— azure-pipelines.yml 只调 `cargo xtask ci`、不逐条重列门 run
//!   命令（门逻辑单源在 xtask）；由 `azure_pipeline_delegates_to_xtask_ci` 治理测试守。

use crate::diagnostic::run_check;
use crate::workspace_root;
use crate::{codegen, contract, layerdeps, wsdeps};
use anyhow::{Result, bail};
use std::path::Path;
use std::process::Stdio;

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
    LayerDeps,
    WsDepsDrift,
    CodegenCheck,
    /// bins 生产 src 的 `#[allow(rss_pdp_impl_adapter_only)]` 逃生门计数门（信任根二次门，PDP-ALLOW-CONFINE-01）。
    PdpAllowGuard,
    /// ci 专用：`cargo llvm-cov nextest`（兼 nextest 门）+ basis/engine ≥90% 覆盖率判定（见 `coverage.rs`）。
    Coverage,
    /// ci 专用：`public-api --check`（basis+engine 封装面 baseline 漂移门 = 轴 A，见 `publicapi.rs`）。
    PublicApiCheck,
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
struct Step {
    label: &'static str,
    args: &'static [&'static str],
    kind: StepKind,
    /// 该步额外设置的环境变量（如 dylint 的 `DYLINT_RUSTFLAGS=-D warnings` 把 lint 升为 fail-closed）。
    env: &'static [(&'static str, &'static str)],
    /// 是否需要编译全 workspace —— `--fast` 据此裁剪（true 的步在 fast 下跳过）。
    needs_compile: bool,
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
fn step_deny() -> Step {
    Step {
        label: "deny",
        args: &["deny", "check"],
        kind: StepKind::Tool {
            probe: "deny",
            install_hint: "cargo install cargo-deny --locked",
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
            install_hint: "cargo install cargo-deny --locked",
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
            install_hint: "cargo install cargo-audit --locked",
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
            install_hint: "cargo install cargo-dylint dylint-link",
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
            "--features",
            "integration",
        ],
        kind: StepKind::Tool {
            probe: "nextest",
            install_hint: "cargo install cargo-nextest --locked（实跑还需 docker 或设 PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD + REDIS_TEST_URL + RSS_AMQP_TEST_URL + RSS_MQTT_TEST_URL 等 env URL）",
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
            install_hint: "cargo install cargo-nextest --locked",
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
            install_hint: "cargo install cargo-nextest --locked",
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
            install_hint: "cargo install cargo-nextest --locked",
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
            install_hint: "cargo install cargo-nextest --locked",
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
            install_hint: "cargo install cargo-nextest --locked",
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
            install_hint: "cargo install cargo-nextest --locked",
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
            install_hint: "cargo install cargo-nextest --locked",
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
            install_hint: "cargo install cargo-llvm-cov --locked",
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
            install_hint: "rustup toolchain install nightly && cargo install cargo-public-api --locked",
            check: InternalCheck::PublicApiCheck,
        },
        env: &[],
        needs_compile: true,
    }
}

/// verify 全量门步计划（单一事实源；顺序 = 执行顺序）。feature-test 门紧随 nextest（同测试相位）。
fn full_plan() -> Vec<Step> {
    let mut plan = vec![
        step_fmt(),
        step_contract_validate(),
        step_layer_deps(),
        step_wsdeps_drift(),
        step_codegen_check(),
        step_pdp_allow_guard(),
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
fn ci_plan() -> Vec<Step> {
    let mut plan = vec![
        step_fmt(),
        step_contract_validate(),
        step_layer_deps(),
        step_wsdeps_drift(),
        step_codegen_check(),
        step_pdp_allow_guard(),
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

/// audit 精简供应链门步计划（issue #1133；azure-pipelines.yml 每日 cron 调 `cargo xtask audit`）。
/// advisory-scoped deny + cargo-audit 两门，皆 no-compile、快——定时刷新只查漏洞库（捕获「未变依赖」新
/// 披露 CVE）。**不含** licenses/bans：它们只随 Cargo.lock 变（= 随 PR 变），定时跑无增益；PR 门的
/// [`ci_plan`] 已用全量 `deny check` + cargo-audit 覆盖。audit 步与 ci 共享同一 [`step_cargo_audit`] 构造。
///
/// INVARIANT: CI-PIPELINE-DELEGATE-01 —— audit lane 亦经 YAML 委托 `cargo xtask audit`（不内联门命令），
/// 由 `azure_pipeline_has_scheduled_audit_lane` 守。
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
/// → 警告跳过。**不入** verify/ci（默认门须无 docker 可跑）；azure-pipelines 接线待 #1145（需 docker agent）。
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
                     外部 PG 路径需：RSS_TEST_ALLOW_EXTERNAL_POSTGRES + PGHOST+PGPORT+PGDATABASE+PGUSER+PGPASSWORD（5 元组）；\
                     + REDIS_TEST_URL + RSS_AMQP_TEST_URL 指向长存 pg/redis/rabbitmq 可免 docker。"
                );
                return Ok(());
            }
            ToolAction::Fail => bail!(
                "integration: docker daemon 不可达（容器 self-provision 需 docker）。\
                 启动 Docker，或同时设 RSS_TEST_ALLOW_EXTERNAL_POSTGRES + \
                 PGHOST+PGPORT+PGDATABASE+PGUSER+PGPASSWORD（PG 5 元组）\
                 + REDIS_TEST_URL + RSS_AMQP_TEST_URL 指向运行中的 pg/redis/rabbitmq；\
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
        run_one(step, &opts, &root)?;
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
fn run_step(label: &str, args: &[&str], env: &[(&str, &str)], cwd: &Path) -> Result<()> {
    let status = crate::cmd::clean_cmd("cargo", args, env, Some(cwd))
        .status()
        .map_err(|e| {
            anyhow::anyhow!(
                "verify: 启动门步 `{label}`（cargo {}）失败: {e}",
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
        "verify: 门步 `{label}` 失败（cargo {} 退出码 {code}）",
        args.join(" ")
    )
}

/// 跑单步：Internal 进程内执行；CargoBuiltin 直接 spawn；Tool 先探测再按决策分派。
fn run_one(step: &Step, opts: &VerifyOpts, root: &Path) -> Result<()> {
    match &step.kind {
        StepKind::Internal(check) => run_internal(*check),
        StepKind::CargoBuiltin => run_step(step.label, step.args, step.env, root),
        StepKind::Tool {
            probe,
            install_hint,
        } => run_tool_gated(
            crate::cmd::tool_available(probe),
            opts.allow_missing_tools,
            probe,
            install_hint,
            step.label,
            || run_step(step.label, step.args, step.env, root),
        ),
        StepKind::ToolGatedInternal {
            probe,
            install_hint,
            check,
        } => run_tool_gated(
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
                "verify: [跳过] `{label}`（缺 `cargo {probe}`，--allow-missing-tools 宽限）。装：{install_hint}"
            );
            Ok(())
        }
        ToolAction::Fail => bail!(
            "verify: 缺 `cargo {probe}`（门步 `{label}`）。装：{install_hint}\n（门不建议绕过；确需可显式 --allow-missing-tools）"
        ),
    }
}

fn run_internal(check: InternalCheck) -> Result<()> {
    match check {
        InternalCheck::ContractValidate => run_check(&contract::validate::ContractValidate),
        InternalCheck::LayerDeps => run_check(&layerdeps::LayerDeps),
        InternalCheck::WsDepsDrift => run_check(&wsdeps::WsDepsDrift),
        InternalCheck::CodegenCheck => codegen::run(true),
        InternalCheck::PdpAllowGuard => run_check(&crate::pdpallow::PdpAllowGuard),
        InternalCheck::Coverage => crate::coverage::run(),
        // 轴 A 封装面：basis+engine 全集（layer=None）；check=true 漂移门 fail-closed（PUBLICAPI-DRIFT-GATE-01）。
        InternalCheck::PublicApiCheck => crate::publicapi::run(true, false, None),
    }
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
    for (i, step) in plan.iter().enumerate() {
        // 每步开始打 label——build/clippy/nextest 各数分钟，让操作者实时知道卡在哪步。
        eprintln!("verify: [{}/{}] {}", i + 1, plan.len(), step.label);
        run_one(step, &opts, &root)?;
    }
    eprintln!("verify（{mode}）：全部通过");
    Ok(())
}

/// ci 入口（issue #1132 CI lane 超集）：按 [`ci_plan`] 顺序跑每步，fail-fast。CI 由 azure-pipelines.yml
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
    for (i, step) in plan.iter().enumerate() {
        eprintln!("ci: [{}/{}] {}", i + 1, plan.len(), step.label);
        run_one(step, &opts, &root)?;
    }
    eprintln!("ci：全部通过");
    Ok(())
}

/// audit 入口（issue #1133 供应链定时刷新 lane）：按 [`audit_plan`] 顺序跑每步，fail-fast。
/// azure-pipelines.yml 每日 cron 调 `cargo xtask audit`（薄壳唯一入口，CI-PIPELINE-DELEGATE-01 同族）。
/// `allow_missing_tools` 仅本地便利——CI 不传 = 缺 deny/audit 工具 fail-closed。
pub(crate) fn run_audit(allow_missing_tools: bool) -> Result<()> {
    let opts = VerifyOpts {
        fast: false,
        allow_missing_tools,
    };
    let root = workspace_root()?;
    let plan = audit_plan();
    eprintln!("audit：{} 步（供应链漏洞刷新 lane）", plan.len());
    for (i, step) in plan.iter().enumerate() {
        eprintln!("audit: [{}/{}] {}", i + 1, plan.len(), step.label);
        run_one(step, &opts, &root)?;
    }
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
                "layer-deps",
                "wsdeps-drift",
                "codegen-check",
                "pdp-allow-guard",
                "build",
                "integration-compile",
                "clippy",
                "nextest",
                "s3-backend-tests",
                "redis-backend-tests",
                "oidc-backend-tests",
                "prometheus-backend-tests",
                "grpc-backend-tests",
                "vault-backend-tests",
                "deny",
                "dylint",
            ]
        );
    }

    /// `--fast` 只留无需编译的步：fmt + meta(5) + deny；裁掉 build/clippy/nextest/dylint。
    #[test]
    fn fast_plan_keeps_fmt_meta_deny_drops_compile() {
        let plan = verify_plan(&opts(true, false));
        assert_eq!(
            labels(&plan),
            vec![
                "fmt",
                "contract-validate",
                "layer-deps",
                "wsdeps-drift",
                "codegen-check",
                "pdp-allow-guard",
                "deny"
            ]
        );
        for dropped in ["build", "clippy", "nextest", "dylint"] {
            assert!(!labels(&plan).contains(&dropped), "fast 不应含 {dropped}");
        }
    }

    /// meta 五项（contract validate / layer-deps / wsdeps-drift / codegen / pdp-allow-guard）在两种模式恒在。
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
                    "layer-deps",
                    "wsdeps-drift",
                    "codegen-check",
                    "pdp-allow-guard"
                ],
                "fast={fast}"
            );
        }
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
        assert!(run_step("redcase", &["zzz-not-a-cargo-subcommand"], &[], &root).is_err());
        Ok(())
    }

    /// 对照绿例：成功步 ⇒ `Ok`。
    #[test]
    fn run_step_success_is_ok() -> anyhow::Result<()> {
        let root = workspace_root()?;
        assert!(run_step("greencase", &["--version"], &[], &root).is_ok());
        Ok(())
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
        assert!(run_one(&step, &opts(false, false), &root).is_err());
        Ok(())
    }

    /// 缺工具 + 显式宽限 ⇒ `run_one` 警告跳过、返回 `Ok`（`--allow-missing-tools` 路径）。
    #[test]
    fn run_one_missing_tool_skipwarn_is_ok() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let step = missing_tool_step();
        assert!(run_one(&step, &opts(false, true), &root).is_ok());
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
                "layer-deps",
                "wsdeps-drift",
                "codegen-check",
                "pdp-allow-guard",
                "build",
                "clippy",
                "coverage",
                "s3-backend-tests",
                "redis-backend-tests",
                "oidc-backend-tests",
                "prometheus-backend-tests",
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
            "layer-deps",
            "wsdeps-drift",
            "codegen-check",
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

    /// integration 实跑步：`--profile integration`（放宽 timeout）+ `--features integration` + 三 adapter 全覆盖；
    /// Tool gate probe `nextest`（缺工具 fail-closed）。
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
        for p in ["postgres", "redis-adapter", "amqp", "mqtt", "journeys"] {
            assert!(step.args.contains(&p), "integration 实跑须覆盖 {p}");
        }
    }

    /// integration-compile（默认 verify 抓编译漂移）`--no-run` 覆盖各 adapter + journeys durable journey
    /// （F7 + #1137：原仅 postgres；#1010 加 mqtt）。
    #[test]
    fn integration_compile_covers_adapters_and_journeys_no_run() {
        let step = step_integration_compile();
        assert_eq!(step.label, "integration-compile");
        assert!(step.args.contains(&"--no-run"), "默认门只编译不实跑");
        for p in ["postgres", "redis-adapter", "amqp", "mqtt", "journeys"] {
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
        assert!(run_one(&missing_toolgated_step(), &opts(false, false), &root).is_err());
        Ok(())
    }

    /// ToolGatedInternal 缺工具 + 宽限 ⇒ `Ok`（SkipWarn；不执行内部逻辑）。
    #[test]
    fn run_one_toolgated_missing_skipwarn_is_ok() -> anyhow::Result<()> {
        let root = workspace_root()?;
        assert!(run_one(&missing_toolgated_step(), &opts(false, true), &root).is_ok());
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

    // ---- CI-PIPELINE-DELEGATE-01：azure-pipelines.yml 委托 `cargo xtask ci`、不逐条重列门 ----

    /// 委托豁免的 cargo 子命令**正向白名单**：`xtask`（alias 形）+ `run`（CI 锁定入口 `cargo run --locked
    /// -p xtask -- ci`——run 跑 xtask 而非门）+ 工具安装（install/binstall）。除此之外任何裸 `cargo <sub>`
    /// 都视作门 run（build/clippy/nextest/deny/dylint/llvm-cov/public-api/fmt 及**任何未来新门**）——正向
    /// 白名单无枚举盲区（review #206 A1/A3 黑名单漏 build/llvm-cov/public-api；codex F2 入口改 --locked run
    /// 形需放行 run）。
    const DELEGATION_CARGO_SUBCOMMANDS: &[&str] = &["xtask", "run", "install", "binstall"];

    /// xtask ci 委托的规范形（至少一种须在 YAML 出现，anti-vacuity）：alias 形（本地/文档）与 CI 锁定入口
    /// 形（`--locked` 锁 xtask 子树依赖解析，与内部 `--workspace --locked` 门共同锁全链，codex F2）。
    const XTASK_CI_FORMS: &[&str] = &["cargo xtask ci", "cargo run --locked -p xtask -- ci"];

    /// 扫 YAML **命令文本**里每个 `cargo <token>`（run 形带空格；连字符的 `cargo-nextest` 等 arg 不匹配），
    /// 返回紧跟的子命令 token。先按行剥 YAML 注释（`#` 起）——散文注释里的 `cargo …`（如「cargo 默认
    /// target …」）不计入门 run 判定。
    fn cargo_subcommands(yaml: &str) -> Vec<&str> {
        yaml.lines()
            .flat_map(|line| {
                let code = line.split('#').next().unwrap_or("");
                code.match_indices("cargo ")
                    .filter_map(|(i, _)| code[i + "cargo ".len()..].split_whitespace().next())
            })
            .collect()
    }

    /// 剥 `#` 注释 + 去缩进后的 YAML「代码行」（注释行 → 空串）。委托守卫据此**绑定结构**而非裸全文匹配——
    /// 散文注释（已剥）与 displayName/name 等字符串字段值都不能满足守卫（fail-closed，对标 codex F1：
    /// 守卫不可被注释 / displayName 文本误满足）。
    fn yaml_code_lines(yaml: &str) -> Vec<&str> {
        yaml.lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .collect()
    }

    /// 某委托命令形是否出现在**真实 script 命令**里（而非注释 / displayName 等字符串字段）。命令形态：
    /// `script: |` block 的命令体行（trimmed 以委托形起头），或 inline `- script: <cmd>`（`script:` 冒号后含委托形）。
    /// displayName/name 行的引号内文本既不以委托形起头、也无 `script:` 前缀 ⇒ 被排除（结构绑定，非裸 `contains`）。
    fn form_in_script(yaml: &str, forms: &[&str]) -> bool {
        yaml_code_lines(yaml).iter().any(|&raw| {
            let line = raw.strip_prefix("- ").map(str::trim).unwrap_or(raw);
            let is_script = line.starts_with("script:");
            let cmd = line.strip_prefix("script:").map(str::trim).unwrap_or(line);
            forms
                .iter()
                .any(|f| cmd.starts_with(f) || (is_script && cmd.contains(f)))
        })
    }

    /// 委托谓词（正向白名单）：YAML 的**真实 script 命令**含 xtask ci 规范形之一（经 [`form_in_script`] 结构
    /// 绑定，不被注释 / displayName 误满足；codex F1 同类加固），且每个 `cargo <sub>` 的 sub ∈
    /// [`DELEGATION_CARGO_SUBCOMMANDS`]——即除安装/跑 xtask 外不逐条重列任何门。
    fn pipeline_delegates_to_xtask_ci(yaml: &str) -> bool {
        form_in_script(yaml, XTASK_CI_FORMS)
            && cargo_subcommands(yaml)
                .iter()
                .all(|sub| DELEGATION_CARGO_SUBCOMMANDS.contains(sub))
    }

    /// 谓词绿/红例（anti-vacuity）：委托=真；不委托或重列**任一**门（含黑名单曾漏的 build/llvm-cov/
    /// public-api）=假。
    #[test]
    fn pipeline_delegate_predicate_green_and_red() {
        assert!(pipeline_delegates_to_xtask_ci(
            "steps:\n  - script: cargo xtask ci\n"
        ));
        // 绿：安装形（install/binstall）豁免，连字符 arg 不误判。
        assert!(pipeline_delegates_to_xtask_ci(
            "steps:\n  - script: cargo install cargo-binstall\n  - script: cargo binstall -y cargo-nextest cargo-deny\n  - script: cargo xtask ci\n"
        ));
        // 绿：散文注释里的 `cargo <词>`（如「cargo 默认 target …」/「cargo build 历史」）不计入门 run 判定。
        assert!(pipeline_delegates_to_xtask_ci(
            "  # cargo 默认 target 在 repo 根；曾用 cargo build 直跑\nsteps:\n  - script: cargo xtask ci\n"
        ));
        // 绿：CI 锁定入口形 `cargo run --locked -p xtask -- ci`（run 跑 xtask 非门）+ 安装形（codex F2）。
        assert!(pipeline_delegates_to_xtask_ci(
            "steps:\n  - script: cargo install cargo-binstall@1.20.1 --locked\n  - script: cargo run --locked -p xtask -- ci\n"
        ));
        // 红：run 形入口但仍重列门（build）——run 放行不削弱门捕获。
        assert!(!pipeline_delegates_to_xtask_ci(
            "steps:\n  - script: cargo run --locked -p xtask -- ci\n  - script: cargo build --workspace\n"
        ));
        // 红：未委托。
        assert!(!pipeline_delegates_to_xtask_ci(
            "steps:\n  - script: cargo clippy --workspace\n"
        ));
        // 红（codex F1）：xtask ci 形仅在**注释**里、无真实 script 委托 → 结构绑定不满足（安装步通过白名单但 form_in_script 假）。
        assert!(!pipeline_delegates_to_xtask_ci(
            "# cargo xtask ci\nsteps:\n  - script: cargo install cargo-binstall\n"
        ));
        // 红（codex F1）：xtask ci 形仅在 **displayName**（字符串字段值）、无真实 script 委托 → 不满足。
        assert!(!pipeline_delegates_to_xtask_ci(
            "steps:\n  - script: cargo install cargo-binstall\n    displayName: 'cargo xtask ci'\n"
        ));
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
            let yaml = format!("steps:\n  - script: cargo xtask ci\n  - script: {gate}\n");
            assert!(
                !pipeline_delegates_to_xtask_ci(&yaml),
                "重列门 `{gate}` 应被谓词捕获"
            );
        }
    }

    /// 真实 committed 文件：azure-pipelines.yml 委托 `cargo xtask ci`、不重列门（INVARIANT CI-PIPELINE-DELEGATE-01）。
    #[test]
    fn azure_pipeline_delegates_to_xtask_ci() -> anyhow::Result<()> {
        let path = workspace_root()?.join("azure-pipelines.yml");
        let yaml = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))?;
        assert!(
            pipeline_delegates_to_xtask_ci(&yaml),
            "azure-pipelines.yml 须只调 `cargo xtask ci` 且不逐条重列门 run 命令"
        );
        Ok(())
    }

    // ---- 供应链定时刷新 lane 守卫（issue #1133）----

    /// xtask audit 委托的规范形（至少一种须在 YAML 出现，anti-vacuity）：alias 形与 CI 锁定入口形。
    const XTASK_AUDIT_FORMS: &[&str] =
        &["cargo xtask audit", "cargo run --locked -p xtask -- audit"];

    /// 调度 lane 谓词（**结构绑定**，fail-closed；codex F1：守卫不可被注释 / displayName 误满足）。YAML 须同时
    /// 满足——① 顶层 `schedules:` 键（去注释后整行 == `schedules:`，非字符串值）；② `always: true` 映射项
    /// （无代码变更也跑，否则捕不到「未变依赖」新披露 CVE，是定时刷新核心用途）；③ audit 委托形在**真实 script
    /// 命令**（[`form_in_script`]，非 displayName / 注释；门逻辑单源在 xtask，CI-PIPELINE-DELEGATE-01 同族）；
    /// ④ Build.Reason **互斥分流**两 `condition:` 都在（`eq(...,'Schedule')` 给 audit lane、`ne(...,'Schedule')` 给
    /// ci lane）——缺任一则两步可能都跑或都不跑；⑤ 每个 `cargo <sub>` ∈ 委托白名单。
    fn pipeline_has_scheduled_audit_lane(yaml: &str) -> bool {
        let code = yaml_code_lines(yaml);
        let line_is = |s: &str| code.contains(&s);
        let condition_has = |needle: &str| {
            code.iter()
                .any(|l| l.starts_with("condition:") && l.contains(needle))
        };
        line_is("schedules:")
            && line_is("always: true")
            && form_in_script(yaml, XTASK_AUDIT_FORMS)
            && condition_has("eq(variables['Build.Reason'], 'Schedule')")
            && condition_has("ne(variables['Build.Reason'], 'Schedule')")
            && cargo_subcommands(yaml)
                .iter()
                .all(|sub| DELEGATION_CARGO_SUBCOMMANDS.contains(sub))
    }

    /// 谓词绿/红例（anti-vacuity）：逐一抽掉每个必需子句都使谓词变假（守卫非恒真）。
    #[test]
    fn scheduled_audit_lane_predicate_green_and_red() {
        let green = "schedules:\n  - cron: \"0 6 * * *\"\n    always: true\nsteps:\n  - script: cargo install cargo-binstall\n  - script: cargo run --locked -p xtask -- ci\n    condition: ne(variables['Build.Reason'], 'Schedule')\n  - script: cargo run --locked -p xtask -- audit\n    condition: eq(variables['Build.Reason'], 'Schedule')\n";
        assert!(
            pipeline_has_scheduled_audit_lane(green),
            "完整定时 lane 应为真"
        );
        // 红：逐一抽掉一个必需子句。
        assert!(
            !pipeline_has_scheduled_audit_lane(&green.replace("schedules:", "trigger:")),
            "缺 schedules 块"
        );
        assert!(
            !pipeline_has_scheduled_audit_lane(&green.replace("    always: true\n", "")),
            "缺 always:true（无代码变更不跑、捕不到未变依赖新 CVE）"
        );
        assert!(
            !pipeline_has_scheduled_audit_lane(
                &green.replace("ne(variables['Build.Reason'], 'Schedule')", "always()")
            ),
            "缺 ne 分流条件（ci/audit 可能都跑或都不跑）"
        );
        assert!(
            !pipeline_has_scheduled_audit_lane(
                &green.replace("cargo run --locked -p xtask -- audit", "cargo xtask ci")
            ),
            "缺 audit 委托形"
        );
        // 红：内联 `cargo audit` 门命令（不委托 xtask）——门逻辑须单源在 xtask。
        assert!(
            !pipeline_has_scheduled_audit_lane(&format!("{green}  - script: cargo audit\n")),
            "内联 cargo audit 门命令"
        );
        // 红（codex F1 核心）：全部关键字仅在**注释**里、无真实结构 → 结构绑定守卫不满足
        //（旧裸 `yaml.contains` 谓词会误判为真）。安装步使 cargo_subcommands 通过，隔离出结构断言失败。
        assert!(
            !pipeline_has_scheduled_audit_lane(
                "# schedules:\n# always: true\n# condition: eq(variables['Build.Reason'], 'Schedule')\n# condition: ne(variables['Build.Reason'], 'Schedule')\n# cargo run --locked -p xtask -- audit\nsteps:\n  - script: cargo install cargo-binstall\n"
            ),
            "关键字仅在注释里不应满足守卫（fail-closed）"
        );
        // 红（codex F1 核心）：audit 委托形仅在 **displayName**（字符串字段值）、无真实 audit script → 不满足。
        assert!(
            !pipeline_has_scheduled_audit_lane(
                "schedules:\n  - cron: \"0 6 * * *\"\n    always: true\nsteps:\n  - script: cargo run --locked -p xtask -- ci\n    condition: ne(variables['Build.Reason'], 'Schedule')\n  - script: cargo install cargo-binstall\n    displayName: 'cargo run --locked -p xtask -- audit'\n    condition: eq(variables['Build.Reason'], 'Schedule')\n"
            ),
            "audit 形仅在 displayName 不应满足守卫（fail-closed）"
        );
    }

    /// 真实 committed 文件：azure-pipelines.yml 含每日定时刷新 lane，经 `cargo xtask audit` 委托
    /// （issue #1133：捕获「未变依赖」新披露 CVE；门逻辑单源在 xtask，不内联）。
    #[test]
    fn azure_pipeline_has_scheduled_audit_lane() -> anyhow::Result<()> {
        let path = workspace_root()?.join("azure-pipelines.yml");
        let yaml = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("读 {} 失败: {e}", path.display()))?;
        assert!(
            pipeline_has_scheduled_audit_lane(&yaml),
            "azure-pipelines.yml 须含 `schedules:` 定时刷新 lane 且经 `cargo xtask audit` 委托"
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
}
