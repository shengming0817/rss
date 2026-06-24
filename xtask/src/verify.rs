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
//!   6. `cargo deny check`（外部工具）
//!   7. `cargo dylint --all`（外部工具；跑 `lints/` 嵌套 nightly workspace；`DYLINT_RUSTFLAGS=-D warnings`
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
//! **`cargo-udeps` 仍不入两者**（多余/未声明依赖，需 nightly `-Z`，与根 stable 1.96 冲突）——独立可选门。
//! `cargo-semver-checks`（轴 A 语义破坏检测）当前所有 crate `publish = false` ⇒ `--workspace` 选 0 包、门
//! 空转，故本轮不入 ci（public-api --check 已非空转兜轴 A）；待 crate 可发布后 follow-up 接入（见 PR body）。
//!
//! INVARIANT: VERIFY-AGGREGATE-01 —— 任一门步失败 ⇒ verify/ci 非零退出（聚合 fail-fast，不吞错）。
//! INVARIANT: VERIFY-TOOL-GATE-01 —— 缺外部工具默认 fail-closed；豁免仅经显式 `--allow-missing-tools`。
//! INVARIANT: CI-PIPELINE-DELEGATE-01 —— azure-pipelines.yml 只调 `cargo xtask ci`、不逐条重列门 run
//!   命令（门逻辑单源在 xtask）；由 `azure_pipeline_delegates_to_xtask_ci` 治理测试守。

use crate::diagnostic::run_check;
use crate::workspace_root;
use crate::{codegen, contract, layerdeps};
use anyhow::{Result, bail};
use std::path::Path;

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
    CodegenCheck,
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
fn step_codegen_check() -> Step {
    Step {
        label: "codegen-check",
        args: &[],
        kind: StepKind::Internal(InternalCheck::CodegenCheck),
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
/// F7：postgres outbox 集成测试由 `#[cfg(feature = "integration")]` gate，verify 的 build/clippy/nextest
/// 仅 workspace 默认 feature ⇒ 关键状态机测试（崩溃重投 / CAS fencing / DLX / sweep）默认门外、回归漏网。
/// 本步 `--no-run` 仅编译（不跑、无需真实 PG）纳入默认 verify 抓漂移；有 PG 时另跑
/// `cargo nextest run -p postgres --features integration` 行实跑。ci lane 经 `--all-features --all-targets`
/// 已覆盖该编译面，故仅入 [`full_plan`]，不入 [`ci_plan`]。
fn step_integration_compile() -> Step {
    Step {
        label: "integration-compile",
        args: &[
            "test",
            "-p",
            "postgres",
            "--features",
            "integration",
            "--no-run",
        ],
        kind: StepKind::CargoBuiltin,
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

/// verify 全量门步计划（单一事实源；顺序 = 执行顺序）。
fn full_plan() -> Vec<Step> {
    vec![
        step_fmt(),
        step_contract_validate(),
        step_layer_deps(),
        step_codegen_check(),
        step_build_workspace(),
        step_integration_compile(),
        step_clippy_workspace(),
        step_nextest(),
        step_deny(),
        step_dylint(),
    ]
}

/// ci 超集门步计划（issue #1132 CI lane）。与 verify 共享 fmt/meta/deny/dylint 同一构造；build/clippy 升
/// `--all-features --all-targets`；覆盖率门替 nextest（兼跑 workspace 测试）；尾追 public-api --check（轴 A）。
/// ci 恒全量（无 `--fast`）。
fn ci_plan() -> Vec<Step> {
    vec![
        step_fmt(),
        step_contract_validate(),
        step_layer_deps(),
        step_codegen_check(),
        step_build_all_features(),
        step_clippy_all_features(),
        step_coverage(),
        step_deny(),
        step_dylint(),
        step_public_api(),
    ]
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
        InternalCheck::CodegenCheck => codegen::run(true),
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
                "codegen-check",
                "build",
                "integration-compile",
                "clippy",
                "nextest",
                "deny",
                "dylint",
            ]
        );
    }

    /// `--fast` 只留无需编译的步：fmt + meta(3) + deny；裁掉 build/clippy/nextest/dylint。
    #[test]
    fn fast_plan_keeps_fmt_meta_deny_drops_compile() {
        let plan = verify_plan(&opts(true, false));
        assert_eq!(
            labels(&plan),
            vec![
                "fmt",
                "contract-validate",
                "layer-deps",
                "codegen-check",
                "deny"
            ]
        );
        for dropped in ["build", "clippy", "nextest", "dylint"] {
            assert!(!labels(&plan).contains(&dropped), "fast 不应含 {dropped}");
        }
    }

    /// meta 三项（contract validate / layer-deps / codegen）在两种模式恒在。
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
                vec!["contract-validate", "layer-deps", "codegen-check"],
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

    /// ci_plan 顺序与门集（单一事实源；CI lane 实跑顺序）。
    #[test]
    fn ci_plan_order_and_count() {
        assert_eq!(
            labels(&ci_plan()),
            vec![
                "fmt",
                "contract-validate",
                "layer-deps",
                "codegen-check",
                "build",
                "clippy",
                "coverage",
                "deny",
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

    /// 委托谓词（正向白名单）：YAML 含 xtask ci 规范形之一，且每个 `cargo <sub>` 的 sub ∈
    /// [`DELEGATION_CARGO_SUBCOMMANDS`]——即除安装/跑 xtask 外不逐条重列任何门。
    fn pipeline_delegates_to_xtask_ci(yaml: &str) -> bool {
        XTASK_CI_FORMS.iter().any(|f| yaml.contains(f))
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
}
