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
//! **故意不入 verify（语义/工具链不同，非遗漏）**：`cargo-udeps`（多余/未声明依赖，需 nightly `-Z`，
//! 与根 stable 1.96 冲突）、`public-api`（库封装面 baseline 冻结门，需 nightly rustdoc-json，见
//! `publicapi.rs`）、`llvm-cov` 覆盖率阈值（per-PR-diff 语义、非全 workspace pass/fail）——均为独立可选门。
//!
//! INVARIANT: VERIFY-AGGREGATE-01 —— 任一门步失败 ⇒ verify 非零退出（聚合 fail-fast，不吞错）。
//! INVARIANT: VERIFY-TOOL-GATE-01 —— 缺外部工具默认 fail-closed；豁免仅经显式 `--allow-missing-tools`。

use crate::diagnostic::run_check;
use crate::workspace_root;
use crate::{codegen, contract, layerdeps};
use anyhow::{Result, bail};
use std::path::Path;
use std::process::{Command, Stdio};

/// verify 选项。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifyOpts {
    /// 只跑无需编译的步（fmt + meta + deny），跳过 build/clippy/nextest/dylint。
    fast: bool,
    /// 缺外部工具时显式宽限（默认 fail-closed，唯一门不建议）。
    allow_missing_tools: bool,
}

/// in-process Rust 门（无外部进程）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InternalCheck {
    ContractValidate,
    LayerDeps,
    CodegenCheck,
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

/// 全量门步计划（单一事实源；顺序 = 执行顺序）。
fn full_plan() -> Vec<Step> {
    vec![
        Step {
            label: "fmt",
            args: &["fmt", "--all", "--", "--check"],
            kind: StepKind::CargoBuiltin,
            env: &[],
            needs_compile: false,
        },
        Step {
            label: "contract-validate",
            args: &[],
            kind: StepKind::Internal(InternalCheck::ContractValidate),
            env: &[],
            needs_compile: false,
        },
        Step {
            label: "layer-deps",
            args: &[],
            kind: StepKind::Internal(InternalCheck::LayerDeps),
            env: &[],
            needs_compile: false,
        },
        Step {
            label: "codegen-check",
            args: &[],
            kind: StepKind::Internal(InternalCheck::CodegenCheck),
            env: &[],
            needs_compile: false,
        },
        Step {
            label: "build",
            args: &["build", "--workspace"],
            kind: StepKind::CargoBuiltin,
            env: &[],
            needs_compile: true,
        },
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
        },
        Step {
            label: "nextest",
            args: &["nextest", "run", "--workspace", "--no-tests=pass"],
            kind: StepKind::Tool {
                probe: "nextest",
                install_hint: "cargo install cargo-nextest --locked",
            },
            env: &[],
            needs_compile: true,
        },
        Step {
            label: "deny",
            args: &["deny", "check"],
            kind: StepKind::Tool {
                probe: "deny",
                install_hint: "cargo install cargo-deny --locked",
            },
            env: &[],
            needs_compile: false,
        },
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
        },
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

/// 探测第三方 cargo 子命令是否可用：`cargo <sub> --version`（静默）。
/// cargo 对「无此子命令」和「检查失败」都返回 101，故用 `--version` 探测做判别。
fn tool_available(probe_sub: &str) -> bool {
    clean_cargo_cmd(&[probe_sub, "--version"], &[], None)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// verify 子进程须清洗的 ambient 环境变量。两类：
/// - **toolchain 选择**（`RUSTUP_TOOLCHAIN`/`RUSTC`/`RUSTDOC`/`RUSTC_WRAPPER`）：`cargo xtask verify`
///   = `cargo run -p xtask`，子进程继承父 cargo 的 toolchain 环境会**覆盖** per-dir `rust-toolchain.toml`，
///   打破根 stable 1.96 与 `lints/` nightly 的隔离（`cargo dylint --all` 须用 lints/ nightly）。
/// - **编译 flag**（`RUSTFLAGS`/`CARGO_ENCODED_RUSTFLAGS`/`CARGO_BUILD_RUSTFLAGS`/`DYLINT_RUSTFLAGS`）：
///   ambient flag 会静默改变 `clippy -D warnings`/`dylint -D warnings` 的判定（注入或抑制 lint），
///   破坏门的 fail-closed 语义。清掉使门**对环境无关**——dylint 步要的 `-D warnings` 经显式 `env` 重设。
const STRIPPED_ENV: &[&str] = &[
    "RUSTUP_TOOLCHAIN",
    "RUSTC",
    "RUSTDOC",
    "RUSTC_WRAPPER",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "DYLINT_RUSTFLAGS",
];

/// 构造清洗了 ambient 环境（再叠加显式 `env`）的 cargo 命令。先 `env_remove`（[`STRIPPED_ENV`]）
/// 再 set `env`——故 dylint 步显式传的 `DYLINT_RUSTFLAGS=-D warnings` 是该步该变量的唯一来源。
fn clean_cargo_cmd(args: &[&str], env: &[(&str, &str)], cwd: Option<&Path>) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    for var in STRIPPED_ENV {
        cmd.env_remove(var);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd
}

/// spawn 一个 cargo 门步，继承 stdio（用户实时看输出），校验退出码。
/// INVARIANT VERIFY-AGGREGATE-01：非零退出 ⇒ `Err`（不吞错）。
fn run_step(label: &str, args: &[&str], env: &[(&str, &str)], cwd: &Path) -> Result<()> {
    let status = clean_cargo_cmd(args, env, Some(cwd))
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
        } => match resolve_tool(tool_available(probe), opts.allow_missing_tools) {
            ToolAction::Run => run_step(step.label, step.args, step.env, root),
            ToolAction::SkipWarn => {
                eprintln!(
                    "verify: [跳过] `{}`（缺 `cargo {probe}`，--allow-missing-tools 宽限）。装：{install_hint}",
                    step.label
                );
                Ok(())
            }
            ToolAction::Fail => bail!(
                "verify: 缺 `cargo {probe}`（门步 `{}`）。装：{install_hint}\n（唯一门不建议绕过；确需可显式 --allow-missing-tools）",
                step.label
            ),
        },
    }
}

fn run_internal(check: InternalCheck) -> Result<()> {
    match check {
        InternalCheck::ContractValidate => run_check(&contract::validate::ContractValidate),
        InternalCheck::LayerDeps => run_check(&layerdeps::LayerDeps),
        InternalCheck::CodegenCheck => codegen::run(true),
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

    /// `clean_cargo_cmd` 须 `env_remove` 全部 ambient toolchain/flag 变量（防外部环境污染门结果），
    /// 且显式 `env`（如 dylint 的 `DYLINT_RUSTFLAGS`）在清洗后重设、为该步唯一来源。
    #[test]
    fn clean_cargo_cmd_strips_ambient_and_applies_explicit_env() {
        use std::ffi::OsStr;
        // 显式步：传 DYLINT_RUSTFLAGS ⇒ 它在 env_remove 后被重设为该值。
        let cmd = clean_cargo_cmd(&["dylint"], &[("DYLINT_RUSTFLAGS", "-D warnings")], None);
        let envs: Vec<(&OsStr, Option<&OsStr>)> = cmd.get_envs().collect();
        // toolchain + flag 变量（DYLINT_RUSTFLAGS 除外——本步显式重设）均须为「移除」(value=None)。
        for stripped in STRIPPED_ENV.iter().filter(|v| **v != "DYLINT_RUSTFLAGS") {
            assert!(
                envs.iter()
                    .any(|(k, v)| *k == OsStr::new(stripped) && v.is_none()),
                "{stripped} 应被 env_remove"
            );
        }
        assert!(
            envs.iter()
                .any(|(k, v)| *k == OsStr::new("DYLINT_RUSTFLAGS")
                    && *v == Some(OsStr::new("-D warnings"))),
            "显式 DYLINT_RUSTFLAGS 应在清洗后重设"
        );
        // 非显式步（env=&[]）：ambient DYLINT_RUSTFLAGS 也被移除，不被继承。
        let bare = clean_cargo_cmd(&["build"], &[], None);
        let bare_envs: Vec<(&OsStr, Option<&OsStr>)> = bare.get_envs().collect();
        assert!(
            bare_envs
                .iter()
                .any(|(k, v)| *k == OsStr::new("DYLINT_RUSTFLAGS") && v.is_none()),
            "非 dylint 步须移除 ambient DYLINT_RUSTFLAGS"
        );
    }
}
