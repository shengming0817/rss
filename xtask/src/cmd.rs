//! xtask 子进程构造**单一漏斗** —— cargo 子进程经闭合 [`CargoSubcommand`] + [`cargo_cmd`]，
//! 非 cargo 程序经闭合 [`ExternalProgram`] + [`external_cmd`]；二者最终汇入私有 `clean_cmd`，
//! 先 `env_remove` ambient toolchain/flag 变量（[`STRIPPED_ENV`]）再叠加显式 env，使治理门与
//! codegen 派生**对环境无关**。
//!
//! 背景：`cargo xtask …` = `cargo run -p xtask`，子进程会继承父 cargo 设的 toolchain 环境：
//! - **toolchain 选择**（`RUSTUP_TOOLCHAIN`/`RUSTC`/`RUSTDOC`/`RUSTC_WRAPPER`）会**覆盖** per-dir
//!   `rust-toolchain.toml`（rustup 优先级 `RUSTUP_TOOLCHAIN` > `rust-toolchain.toml`），打破根 stable
//!   1.96 与 `lints/` nightly 隔离；并污染 `cargo-public-api` 内部 `rustup run nightly cargo rustdoc`
//!   的 nightly rustdoc-json 生成（其先 `cargo --version` 探测 stable 再强制 nightly，继承的
//!   `RUSTUP_TOOLCHAIN=1.96.0` 会把内层强拉回 stable ⇒ 隔离失效）。剥离对**所有步**成立。
//!   **public-api 步钉版**：剥离后由显式 `env` 把 `RUSTUP_TOOLCHAIN` 重设为 `publicapi::PINNED_NIGHTLY`
//!   （等价 `cargo +<钉版> public-api`），使 cargo-public-api 在钉版 nightly 下生成可复现 rustdoc-json
//!   （否则在 root stable 下被强制回退 rolling `nightly`，格式随日期漂移致 baseline 误报）——这是
//!   CMD-ENV-CLEAN-01「剥离后显式 env 成唯一来源」的标准用法，非隔离破例（NIGHTLY-PIN-01）。
//! - **编译 / rustdoc flag**（`RUSTFLAGS`/`CARGO_ENCODED_RUSTFLAGS`/`CARGO_BUILD_RUSTFLAGS`/
//!   `DYLINT_RUSTFLAGS`，以及 rustdoc 家族 `RUSTDOCFLAGS`/`CARGO_ENCODED_RUSTDOCFLAGS`/
//!   `CARGO_BUILD_RUSTDOCFLAGS`）会静默改变 `clippy -D warnings`/`dylint -D warnings` 判定，或经
//!   cfg-gate 改变 `cargo public-api`（走 rustdoc-json）的封装面快照符号集，破坏门 fail-closed 与
//!   baseline 可复现。
//!
//! 清掉这些使门**对环境无关**——某步显式要的 flag（如 dylint 的 `-D warnings`）经显式 `env` 重设。
//! `PATH` **不**清洗（rustup proxy 须可寻址）。stdio 由调用方在返回的 [`Command`] 上配置（本模块
//! 只构造、不碰 stdin/stdout/stderr，故 cargo 的 inherit/`null` 与 rustfmt 的 pipe 两种形态共用一个漏斗）。
//!
//! ref: Enselic/cargo-public-api rustdoc-json/src/builder.rs cargo_rustdoc_command()@main
//! ref: rust-lang/rustup doc/user-guide/src/overrides.md@main（toolchain 优先级表）
//!
//! INVARIANT: CMD-ENV-CLEAN-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— typed command API 构造的子进程恒先 `env_remove`([`STRIPPED_ENV`]) 再
//!   set 显式 env（显式 env 是该步该变量的唯一来源）。
//! INVARIANT: CMD-FUNNEL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— `xtask/src` 内 `Command::new(...)` 的**唯一合法构造点** = 本 `cmd.rs`
//!   的私有 `clean_cmd`；其余子进程一律须经 typed API。**上游**：cargo 首段只能由闭枚举产生，
//!   nextest capability 与 spawn API 仅对 `cmd::nextest` 子模块可见；**下游**：governance 测试用 `syn` AST 扫描
//!   `xtask/src` 每个 `.rs`（**含 cmd.rs 本体**，不豁免整文件），统计 `Command::new` 调用表达式——
//!   cmd.rs 恰 1（clean_cmd）、其它文件 0，越界即 fail（Medium，载体 4 governance test；AST 词法天然
//!   忽略字符串 / 注释内同名文本，无 text-scan 的盲区，故 fail-closed 而非「带已知绕过」）。上下游同守
//!   才闭环。dylint 未选用——funnel 是 xtask-local，dylint workspace-wide 会对其它 crate 合法
//!   `Command::new("cargo")` 误报、须额外 crate 作用域裁剪；AST 扫描天然限定 `xtask/src`，粒度恰好等于
//!   不变式边界。Hard 不可达（std `Command::new` 无法 seal）。

use std::path::Path;
use std::process::{Command, Stdio};

#[path = "nextest.rs"]
pub(crate) mod nextest;

/// 子进程须清洗的 ambient 环境变量——凡能改变门 **verdict** 者（toolchain 选择 / 编译器行为 / 编译
/// flag）皆清，语义见模块文档。charter：只清「改 verdict」的变量；`CARGO_TARGET_DIR` 等只改产物**落盘
/// 位置**、不改门结论的变量**不**清（用户/CI 常有意设它做缓存，cargo 对 target 有锁、无竞争损坏）。
pub(crate) const STRIPPED_ENV: &[&str] = &[
    // toolchain 选择
    "RUSTUP_TOOLCHAIN",
    "RUSTC",
    "RUSTDOC",
    "RUSTC_WRAPPER",
    // 编译器行为：RUSTC_BOOTSTRAP=1 让 stable 解锁 nightly 特性 ⇒ 改变 clippy/build 判定，须清。
    "RUSTC_BOOTSTRAP",
    // 编译 flag（静默改 `-D warnings` 判定 / 经 cfg-gate 改 public-api 符号面）
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "DYLINT_RUSTFLAGS",
    // rustdoc flag：`cargo public-api` baseline 走 rustdoc-json，ambient rustdoc flag 会经 cfg-gate
    // 等污染封装面快照（与 RUSTFLAGS 同类，作用于 rustdoc 执行路径）。cargo env-var 参考见模块文档 ref。
    "RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTDOCFLAGS",
    "CARGO_BUILD_RUSTDOCFLAGS",
];

/// 构造清洗了 ambient 环境（再叠加显式 `env`）的子进程命令。先 `env_remove`（[`STRIPPED_ENV`]）再
/// set `env`——故某步显式传的 env（如 dylint 的 `DYLINT_RUSTFLAGS=-D warnings`）是该步该变量的唯一
/// 来源。stdio 不在此设置（调用方按需 inherit / `null` / pipe）。
///
/// 私有最终构造器；调用方必须使用闭合 typed API，勿裸 `Command::new`（CMD-FUNNEL-01 守）。
///
/// INVARIANT: CMD-ENV-CLEAN-01 { level = "Medium", exec = "manual/opt-in", source = "code" }.
fn clean_cmd(program: &str, args: &[&str], env: &[(&str, &str)], cwd: Option<&Path>) -> Command {
    let mut cmd = Command::new(program);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalProgram {
    Rustfmt,
    Docker,
    #[cfg(test)]
    Bash,
    Git,
    SystemGit,
}

impl ExternalProgram {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Rustfmt => "rustfmt",
            Self::Docker => "docker",
            #[cfg(test)]
            Self::Bash => "bash",
            Self::Git => "git",
            Self::SystemGit => "/usr/bin/git",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CargoSubcommand {
    Metadata,
    Tree,
    Check,
    #[cfg(test)]
    GenerateLockfile,
    Fmt,
    Build,
    Test,
    Clippy,
    Deny,
    Audit,
    Dylint,
    PublicApi,
    LlvmCovReport,
}

impl CargoSubcommand {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Tree => "tree",
            Self::Check => "check",
            #[cfg(test)]
            Self::GenerateLockfile => "generate-lockfile",
            Self::Fmt => "fmt",
            Self::Build => "build",
            Self::Test => "test",
            Self::Clippy => "clippy",
            Self::Deny => "deny",
            Self::Audit => "audit",
            Self::Dylint => "dylint",
            Self::PublicApi => "public-api",
            Self::LlvmCovReport => "llvm-cov",
        }
    }
}

pub(crate) fn external_cmd(
    program: ExternalProgram,
    args: &[&str],
    env: &[(&str, &str)],
    cwd: Option<&Path>,
) -> Command {
    clean_cmd(program.as_str(), args, env, cwd)
}

pub(crate) fn source_revision(root: &Path) -> anyhow::Result<String> {
    let output = external_cmd(
        ExternalProgram::SystemGit,
        &["rev-parse", "--verify", "HEAD"],
        &[],
        Some(root),
    )
    .output()?;
    let revision = String::from_utf8(output.stdout)?.trim().to_owned();
    if !output.status.success()
        || revision.len() != 40
        || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        anyhow::bail!("无法取得严格 40-hex sourceRevision");
    }
    Ok(revision)
}

pub(crate) fn cargo_cmd(
    subcommand: CargoSubcommand,
    args: &[&str],
    env: &[(&str, &str)],
    cwd: Option<&Path>,
) -> Command {
    let mut argv = Vec::with_capacity(args.len() + 2);
    argv.push(subcommand.as_str());
    if subcommand == CargoSubcommand::LlvmCovReport {
        argv.push("report");
    }
    argv.extend_from_slice(args);
    clean_cmd("cargo", &argv, env, cwd)
}

/// 该 capability 与 spawn API 均为 cmd carrier 私有；仅子模块 `nextest` 可使用。
struct NextestCapability;

#[derive(Clone, Copy)]
enum NextestMode {
    Direct,
    LlvmCov,
}

fn nextest_cmd(
    _capability: NextestCapability,
    mode: NextestMode,
    args: &[&str],
    env: &[(&str, &str)],
    cwd: Option<&Path>,
) -> Command {
    let prefix: &[&str] = match mode {
        NextestMode::Direct => &["nextest", "run"],
        NextestMode::LlvmCov => &["llvm-cov", "nextest"],
    };
    let mut argv = Vec::with_capacity(prefix.len() + args.len());
    argv.extend_from_slice(prefix);
    argv.extend_from_slice(args);
    clean_cmd("cargo", &argv, env, cwd)
}

/// 探测闭合的第三方 cargo 子命令（静默，经 [`clean_cmd`] 清洗环境）。
pub(crate) fn tool_available(tool: CargoSubcommand) -> bool {
    clean_cmd("cargo", &[tool.as_str(), "--version"], &[], None)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn nextest_available(_capability: NextestCapability) -> bool {
    clean_cmd("cargo", &["nextest", "--version"], &[], None)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    // ---- CMD-ENV-CLEAN-01：clean_cmd 清洗 ambient + 显式 env 重设 ----

    /// `clean_cmd` 须设对 program/cwd、`env_remove` 全部 ambient toolchain/flag 变量（`get_envs()`
    /// value=None）、显式 `env` 在清洗后重设为该变量唯一来源。rstest 参数化覆盖 cargo / rustfmt 两类
    /// program（漏斗对二者同构）。INVARIANT: CMD-ENV-CLEAN-01 { level = "Medium", exec = "manual/opt-in", source = "code" }.
    #[rstest]
    #[case("cargo")]
    #[case("rustfmt")]
    fn clean_cmd_strips_ambient_and_applies_explicit_env(#[case] program: &str) {
        let cwd = Path::new("/tmp");
        let cmd = clean_cmd(
            program,
            &["--edition", "2024"],
            &[("DYLINT_RUSTFLAGS", "-D warnings")],
            Some(cwd),
        );
        assert_eq!(cmd.get_program(), OsStr::new(program));
        assert_eq!(cmd.get_current_dir(), Some(cwd));
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
    }

    /// 非显式步（env=&[]）：**全部** ambient `STRIPPED_ENV` 变量都被移除、不被继承；无 cwd 则不设
    /// current_dir。（参数化测试因显式重设 DYLINT_RUSTFLAGS 而 filter 掉它，本测试补「不传显式 env
    /// 时全量移除」路径。）
    #[test]
    fn clean_cmd_bare_strips_all_ambient_and_no_cwd() {
        let bare = clean_cmd("cargo", &["build"], &[], None);
        let envs: Vec<(&OsStr, Option<&OsStr>)> = bare.get_envs().collect();
        for stripped in STRIPPED_ENV {
            assert!(
                envs.iter()
                    .any(|(k, v)| *k == OsStr::new(stripped) && v.is_none()),
                "非显式步须移除 ambient {stripped}"
            );
        }
        assert_eq!(bare.get_current_dir(), None);
    }

    #[test]
    fn typed_programs_preserve_exact_argv_and_close_llvm_cov_operation() {
        let metadata = cargo_cmd(
            CargoSubcommand::Metadata,
            &["--locked", "--no-deps"],
            &[],
            None,
        );
        assert_eq!(metadata.get_program(), OsStr::new("cargo"));
        assert_eq!(
            metadata.get_args().collect::<Vec<_>>(),
            ["metadata", "--locked", "--no-deps"].map(OsStr::new)
        );

        let test_no_run = cargo_cmd(
            CargoSubcommand::Test,
            &["-p", "postgres", "--features", "integration", "--no-run"],
            &[],
            None,
        );
        assert_eq!(
            test_no_run.get_args().collect::<Vec<_>>(),
            [
                "test",
                "-p",
                "postgres",
                "--features",
                "integration",
                "--no-run",
            ]
            .map(OsStr::new)
        );

        let report = cargo_cmd(
            CargoSubcommand::LlvmCovReport,
            &["--lcov", "--output-path", "target/report.lcov"],
            &[],
            None,
        );
        assert_eq!(
            report.get_args().collect::<Vec<_>>(),
            [
                "llvm-cov",
                "report",
                "--lcov",
                "--output-path",
                "target/report.lcov",
            ]
            .map(OsStr::new)
        );

        let git = external_cmd(
            ExternalProgram::SystemGit,
            &["status", "--short"],
            &[],
            None,
        );
        assert_eq!(git.get_program(), OsStr::new("/usr/bin/git"));
        assert_eq!(
            git.get_args().collect::<Vec<_>>(),
            ["status", "--short"].map(OsStr::new)
        );
    }

    // ---- CMD-FUNNEL-01：子进程构造唯一漏斗 governance AST 扫描（syn，含 cmd.rs 本体）----

    /// syn AST 访问者：统计 `Command::new(...)` 调用表达式个数（路径末两段 `Command`::`new`，
    /// 含 `std::process::Command::new`）。AST 级 ⇒ 字符串 / 注释内的同名文本不计（非调用表达式），
    /// 故无 text-scan 的注释 / 字符串盲区。
    #[derive(Default)]
    struct CommandNewCounter {
        count: usize,
    }

    impl<'ast> syn::visit::Visit<'ast> for CommandNewCounter {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(p) = node.func.as_ref() {
                let segs = &p.path.segments;
                let n = segs.len();
                if n >= 2 && segs[n - 1].ident == "new" && segs[n - 2].ident == "Command" {
                    self.count += 1;
                }
            }
            syn::visit::visit_expr_call(self, node); // 继续下探嵌套调用
        }
    }

    /// 一个 Rust 源文件里 `Command::new(...)` 调用表达式的个数；解析失败即 `Err`（非法源不该进扫描）。
    fn count_command_new(src: &str) -> syn::Result<usize> {
        let file = syn::parse_file(src)?;
        let mut c = CommandNewCounter::default();
        syn::visit::Visit::visit_file(&mut c, &file);
        Ok(c.count)
    }

    /// 扫 `xtask/src` 下所有 `.rs`（**含 cmd.rs**），返回 (每文件 `(路径, Command::new 调用数)`, 扫描 .rs 数)。
    fn scan_command_new(xtask_src: &Path) -> anyhow::Result<(Vec<(PathBuf, usize)>, usize)> {
        let mut per_file = Vec::new();
        let mut stack = vec![xtask_src.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir)? {
                let path = entry?.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(OsStr::to_str) == Some("rs") {
                    let count = count_command_new(&std::fs::read_to_string(&path)?)
                        .map_err(|e| anyhow::anyhow!("解析 {} 失败: {e}", path.display()))?;
                    per_file.push((path, count));
                }
            }
        }
        let scanned = per_file.len();
        Ok((per_file, scanned))
    }

    /// AST 扫描红例：真实 `Command::new(...)` 调用被计数——即使同行字符串内含 `//`（旧 text-scan 的
    /// 「已知盲区」现被抓到）、变量 program、完整路径 `std::process::Command::new` 亦然。anti-vacuity。
    #[test]
    fn count_command_new_catches_real_calls() -> syn::Result<()> {
        assert_eq!(
            count_command_new(
                r#"fn f() { let _u = "http://x"; let _c = Command::new("cargo"); }"#
            )?,
            1
        );
        assert_eq!(
            count_command_new("fn f() { let _ = Command::new(prog); }")?,
            1
        );
        assert_eq!(
            count_command_new("fn f() { std::process::Command::new(\"x\"); }")?,
            1
        );
        Ok(())
    }

    /// AST 扫描绿例：注释 / 字符串内提及 `Command::new(`、以及 `Command` 枚举变体（`Command::A`）均
    /// **不**计（非 `Command::new` 调用表达式）——证明扫描不误报。
    #[test]
    fn count_command_new_ignores_non_calls() -> syn::Result<()> {
        assert_eq!(
            count_command_new("// Command::new( in comment\nfn f() {}")?,
            0
        );
        assert_eq!(
            count_command_new(r#"fn f() { let _s = "Command::new(x)"; }"#)?,
            0
        );
        assert_eq!(
            count_command_new("enum Command { A } fn f() { let _ = Command::A; }")?,
            0
        );
        Ok(())
    }

    /// CMD-FUNNEL-01 真实绿例：`xtask/src` 每个 `.rs` 的 `Command::new` 调用数 = 唯一合法点
    /// （cmd.rs 恰 1 = clean_cmd，其它文件 0）；且确扫到多个 `.rs`（非空 anti-vacuity）。
    /// INVARIANT: CMD-FUNNEL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }.
    #[test]
    fn subprocess_funnel_only_sanctioned_command_new() -> anyhow::Result<()> {
        let xtask_src = crate::workspace_root()?.join("xtask").join("src");
        let cmd_rs = xtask_src.join("cmd.rs");
        let (per_file, scanned) = scan_command_new(&xtask_src)?;
        let violations: Vec<_> = per_file
            .iter()
            .filter_map(|(path, count)| {
                let allowed = usize::from(*path == cmd_rs); // cmd.rs 1（clean_cmd），其它文件 0
                (*count != allowed).then(|| (path.clone(), *count, allowed))
            })
            .collect();
        assert!(
            violations.is_empty(),
            "CMD-FUNNEL-01 违例 (文件, 实际 Command::new 数, 允许数)：{violations:?}；\
             子进程构造须经 cmd::clean_cmd（cmd.rs 仅 clean_cmd 内 1 处合法）"
        );
        assert!(
            scanned >= 5,
            "扫描应覆盖 xtask/src 多个 .rs（实际 {scanned}）"
        );
        Ok(())
    }
}
