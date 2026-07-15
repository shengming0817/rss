//! xtask 子进程构造**单一漏斗** —— cargo 子进程经闭合 [`CargoSubcommand`] + [`cargo_cmd`]，
//! 非 cargo 程序经闭合 [`ExternalProgram`] + [`external_cmd`]；二者最终汇入私有 `clean_cmd`，
//! 先 `env_remove` ambient toolchain/flag 变量（[`STRIPPED_ENV`]）再叠加显式 env，使治理门与
//! codegen 派生**对环境无关**。
//!
//! 背景：`cargo xtask …` = `cargo run -p xtask`，子进程会继承父 cargo 设的 toolchain 环境：
//! - **toolchain 选择**（`RUSTUP_TOOLCHAIN`/`RUSTC`/`RUSTDOC` 及 Cargo 的 rustc wrapper 家族）会**覆盖** per-dir
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
//! INVARIANT: COMPILER-CACHE-POLICY-01 { level = "Hard", exec = "native-compile", source = "code", native = "CompilerCachePolicy closed enum excludes unvalidated wrappers" }——Cargo/nextest 只能处于禁用缓存或使用已验证 sccache 两种状态。
//! INVARIANT: COMPILER-CACHE-POLICY-02 { level = "Medium", exec = "manual/opt-in", source = "code", synthetic_red = "compiler_cache_validates_canonical_absolute_exact_version", anti_vacuity = "enabled_policy_overrides_ambient_wrapper_and_incremental" }——缓存候选须为 canonical absolute executable 且版本精确，启用后统一覆盖 wrapper/incremental/fail-open I/O policy。

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

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
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
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

const COMPILER_CACHE_MODE_ENV: &str = "RSS_COMPILER_CACHE";
const INTERNAL_SCCACHE_PATH_ENV: &str = "RSS_INTERNAL_SCCACHE_PATH";
const SCCACHE_VERSION: &str = env!("RSS_TOOL_VERSION_SCCACHE");
const COMPILER_WRAPPER_ENV: &[&str] = &[
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
];

mod validated_sccache {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct ValidatedSccache(PathBuf);

    impl ValidatedSccache {
        pub(super) fn validate(candidate: &Path) -> anyhow::Result<Self> {
            if !candidate.is_absolute() {
                anyhow::bail!("sccache 路径必须是绝对路径: {}", candidate.display());
            }
            let metadata = fs::symlink_metadata(candidate).map_err(|error| {
                anyhow::anyhow!("读取 sccache 元数据失败 {}: {error}", candidate.display())
            })?;
            if metadata.file_type().is_symlink() {
                anyhow::bail!("sccache 路径不得是符号链接: {}", candidate.display());
            }
            if !metadata.is_file() || !is_executable(&metadata) {
                anyhow::bail!("sccache 必须是可执行普通文件: {}", candidate.display());
            }
            let canonical = fs::canonicalize(candidate).map_err(|error| {
                anyhow::anyhow!("sccache 路径不可解析 {}: {error}", candidate.display())
            })?;
            if canonical != candidate {
                anyhow::bail!("sccache 路径必须是 canonical path: {}", candidate.display());
            }
            let program = canonical
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("sccache canonical path 必须是 UTF-8"))?;
            let output = clean_cmd(program, &["--version"], &[], None)
                .output()
                .map_err(|error| anyhow::anyhow!("执行 sccache 版本探测失败: {error}"))?;
            if !output.status.success() {
                anyhow::bail!("sccache 版本探测失败: exit={}", output.status);
            }
            let version = String::from_utf8(output.stdout)
                .map_err(|_| anyhow::anyhow!("sccache --version 输出必须是 UTF-8"))?;
            let expected = format!("sccache {SCCACHE_VERSION}");
            if version != expected && version != format!("{expected}\n") {
                anyhow::bail!(
                    "sccache 版本不匹配：要求 {SCCACHE_VERSION}，实际 {:?}",
                    version
                );
            }
            Ok(Self(canonical))
        }

        pub(super) fn path(&self) -> &Path {
            &self.0
        }
    }
}

use validated_sccache::ValidatedSccache;

/// xtask 内部 Cargo 的编译缓存状态闭集。`Sccache` 变体仅由 [`Self::resolve`] 在完成路径、权限和
/// 真实版本探测后构造；调用点无法表达“未经验证的 wrapper”状态。
#[derive(Debug, Clone, PartialEq, Eq)]
enum CompilerCachePolicy {
    Disabled,
    Sccache(ValidatedSccache),
}

impl CompilerCachePolicy {
    fn from_env() -> anyhow::Result<Self> {
        Self::resolve(
            env::var_os(COMPILER_CACHE_MODE_ENV).as_deref(),
            env::var_os(INTERNAL_SCCACHE_PATH_ENV).as_deref(),
            env::var_os("PATH").as_deref(),
        )
    }

    fn resolve(
        mode: Option<&OsStr>,
        internal_candidate: Option<&OsStr>,
        path: Option<&OsStr>,
    ) -> anyhow::Result<Self> {
        match mode.and_then(OsStr::to_str).unwrap_or("auto") {
            "off" => return Ok(Self::Disabled),
            "auto" => {}
            value => anyhow::bail!("{COMPILER_CACHE_MODE_ENV} 仅允许 auto|off，收到 {value:?}"),
        }
        if mode.is_some_and(|value| value.to_str().is_none()) {
            anyhow::bail!("{COMPILER_CACHE_MODE_ENV} 必须是 UTF-8 的 auto|off");
        }

        if let Some(candidate) = internal_candidate {
            let candidate = Path::new(candidate);
            if !candidate.is_absolute() {
                anyhow::bail!("{INTERNAL_SCCACHE_PATH_ENV} 必须是绝对路径");
            }
            return ValidatedSccache::validate(candidate).map(Self::Sccache);
        }

        Ok(find_valid_sccache_on_path(path).map_or(Self::Disabled, Self::Sccache))
    }

    fn apply(&self, command: &mut Command) {
        // 位于 clean_cmd 的 caller 侧，确保任何显式 env 也不能绕过闭合 policy。
        for variable in COMPILER_WRAPPER_ENV {
            command.env_remove(variable);
        }
        if let Self::Sccache(wrapper) = self {
            command.env("RUSTC_WRAPPER", wrapper.path());
            command.env("CARGO_INCREMENTAL", "0");
            command.env("SCCACHE_IGNORE_SERVER_IO_ERROR", "1");
        }
    }
}

fn find_valid_sccache_on_path(path: Option<&OsStr>) -> Option<ValidatedSccache> {
    env::split_paths(path?)
        .filter_map(|directory| fs::canonicalize(directory).ok())
        .map(|physical_directory| physical_directory.join("sccache"))
        .find_map(|candidate| ValidatedSccache::validate(&candidate).ok())
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    true
}

fn apply_compiler_cache_policy(command: &mut Command) {
    static POLICY: OnceLock<Result<CompilerCachePolicy, String>> = OnceLock::new();
    match POLICY.get_or_init(|| CompilerCachePolicy::from_env().map_err(|error| error.to_string()))
    {
        Ok(policy) => policy.apply(command),
        Err(error) => {
            eprintln!("compiler-cache policy 配置错误: {error}");
            std::process::exit(78);
        }
    }
}

fn cargo_clean_cmd(args: &[&str], env: &[(&str, &str)], cwd: Option<&Path>) -> Command {
    let mut command = clean_cmd("cargo", args, env, cwd);
    apply_compiler_cache_policy(&mut command);
    command
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
    Xtask,
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
            Self::Xtask => "xtask",
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
    cargo_clean_cmd(&argv, env, cwd)
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
    cargo_clean_cmd(&argv, env, cwd)
}

/// 探测闭合的第三方 cargo 子命令（静默，经 [`clean_cmd`] 清洗环境）。
pub(crate) fn tool_available(tool: CargoSubcommand) -> bool {
    cargo_clean_cmd(&[tool.as_str(), "--version"], &[], None)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn nextest_available(_capability: NextestCapability) -> bool {
    cargo_clean_cmd(&["nextest", "--version"], &[], None)
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

    // ---- COMPILER-CACHE-POLICY-01：闭合 policy + exact executable validation ----

    #[test]
    fn compiler_cache_mode_is_closed_and_auto_without_candidate_is_disabled() -> anyhow::Result<()>
    {
        assert_eq!(
            CompilerCachePolicy::resolve(None, None, None)?,
            CompilerCachePolicy::Disabled
        );
        assert_eq!(
            CompilerCachePolicy::resolve(
                Some(OsStr::new("off")),
                Some(OsStr::new("forged/relative")),
                None,
            )?,
            CompilerCachePolicy::Disabled
        );
        let Err(error) = CompilerCachePolicy::resolve(Some(OsStr::new("on")), None, None) else {
            anyhow::bail!("未知 compiler-cache mode 应失败");
        };
        assert!(error.to_string().contains("RSS_COMPILER_CACHE"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn compiler_cache_validates_canonical_absolute_exact_version() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        fn relative_to_current_dir(target: &Path) -> anyhow::Result<PathBuf> {
            let current = std::fs::canonicalize(std::env::current_dir()?)?;
            let target = std::fs::canonicalize(target)?;
            let current = current.components().collect::<Vec<_>>();
            let target = target.components().collect::<Vec<_>>();
            let common = current
                .iter()
                .zip(&target)
                .take_while(|(left, right)| left == right)
                .count();
            anyhow::ensure!(common > 0, "temporary fixture must share a filesystem root");
            let mut relative = PathBuf::new();
            for _ in common..current.len() {
                relative.push("..");
            }
            for component in &target[common..] {
                relative.push(component.as_os_str());
            }
            Ok(relative)
        }

        let root = crate::testutil::unique_tmp("compiler-cache-policy");
        std::fs::create_dir_all(&root)?;
        let root = std::fs::canonicalize(root)?;
        let fixture_name = root
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("临时 sccache fixture 缺少目录名"))?;
        let relative_root = relative_to_current_dir(&root)?;
        let exact = root.join("sccache");
        std::fs::write(&exact, "#!/bin/sh\nprintf 'sccache 0.15.0\\n'\n")?;
        let mut permissions = std::fs::metadata(&exact)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&exact, permissions)?;

        let policy =
            CompilerCachePolicy::resolve(Some(OsStr::new("auto")), Some(exact.as_os_str()), None)?;
        let CompilerCachePolicy::Sccache(validated) = &policy else {
            anyhow::bail!("合法 sccache 应产生 enabled policy");
        };
        assert_eq!(validated.path(), std::fs::canonicalize(&exact)?);
        assert_eq!(
            CompilerCachePolicy::resolve(None, None, Some(root.as_os_str()))?,
            policy
        );

        let normalization_child = root.join("normalization-child");
        std::fs::create_dir_all(&normalization_child)?;
        let noncanonical_root = normalization_child.join("..");
        let relative_link =
            relative_root.with_file_name(format!("{}-link", fixture_name.to_string_lossy()));
        std::os::unix::fs::symlink(&root, &relative_link)?;
        for (label, directory) in [
            ("relative", relative_root.as_path()),
            ("noncanonical", noncanonical_root.as_path()),
            ("directory-symlink", relative_link.as_path()),
        ] {
            let candidate_path = env::join_paths([directory])?;
            assert_eq!(
                CompilerCachePolicy::resolve(None, None, Some(candidate_path.as_os_str()))?,
                policy,
                "auto 须将 {label} PATH 目录规范化到同一物理 executable"
            );
        }

        let invalid_dir = root.join("invalid-first");
        std::fs::create_dir_all(&invalid_dir)?;
        let invalid = invalid_dir.join("sccache");
        std::fs::write(&invalid, "#!/bin/sh\nprintf 'sccache 0.14.0\\n'\n")?;
        permissions = std::fs::metadata(&invalid)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&invalid, permissions)?;
        let invalid_then_valid = env::join_paths([invalid_dir.as_path(), root.as_path()])?;
        assert_eq!(
            CompilerCachePolicy::resolve(None, None, Some(invalid_then_valid.as_os_str()))?,
            policy,
            "auto 须跳过 PATH 中的坏候选并继续查找"
        );
        let invalid_only = env::join_paths([invalid_dir.as_path()])?;
        assert_eq!(
            CompilerCachePolicy::resolve(None, None, Some(invalid_only.as_os_str()))?,
            CompilerCachePolicy::Disabled,
            "auto 无合法 PATH 候选时须安全禁用"
        );

        let relative = Path::new("relative/sccache");
        assert!(CompilerCachePolicy::resolve(None, Some(relative.as_os_str()), None).is_err());

        let symlink = root.join("sccache-link");
        std::os::unix::fs::symlink(&exact, &symlink)?;
        assert!(CompilerCachePolicy::resolve(None, Some(symlink.as_os_str()), None).is_err());

        std::fs::write(&exact, "#!/bin/sh\nprintf 'sccache 0.14.0\\n'\n")?;
        assert!(CompilerCachePolicy::resolve(None, Some(exact.as_os_str()), None).is_err());

        permissions = std::fs::metadata(&exact)?.permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&exact, permissions)?;
        assert!(CompilerCachePolicy::resolve(None, Some(exact.as_os_str()), None).is_err());
        std::fs::remove_file(relative_link)?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn enabled_policy_overrides_ambient_wrapper_and_incremental() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let root = crate::testutil::unique_tmp("compiler-cache-apply");
        std::fs::create_dir_all(&root)?;
        let root = std::fs::canonicalize(root)?;
        let wrapper = root.join("sccache");
        std::fs::write(&wrapper, "#!/bin/sh\nprintf 'sccache 0.15.0\\n'\n")?;
        let mut permissions = std::fs::metadata(&wrapper)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&wrapper, permissions)?;
        let policy = CompilerCachePolicy::resolve(
            Some(OsStr::new("auto")),
            Some(wrapper.as_os_str()),
            None,
        )?;
        let explicit_wrappers = [
            ("RUSTC_WRAPPER", "/tmp/forged"),
            ("RUSTC_WORKSPACE_WRAPPER", "/tmp/forged-workspace"),
            ("CARGO_BUILD_RUSTC_WRAPPER", "/tmp/forged-config"),
            (
                "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
                "/tmp/forged-config-workspace",
            ),
        ];
        let mut command = clean_cmd(
            "cargo",
            &["check"],
            &[
                explicit_wrappers[0],
                explicit_wrappers[1],
                explicit_wrappers[2],
                explicit_wrappers[3],
                ("CARGO_INCREMENTAL", "1"),
                ("SCCACHE_IGNORE_SERVER_IO_ERROR", "0"),
            ],
            None,
        );
        policy.apply(&mut command);
        let envs = command.get_envs().collect::<Vec<_>>();
        assert!(envs.iter().any(|(key, value)| {
            *key == OsStr::new("RUSTC_WRAPPER") && *value == Some(wrapper.as_os_str())
        }));
        for stripped in [
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        ] {
            assert!(
                envs.iter()
                    .any(|(key, value)| { *key == OsStr::new(stripped) && value.is_none() })
            );
        }
        assert!(envs.iter().any(|(key, value)| {
            *key == OsStr::new("CARGO_INCREMENTAL") && *value == Some(OsStr::new("0"))
        }));
        assert!(envs.iter().any(|(key, value)| {
            *key == OsStr::new("SCCACHE_IGNORE_SERVER_IO_ERROR") && *value == Some(OsStr::new("1"))
        }));

        let mut disabled = clean_cmd("cargo", &["check"], &explicit_wrappers, None);
        CompilerCachePolicy::Disabled.apply(&mut disabled);
        let disabled_envs = disabled.get_envs().collect::<Vec<_>>();
        for stripped in COMPILER_WRAPPER_ENV {
            assert!(
                disabled_envs
                    .iter()
                    .any(|(key, value)| { *key == OsStr::new(stripped) && value.is_none() })
            );
        }
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

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
