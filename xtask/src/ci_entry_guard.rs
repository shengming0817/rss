//! Canonical local-CI executable entry guard.
//!
//! INVARIANT: CI-LOCAL-ENTRY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::canonical_wrapper_transfer_is_closed + tests::executable_wrapper_transfer_rejects_unreachable_canonical_text + tests::makefile_canonical_targets_are_closed", anti_vacuity = "tests::workspace_ci_entry_contract_is_closed" } -- the Make target and public wrapper must remain unique exact entries backed by the bounded committed-snapshot supervisor. Human-facing Markdown is intentionally not an enforcement carrier.
//! INVARIANT: CI-SELFTEST-TEMP-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::ci_selftest_temp_root_guard_rejects_unsafe_fixtures + tests::ci_selftest_temp_root_guard_rejects_symlinks", anti_vacuity = "tests::workspace_ci_entry_contract_is_closed" } -- every recursively discovered GitHub shell selftest that uses temporary storage must create one atomic, canonicalized TMP_ROOT; PID paths, fixed roots, and selftest symlinks fail closed.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, Result, bail};

use crate::cmd::{ExternalProgram, external_cmd};
use crate::diagnostic::{Finding, GovernanceCheck, finding, run_check};
use crate::workspace_root;

pub(crate) const CONTROLLED_PATHS: &[&str] = &["Makefile", "hack/cargo.sh"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    MakefileContract,
    WrapperContract,
    SelftestTempRoot,
}

pub(crate) struct CiEntryGuard;

impl GovernanceCheck for CiEntryGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "ci-entry-guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Self::Rule>>)> {
        let root = workspace_root()?;
        let makefile = fs::read_to_string(root.join("Makefile")).context("读取 Makefile 失败")?;
        let wrapper =
            fs::read_to_string(root.join("hack/cargo.sh")).context("读取 hack/cargo.sh 失败")?;
        let mut findings = findings_for_makefile(&makefile);
        findings.extend(findings_for_wrapper(&wrapper));
        if let Err(error) = wrapper_transfer_conformance(&wrapper) {
            findings.push(finding(
                Rule::WrapperContract,
                "hack/cargo.sh",
                format!(
                    "公开 `xtask ci local` 的可执行委托不符合 committed-snapshot supervisor 契约: {error:#}"
                ),
            ));
        }
        findings.extend(findings_for_github_selftests(&root));
        Ok((
            "Makefile, Cargo wrapper, and GitHub selftest CI entries checked".to_string(),
            findings,
        ))
    }
}

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
    let atomic_mktemp_dir = |value: &str| {
        value
            .strip_prefix("$(mktemp -d \"")
            .and_then(|value| value.strip_suffix("\")"))
            .is_some_and(|template| {
                (template.starts_with("${TMPDIR:-/tmp}/") || template.starts_with("${TMP_BASE%/}/"))
                    && template.ends_with(".XXXXXX")
                    && !template.contains('"')
                    && !template.contains("$(")
                    && !template.contains('`')
            })
    };
    let assignments = executable
        .iter()
        .filter_map(|line| assignment(line))
        .collect::<Vec<_>>();
    let has_tmp_base = assignments
        .iter()
        .any(|(name, value)| *name == "TMP_BASE" && *value == "${TMPDIR:-/tmp}");
    let requires_isolated_root = executable.iter().any(|line| {
        line.contains("TMP_ROOT")
            || line.contains("RUNNER_TEMP")
            || line.contains("/tmp")
            || line.contains("TMPDIR")
            || line.contains("TMP_BASE")
            || line.contains("$(mktemp")
            || line.contains("$$")
    });
    let creators = assignments
        .iter()
        .filter(|(name, value)| {
            *name == "TMP_ROOT"
                && atomic_mktemp_dir(value)
                && (!value.contains("TMP_BASE") || has_tmp_base)
        })
        .count();
    let canonicalizers = assignments
        .iter()
        .filter(|(name, value)| {
            *name == "TMP_ROOT" && *value == "$(CDPATH='' cd -- \"$TMP_ROOT\" && pwd -P)"
        })
        .count();
    let closed_root_syntax = executable.iter().all(|line| {
        if line.contains("TMP_ROOT=") {
            return assignment(line).is_some_and(|(name, value)| {
                name == "TMP_ROOT"
                    && (atomic_mktemp_dir(value)
                        || value == "$(CDPATH='' cd -- \"$TMP_ROOT\" && pwd -P)")
            });
        }
        if line.contains("TMP_BASE=") {
            return assignment(line)
                .is_some_and(|(name, value)| name == "TMP_BASE" && value == "${TMPDIR:-/tmp}");
        }
        !line.contains("/tmp")
            && !line.contains("TMPDIR")
            && !line.contains("TMP_BASE")
            && !line.contains("$(mktemp")
    });
    let unsafe_temp_assignment = assignments.iter().any(|(name, value)| {
        let references_temp_base = value.contains("/tmp")
            || value.contains("TMPDIR")
            || value.contains("TMP_BASE")
            || value.contains("mktemp");
        references_temp_base
            && !(*name == "TMP_BASE" && *value == "${TMPDIR:-/tmp}")
            && !(*name == "TMP_ROOT" && atomic_mktemp_dir(value))
    });
    !executable.iter().any(|line| line.contains("$$"))
        && closed_root_syntax
        && !unsafe_temp_assignment
        && (!requires_isolated_root || (creators == 1 && canonicalizers == 1))
        && assignments.iter().all(|(name, value)| {
            *name != "TMP_ROOT"
                || atomic_mktemp_dir(value)
                || *value == "$(CDPATH='' cd -- \"$TMP_ROOT\" && pwd -P)"
        })
}

fn github_selftests(root: &Path) -> Result<Vec<(String, String)>> {
    fn collect(path: &Path, root: &Path, discovered: &mut Vec<(String, String)>) -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".selftest.sh"))
            {
                bail!("CI selftest 不得是 symlink: {}", path.display());
            }
            return Ok(());
        }
        if metadata.is_dir() {
            let mut entries = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
            entries.sort_by_key(fs::DirEntry::file_name);
            for entry in entries {
                collect(&entry.path(), root, discovered)?;
            }
        } else if metadata.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".selftest.sh"))
        {
            discovered.push((
                path.strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/"),
                fs::read_to_string(path)?,
            ));
        }
        Ok(())
    }

    let mut discovered = Vec::new();
    collect(&root.join(".github"), root, &mut discovered)?;
    Ok(discovered)
}

fn findings_for_github_selftests(root: &Path) -> Vec<Finding<Rule>> {
    let discovered = match github_selftests(root) {
        Ok(discovered) => discovered,
        Err(error) => {
            return vec![finding(
                Rule::SelftestTempRoot,
                ".github",
                format!("递归读取 GitHub selftest 闭包失败: {error:#}"),
            )];
        }
    };
    let has_atomic_carrier = discovered.iter().any(|(_, source)| {
        source
            .lines()
            .map(shell_executable_prefix)
            .any(|line| line.contains("TMP_ROOT"))
    });
    let unsafe_paths = discovered
        .iter()
        .filter_map(|(path, source)| {
            (!ci_selftest_tmp_root_is_atomic(source)).then_some(path.as_str())
        })
        .collect::<Vec<_>>();
    if discovered.is_empty() || !has_atomic_carrier || !unsafe_paths.is_empty() {
        vec![finding(
            Rule::SelftestTempRoot,
            ".github/**/*.selftest.sh",
            format!(
                "selftest 闭包必须非空且含实际原子 TMP_ROOT carrier；不安全文件: {}",
                unsafe_paths.join(", ")
            ),
        )]
    } else {
        Vec::new()
    }
}

fn findings_for_wrapper(content: &str) -> Vec<Finding<Rule>> {
    let required_once = [
        "[ \"$#\" -ge 3 ] && [ \"$1\" = xtask ] && [ \"$2\" = ci ] && [ \"$3\" = local ]",
        "--repo-root \"$repo_root\" --budget-seconds 600 --local-ci",
        "--cargo-wrapper \"$0\" -- \"$@\"",
        "if [ \"${1-}\" = __ci-local-worker ]; then",
        "fail \"internal local-CI inherited handshake is missing or invalid\"",
    ];
    let exact = required_once
        .iter()
        .all(|needle| content.matches(needle).count() == 1);
    let hidden_worker_is_not_public = content.matches("__ci-local-worker").count() == 1
        && !content.contains("xtask ci local|__ci-local-worker")
        && content.matches("--local-ci-worker").count() == 0;
    let help_is_transparent = content.contains("[ \"$#\" -eq 4 ]")
        && content.contains("[ \"$4\" = --help ] || [ \"$4\" = -h ]")
        && content.contains("exec cargo \"$@\"");
    if exact && hidden_worker_is_not_public && help_is_transparent {
        Vec::new()
    } else {
        vec![finding(
            Rule::WrapperContract,
            "hack/cargo.sh",
            "公开 `xtask ci local` 必须精确进入固定 600 秒 supervisor；help 保留 Clap 语义；内部 worker 必须只经 inherited handshake 进入且不得成为公开替代入口",
        )]
    }
}

static WRAPPER_PROBE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct WrapperProbeRoot(PathBuf);

impl WrapperProbeRoot {
    fn create() -> Result<Self> {
        let sequence = WRAPPER_PROBE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rss-ci-entry-guard-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).with_context(|| {
            format!("创建 wrapper executable probe 目录失败: {}", path.display())
        })?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for WrapperProbeRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn wrapper_transfer_conformance(content: &str) -> Result<()> {
    let probe = WrapperProbeRoot::create()?;
    let root = probe.path();
    let hack = root.join("hack");
    let bin = root.join("bin");
    fs::create_dir_all(&hack)?;
    fs::create_dir_all(&bin)?;

    let wrapper = hack.join("cargo.sh");
    fs::write(&wrapper, content)?;
    let supervisor_probe = root.join("supervisor.probe");
    fs::write(
        hack.join("ci-local-supervisor.py"),
        r#"import pathlib
import sys

root = pathlib.Path(__file__).resolve().parent.parent
observed = sys.argv[1:]
if len(observed) == 11:
    observed[1] = str(pathlib.Path(observed[1]).resolve())
    observed[6] = str(pathlib.Path(observed[6]).resolve())
expected = [
    "--repo-root", str(root),
    "--budget-seconds", "600",
    "--local-ci",
    "--cargo-wrapper", str(root / "hack" / "cargo.sh"),
    "--",
    "--base", "origin/develop", "--fail-fast",
]
if observed != expected:
    print(f"unexpected supervisor argv: {observed!r}", file=sys.stderr)
    raise SystemExit(42)
(root / "supervisor.probe").write_text("transferred\n", encoding="utf-8")
"#,
    )?;

    let help_probe = root.join("help.probe");
    let fake_cargo = bin.join("cargo");
    fs::write(
        &fake_cargo,
        "#!/bin/sh\nset -eu\n[ \"$#\" -eq 4 ]\n[ \"$1\" = xtask ]\n[ \"$2\" = ci ]\n[ \"$3\" = local ]\n[ \"$4\" = --help ]\nprintf 'help\\n' >\"$RSS_CI_ENTRY_HELP_PROBE\"\n",
    )?;
    let mut permissions = fs::metadata(&fake_cargo)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_cargo, permissions)?;

    let git = external_cmd(ExternalProgram::SystemGit, &["init", "-q"], &[], Some(root))
        .output()
        .context("启动 git init wrapper probe 失败")?;
    if !git.status.success() {
        bail!(
            "初始化 wrapper probe Git 仓库失败: {}",
            String::from_utf8_lossy(&git.stderr).trim()
        );
    }

    let mut public_command = crate::cmd::ci_wrapper_public_probe(root, &wrapper)?;
    let public = public_command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .context("启动 public local-CI wrapper probe 失败")?;
    if !public.status.success()
        || !matches!(
            fs::read_to_string(&supervisor_probe).as_deref(),
            Ok("transferred\n")
        )
    {
        bail!(
            "public transfer status={} stdout={} stderr={}",
            public.status,
            String::from_utf8_lossy(&public.stdout).trim(),
            String::from_utf8_lossy(&public.stderr).trim()
        );
    }

    let help_probe_arg = help_probe
        .to_str()
        .context("wrapper help probe path 不是 UTF-8")?;
    let mut help_command = crate::cmd::ci_wrapper_help_probe(root, &wrapper)?;
    let help = help_command
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("RSS_CI_ENTRY_HELP_PROBE", help_probe_arg)
        .output()
        .context("启动 local-CI help wrapper probe 失败")?;
    if !help.status.success() || !matches!(fs::read_to_string(&help_probe).as_deref(), Ok("help\n"))
    {
        bail!(
            "help transfer status={} stdout={} stderr={}",
            help.status,
            String::from_utf8_lossy(&help.stdout).trim(),
            String::from_utf8_lossy(&help.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn wrapper_transfer_conformance(_content: &str) -> Result<()> {
    bail!("wrapper executable conformance requires a POSIX host")
}

pub(crate) fn run() -> Result<()> {
    run_check(&CiEntryGuard)
}

fn findings_for_makefile(content: &str) -> Vec<Finding<Rule>> {
    const VERIFY_RECIPE: &str = "$(RSS_CARGO) xtask verify $(VERIFY_ARGS)";
    const VERIFY_FAST_RECIPE: &str = "$(RSS_CARGO) xtask verify --fast $(VERIFY_ARGS)";
    const CI_RECIPE: &str = "$(RSS_CARGO) xtask ci local --base \"$(CI_BASE)\" $(CI_ARGS)";
    const CI_FULL_RECIPE: &str = "$(RSS_CARGO) xtask ci full $(CI_ARGS)";
    let base_count = content
        .lines()
        .filter(|line| line.trim() == "CI_BASE ?= origin/develop")
        .count();
    let base_assignments = content
        .lines()
        .filter(|line| make_variable_assignment(line, "CI_BASE"))
        .count();
    let verify_args_count = content
        .lines()
        .filter(|line| line.trim() == "VERIFY_ARGS =")
        .count();
    let verify_args_assignments = content
        .lines()
        .filter(|line| make_variable_assignment(line, "VERIFY_ARGS"))
        .count();
    let ci_args_count = content
        .lines()
        .filter(|line| line.trim() == "CI_ARGS =")
        .count();
    let ci_args_assignments = content
        .lines()
        .filter(|line| make_variable_assignment(line, "CI_ARGS"))
        .count();
    let verify = make_target_recipes(content, "verify");
    let verify_fast = make_target_recipes(content, "verify-fast");
    let ci = make_target_recipes(content, "ci");
    let full = make_target_recipes(content, "ci-full");
    if base_count == 1
        && base_assignments == 1
        && verify_args_count == 1
        && verify_args_assignments == 1
        && ci_args_count == 1
        && ci_args_assignments == 1
        && make_target_declarations(content, "verify") == 1
        && make_target_declarations(content, "verify-fast") == 1
        && make_target_declarations(content, "ci") == 1
        && make_target_declarations(content, "ci-full") == 1
        && verify == [vec![VERIFY_RECIPE]]
        && verify_fast == [vec![VERIFY_FAST_RECIPE]]
        && ci == [vec![CI_RECIPE]]
        && full == [vec![CI_FULL_RECIPE]]
    {
        Vec::new()
    } else {
        vec![finding(
            Rule::MakefileContract,
            "Makefile",
            "`verify`/`verify-fast`/`ci`/`ci-full` 必须经受控参数变量精确委托；`ci` 经 wrapper 进入 600 秒 committed-snapshot supervisor，默认 base 为 origin/develop",
        )]
    }
}

fn make_variable_assignment(line: &str, variable: &str) -> bool {
    let line = line.trim_start();
    if line.starts_with('#') {
        return false;
    }
    line.match_indices(variable).any(|(index, _)| {
        let boundary = index == 0
            || line[..index]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_whitespace() || ch == ':');
        let suffix = line[index + variable.len()..].trim_start();
        boundary
            && (suffix.starts_with("?=")
                || suffix.starts_with(":=")
                || suffix.starts_with("+=")
                || suffix.starts_with("!=")
                || suffix.starts_with('='))
    })
}

fn make_target_declarations(content: &str, target: &str) -> usize {
    content
        .lines()
        .filter(|line| {
            if line.starts_with('\t') {
                return false;
            }
            let line = line.trim_start();
            if line.starts_with('#') {
                return false;
            }
            line.split_once(':')
                .is_some_and(|(targets, _)| targets.split_whitespace().any(|word| word == target))
        })
        .count()
}

fn make_target_recipes<'a>(content: &'a str, target: &str) -> Vec<Vec<&'a str>> {
    let header = format!("{target}:");
    let lines = content.lines().collect::<Vec<_>>();
    let mut recipes = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if *line != header {
            continue;
        }
        let recipe = lines[index + 1..]
            .iter()
            .take_while(|line| line.starts_with('\t'))
            .map(|line| line.trim_start_matches('\t'))
            .collect::<Vec<_>>();
        recipes.push(recipe);
    }
    recipes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_rule(findings: &[Finding<Rule>], rule: Rule) -> bool {
        findings.iter().any(|finding| finding.rule == rule)
    }

    #[test]
    fn workspace_ci_entry_contract_is_closed() -> anyhow::Result<()> {
        let (summary, findings) = CiEntryGuard.check()?;
        assert!(summary.contains("Cargo wrapper"), "{summary}");
        assert!(
            findings.is_empty(),
            "committed Makefile contract must pass: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn ci_selftest_temp_root_guard_rejects_unsafe_fixtures() {
        let green = "# TMP_ROOT=/tmp/comment-only.$$\n\
                     TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/fixture.XXXXXX\")\n\
                     TMP_ROOT=$(CDPATH='' cd -- \"$TMP_ROOT\" && pwd -P)\n";
        assert!(ci_selftest_tmp_root_is_atomic(green));
        assert!(ci_selftest_tmp_root_is_atomic(
            "printf 'selftest without temporary storage\\n'\n"
        ));
        assert!(ci_selftest_tmp_root_is_atomic(&format!(
            "{green}SCOPE=fixture-scope\nROOT=\"$TMP_ROOT/logs-$SCOPE\"\n"
        )));
        for red in [
            "TMP_ROOT=${TMPDIR:-/tmp}/fixture.$$\n",
            "TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/fixture.XXXXXX\")\n",
            "local TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/fixture.XXXXXX\")\n",
            "true && TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/fixture.XXXXXX\")\n",
            "ROOT=/tmp/alternate-name.$$\n",
            "ROOT=/tmp/fixed-root\n",
            "if true; then ROOT=/tmp/fixed; fi\n",
            "if true; then ROOT=$RUNNER_TEMP/fixed; fi\n",
            "if true; then ROOT=$(mktemp -d); fi\n",
            "ROOT=$RUNNER_TEMP/fixed\n",
            "ROOT=$(mktemp -d)\n",
            "export ROOT=/tmp/fixed\n",
            "TMP_ROOT=$(mktemp \"${TMPDIR:-/tmp}/fixture.XXXXXX\")\n",
            "TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/fixture\")\n",
            "TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/fixture.XXXXXX\" || printf /tmp/fixed)\n",
            "TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/fixture.XXXXXX\")\nTMP_ROOT=${TMPDIR:-/tmp}/second\n",
        ] {
            assert!(
                !ci_selftest_tmp_root_is_atomic(red),
                "unsafe fixture: {red}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn ci_selftest_temp_root_guard_rejects_symlinks() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let root = crate::testutil::unique_tmp("ci-entry-selftest-symlink");
        let nested = root.join(".github/nested");
        fs::create_dir_all(&nested)?;
        let target = root.join("target.selftest.sh");
        fs::write(
            &target,
            "TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/safe.XXXXXX\")\n",
        )?;
        symlink(&target, nested.join("linked.selftest.sh"))?;
        let findings = findings_for_github_selftests(&root);
        fs::remove_dir_all(&root)?;
        assert!(has_rule(&findings, Rule::SelftestTempRoot), "{findings:?}");
        Ok(())
    }

    #[test]
    fn ci_selftest_temp_root_guard_discovers_nested_aliases() -> anyhow::Result<()> {
        let root = crate::testutil::unique_tmp("ci-entry-selftest-nested");
        let scripts = root.join(".github/scripts");
        let nested = root.join(".github/fixtures/nested");
        fs::create_dir_all(&scripts)?;
        fs::create_dir_all(&nested)?;
        fs::write(
            scripts.join("safe.selftest.sh"),
            "TMP_ROOT=$(mktemp -d \"${TMPDIR:-/tmp}/safe.XXXXXX\")\n",
        )?;
        fs::write(nested.join("unsafe.selftest.sh"), "ROOT=/tmp/fixed\n")?;
        let discovered = github_selftests(&root)?;
        let findings = findings_for_github_selftests(&root);
        fs::remove_dir_all(&root)?;
        assert_eq!(
            discovered
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>(),
            [
                ".github/fixtures/nested/unsafe.selftest.sh",
                ".github/scripts/safe.selftest.sh",
            ]
        );
        assert!(has_rule(&findings, Rule::SelftestTempRoot), "{findings:?}");
        Ok(())
    }

    #[test]
    fn canonical_wrapper_transfer_is_closed() {
        let green = r#"if [ "$#" -eq 4 ] && [ "$1" = xtask ] && [ "$2" = ci ] && [ "$3" = local ] &&
    { [ "$4" = --help ] || [ "$4" = -h ]; }; then
    exec cargo "$@"
fi
if [ "$#" -ge 3 ] && [ "$1" = xtask ] && [ "$2" = ci ] && [ "$3" = local ]; then
    exec /usr/bin/python3 supervisor --repo-root "$repo_root" --budget-seconds 600 --local-ci \
        --cargo-wrapper "$0" -- "$@"
fi
if [ "${1-}" = __ci-local-worker ]; then
    fail "internal local-CI inherited handshake is missing or invalid"
fi
"#;
        assert!(findings_for_wrapper(green).is_empty());
        for red in [
            green.replace("--budget-seconds 600", "--budget-seconds 900"),
            green.replace("--local-ci", "--local-ci-worker"),
            green.replace("exec cargo \"$@\"", "exit 0"),
            green.replace(
                "fail \"internal local-CI inherited handshake is missing or invalid\"",
                ":",
            ),
            format!("{green}\n# public: xtask ci local|__ci-local-worker\n"),
        ] {
            assert!(
                has_rule(&findings_for_wrapper(&red), Rule::WrapperContract),
                "must reject drifted wrapper:\n{red}"
            );
        }
    }

    #[test]
    fn executable_wrapper_transfer_rejects_unreachable_canonical_text() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let green = fs::read_to_string(root.join("hack/cargo.sh"))?;
        wrapper_transfer_conformance(&green)?;
        let red = green.replacen(
            "if [ \"$#\" -ge 3 ] && [ \"$1\" = xtask ]",
            "if false && [ \"$#\" -ge 3 ] && [ \"$1\" = xtask ]",
            1,
        );
        assert_ne!(red, green, "wrapper transfer mutation must be live");
        assert!(
            wrapper_transfer_conformance(&red).is_err(),
            "unreachable canonical text must not satisfy executable conformance"
        );
        Ok(())
    }

    #[test]
    fn makefile_canonical_targets_are_closed() {
        let green = "CI_BASE ?= origin/develop\nVERIFY_ARGS =\nCI_ARGS =\nverify:\n\t$(RSS_CARGO) xtask verify $(VERIFY_ARGS)\nverify-fast:\n\t$(RSS_CARGO) xtask verify --fast $(VERIFY_ARGS)\nci:\n\t$(RSS_CARGO) xtask ci local --base \"$(CI_BASE)\" $(CI_ARGS)\nci-full:\n\t$(RSS_CARGO) xtask ci full $(CI_ARGS)\n";
        assert!(findings_for_makefile(green).is_empty());
        for red in [
            green.replace("ci local --base \"$(CI_BASE)\"", "ci full"),
            green.replace("CI_BASE ?= origin/develop", "CI_BASE ?= HEAD"),
            green.replace(
                "ci-full:\n\t$(RSS_CARGO) xtask ci full $(CI_ARGS)",
                "ci-full:\n\t@true",
            ),
            green.replace(
                "ci local --base \"$(CI_BASE)\"",
                "ci local --base \"$(CI_BASE)\"\n\t$(RSS_CARGO) check --workspace",
            ),
            green.replace(" $(VERIFY_ARGS)", ""),
            green.replace("verify-fast:\n", "verify-fast: verify-hooks\n"),
            green.replace(" $(CI_ARGS)", ""),
            format!("{green}override VERIFY_ARGS := --fail-fast\n"),
            format!("{green}override CI_ARGS := --fail-fast\n"),
            green.replace("VERIFY_ARGS =", "VERIFY_ARGS ?="),
            green.replace("CI_ARGS =", "CI_ARGS ?="),
            green.replace("$(RSS_CARGO) xtask ci local --base \"$(CI_BASE)\" ", ""),
            format!("{green}ci:\n\t$(RSS_CARGO) xtask ci local --base \"$(CI_BASE)\"\n"),
            format!("{green}ci: legacy-check\n"),
            format!("{green}ci: ; @true\n"),
            format!("{green}ci : ; @true\n"),
            format!("{green}ci\t: legacy-check\n"),
            format!("{green}ci: CI_BASE = HEAD\n"),
            format!("{green}CI_BASE := HEAD\n"),
            format!("{green}override CI_BASE := HEAD\n"),
            format!("{green}export CI_BASE := HEAD\n"),
        ] {
            assert!(
                has_rule(&findings_for_makefile(&red), Rule::MakefileContract),
                "must reject drifted Makefile:\n{red}"
            );
        }
    }
}
