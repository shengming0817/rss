//! Canonical local-CI executable entry guard.
//!
//! INVARIANT: CI-LOCAL-ENTRY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::canonical_wrapper_transfer_is_closed + tests::executable_wrapper_transfer_rejects_unreachable_canonical_text + tests::makefile_canonical_targets_are_closed", anti_vacuity = "tests::workspace_ci_entry_contract_is_closed" } -- the Make target and public wrapper must remain unique exact entries backed by the bounded committed-snapshot supervisor. Human-facing Markdown is intentionally not an enforcement carrier.

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
        Ok((
            "Makefile and Cargo wrapper canonical CI entries checked".to_string(),
            findings,
        ))
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

    let mut public_command = external_cmd(
        ExternalProgram::SystemShell,
        &[
            "hack/cargo.sh",
            "xtask",
            "ci",
            "local",
            "--base",
            "origin/develop",
            "--fail-fast",
        ],
        &[],
        Some(root),
    );
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
    let mut help_command = external_cmd(
        ExternalProgram::SystemShell,
        &["hack/cargo.sh", "xtask", "ci", "local", "--help"],
        &[],
        Some(root),
    );
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
