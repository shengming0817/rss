//! Canonical local-CI entry guard for agent skills and project templates.
//!
//! INVARIANT: CI-LOCAL-ENTRY-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::missing_canonical_entry_is_rejected|tests::legacy_workspace_closeout_is_rejected|tests::makefile_canonical_targets_are_closed|tests::empty_carrier_set_is_rejected", anti_vacuity = "tests::canonical_carrier_set_is_accepted|tests::workspace_controlled_carriers_use_canonical_entry" } -- the six controlled agent/template carriers must funnel final local validation through `make ci CI_BASE=<ref>`; the Make targets must be unique exact recipes and flattened or bare CI executors must not return.

use std::collections::BTreeMap;
use std::fs;

use anyhow::{Context as _, Result};

use crate::diagnostic::{Finding, GovernanceCheck, finding, run_check};
use crate::workspace_root;

pub(crate) const CONTROLLED_PATHS: &[&str] = &[
    "CLAUDE.md",
    ".claude/skills/ship/SKILL.md",
    ".claude/skills/fix/SKILL.md",
    ".github/project-template/PROJECT.md",
    ".github/project-template/pr-comment.md",
    ".github/project-template/pull_request_template.md",
];

const CLOSEOUT_MARKERS: &[(&str, &[&str])] = &[
    ("CLAUDE.md", &["收尾统一运行"]),
    (
        ".claude/skills/ship/SKILL.md",
        &["**本地验证（label 后执行）**"],
    ),
    (
        ".claude/skills/fix/SKILL.md",
        &["**本地验证（label 后执行）**"],
    ),
    (
        ".github/project-template/PROJECT.md",
        &["pr-status/needs-review-again", "pr-status/needs-check-fix"],
    ),
    (
        ".github/project-template/pr-comment.md",
        &["ship/fix 默认执行本地 canonical"],
    ),
    (
        ".github/project-template/pull_request_template.md",
        &["本地通过（只分析已提交差异"],
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    MissingCarrier,
    EmptyCarrier,
    DuplicateCarrier,
    MissingCanonicalEntry,
    LegacyWorkspaceCloseout,
    LegacyFlatCommand,
    MakefileContract,
}

pub(crate) struct CiEntryGuard;

impl GovernanceCheck for CiEntryGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "ci-entry-guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Self::Rule>>)> {
        let root = workspace_root()?;
        let mut carriers = Vec::with_capacity(CONTROLLED_PATHS.len());
        for relative in CONTROLLED_PATHS {
            let path = root.join(relative);
            match fs::read_to_string(&path) {
                Ok(content) => carriers.push((*relative, content)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("读取 CI 入口受控载体 `{relative}` 失败"));
                }
            }
        }
        let borrowed = carriers
            .iter()
            .map(|(path, content)| (*path, content.as_str()))
            .collect::<Vec<_>>();
        let makefile = fs::read_to_string(root.join("Makefile")).context("读取 Makefile 失败")?;
        let mut findings = findings_for_contents(&borrowed);
        findings.extend(findings_for_makefile(&makefile));
        Ok((
            format!(
                "{} 个 CI 入口载体均使用 canonical `make ci`",
                CONTROLLED_PATHS.len()
            ),
            findings,
        ))
    }
}

pub(crate) fn run() -> Result<()> {
    run_check(&CiEntryGuard)
}

fn findings_for_contents(files: &[(&str, &str)]) -> Vec<Finding<Rule>> {
    let mut by_path = BTreeMap::<&str, Vec<&str>>::new();
    for (path, content) in files {
        if CONTROLLED_PATHS.contains(path) {
            by_path.entry(path).or_default().push(content);
        }
    }

    let mut findings = Vec::new();
    for path in CONTROLLED_PATHS {
        let Some(contents) = by_path.get(path) else {
            findings.push(finding(
                Rule::MissingCarrier,
                *path,
                "受控 CI 入口载体缺失，无法证明 canonical 本地验证漏斗",
            ));
            continue;
        };
        if contents.len() != 1 {
            findings.push(finding(
                Rule::DuplicateCarrier,
                *path,
                format!("受控载体必须恰好出现一次，实际 {} 次", contents.len()),
            ));
        }

        let content = contents[0];
        if content.trim().is_empty() {
            findings.push(finding(
                Rule::EmptyCarrier,
                *path,
                "受控载体为空，拒绝 vacuous pass",
            ));
            continue;
        }
        if !has_bound_canonical_make_ci(path, content) {
            findings.push(finding(
                Rule::MissingCanonicalEntry,
                *path,
                "必须包含 `make ci CI_BASE=<ref>`；worktree 形式仅允许在 make 与 ci 之间增加 `-C worktrees/...`",
            ));
        }
        if has_legacy_workspace_closeout(content) {
            findings.push(finding(
                Rule::LegacyWorkspaceCloseout,
                *path,
                "禁止直接恢复 verify/verify-fast/workspace-check 收尾；统一调用 canonical `make ci`",
            ));
        }
        if has_legacy_flat_command(content) {
            findings.push(finding(
                Rule::LegacyFlatCommand,
                *path,
                "禁止调用旧平铺、bare ci 或 top-level audit 入口；CI 内部仅使用 typed `ci <subcommand>`",
            ));
        }
    }
    findings
}

fn tokens(text: &str) -> Vec<&str> {
    text.split_whitespace()
        .map(|token| {
            token.trim_matches(|ch: char| {
                matches!(
                    ch,
                    '`' | '\''
                        | '"'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | ','
                        | '.'
                        | ':'
                        | ';'
                        | '\\'
                )
            })
        })
        .filter(|token| !token.is_empty())
        .collect()
}

fn has_canonical_make_ci(content: &str) -> bool {
    content.lines().any(|line| {
        let words = tokens(line);
        words.iter().enumerate().any(|(index, word)| {
            if *word != "make" {
                return false;
            }
            let ci_index = match words.get(index + 1).copied() {
                Some("ci") => index + 1,
                Some("-C") => {
                    let Some(directory) = words.get(index + 2).copied() else {
                        return false;
                    };
                    let worktree_directory =
                        directory.starts_with("worktrees/") || directory.contains("/worktrees/");
                    if !worktree_directory || words.get(index + 3).copied() != Some("ci") {
                        return false;
                    }
                    index + 3
                }
                _ => return false,
            };
            words[ci_index + 1..].iter().any(|argument| {
                argument
                    .strip_prefix("CI_BASE=")
                    .is_some_and(|value| !value.is_empty())
            })
        })
    })
}

fn has_bound_canonical_make_ci(path: &str, content: &str) -> bool {
    let markers = CLOSEOUT_MARKERS
        .iter()
        .find_map(|(candidate, markers)| (*candidate == path).then_some(*markers));
    let Some(markers) = markers else {
        return false;
    };
    markers.iter().all(|marker| {
        content
            .lines()
            .any(|line| line.contains(marker) && has_canonical_make_ci(line))
    })
}

fn has_legacy_workspace_closeout(content: &str) -> bool {
    content.lines().any(|line| {
        let words = tokens(line);
        words
            .windows(2)
            .any(|window| window == ["make", "verify"] || window == ["make", "verify-fast"])
            || cargo_like_invocations(&words).any(|(_, command_index)| {
                words.get(command_index).copied() == Some("check")
                    && words[command_index + 1..].contains(&"--workspace")
            })
            || xtask_command_indices(&words).into_iter().any(|index| {
                matches!(
                    words.get(index).copied(),
                    Some("verify") | Some("verify-fast")
                )
            })
    })
}

fn has_legacy_flat_command(content: &str) -> bool {
    content.lines().any(|line| {
        let words = tokens(line);
        xtask_command_indices(&words).into_iter().any(|index| {
            let Some(command) = words.get(index).copied() else {
                return false;
            };
            matches!(
                command,
                "ci-plan"
                    | "ci-gate"
                    | "ci-meta"
                    | "ci-core"
                    | "ci-security"
                    | "ci-coverage"
                    | "ci-integration"
                    | "audit"
            ) || command.starts_with("ci-core-")
                || (command == "ci"
                    && !matches!(
                        words.get(index + 1).copied(),
                        Some("local" | "full" | "plan" | "run" | "gate")
                    ))
        })
    })
}

fn xtask_command_indices(words: &[&str]) -> Vec<usize> {
    let mut commands = Vec::new();
    for (launcher_index, launcher) in words.iter().enumerate() {
        if *launcher != "cargo" && !launcher.ends_with("hack/cargo.sh") {
            continue;
        }
        if words.get(launcher_index + 1).copied() == Some("xtask") {
            commands.push(launcher_index + 2);
            continue;
        }
        let tail = &words[launcher_index + 1..];
        if tail.first().copied() != Some("run") {
            continue;
        }
        if let Some(separator) = tail.iter().position(|word| *word == "--")
            && cargo_run_targets_xtask(&tail[..separator])
        {
            commands.push(launcher_index + separator + 2);
        }
    }
    commands
}

fn cargo_run_targets_xtask(arguments: &[&str]) -> bool {
    arguments.windows(2).any(|window| {
        window == ["-p", "xtask"]
            || window == ["--package", "xtask"]
            || (window[0] == "--manifest-path" && xtask_manifest(window[1]))
    }) || arguments.iter().any(|argument| {
        matches!(*argument, "-pxtask" | "--package=xtask")
            || argument
                .strip_prefix("--manifest-path=")
                .is_some_and(xtask_manifest)
    })
}

fn xtask_manifest(path: &str) -> bool {
    path == "xtask/Cargo.toml" || path.ends_with("/xtask/Cargo.toml")
}

fn cargo_like_invocations<'a>(words: &'a [&'a str]) -> impl Iterator<Item = (usize, usize)> + 'a {
    words.iter().enumerate().filter_map(|(index, launcher)| {
        (*launcher == "cargo" || launcher.ends_with("hack/cargo.sh")).then_some((index, index + 1))
    })
}

fn findings_for_makefile(content: &str) -> Vec<Finding<Rule>> {
    let base_count = content
        .lines()
        .filter(|line| line.trim() == "CI_BASE ?= origin/develop")
        .count();
    let base_assignments = content
        .lines()
        .filter(|line| ci_base_assignment(line))
        .count();
    let ci = make_target_recipes(content, "ci");
    let full = make_target_recipes(content, "ci-full");
    if base_count == 1
        && base_assignments == 1
        && make_target_declarations(content, "ci") == 1
        && make_target_declarations(content, "ci-full") == 1
        && ci == [vec!["$(RSS_CARGO) xtask ci local --base \"$(CI_BASE)\""]]
        && full == [vec!["$(RSS_CARGO) xtask ci full"]]
    {
        Vec::new()
    } else {
        vec![finding(
            Rule::MakefileContract,
            "Makefile",
            "`ci` 必须精确委托 `ci local --base $(CI_BASE)`，`ci-full` 必须精确委托 `ci full`，默认 base 为 origin/develop",
        )]
    }
}

fn ci_base_assignment(line: &str) -> bool {
    let line = line.trim_start();
    if line.starts_with('#') {
        return false;
    }
    line.match_indices("CI_BASE").any(|(index, _)| {
        let boundary = index == 0
            || line[..index]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_whitespace() || ch == ':');
        let suffix = line[index + "CI_BASE".len()..].trim_start();
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

    fn canonical_fixture() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "CLAUDE.md",
                "收尾统一运行 `make ci CI_BASE=<remote>/develop`",
            ),
            (
                ".claude/skills/ship/SKILL.md",
                "**本地验证（label 后执行）**：运行 `make ci CI_BASE=<remote>/develop`",
            ),
            (
                ".claude/skills/fix/SKILL.md",
                "**本地验证（label 后执行）**：run make ci CI_BASE=origin/develop",
            ),
            (
                ".github/project-template/PROJECT.md",
                "pr-status/needs-review-again → make ci CI_BASE=upstream/develop\npr-status/needs-check-fix → make ci CI_BASE=upstream/develop",
            ),
            (
                ".github/project-template/pr-comment.md",
                "ship/fix 默认执行本地 canonical `make ci CI_BASE=<remote>/develop`",
            ),
            (
                ".github/project-template/pull_request_template.md",
                "- [ ] `make ci CI_BASE=origin/develop` 本地通过（只分析已提交差异；typed）",
            ),
        ]
    }

    fn has_rule(findings: &[Finding<Rule>], rule: Rule) -> bool {
        findings.iter().any(|finding| finding.rule == rule)
    }

    #[test]
    fn canonical_carrier_set_is_accepted() {
        let findings = findings_for_contents(&canonical_fixture());
        assert!(
            findings.is_empty(),
            "canonical fixture must pass: {findings:?}"
        );
    }

    #[test]
    fn workspace_controlled_carriers_use_canonical_entry() -> anyhow::Result<()> {
        let (summary, findings) = CiEntryGuard.check()?;
        assert!(summary.contains("6 个 CI 入口载体"), "{summary}");
        assert!(
            findings.is_empty(),
            "committed controlled carriers must pass: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn missing_canonical_entry_is_rejected() {
        let mut fixture = canonical_fixture();
        fixture[0].1 = "final validation described only in prose";
        let findings = findings_for_contents(&fixture);
        assert!(
            has_rule(&findings, Rule::MissingCanonicalEntry),
            "{findings:?}"
        );
        fixture = canonical_fixture();
        fixture[1].1 =
            "**本地验证（label 后执行）**：make ci-full\n最终收尾前 make ci CI_BASE=origin/develop";
        let findings = findings_for_contents(&fixture);
        assert!(
            has_rule(&findings, Rule::MissingCanonicalEntry),
            "unbound summary text must not satisfy the real closeout: {findings:?}"
        );
    }

    #[test]
    fn legacy_workspace_closeout_is_rejected() {
        let mut fixture = canonical_fixture();
        for red in [
            "make ci CI_BASE=origin/develop; make verify",
            "make ci CI_BASE=origin/develop; make verify-fast && cargo check --workspace",
            "make ci CI_BASE=origin/develop; ./hack/cargo.sh xtask verify --fast",
            "make ci CI_BASE=origin/develop; ./hack/cargo.sh check --workspace",
        ] {
            fixture[1].1 = red;
            let findings = findings_for_contents(&fixture);
            assert!(
                has_rule(&findings, Rule::LegacyWorkspaceCloseout),
                "must reject direct internal closeout `{red}`: {findings:?}"
            );
        }
    }

    #[test]
    fn flattened_ci_commands_are_rejected_but_typed_subcommands_are_allowed() {
        let mut fixture = canonical_fixture();
        fixture[3].1 = "pr-status/needs-review-again → make ci CI_BASE=origin/develop\npr-status/needs-check-fix → make ci CI_BASE=origin/develop\ncargo xtask ci-plan --event-path event.json";
        let findings = findings_for_contents(&fixture);
        assert!(has_rule(&findings, Rule::LegacyFlatCommand), "{findings:?}");

        fixture[3].1 = "pr-status/needs-review-again → make ci CI_BASE=origin/develop\npr-status/needs-check-fix → make ci CI_BASE=origin/develop\n./hack/cargo.sh xtask ci-plan --event-path event.json";
        let findings = findings_for_contents(&fixture);
        assert!(has_rule(&findings, Rule::LegacyFlatCommand), "{findings:?}");

        for red in [
            "make ci CI_BASE=origin/develop; cargo run --locked -p xtask -- ci-plan --event-path event.json",
            "make ci CI_BASE=origin/develop; cargo run --package=xtask -- ci-plan --event-path event.json",
            "make ci CI_BASE=origin/develop; cargo run --manifest-path xtask/Cargo.toml -- audit",
            "make ci CI_BASE=origin/develop; cargo xtask audit",
            "make ci CI_BASE=origin/develop; cargo xtask ci",
        ] {
            let project_red = Box::leak(
                format!("pr-status/needs-review-again → make ci CI_BASE=origin/develop\npr-status/needs-check-fix → make ci CI_BASE=origin/develop\n{red}")
                    .into_boxed_str(),
            );
            fixture[3].1 = project_red;
            let findings = findings_for_contents(&fixture);
            assert!(
                has_rule(&findings, Rule::LegacyFlatCommand),
                "must reject removed entry `{red}`: {findings:?}"
            );
        }

        fixture[3].1 = "pr-status/needs-review-again → make ci CI_BASE=origin/develop\npr-status/needs-check-fix → make ci CI_BASE=origin/develop\ncargo xtask ci plan --event-path event.json";
        let findings = findings_for_contents(&fixture);
        assert!(
            findings.is_empty(),
            "typed subcommand must pass: {findings:?}"
        );
    }

    #[test]
    fn empty_carrier_set_is_rejected() {
        let findings = findings_for_contents(&[]);
        assert!(has_rule(&findings, Rule::MissingCarrier), "{findings:?}");
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule == Rule::MissingCarrier)
                .count(),
            CONTROLLED_PATHS.len(),
            "every controlled carrier must be proven present"
        );
    }

    #[test]
    fn empty_and_duplicate_carriers_fail_closed() {
        let mut fixture = canonical_fixture();
        fixture[0].1 = " \n\t";
        fixture.push(("CLAUDE.md", "make ci CI_BASE=origin/develop"));
        let findings = findings_for_contents(&fixture);
        assert!(has_rule(&findings, Rule::EmptyCarrier), "{findings:?}");
        assert!(has_rule(&findings, Rule::DuplicateCarrier), "{findings:?}");
    }

    #[test]
    fn makefile_canonical_targets_are_closed() {
        let green = "CI_BASE ?= origin/develop\nci:\n\t$(RSS_CARGO) xtask ci local --base \"$(CI_BASE)\"\nci-full:\n\t$(RSS_CARGO) xtask ci full\n";
        assert!(findings_for_makefile(green).is_empty());
        for red in [
            green.replace("ci local --base \"$(CI_BASE)\"", "ci full"),
            green.replace("CI_BASE ?= origin/develop", "CI_BASE ?= HEAD"),
            green.replace(
                "ci-full:\n\t$(RSS_CARGO) xtask ci full",
                "ci-full:\n\t@true",
            ),
            green.replace(
                "ci:\n\t$(RSS_CARGO) xtask ci local --base \"$(CI_BASE)\"",
                "ci:\n\t$(RSS_CARGO) xtask ci local --base \"$(CI_BASE)\"\n\t$(RSS_CARGO) check --workspace",
            ),
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
