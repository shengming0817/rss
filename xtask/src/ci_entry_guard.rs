//! Canonical local-CI executable entry guard.
//!
//! INVARIANT: CI-LOCAL-ENTRY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::makefile_canonical_targets_are_closed", anti_vacuity = "tests::workspace_makefile_contract_is_closed" } -- the Make targets must remain unique exact recipes backed by the bounded local-CI supervisor. Human-facing Markdown is intentionally not an enforcement carrier.

use std::fs;

use anyhow::{Context as _, Result};

use crate::diagnostic::{Finding, GovernanceCheck, finding, run_check};
use crate::workspace_root;

pub(crate) const CONTROLLED_PATHS: &[&str] = &["Makefile"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
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
        let makefile = fs::read_to_string(root.join("Makefile")).context("读取 Makefile 失败")?;
        Ok((
            "Makefile canonical CI targets checked".to_string(),
            findings_for_makefile(&makefile),
        ))
    }
}

pub(crate) fn run() -> Result<()> {
    run_check(&CiEntryGuard)
}

fn findings_for_makefile(content: &str) -> Vec<Finding<Rule>> {
    const VERIFY_RECIPE: &str = "$(RSS_CARGO) xtask verify $(VERIFY_ARGS)";
    const CI_RECIPE: &str = "/usr/bin/python3 hack/ci-local-supervisor.py --repo-root \"$(CURDIR)\" --budget-seconds 600 -- $(RSS_CARGO) xtask ci local --base \"$(CI_BASE)\" $(CI_ARGS)";
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
    let ci = make_target_recipes(content, "ci");
    let full = make_target_recipes(content, "ci-full");
    if base_count == 1
        && base_assignments == 1
        && verify_args_count == 1
        && verify_args_assignments == 1
        && ci_args_count == 1
        && ci_args_assignments == 1
        && make_target_declarations(content, "verify") == 1
        && make_target_declarations(content, "ci") == 1
        && make_target_declarations(content, "ci-full") == 1
        && verify == [vec![VERIFY_RECIPE]]
        && ci == [vec![CI_RECIPE]]
        && full == [vec![CI_FULL_RECIPE]]
    {
        Vec::new()
    } else {
        vec![finding(
            Rule::MakefileContract,
            "Makefile",
            "`verify`/`ci`/`ci-full` 必须经受控参数变量精确委托；`ci` 保持 600 秒 supervisor，默认 base 为 origin/develop",
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
    fn workspace_makefile_contract_is_closed() -> anyhow::Result<()> {
        let (summary, findings) = CiEntryGuard.check()?;
        assert!(summary.contains("Makefile"), "{summary}");
        assert!(
            findings.is_empty(),
            "committed Makefile contract must pass: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn makefile_canonical_targets_are_closed() {
        let green = "CI_BASE ?= origin/develop\nVERIFY_ARGS =\nCI_ARGS =\nverify:\n\t$(RSS_CARGO) xtask verify $(VERIFY_ARGS)\nci:\n\t/usr/bin/python3 hack/ci-local-supervisor.py --repo-root \"$(CURDIR)\" --budget-seconds 600 -- $(RSS_CARGO) xtask ci local --base \"$(CI_BASE)\" $(CI_ARGS)\nci-full:\n\t$(RSS_CARGO) xtask ci full $(CI_ARGS)\n";
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
            green.replace("--budget-seconds 600", "--budget-seconds 601"),
            green.replace(" $(VERIFY_ARGS)", ""),
            green.replace(" $(CI_ARGS)", ""),
            format!("{green}override VERIFY_ARGS := --fail-fast\n"),
            format!("{green}override CI_ARGS := --fail-fast\n"),
            green.replace("VERIFY_ARGS =", "VERIFY_ARGS ?="),
            green.replace("CI_ARGS =", "CI_ARGS ?="),
            green.replace(
                "/usr/bin/python3 hack/ci-local-supervisor.py --repo-root \"$(CURDIR)\" --budget-seconds 600 -- ",
                "",
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
