//! Canonical local-CI executable entry guard.
//!
//! INVARIANT: CI-LOCAL-ENTRY-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::makefile_canonical_targets_are_closed", anti_vacuity = "tests::workspace_makefile_contract_is_closed" } -- the Make targets must remain unique exact recipes backed by the bounded local-CI supervisor. Human-facing Markdown is intentionally not an enforcement carrier.

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
    const CI_RECIPE: &str = "/usr/bin/python3 hack/ci-local-supervisor.py --repo-root \"$(CURDIR)\" --budget-seconds 600 -- $(RSS_CARGO) xtask ci local --base \"$(CI_BASE)\"";
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
        && ci == [vec![CI_RECIPE]]
        && full == [vec!["$(RSS_CARGO) xtask ci full"]]
    {
        Vec::new()
    } else {
        vec![finding(
            Rule::MakefileContract,
            "Makefile",
            "`ci` 必须在 Cargo bootstrap 外由 600 秒 supervisor 精确委托 `ci local --base $(CI_BASE)`，`ci-full` 必须精确委托 `ci full`，默认 base 为 origin/develop",
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
        let green = "CI_BASE ?= origin/develop\nci:\n\t/usr/bin/python3 hack/ci-local-supervisor.py --repo-root \"$(CURDIR)\" --budget-seconds 600 -- $(RSS_CARGO) xtask ci local --base \"$(CI_BASE)\"\nci-full:\n\t$(RSS_CARGO) xtask ci full\n";
        assert!(findings_for_makefile(green).is_empty());
        for red in [
            green.replace("ci local --base \"$(CI_BASE)\"", "ci full"),
            green.replace("CI_BASE ?= origin/develop", "CI_BASE ?= HEAD"),
            green.replace(
                "ci-full:\n\t$(RSS_CARGO) xtask ci full",
                "ci-full:\n\t@true",
            ),
            green.replace(
                "ci local --base \"$(CI_BASE)\"",
                "ci local --base \"$(CI_BASE)\"\n\t$(RSS_CARGO) check --workspace",
            ),
            green.replace("--budget-seconds 600", "--budget-seconds 601"),
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
