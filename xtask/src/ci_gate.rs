//! Fixed GitHub Actions result gate.
//!
//! INVARIANT: CI-RESULT-GATE-01 { level = "Hard", exec = "native-compile", source = "code", facet = "typed-result-gate", native = "closed JobResult enum, strict FromStr parser, and exhaustive fail-closed result match" }.
//! INVARIANT: CI-RESULT-GATE-01 { level = "Medium", exec = "check", source = "code", facet = "workflow-parameter-binding", synthetic_red = "workflow_parameter_binding_rejects_drift", anti_vacuity = "committed_workflow_binds_every_result_parameter" }.

use anyhow::{Result, bail};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JobResult {
    Success,
    Failure,
    Cancelled,
    Skipped,
}

impl FromStr for JobResult {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            "cancelled" => Ok(Self::Cancelled),
            "skipped" => Ok(Self::Skipped),
            _ => bail!("unknown GitHub job result `{value}`"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Options {
    selector: JobResult,
    check: JobResult,
    test_affected: JobResult,
    integration_critical: JobResult,
}

pub(crate) fn parse_options(args: &[&str]) -> Result<Options> {
    let mut selector = None;
    let mut check = None;
    let mut test_affected = None;
    let mut integration_critical = None;
    let mut iter = args.iter().copied();
    while let Some(flag) = iter.next() {
        let value = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("ci gate argument {flag} is missing a value"))?;
        let slot = match flag {
            "--selector-result" => &mut selector,
            "--check-result" => &mut check,
            "--test-affected-result" => &mut test_affected,
            "--integration-critical-result" => &mut integration_critical,
            _ => bail!("ci gate unknown or duplicate argument: {flag}"),
        };
        if slot.replace(value.parse()?).is_some() {
            bail!("ci gate unknown or duplicate argument: {flag}");
        }
    }
    Ok(Options {
        selector: selector.ok_or_else(|| anyhow::anyhow!("ci gate missing --selector-result"))?,
        check: check.ok_or_else(|| anyhow::anyhow!("ci gate missing --check-result"))?,
        test_affected: test_affected
            .ok_or_else(|| anyhow::anyhow!("ci gate missing --test-affected-result"))?,
        integration_critical: integration_critical
            .ok_or_else(|| anyhow::anyhow!("ci gate missing --integration-critical-result"))?,
    })
}

pub(crate) fn run(options: &Options) -> Result<()> {
    let results = [
        ("selector", options.selector),
        ("check", options.check),
        ("test-affected", options.test_affected),
        ("integration-critical", options.integration_critical),
    ];
    let failed = results
        .into_iter()
        .filter_map(|(job, result)| match result {
            JobResult::Success => None,
            JobResult::Failure => Some(format!("{job}=Failure")),
            JobResult::Cancelled => Some(format!("{job}=Cancelled")),
            JobResult::Skipped => Some(format!("{job}=Skipped")),
        })
        .collect::<Vec<_>>();
    if failed.is_empty() {
        Ok(())
    } else {
        bail!("fixed CI jobs did not all succeed: {}", failed.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GREEN: &[&str] = &[
        "--selector-result",
        "success",
        "--check-result",
        "success",
        "--test-affected-result",
        "success",
        "--integration-critical-result",
        "success",
    ];

    const WORKFLOW_RESULT_BINDING: &[&str] = &[
        "cargo run --locked -p xtask -- ci gate \\",
        "--selector-result \"${{ needs.selector.result }}\" \\",
        "--check-result \"${{ needs.check.result }}\" \\",
        "--test-affected-result \"${{ needs.test-affected.result }}\" \\",
        "--integration-critical-result \"${{ needs.integration-critical.result }}\"",
    ];

    fn workflow_binds_all_result_parameters(workflow: &str) -> bool {
        let lines = workflow.lines().map(str::trim).collect::<Vec<_>>();
        lines
            .windows(WORKFLOW_RESULT_BINDING.len())
            .any(|window| window == WORKFLOW_RESULT_BINDING)
    }

    #[test]
    fn result_gate_accepts_exact_success_tuple() -> Result<()> {
        run(&parse_options(GREEN)?)
    }

    #[test]
    fn result_gate_rejects_every_non_success_state() -> Result<()> {
        for state in ["failure", "cancelled", "skipped"] {
            for flag in [
                "--selector-result",
                "--check-result",
                "--test-affected-result",
                "--integration-critical-result",
            ] {
                let mut args = GREEN.to_vec();
                let Some(index) = args.iter().position(|value| *value == flag) else {
                    bail!("test tuple omits {flag}");
                };
                let index = index + 1;
                args[index] = state;
                assert!(run(&parse_options(&args)?).is_err(), "{flag}={state}");
            }
        }
        Ok(())
    }

    #[test]
    fn result_gate_rejects_legacy_and_malformed_arguments() {
        assert!(parse_options(&["--plan", "plan.json"]).is_err());
        assert!(parse_options(&["--receipts", "receipts"]).is_err());
        assert!(parse_options(&["--selector-result", "unknown"]).is_err());
        for malformed in ["Success", " success", "success ", "SUCCESS", ""] {
            assert!(
                malformed.parse::<JobResult>().is_err(),
                "parser accepted `{malformed}`"
            );
        }
        assert!(
            parse_options(&[
                "--selector-result",
                "success",
                "--selector-result",
                "success",
            ])
            .is_err()
        );
    }

    #[test]
    fn committed_workflow_binds_every_result_parameter() {
        assert!(workflow_binds_all_result_parameters(include_str!(
            "../../.github/workflows/ci.yml"
        )));
    }

    #[test]
    fn workflow_parameter_binding_rejects_drift() {
        let workflow = include_str!("../../.github/workflows/ci.yml");
        for expected in &WORKFLOW_RESULT_BINDING[1..] {
            let drifted = workflow.replacen(expected, "--wrong-result \"failure\"", 1);
            assert!(
                !workflow_binds_all_result_parameters(&drifted),
                "accepted drift of `{expected}`"
            );
        }
        assert!(!workflow_binds_all_result_parameters(
            "cargo run --locked -p xtask -- ci gate"
        ));
    }
}
