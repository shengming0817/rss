//! Fixed GitHub Actions result gate.
//!
//! INVARIANT: CI-RESULT-GATE-01 { level = "Hard", exec = "native-compile", source = "code", facet = "typed-result-gate", native = "closed JobResult enum, strict FromStr parser (clap value_parser 委托同一漏斗), and exhaustive fail-closed result match" }.
//! INVARIANT: CI-RESULT-GATE-01 { level = "Medium", exec = "check", source = "code", facet = "workflow-parameter-binding", synthetic_red = "workflow_parameter_binding_rejects_drift", anti_vacuity = "committed_workflow_binds_every_result_parameter" }.

use anyhow::{Result, bail};
use clap::Args;
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

fn parse_job_result(value: &str) -> std::result::Result<JobResult, String> {
    value.parse().map_err(|err: anyhow::Error| err.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub(crate) struct Options {
    /// Append + validate 拒绝重复（clap Set 默认为 last-wins）。
    #[arg(long = "selector-result", value_parser = parse_job_result, action = clap::ArgAction::Append, required = true)]
    selector: Vec<JobResult>,
    #[arg(long = "check-result", value_parser = parse_job_result, action = clap::ArgAction::Append, required = true)]
    check: Vec<JobResult>,
    #[arg(long = "test-affected-result", value_parser = parse_job_result, action = clap::ArgAction::Append, required = true)]
    test_affected: Vec<JobResult>,
    #[arg(long = "integration-critical-result", value_parser = parse_job_result, action = clap::ArgAction::Append, required = true)]
    integration_critical: Vec<JobResult>,
}

impl Options {
    /// 每个 result flag 恰好一次。
    pub(crate) fn validate(&self) -> Result<()> {
        for (flag, values) in [
            ("--selector-result", self.selector.as_slice()),
            ("--check-result", self.check.as_slice()),
            ("--test-affected-result", self.test_affected.as_slice()),
            (
                "--integration-critical-result",
                self.integration_critical.as_slice(),
            ),
        ] {
            if values.len() != 1 {
                bail!("ci gate unknown or duplicate argument: {flag}");
            }
        }
        Ok(())
    }
}

pub(crate) fn run(options: &Options) -> Result<()> {
    let results = [
        ("selector", options.selector[0]),
        ("check", options.check[0]),
        ("test-affected", options.test_affected[0]),
        ("integration-critical", options.integration_critical[0]),
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

    fn parse_options(args: &[&str]) -> Result<Options> {
        use clap::Parser;
        #[derive(Parser)]
        #[command(name = "ci-gate")]
        struct Wrapper {
            #[command(flatten)]
            options: Options,
        }
        let options =
            Wrapper::try_parse_from(std::iter::once("ci-gate").chain(args.iter().copied()))?
                .options;
        options.validate()?;
        Ok(options)
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
            // clap value_parser 委托同一 FromStr 漏斗，拒绝对称畸形值。
            let mut args = GREEN.to_vec();
            args[1] = malformed;
            assert!(
                parse_options(&args).is_err(),
                "clap accepted malformed JobResult `{malformed}`"
            );
        }
        assert!(
            parse_options(&["--selector-result", "success", "--check-result", "success",]).is_err()
        );
        assert!(
            parse_options(&[
                "--selector-result",
                "success",
                "--selector-result",
                "success",
                "--check-result",
                "success",
                "--test-affected-result",
                "success",
                "--integration-critical-result",
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
