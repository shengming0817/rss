//! Prometheus rule/test gate backed by one digest-pinned official image.
//!
//! INVARIANT: PROMTOOL-RULES-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::gate_rejects_missing_runner_bad_version_bad_rules_and_no_consumer", anti_vacuity = "tests::gate_accepts_rules_and_consuming_tests" }——
//! verify-fast and ci-meta execute the exact promtool version declared in the existing CI tool
//! catalog. Missing Docker, a catalog mismatch, invalid rules, or a test file without a real
//! alert-rule consumer fails closed.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

use crate::{
    cmd::{ExternalProgram, external_cmd},
    workspace_root,
};

const CATALOG: &str = ".github/scripts/ci-tool-catalog.txt";
const TESTS: &str = "docs/ops/outbox-relay-alerts.test.yaml";
const RULES_BASENAME: &str = "outbox-relay-alerts.rules.yaml";
const TESTS_BASENAME: &str = "outbox-relay-alerts.test.yaml";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Policy {
    version: String,
    image: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

trait Runner {
    fn run(&mut self, args: &[String]) -> Result<CommandOutput>;
}

struct DockerRunner;

impl Runner for DockerRunner {
    fn run(&mut self, args: &[String]) -> Result<CommandOutput> {
        let args = args.iter().map(String::as_str).collect::<Vec<_>>();
        let output = external_cmd(ExternalProgram::Docker, &args, &[], None)
            .output()
            .context("promtool gate: required `docker` executable is missing or failed to start")?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

pub(crate) fn run() -> Result<()> {
    let root = workspace_root()?;
    let catalog = std::fs::read_to_string(root.join(CATALOG))
        .with_context(|| format!("promtool gate: read {CATALOG}"))?;
    run_with(&root, &catalog, &mut DockerRunner)
}

fn run_with(root: &Path, catalog: &str, runner: &mut impl Runner) -> Result<()> {
    let policy = parse_policy(catalog)?;
    validate_consumer(&root.join(TESTS))?;

    let version = invoke(root, &policy, &["--version"], runner)?;
    let combined = format!("{}\n{}", version.stdout, version.stderr);
    if !version.success || !exact_version(&combined, &policy.version) {
        bail!(
            "promtool gate: version mismatch; expected exact promtool {} from {}",
            policy.version,
            policy.image
        );
    }

    let rules = invoke(root, &policy, &["check", "rules", RULES_BASENAME], runner)?;
    require_success("promtool check rules", rules)?;
    let tests = invoke(root, &policy, &["test", "rules", TESTS_BASENAME], runner)?;
    require_success("promtool test rules", tests)?;
    println!(
        "promtool: rules + consuming tests valid (version {}, digest-pinned image)",
        policy.version
    );
    Ok(())
}

fn parse_policy(catalog: &str) -> Result<Policy> {
    let mut matches = catalog
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .filter_map(|line| {
            let fields = line.split('|').collect::<Vec<_>>();
            (fields.first() == Some(&"promtool")).then_some(fields)
        });
    let fields = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("promtool gate: catalog has no promtool policy"))?;
    if matches.next().is_some()
        || fields.len() != 5
        || fields[2] != "docker"
        || fields[4] != "promtool"
        || !valid_semver(fields[1])
        || !digest_pinned_image(fields[3])
    {
        bail!("promtool gate: catalog promtool policy is malformed or ambiguous");
    }
    Ok(Policy {
        version: fields[1].to_owned(),
        image: fields[3].to_owned(),
    })
}

fn valid_semver(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn digest_pinned_image(value: &str) -> bool {
    let Some((repository, digest)) = value.split_once("@sha256:") else {
        return false;
    };
    repository == "prom/prometheus"
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_consumer(path: &Path) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("promtool gate: read consumer {}", path.display()))?;
    let active = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();
    let consumes_rules =
        active.contains(&"rule_files:") && active.contains(&"- outbox-relay-alerts.rules.yaml");
    let exercises_alerts = active.contains(&"tests:")
        && active.contains(&"alert_rule_test:")
        && active.contains(&"alertname: OutboxSameIdWindowExpired");
    if !consumes_rules || !exercises_alerts {
        bail!(
            "promtool gate: {} must consume the outbox rules and assert at least one alert",
            path.display()
        );
    }
    Ok(())
}

fn invoke(
    root: &Path,
    policy: &Policy,
    promtool_args: &[&str],
    runner: &mut impl Runner,
) -> Result<CommandOutput> {
    let mount = format!("{}:/workspace:ro", canonical_root(root)?.display());
    let mut args = vec![
        "run".to_owned(),
        "--rm".to_owned(),
        "--network=none".to_owned(),
        "--entrypoint=/bin/promtool".to_owned(),
        "--volume".to_owned(),
        mount,
        "--workdir=/workspace/docs/ops".to_owned(),
        policy.image.clone(),
    ];
    args.extend(promtool_args.iter().map(|arg| (*arg).to_owned()));
    runner.run(&args)
}

fn canonical_root(root: &Path) -> Result<PathBuf> {
    let canonical = root
        .canonicalize()
        .with_context(|| format!("promtool gate: canonicalize {}", root.display()))?;
    if canonical != root {
        bail!("promtool gate: workspace root must be a canonical physical path");
    }
    Ok(canonical)
}

fn exact_version(output: &str, expected: &str) -> bool {
    output.lines().any(|line| {
        line.strip_prefix("promtool, version ")
            .and_then(|tail| tail.split_whitespace().next())
            == Some(expected)
    })
}

fn require_success(label: &str, output: CommandOutput) -> Result<()> {
    if output.success {
        return Ok(());
    }
    let detail = output.stderr.lines().next().unwrap_or("no diagnostic");
    bail!("promtool gate: {label} failed: {detail}")
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::testutil::unique_tmp;

    const IMAGE: &str =
        "prom/prometheus@sha256:ddc2493835a1509976d5e4e0c94199c4f843ce1f42dd6bcfc8231ba734a93ff7";

    struct FakeRunner {
        outputs: VecDeque<Result<CommandOutput>>,
        calls: Vec<Vec<String>>,
    }

    struct Fixture(PathBuf);

    impl Fixture {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    impl Runner for FakeRunner {
        fn run(&mut self, args: &[String]) -> Result<CommandOutput> {
            self.calls.push(args.to_vec());
            self.outputs
                .pop_front()
                .unwrap_or_else(|| bail!("unexpected fake invocation"))
        }
    }

    fn catalog(version: &str) -> String {
        format!("promtool|{version}|docker|{IMAGE}|promtool\n")
    }

    fn fixture(test_yaml: &str) -> Result<Fixture> {
        let raw = unique_tmp("promtool-gate");
        std::fs::create_dir_all(&raw)?;
        let temp = Fixture(raw.canonicalize()?);
        let ops = temp.path().join("docs/ops");
        std::fs::create_dir_all(&ops)?;
        std::fs::write(ops.join("outbox-relay-alerts.rules.yaml"), "groups: []\n")?;
        std::fs::write(ops.join("outbox-relay-alerts.test.yaml"), test_yaml)?;
        Ok(temp)
    }

    fn consumer() -> &'static str {
        "rule_files:\n  - outbox-relay-alerts.rules.yaml\ntests:\n  - interval: 1m\n    alert_rule_test:\n      - eval_time: 1m\n        alertname: OutboxSameIdWindowExpired\n"
    }

    fn ok(stdout: &str) -> Result<CommandOutput> {
        Ok(CommandOutput {
            success: true,
            stdout: stdout.to_owned(),
            stderr: String::new(),
        })
    }

    #[test]
    fn gate_rejects_missing_runner_bad_version_bad_rules_and_no_consumer() -> Result<()> {
        let no_consumer = fixture("rule_files: []\ntests: []\n")?;
        let mut never = FakeRunner {
            outputs: VecDeque::new(),
            calls: Vec::new(),
        };
        assert!(run_with(no_consumer.path(), &catalog("3.5.3"), &mut never).is_err());
        assert!(never.calls.is_empty());

        let root = fixture(consumer())?;
        let mut missing = FakeRunner {
            outputs: VecDeque::from([Err(anyhow::anyhow!("docker missing"))]),
            calls: Vec::new(),
        };
        assert!(run_with(root.path(), &catalog("3.5.3"), &mut missing).is_err());

        let mut wrong_version = FakeRunner {
            outputs: VecDeque::from([ok("promtool, version 3.5.2")]),
            calls: Vec::new(),
        };
        assert!(run_with(root.path(), &catalog("3.5.3"), &mut wrong_version).is_err());

        let mut bad_rules = FakeRunner {
            outputs: VecDeque::from([
                ok("promtool, version 3.5.3"),
                Ok(CommandOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: "bad rule".to_owned(),
                }),
            ]),
            calls: Vec::new(),
        };
        assert!(run_with(root.path(), &catalog("3.5.3"), &mut bad_rules).is_err());
        Ok(())
    }

    #[test]
    fn gate_accepts_rules_and_consuming_tests() -> Result<()> {
        let root = fixture(consumer())?;
        let mut runner = FakeRunner {
            outputs: VecDeque::from([
                ok("promtool, version 3.5.3"),
                ok("SUCCESS: 1 rules found"),
                ok("SUCCESS"),
            ]),
            calls: Vec::new(),
        };
        run_with(root.path(), &catalog("3.5.3"), &mut runner)?;
        assert_eq!(runner.calls.len(), 3);
        assert!(
            runner
                .calls
                .iter()
                .all(|call| call.contains(&IMAGE.to_owned()))
        );
        assert_eq!(
            runner.calls[1].last().map(String::as_str),
            Some(RULES_BASENAME)
        );
        assert_eq!(
            runner.calls[2].last().map(String::as_str),
            Some(TESTS_BASENAME)
        );
        Ok(())
    }
}
