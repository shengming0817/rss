use std::process::{Command, Output};

const ADOPTION_TEMPLATE: &str =
    include_str!("../../.specify/templates/overrides/localtx-tasks-template.md");

fn run(args: &[&str]) -> anyhow::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .map_err(Into::into)
}

fn assert_deterministic_success(first: &Output, second: &Output) {
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
    assert!(second.stderr.is_empty());
}

fn report_argv_from_template(template: &str) -> anyhow::Result<Vec<Vec<&str>>> {
    let mut commands = Vec::new();
    for inline_code in template
        .lines()
        .flat_map(|line| line.split('`').skip(1).step_by(2))
        .filter(|code| code.starts_with("cargo xtask localtx report "))
    {
        anyhow::ensure!(
            !inline_code
                .chars()
                .any(|character| matches!(character, '|' | '&' | ';' | '<' | '>')),
            "canonical command contains a pipeline or redirection metacharacter: {inline_code}"
        );
        let argv = inline_code.split_ascii_whitespace().collect::<Vec<_>>();
        anyhow::ensure!(
            argv.starts_with(&["cargo", "xtask"]),
            "canonical command must start with `cargo xtask`"
        );
        commands.push(argv[2..].to_vec());
    }
    anyhow::ensure!(
        commands.len() == 2,
        "expected two independent LocalTx report commands, found {}",
        commands.len()
    );
    Ok(commands)
}

#[test]
fn localtx_report_cli_emits_complete_deterministic_artifacts() -> anyhow::Result<()> {
    let first_json = run(&["localtx", "report", "--format", "json"])?;
    let second_json = run(&["localtx", "report", "--format", "json"])?;
    assert_deterministic_success(&first_json, &second_json);
    let json: serde_json::Value = serde_json::from_slice(&first_json.stdout)?;
    let mut expected_ids = generated::http::LOCAL_TX_SPECS
        .iter()
        .map(|spec| spec.route.contract_id())
        .collect::<Vec<_>>();
    expected_ids.sort();
    let actual_ids = json["contracts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|contract| contract["contractId"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(json["schemaVersion"], 1);
    assert_eq!(json["status"], "passed");
    assert_eq!(json["evidenceScope"], "staticInventory");
    assert_eq!(
        json["activeLocalTxContractCount"].as_u64(),
        Some(u64::try_from(expected_ids.len())?)
    );
    assert_eq!(actual_ids, expected_ids);
    assert_eq!(json["operations"]["validation"], "referenceOnly");
    assert_eq!(json["operations"]["includedInReportStatus"], false);
    assert_eq!(
        json["operations"]["retryPressure"]["classification"],
        "diagnosticOnly"
    );
    assert!(json.get("promtoolValidation").is_none());

    let first_markdown = run(&["localtx", "report", "--format", "markdown"])?;
    let second_markdown = run(&["localtx", "report", "--format", "markdown"])?;
    assert_deterministic_success(&first_markdown, &second_markdown);
    let markdown = String::from_utf8(first_markdown.stdout)?;
    assert!(markdown.starts_with("# LocalTx Proof Report\n"));
    assert!(markdown.contains(&format!(
        "Active LocalTx contracts: **{}**",
        expected_ids.len()
    )));
    assert!(markdown.ends_with('\n'));
    Ok(())
}

#[test]
fn adoption_template_report_commands_are_independent_executable_argv() -> anyhow::Result<()> {
    let commands = report_argv_from_template(ADOPTION_TEMPLATE)?;
    assert_eq!(
        commands,
        [
            vec!["localtx", "report", "--format", "json"],
            vec!["localtx", "report", "--format", "markdown"],
        ]
    );
    for argv in commands {
        let output = run(&argv)?;
        assert!(
            output.status.success(),
            "template command {argv:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty(), "template command {argv:?}");
    }

    let pipeline = ADOPTION_TEMPLATE.replace(
        "cargo xtask localtx report --format json",
        "cargo xtask localtx report --format json | tee proof.json",
    );
    assert!(
        report_argv_from_template(&pipeline).is_err(),
        "pipeline metacharacters must be rejected"
    );
    Ok(())
}

#[test]
fn localtx_report_cli_rejects_every_noncanonical_shape_without_stdout() -> anyhow::Result<()> {
    for args in [
        vec!["localtx", "report"],
        vec!["localtx", "report", "--format"],
        vec!["localtx", "report", "--format", "md"],
        vec!["localtx", "report", "--format", "json", "extra"],
        vec![
            "localtx", "report", "--format", "json", "--format", "markdown",
        ],
        vec!["localtx", "report", "--output", "report.json"],
    ] {
        let output = run(&args)?;
        assert!(!output.status.success(), "unexpectedly accepted {args:?}");
        assert!(output.stdout.is_empty(), "partial stdout for {args:?}");
        assert!(
            String::from_utf8(output.stderr)?
                .contains("cargo xtask localtx report --format <json|markdown>")
        );
    }
    Ok(())
}
