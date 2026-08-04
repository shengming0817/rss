use std::process::{Command, Output};

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
        vec!["localtx", "report", "--format", "SECRET_BAIT"],
    ] {
        let output = run(&args)?;
        assert_eq!(
            output.status.code(),
            Some(2),
            "expected clap exit 2 for {args:?}, got {:?}",
            output.status
        );
        assert!(output.stdout.is_empty(), "partial stdout for {args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("SECRET_BAIT"),
            "stderr leaked SECRET_BAIT for {args:?}: {stderr}"
        );
    }
    Ok(())
}
