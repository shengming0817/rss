use std::process::{Command, Output};

fn run(args: &[&str]) -> anyhow::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .map_err(Into::into)
}

fn assert_successful_pair(first: &Output, second: &Output) {
    assert!(first.status.success(), "{:?}", first.stderr);
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
}

fn assert_json_coverage(json: &serde_json::Value) {
    let coverage = &json["localOnlyReceiptCoverage"];
    assert_eq!(coverage["enforcement"], "failClosed");
    assert_eq!(coverage["evidence"], "sourceRegistered");
    assert_eq!(coverage["status"], "complete");
    assert_eq!(coverage["activeCount"], 6);
    assert_eq!(coverage["registeredCount"], 6);
    assert_eq!(coverage["missingCount"], 0);
    assert_eq!(coverage["missingContracts"], serde_json::json!([]));
}

fn assert_json_rows(json: &serde_json::Value) {
    assert_eq!(json["schemaVersion"], 4);
    assert_eq!(json["status"], "passed");
    assert_eq!(json["activeHttpContractCount"], 20);
    assert_eq!(json["contracts"].as_array().map(Vec::len), Some(20));
    assert_eq!(
        json["contracts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|contract| {
                contract["sourceReceiptRegistration"]
                    == serde_json::json!({
                        "enforcement": "failClosed",
                        "evidence": "sourceRegistered",
                        "status": "registered"
                    })
            })
            .count(),
        6
    );
    assert!(
        json["contracts"]
            .as_array()
            .into_iter()
            .flatten()
            .all(|contract| contract.get("runtimeConformance").is_none())
    );
}

#[test]
fn consistency_report_cli_emits_complete_deterministic_artifacts() -> anyhow::Result<()> {
    let first_json = run(&["consistency", "report", "--format", "json"])?;
    let second_json = run(&["consistency", "report", "--format", "json"])?;
    assert_successful_pair(&first_json, &second_json);
    let json: serde_json::Value = serde_json::from_slice(&first_json.stdout)?;
    assert_json_rows(&json);
    assert_json_coverage(&json);

    let first_markdown = run(&["consistency", "report", "--format", "md"])?;
    let second_markdown = run(&["consistency", "report", "--format", "md"])?;
    assert_successful_pair(&first_markdown, &second_markdown);
    let markdown = String::from_utf8(first_markdown.stdout)?;
    assert!(markdown.starts_with("# Consistency / Effect Posture\n"));
    assert!(markdown.contains("Static status: **passed** · Active HTTP contracts: **20**"));
    assert!(markdown.contains(
        "Source receipt registration (fail-closed; tests not executed): **6/6 registered** · Missing: **0**"
    ));
    assert!(markdown.ends_with('\n'));
    Ok(())
}

#[test]
fn consistency_report_cli_rejects_invalid_shape_without_stdout() -> anyhow::Result<()> {
    let output = run(&["consistency", "report", "--format", "markdown"])?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("cargo xtask consistency report --format <json|md>"));
    Ok(())
}
