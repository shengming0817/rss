use std::process::{Command, Output};

fn run(args: &[&str]) -> anyhow::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .map_err(Into::into)
}

#[test]
fn consistency_report_cli_emits_complete_deterministic_artifacts() -> anyhow::Result<()> {
    let first_json = run(&["consistency", "report", "--format", "json"])?;
    let second_json = run(&["consistency", "report", "--format", "json"])?;
    assert!(first_json.status.success(), "{:?}", first_json.stderr);
    assert_eq!(first_json.stdout, second_json.stdout);
    assert!(first_json.stderr.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&first_json.stdout)?;
    assert_eq!(json["schemaVersion"], 1);
    assert_eq!(json["status"], "passed");
    assert_eq!(json["activeHttpContractCount"], 20);
    assert_eq!(json["contracts"].as_array().map(Vec::len), Some(20));

    let first_markdown = run(&["consistency", "report", "--format", "md"])?;
    let second_markdown = run(&["consistency", "report", "--format", "md"])?;
    assert!(
        first_markdown.status.success(),
        "{:?}",
        first_markdown.stderr
    );
    assert_eq!(first_markdown.stdout, second_markdown.stdout);
    assert!(first_markdown.stderr.is_empty());
    let markdown = String::from_utf8(first_markdown.stdout)?;
    assert!(markdown.starts_with("# Consistency / Effect Posture\n"));
    assert!(markdown.contains("Status: **passed** · Active HTTP contracts: **20**"));
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
