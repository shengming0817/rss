use anyhow::Context as _;
use std::collections::BTreeSet;
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

fn generated_contract_ids(specs: &[generated::http::HttpSpec]) -> BTreeSet<String> {
    specs
        .iter()
        .map(|spec| spec.route.contract_id().to_owned())
        .collect()
}

fn report_contract_ids(rows: &[serde_json::Value]) -> anyhow::Result<Vec<String>> {
    rows.iter()
        .map(|contract| {
            contract["contractId"]
                .as_str()
                .map(str::to_owned)
                .context("consistency report row lacks contractId")
        })
        .collect()
}

fn assert_json_coverage(
    json: &serde_json::Value,
    rows: &[serde_json::Value],
    expected_ids: &BTreeSet<String>,
) -> anyhow::Result<()> {
    let coverage = &json["localOnlyReceiptCoverage"];
    assert_eq!(coverage["enforcement"], "failClosed");
    assert_eq!(coverage["evidence"], "sourceRegistered");
    assert_eq!(coverage["status"], "complete");
    assert_eq!(
        coverage["activeCount"].as_u64(),
        Some(u64::try_from(expected_ids.len())?)
    );
    assert_eq!(
        coverage["registeredCount"].as_u64(),
        Some(u64::try_from(expected_ids.len())?)
    );
    assert_eq!(coverage["missingCount"], 0);
    assert_eq!(coverage["missingContracts"], serde_json::json!([]));
    let registered_ids = rows
        .iter()
        .filter(|contract| {
            contract["sourceReceiptRegistration"]
                == serde_json::json!({
                    "enforcement": "failClosed",
                    "evidence": "sourceRegistered",
                    "status": "registered"
                })
        })
        .map(|contract| {
            contract["contractId"]
                .as_str()
                .map(str::to_owned)
                .context("registered consistency report row lacks contractId")
        })
        .collect::<anyhow::Result<BTreeSet<_>>>()?;
    assert_eq!(&registered_ids, expected_ids);
    Ok(())
}

fn assert_json_rows(
    json: &serde_json::Value,
    expected_ids: &BTreeSet<String>,
) -> anyhow::Result<Vec<serde_json::Value>> {
    assert_eq!(json["schemaVersion"], 4);
    assert_eq!(json["status"], "passed");
    let rows = json["contracts"]
        .as_array()
        .context("consistency report contracts must be an array")?;
    let actual_ids = report_contract_ids(rows)?;
    let actual_set = actual_ids.iter().cloned().collect::<BTreeSet<_>>();
    assert_eq!(actual_ids.len(), actual_set.len(), "duplicate contract ID");
    assert_eq!(&actual_set, expected_ids);
    assert_eq!(
        json["activeHttpContractCount"].as_u64(),
        Some(u64::try_from(expected_ids.len())?)
    );
    assert!(
        rows.iter()
            .all(|contract| contract.get("runtimeConformance").is_none())
    );
    Ok(rows.clone())
}

#[test]
fn consistency_report_cli_emits_complete_deterministic_artifacts() -> anyhow::Result<()> {
    let first_json = run(&["consistency", "report", "--format", "json"])?;
    let second_json = run(&["consistency", "report", "--format", "json"])?;
    assert_successful_pair(&first_json, &second_json);
    let json: serde_json::Value = serde_json::from_slice(&first_json.stdout)?;
    let expected_ids = generated_contract_ids(generated::http::SPECS);
    let expected_local_only_ids = generated_contract_ids(generated::http::LOCAL_ONLY_SPECS);
    assert!(!expected_ids.is_empty());
    assert!(!expected_local_only_ids.is_empty());
    let rows = assert_json_rows(&json, &expected_ids)?;
    assert_json_coverage(&json, &rows, &expected_local_only_ids)?;

    let first_markdown = run(&["consistency", "report", "--format", "md"])?;
    let second_markdown = run(&["consistency", "report", "--format", "md"])?;
    assert_successful_pair(&first_markdown, &second_markdown);
    let markdown = String::from_utf8(first_markdown.stdout)?;
    assert!(markdown.starts_with("# Consistency / Effect Posture\n"));
    assert!(markdown.contains(&format!(
        "Static status: **passed** · Active HTTP contracts: **{}**",
        expected_ids.len()
    )));
    assert!(markdown.contains(&format!(
        "Source receipt registration (fail-closed; tests not executed): **{0}/{0} registered** · Missing: **0**",
        expected_local_only_ids.len()
    )));
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
