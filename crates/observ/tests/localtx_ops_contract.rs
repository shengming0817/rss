use observ::{LocalTxMetricPurpose, localtx_operations_descriptor};

const ALERT_RULES: &str = include_str!("../../../docs/ops/localtx-alerts.rules.yaml");
const DASHBOARD: &str =
    include_str!("../../../docs/ops/202607082104-1642-consistency-dashboard-checklist.md");
const RUNBOOK: &str =
    include_str!("../../../docs/runbooks/202607130312-1705-localtx-unsafe-settlement.md");
const RUNBOOK_INDEX: &str =
    include_str!("../../../docs/runbooks/202607082104-1642-consistency-ops-runbook-index.md");
const LOCALTX_RULES: &str = include_str!("../../../docs/rules/localtx.md");
const PROOF_REPORT: &str = include_str!("../../../docs/ops/localtx-proof-report.md");
const ADOPTION_TEMPLATE: &str =
    include_str!("../../../.specify/templates/overrides/localtx-tasks-template.md");

#[test]
fn dashboard_consumes_every_typed_localtx_metric_with_closed_labels() {
    let operations = localtx_operations_descriptor();
    assert!(operations.is_consistent());
    assert_eq!(
        operations.metrics().len(),
        4,
        "real descriptor anti-vacuity"
    );
    let mut deadline_diagnostics = 0;
    for metric in operations.metrics() {
        let query = match metric.purpose() {
            LocalTxMetricPurpose::RetryPressureDiagnostic => format!(
                "sum by (domain, contract_id, boundary, retry_class) (rate({}[5m]))",
                metric.name()
            ),
            LocalTxMetricPurpose::SettlementFinalStatus => format!(
                "sum by (domain, contract_id, boundary, final_status) (rate({}[5m]))",
                metric.name()
            ),
            LocalTxMetricPurpose::SettledAttemptCount => format!(
                "sum by (domain, contract_id, boundary, final_status, le) (rate({}_bucket[5m]))",
                metric.name()
            ),
            LocalTxMetricPurpose::DeadlineDiagnostic => {
                deadline_diagnostics += 1;
                format!(
                    "sum by (domain, contract_id, boundary, stage) (rate({}[5m]))",
                    metric.name()
                )
            }
        };
        assert!(
            DASHBOARD.contains(&query),
            "dashboard omits exact query/labels for {}",
            metric.name()
        );
    }
    assert!(
        DASHBOARD.contains("sum by (boundary, final_status) (rate(tx_settlement_final_total[5m]))")
    );
    assert_eq!(
        deadline_diagnostics, 1,
        "typed deadline metric anti-vacuity"
    );
    assert!(
        DASHBOARD.contains("Diagnostic only; no paging"),
        "deadline diagnostic must have an explicit non-paging dashboard contract"
    );
}

#[test]
fn alert_rules_page_only_on_actionable_unsafe_settlements() {
    let operations = localtx_operations_descriptor();
    assert_eq!(operations.alerts().len(), 2, "real descriptor anti-vacuity");
    for alert in operations.alerts() {
        let expression = format!(
            "sum by (domain, contract_id, boundary) (increase({}{{final_status=\"{}\"}}[5m])) > 0",
            alert.metric().name(),
            alert.final_status().as_label()
        );
        assert!(
            ALERT_RULES.contains(alert.name()),
            "rules omit {}",
            alert.name()
        );
        assert!(
            ALERT_RULES.contains(&expression),
            "{} does not preserve the closed metric/label contract",
            alert.name()
        );
        assert!(
            ALERT_RULES.contains(&format!(
                "{}#{}",
                operations.runbook_path(),
                alert.runbook_anchor()
            )),
            "{} does not preserve its runbook anchor",
            alert.name()
        );
    }
    for (alert, status) in [
        ("GenericTxCommitUnknown", "commit_unknown"),
        ("GenericTxRollbackFailed", "rollback_failed"),
    ] {
        let expression = format!(
            "sum by (boundary) (increase(tx_settlement_final_total{{final_status=\"{status}\"}}[5m])) > 0"
        );
        assert!(ALERT_RULES.contains(alert), "rules omit {alert}");
        assert!(
            ALERT_RULES.contains(&expression),
            "{alert} does not preserve the closed metric/label contract"
        );
    }
    assert!(
        !ALERT_RULES.contains("tx_retry_final_total"),
        "generic retry exhaustion must not page"
    );
    assert!(
        !ALERT_RULES.contains("retry_status=\"exhausted\""),
        "retry exhaustion must not page"
    );
    for metric in operations
        .metrics()
        .iter()
        .filter(|metric| metric.purpose() == LocalTxMetricPurpose::DeadlineDiagnostic)
    {
        assert!(
            RUNBOOK.contains(metric.name()) && RUNBOOK_INDEX.contains(metric.name()),
            "typed deadline diagnostics must remain discoverable from the runbook and index"
        );
        assert!(
            !ALERT_RULES.contains(metric.name()),
            "typed deadline diagnostics must not acquire a paging alert"
        );
    }
}

#[test]
fn alerts_link_an_actionable_runbook() {
    for token in [
        "202607130312-1705-localtx-unsafe-settlement.md",
        "commit_unknown",
        "rollback_failed",
        "do not retry",
    ] {
        assert!(
            ALERT_RULES.contains(token) || RUNBOOK.contains(token),
            "operator contract omits {token}"
        );
    }
}

#[test]
fn generic_unsafe_warn_uses_the_metric_routing_scope_without_localtx_duplication() {
    for token in [
        "generic WARN routing fields are exactly",
        "`boundary` and",
        "`final_status`; both values come from the same closed settlement routing",
        "The generic runner is the only generic unsafe-settlement WARN emitter",
        "HTTP LocalTx keeps its contract-attributed WARN path",
    ] {
        assert!(
            RUNBOOK.contains(token),
            "runbook does not lock the generic metric/WARN routing contract: {token}"
        );
    }
}

#[test]
fn proof_report_consumers_observe_status_and_static_evidence_boundaries() {
    for token in [
        "cargo xtask localtx report --format json",
        "cargo xtask localtx report --format markdown",
        "`evidenceScope = \"staticInventory\"`",
        "`status = \"failed\"`",
        "exit code 0",
        "exit code non-zero",
        "stdout is empty",
        "byte-for-byte",
        "同一 static inventory",
        "atomic",
        "malformed TOML/Rust",
        "registry/journey",
        "symlink/root escape",
        "render failure",
        "截断文件",
        "does not run `promtool`",
        "does not run a real backend",
        "#1776",
        "does not replace",
        "JSON schema v1",
        "unknown field",
        "严格升序",
        "synthetic fixture",
        "不是当前 workspace 的 live proof",
        "operations.validation = \"referenceOnly\"",
        "operations.includedInReportStatus = false",
        "CI job/artifact 状态都不参与",
        "`ci-plan` job",
        "localtx-proof-${run_id}-${run_attempt}",
        "localtx-proof.json",
        "localtx-proof.md",
        "retention 为 30 days",
        "proof artifact 不会发布",
        "Azure carrier 不属于 #1777",
        "时间戳",
        "Git SHA",
        "主机名",
        "绝对路径",
        "tenant/device 实例",
        "secret",
        "payload",
        "SQL",
        "运行时结果",
    ] {
        assert!(
            PROOF_REPORT.contains(token),
            "proof-report consumer contract omits {token}"
        );
    }

    for unsupported in [
        "没有默认格式",
        "`md` alias",
        "`--output`",
        "live proof snapshot",
    ] {
        assert!(
            PROOF_REPORT.contains(unsupported),
            "proof-report compatibility/snapshot boundary omits {unsupported}"
        );
    }
    assert!(
        !PROOF_REPORT.contains("promtoolValidation"),
        "proof report must not publish a synthetic promtool status field"
    );
}

#[test]
fn proof_report_operations_are_anchored_to_existing_operator_carriers() {
    let operations = localtx_operations_descriptor();
    for token in operations
        .metrics()
        .iter()
        .map(|metric| metric.name())
        .chain(operations.alerts().iter().map(|alert| alert.name()))
        .chain([
            operations.rules_path(),
            operations.runbook_path(),
            "diagnostic-only",
            "referenceOnly",
            "includedInReportStatus = false",
        ])
    {
        assert!(
            PROOF_REPORT.contains(token),
            "proof report operations contract omits {token}"
        );
    }
    for token in [
        "localtx-proof-report.md",
        "cargo xtask localtx report --format json",
        "parse `status`",
        "report `status` excludes",
    ] {
        assert!(
            RUNBOOK.contains(token),
            "runbook does not consume the proof-report contract: {token}"
        );
    }
    for token in operations
        .metrics()
        .iter()
        .map(|metric| metric.name())
        .chain([operations.rules_path(), operations.runbook_path()])
    {
        assert!(
            ADOPTION_TEMPLATE.contains(token),
            "adoption template operations entry drifted from the typed descriptor: {token}"
        );
    }
}

#[test]
fn localtx_adoption_template_is_rated_as_a_planning_entry_not_enforcement() {
    for token in [
        "contract evidence",
        "generated check",
        "typed route marker",
        "backend profile/probes",
        "active journey",
        "metrics/alerts",
        "runbook/report consumption",
        "Hard",
        "Medium",
        "planning entry",
        "not an enforcement carrier",
    ] {
        assert!(
            LOCALTX_RULES.contains(token),
            "LocalTx adoption governance omits {token}"
        );
    }
    assert!(
        LOCALTX_RULES.contains("localtx-proof-report.md")
            && LOCALTX_RULES.contains("cargo xtask localtx report --format markdown"),
        "LocalTx rules do not link the canonical report consumer guidance"
    );
}
